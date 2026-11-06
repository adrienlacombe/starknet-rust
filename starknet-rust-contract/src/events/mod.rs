//! Cairo 1/2 ABI event decoding, including nested and flat event enums.
use starknet_rust_core::{
    types::{
        Event, Felt,
        contract::{AbiEntry, AbiEvent, EventFieldKind, TypedAbiEvent},
    },
    utils::starknet_keccak,
};
use std::collections::{BTreeMap, BTreeSet};
mod value;
pub use value::{EventDecodeError, EventValue};
use value::{EventTypes, NodeBudget, charge_node, error};

/// A decoded event with its ABI path and named fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedEvent {
    /// Contract emitting the event.
    pub from_address: Felt,
    /// Enum variant names from the selected root to the event struct.
    pub path: Vec<String>,
    /// Fully qualified leaf event type.
    pub event_type: String,
    /// Event fields, in a map indexed by ABI member name.
    pub fields: BTreeMap<String, EventValue>,
}
#[derive(Debug, Clone)]
struct Route {
    selectors: Vec<Felt>,
    path: Vec<String>,
    ty: String,
}
/// A decoder constructed for a specific contract's root event type.
///
/// Select the Cairo 2 `Event` enum by its fully qualified ABI name. Only untyped Cairo 1 events
/// start with their short-name selector. Typed struct roots serialize just their members; enum
/// variants supply nested selectors. Cairo 0 ABIs are not accepted. Unsupported value types return
/// an error, never an unvalidated raw fallback.
pub struct EventDecoder {
    types: EventTypes,
    routes: Vec<Route>,
}
impl std::fmt::Debug for EventDecoder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventDecoder")
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}
impl EventDecoder {
    /// Creates a decoder and rejects unknown event types, cycles, and ambiguous selector paths.
    pub fn new(entries: Vec<AbiEntry>, root: &str) -> Result<Self, EventDecodeError> {
        fn flatten(entries: Vec<AbiEntry>, out: &mut Vec<AbiEntry>) {
            for e in entries {
                match e {
                    AbiEntry::Interface(i) => flatten(i.items, out),
                    e => out.push(e),
                }
            }
        }
        let mut flat = vec![];
        flatten(entries, &mut flat);
        let types = EventTypes::new(flat);
        let mut event_names = BTreeSet::new();
        let mut type_names = BTreeSet::new();
        for entry in &types.entries {
            let (names, name) = match entry {
                AbiEntry::Event(e) => (&mut event_names, event_name(e)),
                AbiEntry::Struct(s) => (&mut type_names, s.name.as_str()),
                AbiEntry::Enum(e) => (&mut type_names, e.name.as_str()),
                _ => continue,
            };
            if !names.insert(name) {
                return Err(error("duplicate event or ordinary type name"));
            }
        }
        let mut decoder = Self {
            types,
            routes: vec![],
        };
        let is_untyped = matches!(decoder.event(root)?, AbiEvent::Untyped(_));
        decoder.routes(
            root,
            if is_untyped {
                vec![selector(short_name(root))?]
            } else {
                vec![]
            },
            vec![],
            &mut vec![],
            &mut 4096,
        )?;
        let mut paths = BTreeSet::new();
        if decoder
            .routes
            .iter()
            .any(|r| !paths.insert(r.selectors.clone()))
        {
            return Err(error("ambiguous event selector routes"));
        }
        Ok(decoder)
    }
    /// Parses a JSON Cairo 1/2 ABI and creates a decoder for its root event type.
    pub fn from_json(json: &str, root: &str) -> Result<Self, EventDecodeError> {
        Self::new(
            serde_json::from_str(json).map_err(|e| error(e.to_string()))?,
            root,
        )
    }
    fn event(&self, name: &str) -> Result<&AbiEvent, EventDecodeError> {
        self.types
            .event_indices
            .get(name)
            .and_then(|index| match &self.types.entries[*index] {
                AbiEntry::Event(event) => Some(event),
                _ => None,
            })
            .ok_or_else(|| error(format!("unknown event type: {name}")))
    }
    fn routes(
        &mut self,
        ty: &str,
        selectors: Vec<Felt>,
        path: Vec<String>,
        stack: &mut Vec<String>,
        budget: &mut usize,
    ) -> Result<(), EventDecodeError> {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| error("event ABI traversal exceeds 4096 nodes"))?;
        if self.routes.len() >= 4096 {
            return Err(error("event ABI exceeds 4096 routes"));
        }
        if stack.len() > 64 || stack.iter().any(|s| s == ty) {
            return Err(error("cyclic or excessively nested event ABI"));
        }
        stack.push(ty.into());
        match self.event(ty)?.clone() {
            AbiEvent::Typed(TypedAbiEvent::Enum(e)) => {
                for v in e.variants {
                    let mut selectors = selectors.clone();
                    match v.kind {
                        EventFieldKind::Nested => selectors.push(selector(&v.name)?),
                        EventFieldKind::Flat => {}
                        _ => return Err(error("event enum variants must be nested or flat")),
                    }
                    let mut path = path.clone();
                    path.push(v.name);
                    self.routes(&v.r#type, selectors, path, stack, budget)?;
                }
            }
            _ => self.routes.push(Route {
                selectors,
                path,
                ty: ty.into(),
            }),
        }
        stack.pop();
        Ok(())
    }
    /// Decodes an event, rejecting unknown selectors, truncation and trailing keys/data.
    pub fn decode(&self, event: &Event) -> Result<DecodedEvent, EventDecodeError> {
        self.decode_with_budget(event, &mut NodeBudget::new(1_000_000))
    }
    fn decode_with_budget(
        &self,
        event: &Event,
        budget: &mut NodeBudget,
    ) -> Result<DecodedEvent, EventDecodeError> {
        let mut matches = vec![];
        let mut candidate_error = None;
        for route in &self.routes {
            if event.keys.starts_with(&route.selectors) {
                let mut keys = &event.keys[route.selectors.len()..];
                let mut data = event.data.as_slice();
                let fields = match self.fields(&route.ty, &mut keys, &mut data, 0, budget) {
                    Ok(fields) => fields,
                    Err(error) if budget.exceeded => return Err(error),
                    Err(error) => {
                        candidate_error.get_or_insert(error);
                        continue;
                    }
                };
                if keys.is_empty() && data.is_empty() {
                    matches.push(DecodedEvent {
                        from_address: event.from_address,
                        path: route.path.clone(),
                        event_type: route.ty.clone(),
                        fields,
                    });
                } else {
                    candidate_error.get_or_insert_with(|| error("trailing event keys or data"));
                }
            }
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => Err(candidate_error.unwrap_or_else(|| error("unknown event selector"))),
            _ => Err(error("ambiguous event")),
        }
    }
    /// Decodes only events emitted by the specified address, preserving receipt order.
    pub fn decode_from(
        &self,
        events: &[Event],
        address: Felt,
    ) -> Result<Vec<DecodedEvent>, EventDecodeError> {
        events
            .iter()
            .filter(|e| e.from_address == address)
            .map(|e| self.decode(e))
            .collect()
    }
    fn fields(
        &self,
        ty: &str,
        keys: &mut &[Felt],
        data: &mut &[Felt],
        depth: usize,
        budget: &mut NodeBudget,
    ) -> Result<BTreeMap<String, EventValue>, EventDecodeError> {
        charge_node(budget)?;
        if depth > 64 {
            return Err(error("event nesting exceeds 64"));
        }
        let mut fields = BTreeMap::new();
        match self.event(ty)? {
            AbiEvent::Untyped(e) => {
                for m in &e.inputs {
                    if fields
                        .insert(
                            m.name.clone(),
                            self.types.decode_value(&m.r#type, data, budget)?,
                        )
                        .is_some()
                    {
                        return Err(error("duplicate event member"));
                    }
                }
            }
            AbiEvent::Typed(TypedAbiEvent::Struct(e)) => {
                for m in &e.members {
                    let value = match m.kind {
                        EventFieldKind::Key => self.types.decode_value(&m.r#type, keys, budget)?,
                        EventFieldKind::Data => self.types.decode_value(&m.r#type, data, budget)?,
                        EventFieldKind::Nested | EventFieldKind::Flat => EventValue::Struct(
                            self.fields(&m.r#type, keys, data, depth + 1, budget)?,
                        ),
                    };
                    if fields.insert(m.name.clone(), value).is_some() {
                        return Err(error("duplicate event member"));
                    }
                }
            }
            AbiEvent::Typed(TypedAbiEvent::Enum(_)) => {
                return Err(error(
                    "nested event-enum members are unsupported; select an enum root",
                ));
            }
        }
        Ok(fields)
    }
}
fn short_name(name: &str) -> &str {
    name.rsplit("::").next().unwrap_or(name)
}
fn selector(name: &str) -> Result<Felt, EventDecodeError> {
    if !name.is_ascii() {
        return Err(error("event selector name must be ASCII"));
    }
    // Event selector! hashes even names reserved for default entrypoints.
    Ok(starknet_keccak(name.as_bytes()))
}
fn event_name(e: &AbiEvent) -> &str {
    match e {
        AbiEvent::Typed(TypedAbiEvent::Struct(e)) => &e.name,
        AbiEvent::Typed(TypedAbiEvent::Enum(e)) => &e.name,
        AbiEvent::Untyped(e) => &e.name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ABI: &str = r#"[{"type":"event","name":"app::Event","kind":"enum","variants":[{"name":"Token","type":"erc20::Event","kind":"flat"},{"name":"Paused","type":"app::Paused","kind":"nested"}]},{"type":"event","name":"erc20::Event","kind":"enum","variants":[{"name":"Transfer","type":"erc20::Transfer","kind":"nested"}]},{"type":"struct","name":"core::integer::u256","members":[{"name":"low","type":"core::integer::u128"},{"name":"high","type":"core::integer::u128"}]},{"type":"event","name":"erc20::Transfer","kind":"struct","members":[{"name":"from","type":"core::starknet::contract_address::ContractAddress","kind":"key"},{"name":"to","type":"core::starknet::contract_address::ContractAddress","kind":"key"},{"name":"amount","type":"core::integer::u256","kind":"data"}]},{"type":"event","name":"app::Paused","kind":"struct","members":[{"name":"paused","type":"core::bool","kind":"data"}]}]"#;
    #[test]
    fn matching_routes_preserve_specific_decode_failures() {
        for (ty, data, expected) in [
            ("Unknown", vec![], "unsupported type: Unknown"),
            (
                "core::integer::u8",
                vec![Felt::from(256_u64)],
                "value out of range for core::integer::u8",
            ),
            ("core::integer::u8", vec![], "truncated ABI data"),
            (
                "core::integer::u8",
                vec![Felt::ZERO, Felt::ONE],
                "trailing event keys or data",
            ),
        ] {
            let abi = serde_json::json!([{"type":"event","name":"Root","kind":"struct","members":[{"name":"value","type":ty,"kind":"data"}]}]);
            let decoder = EventDecoder::from_json(&abi.to_string(), "Root").unwrap();
            assert_eq!(
                decoder
                    .decode(&Event {
                        from_address: Felt::ONE,
                        keys: vec![],
                        data
                    })
                    .unwrap_err()
                    .to_string(),
                expected
            );
        }
        let decoder = EventDecoder::from_json(ABI, "app::Event").unwrap();
        assert_eq!(
            decoder
                .decode(&Event {
                    from_address: Felt::ONE,
                    keys: vec![],
                    data: vec![]
                })
                .unwrap_err()
                .to_string(),
            "unknown event selector"
        );
    }
    #[test]
    fn failed_candidates_do_not_hide_successes_or_ambiguity() {
        let abi = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"A","type":"A","kind":"flat"},{"name":"B","type":"B","kind":"nested"}]},{"type":"event","name":"A","kind":"struct","members":[{"name":"value","type":"core::felt252","kind":"data"}]},{"type":"event","name":"B","kind":"struct","members":[]}]"#;
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![selector("B").unwrap()],
            data: vec![],
        };
        let decoder = EventDecoder::from_json(abi, "Root").unwrap();
        assert_eq!(decoder.decode(&event).unwrap().path, vec!["B"]);
        // The flat candidate now consumes B's selector as its key, so both routes succeed.
        let decoder = EventDecoder::from_json(
            &abi.replace("\"kind\":\"data\"", "\"kind\":\"key\""),
            "Root",
        )
        .unwrap();
        assert_eq!(
            decoder.decode(&event).unwrap_err().to_string(),
            "ambiguous event"
        );
    }
    #[test]
    fn exact_budget_boundary_does_not_turn_schema_failure_into_exhaustion() {
        let abi = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"A","type":"A","kind":"flat"},{"name":"B","type":"B","kind":"nested"}]},{"type":"event","name":"A","kind":"struct","members":[{"name":"value","type":"core::felt252","kind":"key"}]},{"type":"event","name":"B","kind":"struct","members":[{"name":"value","type":"Unknown","kind":"data"}]}]"#;
        let decoder = EventDecoder::from_json(abi, "Root").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![selector("B").unwrap()],
            data: vec![],
        };
        // A's root and value consume two nodes. B's root consumes the third node,
        // then its schema fails without asking to decode another value node.
        let mut budget = NodeBudget::new(3);
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap()
                .path,
            vec!["A"]
        );
        assert_eq!(budget.remaining, 0);
        assert!(!budget.exceeded);
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut NodeBudget::new(2))
                .unwrap_err()
                .to_string(),
            "decoded values exceed node budget"
        );
        // With a valid unit payload, both routes can succeed exactly at the boundary.
        let decoder = EventDecoder::from_json(&abi.replace("Unknown", "()"), "Root").unwrap();
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut NodeBudget::new(4))
                .unwrap_err()
                .to_string(),
            "ambiguous event"
        );
    }
    #[test]
    fn event_and_ordinary_types_have_separate_namespaces() {
        let abi = r#"[{"type":"event","name":"Shared","kind":"struct","members":[{"name":"value","type":"core::felt252","kind":"data"}]},{"type":"struct","name":"Shared","members":[{"name":"value","type":"core::felt252"}]}]"#;
        let decoder = EventDecoder::from_json(abi, "Shared").unwrap();
        let result = decoder
            .decode(&Event {
                from_address: Felt::ONE,
                keys: vec![],
                data: vec![Felt::TWO],
            })
            .unwrap();
        assert_eq!(result.fields["value"], EventValue::Felt(Felt::TWO));
        let mut entries: Vec<AbiEntry> = serde_json::from_str(abi).unwrap();
        entries.push(entries[0].clone());
        assert!(EventDecoder::new(entries, "Shared").is_err());
    }
    #[test]
    fn default_like_event_variants_hash_their_names() {
        let abi = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"__default__","type":"Empty","kind":"nested"},{"name":"__l1_default__","type":"Empty","kind":"nested"}]},{"type":"event","name":"Empty","kind":"struct","members":[]}]"#;
        let decoder = EventDecoder::from_json(abi, "Root").unwrap();
        for name in ["__default__", "__l1_default__"] {
            let hash = starknet_keccak(name.as_bytes());
            assert_ne!(hash, Felt::ZERO);
            let result = decoder
                .decode(&Event {
                    from_address: Felt::ONE,
                    keys: vec![hash],
                    data: vec![],
                })
                .unwrap();
            assert_eq!(result.path, vec![name.to_owned()]);
        }
        assert!(
            decoder
                .decode(&Event {
                    from_address: Felt::ONE,
                    keys: vec![Felt::ZERO],
                    data: vec![]
                })
                .is_err()
        );
    }
    #[test]
    fn cairo1_erc20_fixture_decodes_builtin_u256_without_a_struct_entry() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!(
            "../../../starknet-rust-core/test-data/contracts/cairo1/artifacts/erc20_sierra.txt"
        ))
        .unwrap();
        let entries: Vec<AbiEntry> = serde_json::from_value(artifact["abi"].clone()).unwrap();
        assert!(
            !entries
                .iter()
                .any(|e| matches!(e, AbiEntry::Struct(s) if s.name == "core::integer::u256"))
        );
        let decoder = EventDecoder::new(entries, "Transfer").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![starknet_keccak(b"Transfer")],
            data: vec![Felt::TWO, Felt::THREE, Felt::from(u128::MAX), Felt::ONE],
        };
        let value = decoder.decode(&event).unwrap();
        assert_eq!(
            value.fields["value"],
            EventValue::Struct(BTreeMap::from([
                ("low".into(), EventValue::Felt(Felt::from(u128::MAX))),
                ("high".into(), EventValue::Felt(Felt::ONE))
            ]))
        );
        for limb in [2, 3] {
            let mut invalid = event.clone();
            invalid.data[limb] = Felt::from(u128::MAX) + Felt::ONE;
            assert!(decoder.decode(&invalid).is_err());
        }
    }
    #[test]
    fn nested_flat_paths_and_struct_values() {
        let d = EventDecoder::from_json(ABI, "app::Event").unwrap();
        let e = Event {
            from_address: Felt::ONE,
            keys: vec![selector("Transfer").unwrap(), Felt::TWO, Felt::THREE],
            data: vec![Felt::ONE, Felt::ZERO],
        };
        let result = d.decode(&e).unwrap();
        assert_eq!(result.path, vec!["Token", "Transfer"]);
        assert_eq!(result.fields["from"], EventValue::Felt(Felt::TWO));
        assert_eq!(
            result.fields["amount"],
            EventValue::Struct(BTreeMap::from([
                ("low".into(), EventValue::Felt(Felt::ONE)),
                ("high".into(), EventValue::Felt(Felt::ZERO))
            ]))
        );
        let paused = Event {
            from_address: Felt::ONE,
            keys: vec![selector("Paused").unwrap()],
            data: vec![Felt::ONE],
        };
        assert_eq!(
            d.decode(&paused).unwrap().fields["paused"],
            EventValue::Bool(true)
        );
        assert_eq!(d.decode_from(&[e, paused], Felt::TWO).unwrap().len(), 0);
    }
    #[test]
    fn rejects_unknown_malformed_and_extra_data() {
        let d = EventDecoder::from_json(ABI, "app::Event").unwrap();
        for e in [
            Event {
                from_address: Felt::ONE,
                keys: vec![],
                data: vec![],
            },
            Event {
                from_address: Felt::ONE,
                keys: vec![selector("Paused").unwrap()],
                data: vec![Felt::TWO],
            },
            Event {
                from_address: Felt::ONE,
                keys: vec![selector("Paused").unwrap(), Felt::ZERO],
                data: vec![Felt::ONE],
            },
            Event {
                from_address: Felt::ONE,
                keys: vec![selector("Paused").unwrap()],
                data: vec![Felt::ONE, Felt::ZERO],
            },
        ] {
            assert!(d.decode(&e).is_err());
        }
    }
    #[test]
    fn empty_event_arrays_do_not_hide_unsupported_element_types() {
        let decoder = EventDecoder::from_json(r#"[{"type":"event","name":"Changed","inputs":[{"name":"items","type":"core::array::Array::<Unknown>"}]}]"#, "Changed").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![selector("Changed").unwrap()],
            data: vec![Felt::ZERO],
        };
        assert!(decoder.decode(&event).is_err());
    }
    #[test]
    fn typed_struct_roots_emit_members_without_a_type_name_selector() {
        let decoder = EventDecoder::from_json(r#"[{"type":"event","name":"app::Changed","kind":"struct","members":[{"name":"value","type":"core::felt252","kind":"data"}]}]"#, "app::Changed").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![],
            data: vec![Felt::THREE],
        };
        assert_eq!(
            decoder.decode(&event).unwrap().fields["value"],
            EventValue::Felt(Felt::THREE)
        );
        let decoder = EventDecoder::from_json(r#"[{"type":"event","name":"app::Changed","kind":"struct","members":[{"name":"owner","type":"core::felt252","kind":"key"},{"name":"value","type":"core::felt252","kind":"data"}]}]"#, "app::Changed").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![Felt::TWO],
            data: vec![Felt::THREE],
        };
        let output = decoder.decode(&event).unwrap();
        assert_eq!(output.fields["owner"], EventValue::Felt(Felt::TWO));
        assert_eq!(output.fields["value"], EventValue::Felt(Felt::THREE));
        let extra_prefix = Event {
            keys: vec![selector("Changed").unwrap(), Felt::TWO],
            ..event
        };
        assert!(decoder.decode(&extra_prefix).is_err());
    }
    #[test]
    fn nested_and_flat_event_struct_fields_delegate_without_member_selectors() {
        for kind in ["nested", "flat"] {
            let abi = format!(
                r#"[{{"type":"event","name":"Outer","kind":"struct","members":[{{"name":"inner","type":"Inner","kind":"{kind}"}},{{"name":"outer_key","type":"core::felt252","kind":"key"}}]}},{{"type":"event","name":"Inner","kind":"struct","members":[{{"name":"id","type":"core::felt252","kind":"key"}},{{"name":"value","type":"core::felt252","kind":"data"}}]}}]"#
            );
            let decoder = EventDecoder::from_json(&abi, "Outer").unwrap();
            let event = Event {
                from_address: Felt::ONE,
                keys: vec![Felt::from(11u8), Felt::from(22u8)],
                data: vec![Felt::from(33u8)],
            };
            let output = decoder.decode(&event).unwrap();
            assert_eq!(
                output.fields["inner"],
                EventValue::Struct(BTreeMap::from([
                    ("id".into(), EventValue::Felt(Felt::from(11u8))),
                    ("value".into(), EventValue::Felt(Felt::from(33u8)))
                ]))
            );
            assert_eq!(
                output.fields["outer_key"],
                EventValue::Felt(Felt::from(22u8))
            );
        }
    }
    #[test]
    fn one_budget_bounds_recursive_empty_event_maps_and_ordinary_values() {
        let mut entries = vec![];
        for depth in 0..6 {
            let members = if depth == 5 {
                vec![]
            } else {
                ["left", "right"].map(|name| serde_json::json!({"name":name,"type":format!("Node{}", depth+1),"kind":"flat"})).to_vec()
            };
            entries.push(serde_json::json!({"type":"event","name":format!("Node{depth}"),"kind":"struct","members":members}));
        }
        let decoder = EventDecoder::new(
            serde_json::from_value(serde_json::Value::Array(entries)).unwrap(),
            "Node0",
        )
        .unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![],
            data: vec![],
        };
        let mut budget = NodeBudget::new(15);
        assert!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap_err()
                .0
                .contains("node budget")
        );
        assert_eq!(budget.remaining, 0);
        assert!(
            decoder
                .decode_with_budget(&event, &mut NodeBudget::new(63))
                .is_ok()
        );
        let decoder = EventDecoder::from_json(r#"[{"type":"event","name":"Outer","kind":"struct","members":[{"name":"inner","type":"Inner","kind":"flat"},{"name":"items","type":"core::array::Array::<()>","kind":"data"}]},{"type":"event","name":"Inner","kind":"struct","members":[]}]"#, "Outer").unwrap();
        let event = Event {
            data: vec![Felt::ONE],
            ..event
        };
        assert!(
            decoder
                .decode_with_budget(&event, &mut NodeBudget::new(3))
                .is_err()
        );
        assert!(
            decoder
                .decode_with_budget(&event, &mut NodeBudget::new(4))
                .is_ok()
        );
    }
    #[test]
    fn ordinary_duplicate_struct_fields_cannot_be_decoded_as_a_valid_event() {
        let decoder = EventDecoder::from_json(r#"[{"type":"struct","name":"Bad","members":[{"name":"x","type":"core::integer::u8"},{"name":"x","type":"core::integer::u8"}]},{"type":"event","name":"Root","kind":"struct","members":[{"name":"payload","type":"Bad","kind":"data"}]}]"#, "Root").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![],
            data: vec![Felt::ONE, Felt::TWO],
        };
        assert!(decoder.decode(&event).is_err());
    }
    #[test]
    fn cairo1_untyped_event() {
        let d=EventDecoder::from_json(r#"[{"type":"event","name":"old::Changed","inputs":[{"name":"value","type":"core::felt252"}]}]"#,"old::Changed").unwrap();
        let e = Event {
            from_address: Felt::ONE,
            keys: vec![selector("Changed").unwrap()],
            data: vec![Felt::THREE],
        };
        assert_eq!(
            d.decode(&e).unwrap().fields["value"],
            EventValue::Felt(Felt::THREE)
        );
    }
    #[test]
    fn detects_cycles() {
        assert!(EventDecoder::from_json(r#"[{"type":"event","name":"E","kind":"enum","variants":[{"name":"E","type":"E","kind":"flat"}]}]"#,"E").is_err());
    }
}
