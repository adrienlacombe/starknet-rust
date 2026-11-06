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
use value::{EventTypes, NodeBudget, SchemaBudget, charge_node, error};

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
struct RouteBudget {
    remaining: usize,
    resources: SchemaBudget,
}
impl EventDecoder {
    /// Creates a decoder and rejects unknown event types, cycles, and ambiguous selector paths.
    /// Event container identifiers must be unique, and interface nesting is limited to 64.
    pub fn new(entries: Vec<AbiEntry>, root: &str) -> Result<Self, EventDecodeError> {
        fn flatten(entries: Vec<AbiEntry>, out: &mut Vec<AbiEntry>) -> bool {
            let mut pending: Vec<_> = entries
                .into_iter()
                .rev()
                .map(|entry| (entry, 0usize))
                .collect();
            let mut exceeded = false;
            while let Some((entry, depth)) = pending.pop() {
                match entry {
                    AbiEntry::Interface(interface) => {
                        exceeded |= depth >= 64;
                        pending.extend(
                            interface
                                .items
                                .into_iter()
                                .rev()
                                .map(|entry| (entry, depth.saturating_add(1))),
                        );
                    }
                    entry => {
                        if !exceeded {
                            out.push(entry);
                        }
                    }
                }
                // Even after a violation, drain every owned interface subtree iteratively.
                // Returning early would recursively drop an unprocessed deep subtree.
            }
            exceeded
        }
        fn unique_names<'a>(mut names: impl Iterator<Item = &'a str>) -> bool {
            let mut seen = BTreeSet::new();
            names.all(|name| seen.insert(name))
        }
        let mut flat = vec![];
        if flatten(entries, &mut flat) {
            return Err(error("ABI interface nesting exceeds 64"));
        }
        let types = EventTypes::new(flat);
        let mut event_names = BTreeSet::new();
        let mut type_names = BTreeSet::new();
        for entry in &types.entries {
            match entry {
                AbiEntry::Event(AbiEvent::Typed(TypedAbiEvent::Enum(event)))
                    if !unique_names(
                        event.variants.iter().map(|variant| variant.name.as_str()),
                    ) =>
                {
                    return Err(error("duplicate event enum variant"));
                }
                AbiEntry::Event(AbiEvent::Typed(TypedAbiEvent::Struct(event)))
                    if !unique_names(event.members.iter().map(|member| member.name.as_str())) =>
                {
                    return Err(error("duplicate event member"));
                }
                AbiEntry::Event(AbiEvent::Untyped(event))
                    if !unique_names(event.inputs.iter().map(|member| member.name.as_str())) =>
                {
                    return Err(error("duplicate event member"));
                }
                _ => {}
            }
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
        let mut resources = SchemaBudget::new(1_000_000);
        resources.charge_text(root.len())?;
        resources.charge_owned(root.len())?;
        let is_untyped = matches!(Self::event(&decoder.types, root)?, AbiEvent::Untyped(_));
        Self::collect_routes(
            &decoder.types,
            &mut decoder.routes,
            root,
            if is_untyped {
                vec![selector(short_name(root))?]
            } else {
                vec![]
            },
            vec![],
            &mut vec![],
            &mut RouteBudget {
                remaining: 4096,
                resources,
            },
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
    fn event<'a>(types: &'a EventTypes, name: &str) -> Result<&'a AbiEvent, EventDecodeError> {
        types
            .event_indices
            .get(name)
            .and_then(|index| match &types.entries[*index] {
                AbiEntry::Event(event) => Some(event),
                _ => None,
            })
            .ok_or_else(|| error(format!("unknown event type: {name}")))
    }
    fn collect_routes(
        types: &EventTypes,
        routes: &mut Vec<Route>,
        ty: &str,
        selectors: Vec<Felt>,
        path: Vec<String>,
        stack: &mut Vec<String>,
        budget: &mut RouteBudget,
    ) -> Result<(), EventDecodeError> {
        budget.resources.charge_text(ty.len())?;
        budget
            .resources
            .charge_owned(ty.len() + std::mem::size_of::<String>())?;
        budget.remaining = budget
            .remaining
            .checked_sub(1)
            .ok_or_else(|| error("event ABI traversal exceeds 4096 nodes"))?;
        if routes.len() >= 4096 {
            return Err(error("event ABI exceeds 4096 routes"));
        }
        if stack.len() > 64 || stack.iter().any(|s| s == ty) {
            return Err(error("cyclic or excessively nested event ABI"));
        }
        stack.push(ty.into());
        // ABI definitions stay in one immutable store. Only route metadata is
        // copied; a large leaf shared by many aliases is never cloned per visit.
        if let AbiEvent::Typed(TypedAbiEvent::Enum(e)) = Self::event(types, ty)? {
            for v in &e.variants {
                budget.resources.charge_text(v.name.len())?;
                budget.resources.charge_owned(
                    path.iter()
                        .map(|name| name.len().saturating_add(std::mem::size_of::<String>()))
                        .sum::<usize>()
                        .saturating_add(v.name.len())
                        .saturating_add(std::mem::size_of::<String>()),
                )?;
                let mut selectors = selectors.clone();
                match v.kind {
                    EventFieldKind::Nested => selectors.push(selector(&v.name)?),
                    EventFieldKind::Flat => {}
                    _ => return Err(error("event enum variants must be nested or flat")),
                }
                let mut path = path.clone();
                path.push(v.name.clone());
                Self::collect_routes(types, routes, &v.r#type, selectors, path, stack, budget)?;
            }
        } else {
            budget
                .resources
                .charge_owned(ty.len().saturating_add(2 * std::mem::size_of::<Route>()))?;
            routes.push(Route {
                selectors,
                path,
                ty: ty.into(),
            });
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
        let mut matched = None;
        let mut candidate_error = None;
        for route in &self.routes {
            if event.keys.starts_with(&route.selectors) {
                let mut keys = &event.keys[route.selectors.len()..];
                let mut data = event.data.as_slice();
                let fields = match self.fields(&route.ty, &mut keys, &mut data, 0, budget) {
                    Ok(fields) => fields,
                    Err(error) if budget.exceeded || budget.schema.exceeded => return Err(error),
                    Err(error) => {
                        candidate_error.get_or_insert(error);
                        continue;
                    }
                };
                if keys.is_empty() && data.is_empty() {
                    if matched.is_some() {
                        return Err(error("ambiguous event"));
                    }
                    budget.schema.charge_owned(
                        route
                            .ty
                            .len()
                            .saturating_add(2 * std::mem::size_of::<DecodedEvent>()),
                    )?;
                    for name in &route.path {
                        budget.schema.charge_owned(
                            name.len().saturating_add(std::mem::size_of::<String>()),
                        )?;
                    }
                    matched = Some(DecodedEvent {
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
        matched.ok_or_else(|| candidate_error.unwrap_or_else(|| error("unknown event selector")))
    }
    /// Decodes only events emitted by the specified address, preserving receipt order.
    pub fn decode_from(
        &self,
        events: &[Event],
        address: Felt,
    ) -> Result<Vec<DecodedEvent>, EventDecodeError> {
        self.decode_from_with_budget(events, address, &mut NodeBudget::new(1_000_000))
    }
    fn decode_from_with_budget(
        &self,
        events: &[Event],
        address: Felt,
        budget: &mut NodeBudget,
    ) -> Result<Vec<DecodedEvent>, EventDecodeError> {
        events
            .iter()
            .filter(|e| e.from_address == address)
            .map(|e| {
                // Value limits retain their per-event meaning; schema work belongs
                // to the entire receipt operation, including cached root lookups.
                budget.remaining = 1_000_000;
                budget.exceeded = false;
                self.decode_with_budget(e, budget)
            })
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
        budget.schema.charge_text(ty.len())?;
        budget
            .schema
            .charge_owned(2 * std::mem::size_of::<BTreeMap<String, EventValue>>())?;
        if depth > 64 {
            return Err(error("event nesting exceeds 64"));
        }
        let mut fields = BTreeMap::new();
        match Self::event(&self.types, ty)? {
            AbiEvent::Untyped(e) => {
                for m in &e.inputs {
                    budget.schema.charge_text(m.name.len())?;
                    budget
                        .schema
                        .charge_owned(m.name.len().saturating_add(std::mem::size_of::<String>()))?;
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
                    budget.schema.charge_text(m.name.len())?;
                    budget
                        .schema
                        .charge_owned(m.name.len().saturating_add(std::mem::size_of::<String>()))?;
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
    #[test]
    fn logical_byte_limits_cover_event_metadata_and_aggregate_empty_receipts() {
        let name = "e".repeat(256);
        let abi = serde_json::json!([{"type":"event","name":name,"kind":"struct","members":[]}])
            .to_string();
        let decoder = EventDecoder::from_json(&abi, &name).unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![],
            data: vec![],
        };
        let mut budget = NodeBudget::new(100);
        budget.schema.owned = 256;
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI logical allocation exceeds byte budget"
        );
        assert!(budget.schema.exceeded);
        let events = vec![event; 8];
        let mut budget = NodeBudget::new(100);
        budget.schema.owned = 1_024;
        assert_eq!(
            decoder
                .decode_from_with_budget(&events, Felt::ONE, &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI logical allocation exceeds byte budget"
        );
        assert!(budget.schema.exceeded);
        assert_eq!(decoder.decode_from(&events, Felt::ONE).unwrap().len(), 8);
        let mut resources = SchemaBudget::new(1_000_000);
        resources.owned = 256;
        assert_eq!(
            EventDecoder::collect_routes(
                &decoder.types,
                &mut vec![],
                &name,
                vec![],
                vec![],
                &mut vec![],
                &mut RouteBudget {
                    remaining: 4096,
                    resources
                }
            )
            .unwrap_err()
            .to_string(),
            "ABI logical allocation exceeds byte budget"
        );
    }
    #[test]
    fn allocation_exhaustion_cannot_hide_an_uninspected_candidate() {
        let abi = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"A","type":"A","kind":"flat"},{"name":"B","type":"B","kind":"nested"}]},{"type":"event","name":"A","kind":"struct","members":[{"name":"value","type":"core::felt252","kind":"key"}]},{"type":"event","name":"B","kind":"struct","members":[{"name":"value","type":"()","kind":"data"}]}]"#;
        let decoder = EventDecoder::from_json(abi, "Root").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![selector("B").unwrap()],
            data: vec![],
        };
        assert_eq!(
            decoder.decode(&event).unwrap_err().to_string(),
            "ambiguous event"
        );
        let mut consumed = None;
        // Find the small exact allowance needed for A alone, without hard-coding layouts.
        let a_decoder = EventDecoder::from_json(abi, "A").unwrap();
        for _ in 0..2 {
            let mut budget = NodeBudget::new(100);
            a_decoder.decode_with_budget(&event, &mut budget).unwrap();
            consumed = Some(64 * 1024 * 1024 - budget.schema.owned);
        }
        let mut budget = NodeBudget::new(100);
        budget.schema.owned = consumed.unwrap() + 128;
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI logical allocation exceeds byte budget"
        );
        assert!(budget.schema.exceeded);
        assert_eq!(
            decoder.decode(&event).unwrap_err().to_string(),
            "ambiguous event"
        );
    }

    fn nested_interfaces(mut entry: AbiEntry, depth: usize) -> AbiEntry {
        for _ in 0..depth {
            entry = AbiEntry::Interface(starknet_rust_core::types::contract::AbiInterface {
                name: "Interface".into(),
                items: vec![entry],
            });
        }
        entry
    }
    fn empty_event(name: &str) -> AbiEntry {
        serde_json::from_value(
            serde_json::json!({"type":"event","name":name,"kind":"struct","members":[]}),
        )
        .unwrap()
    }
    #[test]
    fn interface_flattening_preserves_order_and_enforces_its_depth_boundary() {
        let decoder = EventDecoder::new(
            vec![
                empty_event("Before"),
                nested_interfaces(empty_event("Leaf"), 64),
                empty_event("After"),
            ],
            "Leaf",
        )
        .unwrap();
        let names: Vec<_> = decoder
            .types
            .entries
            .iter()
            .map(|entry| match entry {
                AbiEntry::Event(event) => event_name(event),
                _ => panic!("unexpected flattened entry"),
            })
            .collect();
        assert_eq!(names, vec!["Before", "Leaf", "After"]);
        assert_eq!(
            EventDecoder::new(vec![nested_interfaces(empty_event("Leaf"), 65)], "Leaf")
                .unwrap_err()
                .to_string(),
            "ABI interface nesting exceeds 64"
        );
        let empty = AbiEntry::Interface(starknet_rust_core::types::contract::AbiInterface {
            name: "Empty".into(),
            items: vec![],
        });
        assert_eq!(
            EventDecoder::new(
                vec![empty_event("Leaf"), nested_interfaces(empty, 64)],
                "Leaf"
            )
            .unwrap_err()
            .to_string(),
            "ABI interface nesting exceeds 64"
        );
    }
    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn deeply_nested_owned_interfaces_are_drained_without_recursive_drops() {
        std::thread::Builder::new()
            .stack_size(512 * 1024)
            .spawn(|| {
                let entries = (0..2)
                    .map(|_| nested_interfaces(empty_event("Leaf"), 20_000))
                    .collect();
                assert_eq!(
                    EventDecoder::new(entries, "Leaf").unwrap_err().to_string(),
                    "ABI interface nesting exceeds 64"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[test]
    fn duplicate_event_identifiers_are_rejected_independently_of_selector_paths() {
        let duplicate_variants = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"Same","type":"Left","kind":"flat"},{"name":"Same","type":"Right","kind":"flat"}]},{"type":"event","name":"Left","kind":"enum","variants":[{"name":"LeftLeaf","type":"Leaf","kind":"nested"}]},{"type":"event","name":"Right","kind":"enum","variants":[{"name":"RightLeaf","type":"Leaf","kind":"nested"}]},{"type":"event","name":"Leaf","kind":"struct","members":[]}]"#;
        assert_eq!(
            EventDecoder::from_json(duplicate_variants, "Root")
                .unwrap_err()
                .to_string(),
            "duplicate event enum variant"
        );
        for abi in [
            r#"[{"type":"event","name":"Root","kind":"struct","members":[{"name":"same","type":"core::felt252","kind":"key"},{"name":"same","type":"core::felt252","kind":"data"}]}]"#,
            r#"[{"type":"event","name":"Root","inputs":[{"name":"same","type":"core::felt252"},{"name":"same","type":"core::felt252"}]}]"#,
        ] {
            assert_eq!(
                EventDecoder::from_json(abi, "Root")
                    .unwrap_err()
                    .to_string(),
                "duplicate event member"
            );
        }
    }
    #[test]
    fn declared_syntactic_types_cannot_be_hidden_in_event_fields() {
        let cases = [
            ("core::array::Array::<core::felt252>", vec![Felt::ZERO]),
            ("core::array::Span::<core::felt252>", vec![Felt::ZERO]),
            ("(core::felt252, core::bool)", vec![Felt::ZERO, Felt::ZERO]),
            ("()", vec![]),
        ];
        let expected: Vec<_> = cases
            .iter()
            .map(|(ty, _)| (*ty, Some("duplicate ABI struct member".to_owned())))
            .collect();
        let mut actual = vec![];
        for (ty, data) in cases {
            let abi = serde_json::json!([
                {"type":"struct","name":ty,"members":[{"name":"same","type":"()"},{"name":"same","type":"()"}]},
                {"type":"event","name":"Root","kind":"struct","members":[{"name":"value","type":ty,"kind":"data"}]}
            ]);
            let decoder = EventDecoder::from_json(&abi.to_string(), "Root").unwrap();
            actual.push((
                ty,
                decoder
                    .decode(&Event {
                        from_address: Felt::ONE,
                        keys: vec![],
                        data,
                    })
                    .err()
                    .map(|error| error.to_string()),
            ));
        }
        assert_eq!(actual, expected);
    }
    #[test]
    fn many_alias_routes_share_and_decode_one_large_leaf_definition() {
        let members: Vec<_> = (0..4096).map(|index| serde_json::json!({"name":format!("field{index}"),"type":"core::felt252","kind":"data"})).collect();
        let variants: Vec<_> = (0..128).map(|index| serde_json::json!({"name":format!("Route{index}"),"type":"LargeLeaf","kind":"nested"})).collect();
        let abi = serde_json::json!([
            {"type":"event","name":"Root","kind":"enum","variants":variants},
            {"type":"event","name":"LargeLeaf","kind":"struct","members":members}
        ]);
        let decoder = EventDecoder::from_json(&abi.to_string(), "Root").unwrap();
        assert_eq!(decoder.routes.len(), 128);
        assert_eq!(decoder.types.entries.len(), 2);
        let leaf = EventDecoder::event(&decoder.types, "LargeLeaf").unwrap();
        for route in &decoder.routes {
            assert!(std::ptr::eq(
                leaf,
                EventDecoder::event(&decoder.types, &route.ty).unwrap()
            ));
        }
        for index in [0, 64, 127] {
            let name = format!("Route{index}");
            let result = decoder
                .decode(&Event {
                    from_address: Felt::THREE,
                    keys: vec![selector(&name).unwrap()],
                    data: (0..4096_u64).map(Felt::from).collect(),
                })
                .unwrap();
            assert_eq!(result.event_type, "LargeLeaf");
            assert_eq!(result.path, vec![name]);
            assert_eq!(result.fields.len(), 4096);
            assert_eq!(result.fields["field0"], EventValue::Felt(Felt::ZERO));
            assert_eq!(
                result.fields["field4095"],
                EventValue::Felt(Felt::from(4095_u64))
            );
        }
    }
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
    fn receipt_schema_budget_is_shared_without_changing_per_event_value_limits() {
        let abi = r#"[{"type":"event","name":"Payload","kind":"struct","members":[{"name":"value","type":"()","kind":"data"}]}]"#;
        let decoder = EventDecoder::from_json(abi, "Payload").unwrap();
        let events = vec![
            Event {
                from_address: Felt::ONE,
                keys: vec![],
                data: vec![]
            };
            2
        ];
        let mut budget = NodeBudget::new(0);
        budget.schema.remaining = 2; // First cold root succeeds; second cached lookup exceeds.
        assert_eq!(
            decoder
                .decode_from_with_budget(&events, Felt::ONE, &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI schema validation exceeds work budget"
        );
        assert!(budget.schema.exceeded);
        assert!(!budget.exceeded);
        assert_eq!(decoder.decode_from(&events, Felt::ONE).unwrap().len(), 2);
        let mut budget = NodeBudget::new(0);
        budget.schema.remaining = 2; // Both roots are now cached: one unit each.
        assert_eq!(
            decoder
                .decode_from_with_budget(&events, Felt::ONE, &mut budget)
                .unwrap()
                .len(),
            2
        );
        assert_eq!(budget.remaining, 999_998);
        assert!(!budget.schema.exceeded);
    }
    #[test]
    fn distinct_roots_share_schema_work_and_exhaustion_is_terminal() {
        let members: Vec<_> = (0..32)
            .map(|i| serde_json::json!({"name":format!("f{i}"),"type":"()"}))
            .collect();
        let mut entries =
            vec![serde_json::json!({"type":"struct","name":"Large","members":members})];
        for i in 0..4 {
            entries.push(serde_json::json!({"type":"struct","name":format!("Wrapper{i}"),"members":[{"name":"shared","type":"Large"}]}));
        }
        let members: Vec<_> = (0..4).map(|i| serde_json::json!({"name":format!("arg{i}"),"type":format!("core::array::Array::<Wrapper{i}>"),"kind":"data"})).collect();
        entries.push(
            serde_json::json!({"type":"event","name":"Payload","kind":"struct","members":members}),
        );
        let decoder =
            EventDecoder::from_json(&serde_json::to_string(&entries).unwrap(), "Payload").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![],
            data: vec![Felt::ZERO; 4],
        };
        let mut budget = NodeBudget::new(100);
        budget.schema.remaining = 100;
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI schema validation exceeds work budget"
        );
        assert_eq!(budget.schema.remaining, 0);
        assert!(budget.schema.exceeded);
        assert!(!budget.exceeded);
        assert!(decoder.decode(&event).is_ok());
        // An earlier successful flat candidate must not hide an uninspected later route.
        let abi = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"A","type":"A","kind":"flat"},{"name":"B","type":"B","kind":"nested"}]},{"type":"event","name":"A","kind":"struct","members":[{"name":"value","type":"core::felt252","kind":"key"}]},{"type":"event","name":"B","kind":"struct","members":[{"name":"value","type":"()","kind":"data"}]}]"#;
        let decoder = EventDecoder::from_json(abi, "Root").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![selector("B").unwrap()],
            data: vec![],
        };
        let mut budget = NodeBudget::new(4);
        budget.schema.remaining = 2; // A completes; B cannot even start validation.
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI schema validation exceeds work budget"
        );
        assert_eq!(
            decoder.decode(&event).unwrap_err().to_string(),
            "ambiguous event"
        );
    }
    const ORDINARY_ENUM_ABI: &str = r#"[{"type":"struct","name":"Pair","members":[{"name":"amount","type":"core::integer::u16"},{"name":"enabled","type":"core::bool"}]},{"type":"enum","name":"Choice","variants":[{"name":"None","type":"()"},{"name":"Some","type":"Pair"}]},{"type":"event","name":"Payload","kind":"struct","members":[{"name":"indexed","type":"Choice","kind":"key"},{"name":"values","type":"core::array::Array::<Choice>","kind":"data"},{"name":"tail","type":"core::felt252","kind":"data"}]}]"#;
    fn ordinary_choice(value: Option<(u16, bool)>) -> EventValue {
        match value {
            None => EventValue::Enum {
                variant: "None".into(),
                value: Box::new(EventValue::Sequence(vec![])),
            },
            Some((amount, enabled)) => EventValue::Enum {
                variant: "Some".into(),
                value: Box::new(EventValue::Struct(BTreeMap::from([
                    ("amount".into(), EventValue::Felt(Felt::from(amount))),
                    ("enabled".into(), EventValue::Bool(enabled)),
                ]))),
            },
        }
    }
    #[test]
    fn ordinary_enum_fields_decode_unit_and_struct_payloads_in_keys_and_data() {
        let decoder = EventDecoder::from_json(ORDINARY_ENUM_ABI, "Payload").unwrap();
        for (keys, data, indexed, values, tail) in [
            (
                vec![0u64],
                vec![2, 0, 1, 42, 1, 99],
                ordinary_choice(None),
                vec![ordinary_choice(None), ordinary_choice(Some((42, true)))],
                99u64,
            ),
            (
                vec![1, 7, 0],
                vec![1, 0, 77],
                ordinary_choice(Some((7, false))),
                vec![ordinary_choice(None)],
                77,
            ),
        ] {
            let event = Event {
                from_address: Felt::ONE,
                keys: keys.into_iter().map(Felt::from).collect(),
                data: data.into_iter().map(Felt::from).collect(),
            };
            // Repeat to exercise completed schema-cache results as well as cold validation.
            for _ in 0..2 {
                let output = decoder.decode(&event).unwrap();
                assert_eq!(output.event_type, "Payload");
                assert_eq!(output.path, [] as [String; 0]);
                assert_eq!(
                    output.fields,
                    BTreeMap::from([
                        ("indexed".into(), indexed.clone()),
                        ("values".into(), EventValue::Sequence(values.clone())),
                        ("tail".into(), EventValue::Felt(Felt::from(tail))),
                    ])
                );
            }
        }
    }
    #[test]
    fn ordinary_enum_fields_reject_invalid_discriminants_and_malformed_payloads() {
        let decoder = EventDecoder::from_json(ORDINARY_ENUM_ABI, "Payload").unwrap();
        for (data, expected) in [
            (vec![], "truncated ABI data"),
            (vec![1u64], "truncated ABI data"),
            (vec![1, 1], "truncated ABI data"),
            (vec![1, 1, 42], "truncated ABI data"),
            (vec![1, 2, 99], "invalid enum discriminant"),
            (vec![1, 1, 42, 2, 99], "invalid boolean"),
            (vec![0, 99, 100], "trailing event keys or data"),
        ] {
            let event = Event {
                from_address: Felt::ONE,
                keys: vec![Felt::ZERO],
                data: data.into_iter().map(Felt::from).collect(),
            };
            assert_eq!(decoder.decode(&event).unwrap_err().to_string(), expected);
        }
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![Felt::from(2u64)],
            data: vec![Felt::ZERO, Felt::ONE],
        };
        assert_eq!(
            decoder.decode(&event).unwrap_err().to_string(),
            "invalid enum discriminant"
        );
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![Felt::ZERO],
            data: vec![Felt::ONE, Felt::MAX],
        };
        assert_eq!(
            decoder.decode(&event).unwrap_err().to_string(),
            "length or discriminant does not fit usize"
        );
    }
    #[test]
    fn oversized_array_is_terminal_after_an_earlier_matching_candidate() {
        let abi = r#"[{"type":"event","name":"Root","kind":"enum","variants":[{"name":"A","type":"A","kind":"flat"},{"name":"B","type":"B","kind":"nested"}]},{"type":"event","name":"A","kind":"struct","members":[{"name":"selector","type":"core::felt252","kind":"key"},{"name":"value","type":"core::felt252","kind":"data"}]},{"type":"event","name":"B","kind":"struct","members":[{"name":"values","type":"core::array::Array::<()>","kind":"data"}]}]"#;
        let decoder = EventDecoder::from_json(abi, "Root").unwrap();
        for count in [Felt::from(1_000_001u64), Felt::MAX] {
            let event = Event {
                from_address: Felt::ONE,
                keys: vec![selector("B").unwrap()],
                data: vec![count],
            };
            let mut budget = NodeBudget::new(1_000_000);
            assert_eq!(
                decoder
                    .decode_with_budget(&event, &mut budget)
                    .unwrap_err()
                    .to_string(),
                "array exceeds one million items"
            );
            assert!(budget.exceeded);
            // A completed before B reached the cap; its match must not hide B's exhaustion.
            assert_eq!(budget.remaining, 999_995);
        }
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
    #[test]
    fn second_successful_byte_payload_proves_ambiguity_without_retaining_more() {
        let abi = serde_json::json!([
            {"type":"event","name":"Root","kind":"enum","variants":[{"name":"A","type":"A","kind":"flat"},{"name":"B","type":"B","kind":"nested"}]},
            {"type":"event","name":"A","kind":"struct","members":[{"name":"k1","type":"core::felt252","kind":"key"},{"name":"k2","type":"core::felt252","kind":"key"},{"name":"bytes","type":"core::byte_array::ByteArray","kind":"data"}]},
            {"type":"event","name":"B","kind":"enum","variants":[{"name":"Flat","type":"Flat","kind":"flat"},{"name":"D","type":"D","kind":"nested"}]},
            {"type":"event","name":"Flat","kind":"struct","members":[{"name":"key","type":"core::felt252","kind":"key"},{"name":"bytes","type":"core::byte_array::ByteArray","kind":"data"}]},
            {"type":"event","name":"D","kind":"struct","members":[{"name":"bytes","type":"core::byte_array::ByteArray","kind":"data"}]}
        ]);
        let decoder = EventDecoder::from_json(&abi.to_string(), "Root").unwrap();
        let event = Event {
            from_address: Felt::ONE,
            keys: vec![selector("B").unwrap(), selector("D").unwrap()],
            data: vec![Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO],
        };
        let mut budget = NodeBudget::new(11);
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut budget)
                .unwrap_err()
                .to_string(),
            "ambiguous event"
        );
        assert_eq!(budget.remaining, 0);
        assert!(!budget.exceeded);
        assert_eq!(
            decoder
                .decode_with_budget(&event, &mut NodeBudget::new(10))
                .unwrap_err()
                .to_string(),
            "decoded values exceed node budget"
        );
    }
}
