//! Cairo 1/2 ABI event decoding, including nested and flat event enums.
use starknet_rust_core::{
    types::{
        Event, Felt,
        contract::{AbiEntry, AbiEvent, EventFieldKind, TypedAbiEvent},
    },
    utils::get_selector_from_name,
};
use std::collections::{BTreeMap, BTreeSet};
mod value;
pub use value::{EventDecodeError, EventValue};
use value::{EventTypes, error};

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
/// Select the Cairo 2 `Event` enum by its fully qualified ABI name. For an untyped Cairo 1 event
/// or a stand-alone typed struct, the first key is its short-name selector. Cairo 0 ABIs are not
/// accepted. Unsupported value types return an error, never an unvalidated raw fallback.
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
        let types = EventTypes { entries: flat };
        let mut names = BTreeSet::new();
        for e in &types.entries {
            let name = match e {
                AbiEntry::Event(e) => Some(event_name(e)),
                AbiEntry::Struct(s) => Some(s.name.as_str()),
                AbiEntry::Enum(e) => Some(e.name.as_str()),
                _ => None,
            };
            if let Some(name) = name
                && !names.insert(name)
            {
                return Err(error("duplicate event/type name"));
            }
        }
        let mut decoder = Self {
            types,
            routes: vec![],
        };
        let is_enum = matches!(
            decoder.event(root)?,
            AbiEvent::Typed(TypedAbiEvent::Enum(_))
        );
        decoder.routes(
            root,
            if is_enum {
                vec![]
            } else {
                vec![selector(short_name(root))?]
            },
            vec![],
            &mut vec![],
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
            .entries
            .iter()
            .find_map(|e| match e {
                AbiEntry::Event(e) if event_name(e) == name => Some(e),
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
    ) -> Result<(), EventDecodeError> {
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
                    self.routes(&v.r#type, selectors, path, stack)?;
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
        let mut matches = vec![];
        for route in &self.routes {
            if event.keys.starts_with(&route.selectors) {
                let mut keys = &event.keys[route.selectors.len()..];
                let mut data = event.data.as_slice();
                if let Ok(fields) = self.fields(&route.ty, &mut keys, &mut data, 0)
                    && keys.is_empty()
                    && data.is_empty()
                {
                    matches.push(DecodedEvent {
                        from_address: event.from_address,
                        path: route.path.clone(),
                        event_type: route.ty.clone(),
                        fields,
                    });
                }
            }
        }
        match matches.len() {
            1 => Ok(matches.remove(0)),
            0 => Err(error("unknown selector or malformed event keys/data")),
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
    ) -> Result<BTreeMap<String, EventValue>, EventDecodeError> {
        if depth > 64 {
            return Err(error("event nesting exceeds 64"));
        }
        let mut fields = BTreeMap::new();
        match self.event(ty)? {
            AbiEvent::Untyped(e) => {
                for m in &e.inputs {
                    if fields
                        .insert(m.name.clone(), self.types.decode_value(&m.r#type, data)?)
                        .is_some()
                    {
                        return Err(error("duplicate event member"));
                    }
                }
            }
            AbiEvent::Typed(TypedAbiEvent::Struct(e)) => {
                for m in &e.members {
                    let value = match m.kind {
                        EventFieldKind::Key => self.types.decode_value(&m.r#type, keys)?,
                        EventFieldKind::Data => self.types.decode_value(&m.r#type, data)?,
                        EventFieldKind::Nested | EventFieldKind::Flat => {
                            if matches!(m.kind, EventFieldKind::Nested) {
                                let (head, tail) = keys
                                    .split_first()
                                    .ok_or_else(|| error("missing nested event selector"))?;
                                if *head != selector(&m.name)? {
                                    return Err(error("wrong nested event selector"));
                                }
                                *keys = tail;
                            }
                            EventValue::Struct(self.fields(&m.r#type, keys, data, depth + 1)?)
                        }
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
    get_selector_from_name(name).map_err(|e| error(e.to_string()))
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
    fn nested_flat_paths_and_struct_values() {
        let d = EventDecoder::from_json(ABI, "app::Event").unwrap();
        let e = Event {
            from_address: Felt::ONE,
            keys: vec![selector("Transfer").unwrap(), Felt::TWO, Felt::THREE],
            data: vec![Felt::ONE, Felt::ZERO],
        };
        let decoded = d.decode(&e).unwrap();
        assert_eq!(decoded.path, vec!["Token", "Transfer"]);
        assert_eq!(decoded.fields["from"], EventValue::Felt(Felt::TWO));
        assert_eq!(
            decoded.fields["amount"],
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
