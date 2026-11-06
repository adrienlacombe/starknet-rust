use starknet_rust_core::types::{Felt, contract::AbiEntry};
use std::{collections::BTreeMap, fmt, sync::RwLock};
/// A value described by a Cairo 1 ABI. Integers use canonical field encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventValue {
    /// A field element, unsigned integer, or address.
    Felt(Felt),
    /// A Cairo boolean.
    Bool(bool),
    /// An ordered tuple or array.
    Sequence(Vec<Self>),
    /// Named struct fields.
    Struct(BTreeMap<String, Self>),
    /// An enum variant and its payload (unit is an empty sequence).
    Enum {
        /// Variant name.
        variant: String,
        /// Variant payload.
        value: Box<Self>,
    },
    /// Cairo `ByteArray` bytes, which need not be UTF-8.
    Bytes(Vec<u8>),
}

/// Invalid ABI, value, or return data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDecodeError(pub String);
impl fmt::Display for EventDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for EventDecodeError {}
pub(super) fn error(message: impl Into<String>) -> EventDecodeError {
    EventDecodeError(message.into())
}

#[derive(Debug)]
struct SchemaCache {
    results: BTreeMap<String, Result<(), EventDecodeError>>,
    remaining: usize,
}
impl SchemaCache {
    const fn new() -> Self {
        Self {
            results: BTreeMap::new(),
            remaining: 64 * 1024 * 1024,
        }
    }
    fn cache(
        &mut self,
        ty: &str,
        result: &Result<(), EventDecodeError>,
        budget: &mut SchemaBudget,
    ) -> Result<(), EventDecodeError> {
        // Cache capacity is optional, shared across operations, and accounted under
        // the same write lock as insertion. Concurrent completed roots never double-charge.
        if self.results.contains_key(ty) {
            return Ok(());
        }
        let bytes = ty
            .len()
            .saturating_add(match result {
                Ok(()) => 0,
                Err(failure) => failure.0.len(),
            })
            .saturating_add(128);
        if let Some(remaining) = self.remaining.checked_sub(bytes) {
            budget.charge_owned(bytes)?;
            self.results.insert(ty.to_owned(), result.clone());
            self.remaining = remaining;
        }
        Ok(())
    }
}
impl std::ops::Deref for SchemaCache {
    type Target = BTreeMap<String, Result<(), EventDecodeError>>;
    fn deref(&self) -> &Self::Target {
        &self.results
    }
}

// Per operation, cold schema traversal is bounded independently of decoded value nodes.
const DEFAULT_SCHEMA_WORK: usize = 1_000_000;
pub(super) struct SchemaBudget {
    pub(super) remaining: usize,
    pub(super) exceeded: bool,
    pub(super) owned: usize,
    pub(super) text: usize,
    pub(super) route_remaining: usize,
}
impl SchemaBudget {
    pub(super) const fn new(remaining: usize) -> Self {
        Self {
            remaining,
            exceeded: false,
            owned: 64 * 1024 * 1024,
            text: 64 * 1024 * 1024,
            route_remaining: 1_000_000,
        }
    }
    fn charge(&mut self) -> Result<(), EventDecodeError> {
        if self.remaining == 0 {
            self.exceeded = true;
            return Err(error("ABI schema validation exceeds work budget"));
        }
        self.remaining -= 1;
        Ok(())
    }

    pub(super) fn charge_routes(&mut self, count: usize) -> Result<(), EventDecodeError> {
        let Some(remaining) = self.route_remaining.checked_sub(count) else {
            self.exceeded = true;
            return Err(error("event route inspection exceeds work budget"));
        };
        self.route_remaining = remaining;
        Ok(())
    }
    pub(super) fn charge_owned(&mut self, count: usize) -> Result<(), EventDecodeError> {
        let Some(remaining) = self.owned.checked_sub(count) else {
            self.exceeded = true;
            return Err(error("ABI logical allocation exceeds byte budget"));
        };
        self.owned = remaining;
        Ok(())
    }
    pub(super) fn charge_text(&mut self, count: usize) -> Result<(), EventDecodeError> {
        let Some(remaining) = self.text.checked_sub(count) else {
            self.exceeded = true;
            return Err(error("ABI type text exceeds work budget"));
        };
        self.text = remaining;
        Ok(())
    }
}

pub(super) struct NodeBudget {
    pub(super) remaining: usize,
    pub(super) exceeded: bool,
    pub(super) schema: SchemaBudget,
}
impl NodeBudget {
    pub(super) const fn new(remaining: usize) -> Self {
        Self {
            remaining,
            exceeded: false,
            schema: SchemaBudget::new(DEFAULT_SCHEMA_WORK),
        }
    }
}
pub(super) fn charge_node(budget: &mut NodeBudget) -> Result<(), EventDecodeError> {
    charge_nodes(budget, 1)
}
fn charge_nodes(budget: &mut NodeBudget, count: usize) -> Result<(), EventDecodeError> {
    let Some(remaining) = budget.remaining.checked_sub(count) else {
        // Reaching exactly zero is valid. Only a failed charge means a candidate
        // could not be inspected, so earlier matches cannot safely be returned.
        budget.exceeded = true;
        return Err(error("decoded values exceed node budget"));
    };
    budget.remaining = remaining;
    Ok(())
}

pub(super) struct EventTypes {
    pub(super) entries: Vec<AbiEntry>,
    type_indices: BTreeMap<String, usize>,
    pub(super) event_indices: BTreeMap<String, usize>,
    #[cfg(test)]
    schema_passes: std::sync::atomic::AtomicUsize,
    schema_results: RwLock<SchemaCache>,
}
impl EventTypes {
    pub(super) fn new(entries: Vec<AbiEntry>) -> Self {
        let mut type_indices = BTreeMap::new();
        let mut event_indices = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            match entry {
                AbiEntry::Struct(s) => {
                    type_indices.insert(s.name.clone(), index);
                }
                AbiEntry::Enum(e) => {
                    type_indices.insert(e.name.clone(), index);
                }
                AbiEntry::Event(e) => {
                    event_indices.insert(super::event_name(e).to_owned(), index);
                }
                _ => {}
            }
        }
        Self {
            entries,
            type_indices,
            event_indices,
            #[cfg(test)]
            schema_passes: std::sync::atomic::AtomicUsize::new(0),
            schema_results: RwLock::new(SchemaCache::new()),
        }
    }
    pub(super) fn decode_value(
        &self,
        ty: &str,
        data: &mut &[Felt],
        budget: &mut NodeBudget,
    ) -> Result<EventValue, EventDecodeError> {
        self.validate_type(ty, &mut budget.schema)?;
        self.decode(ty, data, 0, budget)
    }
    // Validate the schema independently of values, so empty arrays and unselected enum
    // variants cannot hide unsupported types. Each type is visited once, allowing recursive
    // named schemas without revisiting cycles; value depth/node limits still apply separately.
    fn validate_type(&self, ty: &str, budget: &mut SchemaBudget) -> Result<(), EventDecodeError> {
        budget.charge()?;
        budget.charge_text(ty.len().saturating_mul(4))?;
        let ty = ty.trim();
        if let Some(result) = self
            .schema_results
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(ty)
        {
            if let Err(failure) = result {
                budget.charge_owned(failure.0.len())?;
                budget.charge_text(failure.0.len())?;
            }
            return result.clone();
        }
        #[cfg(test)]
        self.schema_passes
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let result =
            self.validate_type_graph(ty, &mut std::collections::BTreeSet::new(), 0, budget);
        if !budget.exceeded {
            self.schema_results
                .write()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .cache(ty, &result, budget)?;
        }
        result
    }
    fn validate_type_graph(
        &self,
        ty: &str,
        seen: &mut std::collections::BTreeSet<String>,
        depth: usize,
        budget: &mut SchemaBudget,
    ) -> Result<(), EventDecodeError> {
        budget.charge()?;
        budget.charge_text(ty.len().saturating_mul(4))?;
        if depth > 64 {
            return Err(error("ABI type nesting exceeds 64"));
        }
        let ty = ty.trim();
        budget.charge_owned(
            ty.len()
                .saturating_mul(2)
                .saturating_add(std::mem::size_of::<String>()),
        )?;
        if !seen.insert(ty.to_owned()) {
            return Ok(());
        }
        // Every explicit declaration is checked before any wire-syntax shortcut.
        // The wire form is still checked afterwards: a declared Array/tuple cannot
        // hide unsupported implicit element types by supplying an empty struct.
        let declared = match self.type_indices.get(ty).map(|index| &self.entries[*index]) {
            Some(AbiEntry::Struct(definition)) => {
                let mut names = std::collections::BTreeSet::new();
                for member in &definition.members {
                    budget.charge()?;
                    budget.charge_text(member.name.len())?;
                    if !names.insert(&member.name) {
                        return Err(error("duplicate ABI struct member"));
                    }
                    self.validate_type_graph(&member.r#type, seen, depth + 1, budget)?;
                }
                true
            }
            Some(AbiEntry::Enum(definition)) => {
                let mut names = std::collections::BTreeSet::new();
                for variant in &definition.variants {
                    budget.charge()?;
                    budget.charge_text(variant.name.len())?;
                    if !names.insert(&variant.name) {
                        return Err(error("duplicate ABI enum variant"));
                    }
                    self.validate_type_graph(&variant.r#type, seen, depth + 1, budget)?;
                }
                true
            }
            _ => false,
        };
        if let Some(inner) = ty.strip_prefix('@') {
            // Snapshot ownership does not change the Cairo Serde wire form. Validate
            // the referenced schema too, including any explicit declaration.
            budget.charge()?;
            return self.validate_type_graph(inner, seen, depth + 1, budget);
        }
        if ty == "core::integer::u256" {
            // The builtin codec recursively uses this named limb type even when
            // the ABI omits a u256 declaration.
            budget.charge()?;
            return self.validate_type_graph("core::integer::u128", seen, depth + 1, budget);
        }
        // Bool and Bytes are atomic public values: they have no named child
        // values. Explicit ABI declaration fields were still validated above.
        // u256 instead exposes named u128 low/high children in its public Struct.
        if scalar_bits(ty).is_some() || matches!(ty, "core::bool" | "core::byte_array::ByteArray") {
            return Ok(());
        }
        if let Some(inner) = array_inner(ty) {
            budget.charge()?;
            return self.validate_type_graph(inner, seen, depth + 1, budget);
        }
        if let Some(types) = tuple_types(ty)? {
            for ty in types {
                budget.charge()?;
                self.validate_type_graph(ty, seen, depth + 1, budget)?;
            }
            return Ok(());
        }
        if declared {
            Ok(())
        } else {
            Err(error(format!("unsupported type: {ty}")))
        }
    }
    fn decode(
        &self,
        ty: &str,
        data: &mut &[Felt],
        depth: usize,
        budget: &mut NodeBudget,
    ) -> Result<EventValue, EventDecodeError> {
        charge_node(budget)?;
        if depth > 64 {
            return Err(error("ABI nesting exceeds 64"));
        }
        budget.schema.charge_text(ty.len().saturating_mul(4))?;
        budget.schema.charge_owned(
            ty.len()
                .saturating_add(2 * std::mem::size_of::<EventValue>()),
        )?;
        let ty = ty.trim();
        if let Some(inner) = ty.strip_prefix('@') {
            return self.decode(inner, data, depth + 1, budget);
        }
        if scalar_bits(ty).is_some() {
            let f = take(data)?;
            validate_scalar(ty, f)?;
            return Ok(EventValue::Felt(f));
        }
        if ty == "core::integer::u256" {
            let mut fields = BTreeMap::new();
            for name in ["low", "high"] {
                budget
                    .schema
                    .charge_owned(name.len() + std::mem::size_of::<String>())?;
                fields.insert(
                    name.to_owned(),
                    self.decode("core::integer::u128", data, depth + 1, budget)?,
                );
            }
            return Ok(EventValue::Struct(fields));
        }
        if ty == "core::bool" {
            return match take(data)? {
                f if f == Felt::ZERO => Ok(EventValue::Bool(false)),
                f if f == Felt::ONE => Ok(EventValue::Bool(true)),
                _ => Err(error("invalid boolean")),
            };
        }
        if ty == "core::byte_array::ByteArray" {
            let n = length(take(data)?)?;
            if data.len() < 2 || n > data.len() - 2 {
                return Err(error("truncated ByteArray"));
            }
            // Charge full words and the pending word before allocating their bytes.
            let words = n
                .checked_add(1)
                .ok_or_else(|| error("ByteArray size overflow"))?;
            charge_nodes(budget, words)?;
            let pending_len = length(data[n + 1])?;
            let pending_word = data[n].to_bytes_be();
            if pending_len > 30 || pending_word[..32 - pending_len].iter().any(|b| *b != 0) {
                return Err(error("invalid ByteArray pending word"));
            }
            let capacity = n
                .checked_mul(31)
                .and_then(|size| size.checked_add(pending_len))
                .ok_or_else(|| error("ByteArray size overflow"))?;
            budget.schema.charge_owned(capacity)?;
            let mut bytes = Vec::with_capacity(capacity);
            for _ in 0..n {
                let word = take(data)?.to_bytes_be();
                if word[0] != 0 {
                    return Err(error("invalid ByteArray full word"));
                }
                bytes.extend_from_slice(&word[1..]);
            }
            let pending = take(data)?.to_bytes_be();
            let len = length(take(data)?)?;
            if len > 30 || pending[..32 - len].iter().any(|b| *b != 0) {
                return Err(error("invalid ByteArray pending word"));
            }
            bytes.extend_from_slice(&pending[32 - len..]);
            return Ok(EventValue::Bytes(bytes));
        }
        if let Some(inner) = array_inner(ty) {
            // Compare before host-sized conversion so every above-cap count,
            // including lengths beyond usize on native/WASM, is a terminal resource abort.
            let count = take(data)?;
            if count > Felt::from(1_000_000u64) {
                budget.exceeded = true;
                return Err(error("array exceeds one million items"));
            }
            let n = length(count)?;
            let mut values = Vec::new();
            for _ in 0..n {
                values.push(self.decode(inner, data, depth + 1, budget)?);
            }
            return Ok(EventValue::Sequence(values));
        }
        if let Some(types) = tuple_types(ty)? {
            return types
                .map(|t| self.decode(t, data, depth + 1, budget))
                .collect::<Result<Vec<_>, _>>()
                .map(EventValue::Sequence);
        }
        if let Some(entry) = self.type_indices.get(ty).map(|index| &self.entries[*index]) {
            match entry {
                AbiEntry::Struct(s) if s.name == ty => {
                    let mut values = BTreeMap::new();
                    for m in &s.members {
                        budget.schema.charge_text(m.name.len())?;
                        budget.schema.charge_owned(
                            m.name.len().saturating_add(std::mem::size_of::<String>()),
                        )?;
                        values.insert(
                            m.name.clone(),
                            self.decode(&m.r#type, data, depth + 1, budget)?,
                        );
                    }
                    return Ok(EventValue::Struct(values));
                }
                AbiEntry::Enum(e) if e.name == ty => {
                    let index = length(take(data)?)?;
                    let v = e
                        .variants
                        .get(index)
                        .ok_or_else(|| error("invalid enum discriminant"))?;
                    budget.schema.charge_owned(v.name.len())?;
                    return Ok(EventValue::Enum {
                        variant: v.name.clone(),
                        value: Box::new(self.decode(&v.r#type, data, depth + 1, budget)?),
                    });
                }
                _ => {}
            }
        }
        Err(error(format!("unsupported type: {ty}")))
    }
}
fn scalar_bits(ty: &str) -> Option<usize> {
    match ty {
        "core::felt252" => Some(252),
        "core::starknet::contract_address::ContractAddress"
        | "core::starknet::class_hash::ClassHash"
        | "core::starknet::storage_access::StorageAddress" => Some(251),
        "core::integer::u8" => Some(8),
        "core::integer::u16" => Some(16),
        "core::integer::u32" => Some(32),
        "core::integer::u64" => Some(64),
        "core::integer::u96" => Some(96),
        "core::integer::u128" => Some(128),
        "core::bytes_31::bytes31" => Some(248),
        _ => None,
    }
}
fn validate_scalar(ty: &str, value: Felt) -> Result<(), EventDecodeError> {
    let bits = scalar_bits(ty).ok_or_else(|| error("unsupported scalar"))?;
    let bytes = value.to_bytes_be();
    if bits < 252 && (0..256 - bits).any(|i| bytes[i / 8] & (1 << (7 - i % 8)) != 0) {
        return Err(error(format!("value out of range for {ty}")));
    }
    Ok(())
}
fn array_inner(ty: &str) -> Option<&str> {
    ["core::array::Array::<", "core::array::Span::<"]
        .iter()
        .find_map(|p| ty.strip_prefix(p).and_then(|t| t.strip_suffix('>')))
}
#[derive(Clone)]
struct TupleTypes<'a> {
    inner: &'a str,
}
impl<'a> Iterator for TupleTypes<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        if self.inner.is_empty() {
            return None;
        }
        let mut depth = 0usize;
        for (index, character) in self.inner.char_indices() {
            match character {
                '(' | '<' | '[' => depth += 1,
                ')' | '>' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    let field = self.inner[..index].trim();
                    self.inner = &self.inner[index + 1..];
                    return Some(field);
                }
                _ => {}
            }
        }
        let field = self.inner.trim();
        self.inner = "";
        Some(field)
    }
}
fn tuple_types(ty: &str) -> Result<Option<TupleTypes<'_>>, EventDecodeError> {
    if !ty.starts_with('(') {
        return Ok(None);
    }
    let inner = ty
        .strip_prefix('(')
        .and_then(|text| text.strip_suffix(')'))
        .ok_or_else(|| error("malformed tuple type"))?;
    let mut depth = 0usize;
    for character in inner.chars() {
        match character {
            '(' | '<' | '[' => {
                depth = depth
                    .checked_add(1)
                    .ok_or_else(|| error("malformed tuple type"))?;
            }
            ')' | '>' | ']' => {
                depth = depth
                    .checked_sub(1)
                    .ok_or_else(|| error("malformed tuple type"))?;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(error("malformed tuple type"));
    }
    Ok(Some(TupleTypes {
        inner: inner.trim(),
    }))
}
fn take(data: &mut &[Felt]) -> Result<Felt, EventDecodeError> {
    let (first, rest) = data
        .split_first()
        .ok_or_else(|| error("truncated ABI data"))?;
    *data = rest;
    Ok(*first)
}
fn length(value: Felt) -> Result<usize, EventDecodeError> {
    usize::try_from(value).map_err(|_| error("length or discriminant does not fit usize"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn opaque_byte_arrays_ignore_unreferenced_named_types_but_validate_explicit_fields() {
        let mut bytes = vec![0xff; 31];
        bytes.extend_from_slice(&[0x80, 0xff]);
        let wire = [
            Felt::ONE,
            Felt::from_bytes_be_slice(&[0xff; 31]),
            Felt::from(0x80ffu64),
            Felt::from(2u64),
        ];
        for ty in [
            "core::bytes_31::bytes31",
            "core::integer::u32",
            "core::felt252",
        ] {
            let malformed = serde_json::json!({"type":"struct","name":ty,"members":[{"name":"bad","type":"Unknown"}]});
            let json = serde_json::json!([malformed]).to_string();
            let codec = EventTypes::new(serde_json::from_str(&json).unwrap());

            assert_eq!(
                codec
                    .decode_value(
                        "core::byte_array::ByteArray",
                        &mut wire.as_slice(),
                        &mut NodeBudget::new(100)
                    )
                    .unwrap(),
                EventValue::Bytes(bytes.clone())
            );
            let json = serde_json::json!([malformed,{"type":"struct","name":"core::byte_array::ByteArray","members":[{"name":"declared","type":ty}]}]).to_string();
            let codec = EventTypes::new(serde_json::from_str(&json).unwrap());
            assert_eq!(
                codec
                    .decode_value(
                        "core::byte_array::ByteArray",
                        &mut wire.as_slice(),
                        &mut NodeBudget::new(100)
                    )
                    .unwrap_err()
                    .to_string(),
                "unsupported type: Unknown"
            );
        }
    }

    #[test]
    fn text_exhaustion_and_cached_diagnostic_copy_cannot_poison_structural_results() {
        let unknown = "Unknown".repeat(64);
        let json = serde_json::json!([{"type":"struct","name":"S","members":[{"name":"field","type":unknown}]}]).to_string();
        let codec = EventTypes::new(serde_json::from_str(&json).unwrap());
        let mut budget = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        budget.text = 16;
        assert_eq!(
            codec
                .validate_type("S", &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI type text exceeds work budget"
        );
        assert!(budget.exceeded);
        assert_eq!(codec.schema_results.read().unwrap().len(), 0);
        let expected = format!("unsupported type: {unknown}");
        assert_eq!(
            codec
                .validate_type("S", &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK))
                .unwrap_err()
                .to_string(),
            expected
        );
        let mut budget = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        budget.owned = 16;
        assert_eq!(
            codec
                .validate_type("S", &mut budget)
                .unwrap_err()
                .to_string(),
            "ABI logical allocation exceeds byte budget"
        );
        assert!(budget.exceeded);
        assert_eq!(
            codec
                .validate_type("S", &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK))
                .unwrap_err()
                .to_string(),
            expected
        );
    }

    #[test]
    fn logical_byte_limit_bounds_repeated_owned_member_and_variant_names() {
        let long = "x".repeat(256);
        for declaration in [
            serde_json::json!({"type":"struct","name":"S","members":[{"name":long,"type":"()"}]}),
            serde_json::json!({"type":"enum","name":"S","variants":[{"name":long,"type":"()"}]}),
        ] {
            let is_enum = declaration["type"] == "enum";
            let json = serde_json::json!([declaration]).to_string();
            let codec = EventTypes::new(serde_json::from_str(&json).unwrap());
            let root = "core::array::Array::<S>".to_owned();
            let data = if is_enum {
                vec![
                    Felt::from(4u64),
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                    Felt::ZERO,
                ]
            } else {
                vec![Felt::from(4u64)]
            };
            assert!(
                matches!(codec.decode_value(&root, &mut data.as_slice(), &mut NodeBudget::new(100)).unwrap(), EventValue::Sequence(values) if values.len() == 4)
            );
            let mut resources = NodeBudget::new(100);
            resources.schema.owned = 512;
            assert_eq!(
                codec
                    .decode_value(&root, &mut data.as_slice(), &mut resources)
                    .unwrap_err()
                    .to_string(),
                "ABI logical allocation exceeds byte budget"
            );
            assert!(resources.schema.exceeded);
            assert!(
                matches!(codec.decode_value(&root, &mut data.as_slice(), &mut NodeBudget::new(100)).unwrap(), EventValue::Sequence(values) if values.len() == 4)
            );
        }
    }
    #[test]
    fn repeated_borrowed_tuple_parsing_obeys_text_work_limit() {
        let json = "[]".to_owned();
        let codec = EventTypes::new(serde_json::from_str(&json).unwrap());
        let root = format!("core::array::Array::<((),{}())>", " ".repeat(512));
        let data = [Felt::from(3u64)];
        assert!(
            matches!(codec.decode_value(&root, &mut data.as_slice(), &mut NodeBudget::new(100)).unwrap(), EventValue::Sequence(values) if values.len() == 3)
        );
        let mut resources = NodeBudget::new(100);
        resources.schema.text = 7_500;
        assert_eq!(
            codec
                .decode_value(&root, &mut data.as_slice(), &mut resources)
                .unwrap_err()
                .to_string(),
            "ABI type text exceeds work budget"
        );
        assert!(resources.schema.exceeded);
        assert!(
            matches!(codec.decode_value(&root, &mut data.as_slice(), &mut NodeBudget::new(100)).unwrap(), EventValue::Sequence(values) if values.len() == 3)
        );
        for malformed in ["(()", "())", "((),<)", "((),>)"] {
            assert!(tuple_types(malformed).is_err());
        }
        assert_eq!(tuple_types(" ( )".trim()).unwrap().unwrap().count(), 0);
        assert_eq!(
            tuple_types("((), (), )")
                .unwrap()
                .unwrap()
                .collect::<Vec<_>>(),
            vec!["()", "()"]
        );
    }
    #[test]
    fn full_optional_schema_cache_does_not_reject_valid_values() {
        let json = r#"[{"type":"struct","name":"S","members":[]}]"#.to_owned();
        let codec = EventTypes::new(serde_json::from_str(&json).unwrap());
        codec.schema_results.write().unwrap().remaining = 0;
        let root = "S".to_owned();
        let data: [Felt; 0] = [];
        for _ in 0..2 {
            assert_eq!(
                codec
                    .decode_value(&root, &mut data.as_slice(), &mut NodeBudget::new(100))
                    .unwrap(),
                EventValue::Struct(BTreeMap::new())
            );
        }
        assert_eq!(codec.schema_results.read().unwrap().len(), 0);
    }

    #[test]
    fn cached_recursive_schema_errors_propagate_and_decoder_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<super::super::EventDecoder>();
        let types = EventTypes::new(serde_json::from_str(r#"[{"type":"struct","name":"Node","members":[{"name":"children","type":"core::array::Array::<Node>"},{"name":"invalid","type":"Unknown"}]}]"#).unwrap());
        for _ in 0..2 {
            for ty in ["core::array::Array::<Node>", "Node"] {
                assert!(
                    types
                        .decode_value(
                            ty,
                            &mut [Felt::ZERO].as_slice(),
                            &mut NodeBudget::new(1_000_000)
                        )
                        .is_err()
                );
            }
        }
        assert_eq!(
            types
                .schema_passes
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
    #[test]
    fn repeated_empty_arrays_validate_the_large_schema_only_once() {
        let mut entries = vec![];
        for index in 0..1_000 {
            entries.push(serde_json::json!({"type":"struct","name":format!("Unrelated{index}"),"members":[]}));
        }
        let members: Vec<_> = (0..4_096)
            .map(|index| serde_json::json!({"name":format!("field{index}"),"type":"core::felt252"}))
            .collect();
        entries.push(serde_json::json!({"type":"struct","name":"Large","members":members}));
        let types =
            EventTypes::new(serde_json::from_value(serde_json::Value::Array(entries)).unwrap());
        for _ in 0..256 {
            assert_eq!(
                types
                    .decode_value(
                        "core::array::Array::<Large>",
                        &mut [Felt::ZERO].as_slice(),
                        &mut NodeBudget::new(1_000_000)
                    )
                    .unwrap(),
                EventValue::Sequence(vec![])
            );
            assert!(
                types
                    .decode_value(
                        "Unknown",
                        &mut [].as_slice(),
                        &mut NodeBudget::new(1_000_000)
                    )
                    .is_err()
            );
        }
        assert_eq!(
            types
                .schema_passes
                .load(std::sync::atomic::Ordering::Relaxed),
            2
        );
    }
    #[test]
    fn empty_array_schema_validation_handles_cycles_and_all_siblings() {
        let entries = serde_json::from_str(r#"[{"type":"struct","name":"Node","members":[{"name":"children","type":"core::array::Array::<Node>"},{"name":"value","type":"Unknown"}]},{"type":"enum","name":"Choice","variants":[{"name":"None","type":"()"},{"name":"Some","type":"Unknown"}]}]"#).unwrap();
        let types = EventTypes::new(entries);
        for ty in [
            "core::array::Array::<Unknown>",
            "core::array::Span::<Unknown>",
            "core::array::Array::<core::array::Array::<Unknown>>",
            "core::array::Array::<(core::felt252, Unknown)>",
            "core::array::Array::<Node>",
            "core::array::Span::<Choice>",
        ] {
            assert!(
                types
                    .decode_value(
                        ty,
                        &mut [Felt::ZERO].as_slice(),
                        &mut NodeBudget::new(1_000_000)
                    )
                    .is_err(),
                "{ty}"
            );
        }
        let types = EventTypes::new(serde_json::from_str(r#"[{"type":"struct","name":"Node","members":[{"name":"children","type":"core::array::Array::<Node>"},{"name":"value","type":"core::felt252"}]}]"#).unwrap());
        assert_eq!(
            types
                .decode_value(
                    "core::array::Array::<Node>",
                    &mut [Felt::ZERO].as_slice(),
                    &mut NodeBudget::new(1_000_000)
                )
                .unwrap(),
            EventValue::Sequence(vec![])
        );
        assert_eq!(
            types
                .decode_value(
                    "Node",
                    &mut [Felt::ZERO, Felt::THREE].as_slice(),
                    &mut NodeBudget::new(1_000_000)
                )
                .unwrap(),
            EventValue::Struct(BTreeMap::from([
                ("children".into(), EventValue::Sequence(vec![])),
                ("value".into(), EventValue::Felt(Felt::THREE))
            ]))
        );
    }
    #[test]
    fn duplicate_ordinary_struct_fields_are_rejected_before_consuming_values() {
        let types = EventTypes::new(serde_json::from_str(r#"[{"type":"struct","name":"Bad","members":[{"name":"x","type":"core::integer::u8"},{"name":"x","type":"core::integer::u8"}]},{"type":"enum","name":"BadEnum","variants":[{"name":"A","type":"core::integer::u8"},{"name":"A","type":"core::integer::u8"}]}]"#).unwrap());
        let data = [Felt::ONE, Felt::TWO];
        let mut input = data.as_slice();
        assert!(
            types
                .decode_value("Bad", &mut input, &mut NodeBudget::new(100))
                .is_err()
        );
        assert_eq!(input, data.as_slice());
        assert!(
            types
                .decode_value("BadEnum", &mut data.as_slice(), &mut NodeBudget::new(100))
                .is_err()
        );
    }
    #[test]
    fn declared_builtin_schemas_are_validated_before_consuming_values() {
        for (ty, kind, fields, expected) in [
            (
                "core::integer::u256",
                "struct",
                serde_json::json!([{"name":"low","type":"core::integer::u128"},{"name":"low","type":"core::integer::u128"}]),
                "duplicate ABI struct member",
            ),
            (
                "core::bool",
                "enum",
                serde_json::json!([{"name":"False","type":"()"},{"name":"False","type":"()"}]),
                "duplicate ABI enum variant",
            ),
            (
                "core::felt252",
                "struct",
                serde_json::json!([{"name":"value","type":"Unknown"}]),
                "unsupported type: Unknown",
            ),
            (
                "core::byte_array::ByteArray",
                "struct",
                serde_json::json!([{"name":"data","type":"Unknown"}]),
                "unsupported type: Unknown",
            ),
        ] {
            let mut declaration = serde_json::json!({"type":kind,"name":ty});
            declaration[if kind == "enum" {
                "variants"
            } else {
                "members"
            }] = fields;
            let types =
                EventTypes::new(serde_json::from_value(serde_json::json!([declaration])).unwrap());
            for root in [ty.to_owned(), format!("core::array::Array::<{ty}>")] {
                for _ in 0..2 {
                    let input = [Felt::ZERO; 3];
                    let mut data = input.as_slice();
                    let mut budget = NodeBudget::new(100);
                    assert_eq!(
                        types
                            .decode_value(&root, &mut data, &mut budget)
                            .unwrap_err()
                            .to_string(),
                        expected
                    );
                    assert_eq!(data, input.as_slice());
                    assert_eq!(budget.remaining, 100);
                    assert!(!budget.exceeded);
                }
            }
        }
    }
    #[test]
    fn valid_declared_builtins_keep_their_special_wire_encodings() {
        let types = EventTypes::new(serde_json::from_str(r#"[{"type":"enum","name":"core::bool","variants":[{"name":"False","type":"()"},{"name":"True","type":"()"}]},{"type":"struct","name":"core::byte_array::ByteArray","members":[{"name":"data","type":"core::array::Array::<core::bytes_31::bytes31>"},{"name":"pending_word","type":"core::felt252"},{"name":"pending_word_len","type":"core::integer::u32"}]}]"#).unwrap());
        for (ty, wire, value) in [
            ("core::bool", vec![Felt::ONE], EventValue::Bool(true)),
            (
                "core::byte_array::ByteArray",
                vec![Felt::ZERO, Felt::from(b'a'), Felt::ONE],
                EventValue::Bytes(vec![b'a']),
            ),
        ] {
            let mut data = wire.as_slice();
            assert_eq!(
                types
                    .decode_value(ty, &mut data, &mut NodeBudget::new(100))
                    .unwrap(),
                value
            );
            assert_eq!(data, [] as [Felt; 0]);
        }
    }
    #[test]
    fn aggregate_budget_bounds_nested_zero_sized_values() {
        let types = EventTypes::new(vec![]);
        let data = [Felt::TWO, Felt::from(6u8), Felt::from(6u8)];
        assert!(
            types
                .decode(
                    "core::array::Array::<core::array::Array::<()>>",
                    &mut data.as_slice(),
                    0,
                    &mut NodeBudget::new(10)
                )
                .is_err()
        );
    }
    #[test]
    fn all_special_wire_forms_validate_explicit_declarations_first() {
        for ty in [
            "core::felt252",
            "core::starknet::contract_address::ContractAddress",
            "core::starknet::class_hash::ClassHash",
            "core::starknet::storage_access::StorageAddress",
            "core::integer::u8",
            "core::integer::u16",
            "core::integer::u32",
            "core::integer::u64",
            "core::integer::u96",
            "core::integer::u128",
            "core::bytes_31::bytes31",
            "core::bool",
            "core::integer::u256",
            "core::byte_array::ByteArray",
            "core::array::Array::<core::felt252>",
            "core::array::Span::<core::felt252>",
            "(core::felt252, core::bool)",
            "()",
        ] {
            for (declaration, expected) in [
                (
                    serde_json::json!({"type":"struct","name":ty,"members":[{"name":"bad","type":"Unknown"}]}),
                    "unsupported type: Unknown",
                ),
                (
                    serde_json::json!({"type":"struct","name":ty,"members":[{"name":"same","type":"()"},{"name":"same","type":"()"}]}),
                    "duplicate ABI struct member",
                ),
                (
                    serde_json::json!({"type":"enum","name":ty,"variants":[{"name":"Same","type":"()"},{"name":"Same","type":"()"}]}),
                    "duplicate ABI enum variant",
                ),
            ] {
                let decoder = EventTypes::new(
                    serde_json::from_value(serde_json::json!([declaration])).unwrap(),
                );
                for root in [ty.to_owned(), format!("core::array::Array::<{ty}>")] {
                    for _ in 0..2 {
                        let input = [Felt::ZERO; 3];
                        let mut data = input.as_slice();
                        assert_eq!(
                            decoder
                                .decode_value(&root, &mut data, &mut NodeBudget::new(100))
                                .unwrap_err()
                                .to_string(),
                            expected,
                            "{root}"
                        );
                        assert_eq!(data, input.as_slice());
                    }
                }
            }
        }
    }
    #[test]
    fn valid_declared_syntactic_forms_keep_their_wire_encodings() {
        for (ty, value, wire) in [
            (
                "core::array::Array::<core::felt252>",
                EventValue::Sequence(vec![EventValue::Felt(Felt::THREE)]),
                vec![Felt::ONE, Felt::THREE],
            ),
            (
                "core::array::Span::<core::felt252>",
                EventValue::Sequence(vec![EventValue::Felt(Felt::THREE)]),
                vec![Felt::ONE, Felt::THREE],
            ),
            (
                "(core::felt252, core::bool)",
                EventValue::Sequence(vec![EventValue::Felt(Felt::THREE), EventValue::Bool(true)]),
                vec![Felt::THREE, Felt::ONE],
            ),
            ("()", EventValue::Sequence(vec![]), vec![]),
        ] {
            let declaration = serde_json::json!({"type":"struct","name":ty,"members":[]});
            let decoder =
                EventTypes::new(serde_json::from_value(serde_json::json!([declaration])).unwrap());

            let mut data = wire.as_slice();
            assert_eq!(
                decoder
                    .decode_value(ty, &mut data, &mut NodeBudget::new(100))
                    .unwrap(),
                value
            );
            assert_eq!(data, [] as [Felt; 0]);
        }
    }
    #[test]
    fn explicit_syntactic_declarations_also_validate_implicit_wire_elements() {
        for ty in [
            "core::array::Array::<Unknown>",
            "core::array::Span::<Unknown>",
            "(core::felt252, Unknown)",
        ] {
            let declaration = serde_json::json!({"type":"struct","name":ty,"members":[]});
            let decoder =
                EventTypes::new(serde_json::from_value(serde_json::json!([declaration])).unwrap());
            for root in [ty.to_owned(), format!("core::array::Array::<{ty}>")] {
                let input = [Felt::ZERO; 3];
                let mut data = input.as_slice();
                assert_eq!(
                    decoder
                        .decode_value(&root, &mut data, &mut NodeBudget::new(100))
                        .unwrap_err()
                        .to_string(),
                    "unsupported type: Unknown"
                );
                assert_eq!(data, input.as_slice());
            }
        }
        let declaration = serde_json::json!({"type":"struct","name":"core::integer::u128","members":[{"name":"bad","type":"Unknown"}]});
        let decoder =
            EventTypes::new(serde_json::from_value(serde_json::json!([declaration])).unwrap());

        let mut input = [Felt::ZERO; 2].as_slice();
        assert_eq!(
            decoder
                .decode_value("core::integer::u256", &mut input, &mut NodeBudget::new(100))
                .unwrap_err()
                .to_string(),
            "unsupported type: Unknown"
        );
    }
    #[test]
    fn compiler_span_snapshots_preserve_array_wire_encoding() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!("../../../starknet-rust-core/test-data/raw_gateway_responses/get_class_by_hash/3_cairo_1.txt")).unwrap();
        let entries: Vec<AbiEntry> =
            serde_json::from_str(artifact["abi"].as_str().unwrap()).unwrap();
        let entries = entries.into_iter().filter(|entry| matches!(entry, AbiEntry::Struct(s) if s.name.starts_with("core::array::Span::<"))).collect();
        let codec = EventTypes::new(entries);
        let span = "core::array::Span::<core::felt252>";
        let nested = "core::array::Span::<core::array::Span::<core::felt252>>";
        for (ty, wire, value) in [
            (span, vec![Felt::ZERO], EventValue::Sequence(vec![])),
            (
                span,
                vec![Felt::ONE, Felt::from(7_u64)],
                EventValue::Sequence(vec![EventValue::Felt(Felt::from(7_u64))]),
            ),
            (nested, vec![Felt::ZERO], EventValue::Sequence(vec![])),
            (
                nested,
                vec![Felt::TWO, Felt::ONE, Felt::from(7_u64), Felt::ZERO],
                EventValue::Sequence(vec![
                    EventValue::Sequence(vec![EventValue::Felt(Felt::from(7_u64))]),
                    EventValue::Sequence(vec![]),
                ]),
            ),
            (
                "core::array::Array::<core::array::Span::<core::felt252>>",
                vec![Felt::ZERO],
                EventValue::Sequence(vec![]),
            ),
            (
                "@core::array::Array::<core::felt252>",
                vec![Felt::ONE, Felt::from(7_u64)],
                EventValue::Sequence(vec![EventValue::Felt(Felt::from(7_u64))]),
            ),
        ] {
            let mut input = wire.as_slice();
            assert_eq!(
                codec
                    .decode_value(ty, &mut input, &mut NodeBudget::new(100))
                    .unwrap(),
                value
            );
            assert_eq!(input, []);
        }
    }
    #[test]
    fn snapshots_validate_underlying_and_explicit_declarations() {
        let codec = EventTypes::new(vec![]);
        for ty in [
            "@Unknown",
            "core::array::Array::<@Unknown>",
            "core::array::Span::<@Unknown>",
        ] {
            let mut input = [Felt::ZERO].as_slice();
            assert_eq!(
                codec
                    .decode_value(ty, &mut input, &mut NodeBudget::new(100))
                    .unwrap_err()
                    .to_string(),
                "unsupported type: Unknown"
            );
        }
        for name in ["@core::felt252", "core::felt252"] {
            let entries: Vec<AbiEntry> = serde_json::from_value(serde_json::json!([{"type":"struct","name":name,"members":[{"name":"bad","type":"Unknown"}]}])).unwrap();
            let codec = EventTypes::new(entries);
            let ty = "@core::felt252";
            let mut input = [Felt::ZERO].as_slice();
            assert_eq!(
                codec
                    .decode_value(ty, &mut input, &mut NodeBudget::new(100))
                    .unwrap_err()
                    .to_string(),
                "unsupported type: Unknown"
            );
        }
    }
    #[test]
    fn byte_array_words_share_budget_before_payload_allocation() {
        let codec = EventTypes::new(vec![]);
        let wire = [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let mut input = wire.as_slice();
        let mut budget = NodeBudget::new(3);
        assert_eq!(
            codec
                .decode("core::byte_array::ByteArray", &mut input, 0, &mut budget)
                .unwrap(),
            EventValue::Bytes(vec![0; 31])
        );
        assert_eq!(budget.remaining, 0);
        let mut input = wire.as_slice();
        let mut budget = NodeBudget::new(2);
        assert!(
            codec
                .decode("core::byte_array::ByteArray", &mut input, 0, &mut budget)
                .unwrap_err()
                .to_string()
                .contains("node")
        );
        assert_eq!(input.len(), 3); // Only the length prefix was consumed.
        assert!(budget.exceeded);
        let mut input = [Felt::ZERO].as_slice();
        let mut budget = NodeBudget::new(3);
        assert_eq!(
            codec
                .decode("core::byte_array::ByteArray", &mut input, 0, &mut budget)
                .unwrap_err()
                .to_string(),
            "truncated ByteArray"
        );
    }
}
