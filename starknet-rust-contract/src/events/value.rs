use starknet_rust_core::types::{Felt, contract::AbiEntry};
use std::{collections::BTreeMap, fmt};
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

pub(super) struct EventTypes {
    pub(super) entries: Vec<AbiEntry>,
}
impl EventTypes {
    pub(super) fn decode_value(
        &self,
        ty: &str,
        data: &mut &[Felt],
    ) -> Result<EventValue, EventDecodeError> {
        self.decode(ty, data, 0)
    }
    fn decode(
        &self,
        ty: &str,
        data: &mut &[Felt],
        depth: usize,
    ) -> Result<EventValue, EventDecodeError> {
        if depth > 64 {
            return Err(error("ABI nesting exceeds 64"));
        }
        let ty = ty.trim();
        if scalar_bits(ty).is_some() {
            let f = take(data)?;
            validate_scalar(ty, f)?;
            return Ok(EventValue::Felt(f));
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
            if n > data.len().saturating_sub(2) {
                return Err(error("truncated ByteArray"));
            }
            let mut bytes = Vec::new();
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
            let n = length(take(data)?)?; // Bound work even for zero-sized types.
            if n > 1_000_000 {
                return Err(error("array exceeds one million items"));
            }
            let mut values = Vec::new();
            for _ in 0..n {
                values.push(self.decode(inner, data, depth + 1)?);
            }
            return Ok(EventValue::Sequence(values));
        }
        if let Some(types) = tuple_types(ty)? {
            return types
                .iter()
                .map(|t| self.decode(t, data, depth + 1))
                .collect::<Result<Vec<_>, _>>()
                .map(EventValue::Sequence);
        }
        for entry in &self.entries {
            match entry {
                AbiEntry::Struct(s) if s.name == ty => {
                    let mut values = BTreeMap::new();
                    for m in &s.members {
                        values.insert(m.name.clone(), self.decode(&m.r#type, data, depth + 1)?);
                    }
                    return Ok(EventValue::Struct(values));
                }
                AbiEntry::Enum(e) if e.name == ty => {
                    let index = length(take(data)?)?;
                    let v = e
                        .variants
                        .get(index)
                        .ok_or_else(|| error("invalid enum discriminant"))?;
                    return Ok(EventValue::Enum {
                        variant: v.name.clone(),
                        value: Box::new(self.decode(&v.r#type, data, depth + 1)?),
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
fn tuple_types(ty: &str) -> Result<Option<Vec<&str>>, EventDecodeError> {
    if !ty.starts_with('(') {
        return Ok(None);
    }
    let inner = ty
        .strip_prefix('(')
        .and_then(|s| s.strip_suffix(')'))
        .ok_or_else(|| error("malformed tuple type"))?;
    if inner.trim().is_empty() {
        return Ok(Some(vec![]));
    }
    let mut depth = 0i32;
    let mut start = 0;
    let mut fields = vec![];
    for (i, c) in inner.char_indices() {
        match c {
            '(' | '<' | '[' => depth += 1,
            ')' | '>' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return Err(error("malformed tuple type"));
                }
            }
            ',' if depth == 0 => {
                fields.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    if depth != 0 {
        return Err(error("malformed tuple type"));
    }
    let tail = inner[start..].trim();
    if !tail.is_empty() {
        fields.push(tail);
    }
    Ok(Some(fields))
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
