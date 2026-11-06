//! Runtime Cairo 1 ABI values and serialization.
use starknet_rust_core::{
    types::{
        Felt,
        contract::{AbiEntry, AbiFunction},
    },
    utils::get_selector_from_name,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{Arc, RwLock},
};

/// A value described by a Cairo 1 ABI. Integers use canonical field encodings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiValue {
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
pub struct AbiError(pub String);
impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for AbiError {}
fn error(message: impl Into<String>) -> AbiError {
    AbiError(message.into())
}

#[derive(Debug)]
struct SchemaCache {
    results: BTreeMap<String, Result<(), AbiError>>,
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
        result: &Result<(), AbiError>,
        budget: &mut SchemaBudget,
    ) -> Result<(), AbiError> {
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
    type Target = BTreeMap<String, Result<(), AbiError>>;
    fn deref(&self) -> &Self::Target {
        &self.results
    }
}

// Per operation, cold schema traversal is bounded independently of decoded value nodes.
const DEFAULT_SCHEMA_WORK: usize = 1_000_000;
struct SchemaBudget {
    remaining: usize,
    exceeded: bool,
    owned: usize,
    text: usize,
}
impl SchemaBudget {
    const fn new(remaining: usize) -> Self {
        Self {
            remaining,
            exceeded: false,
            owned: 64 * 1024 * 1024,
            text: 64 * 1024 * 1024,
        }
    }
    fn charge(&mut self) -> Result<(), AbiError> {
        if self.remaining == 0 {
            self.exceeded = true;
            return Err(error("ABI schema validation exceeds work budget"));
        }
        self.remaining -= 1;
        Ok(())
    }

    fn charge_owned(&mut self, count: usize) -> Result<(), AbiError> {
        let Some(remaining) = self.owned.checked_sub(count) else {
            self.exceeded = true;
            return Err(error("ABI logical allocation exceeds byte budget"));
        };
        self.owned = remaining;
        Ok(())
    }
    fn charge_text(&mut self, count: usize) -> Result<(), AbiError> {
        let Some(remaining) = self.text.checked_sub(count) else {
            self.exceeded = true;
            return Err(error("ABI type text exceeds work budget"));
        };
        self.text = remaining;
        Ok(())
    }
}

/// A runtime Cairo 1 ABI. Unsupported types fail explicitly rather than being treated as felts.
#[derive(Debug, Clone)]
pub struct ContractAbi {
    entries: Vec<AbiEntry>,
    type_indices: BTreeMap<String, usize>,
    function_indices: BTreeMap<String, usize>,
    cacheable_types: BTreeSet<String>,
    schema_results: Arc<RwLock<SchemaCache>>,
}
impl ContractAbi {
    /// Creates an ABI, expanding interface entries. Duplicates within the function namespace or ordinary type namespace are rejected; functions and types may share a name.
    /// Interface nesting is limited to 64; owned input is consumed without recursive traversal or cleanup.
    pub fn new(entries: Vec<AbiEntry>) -> Result<Self, AbiError> {
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
        let mut flattened = vec![];
        if flatten(entries, &mut flattened) {
            return Err(error("ABI interface nesting exceeds 64"));
        }
        let mut names = std::collections::BTreeSet::new();
        let mut type_indices = BTreeMap::new();
        let mut function_indices = BTreeMap::new();
        for (index, e) in flattened.iter().enumerate() {
            let name = match e {
                AbiEntry::Function(f) => Some((0, &f.name)),
                AbiEntry::Struct(s) => Some((1, &s.name)),
                AbiEntry::Enum(e) => Some((1, &e.name)),
                _ => None,
            };
            if let Some((namespace, name)) = name {
                if !names.insert((namespace, name)) {
                    return Err(error("duplicate ABI name"));
                }
                let indices = if namespace == 0 {
                    &mut function_indices
                } else {
                    &mut type_indices
                };
                indices.insert(name.clone(), index);
            }
        }
        // Only finite ABI-owned root names may occupy the cache. Public standalone
        // encode/decode callers can supply arbitrary type strings, including invalid names.
        let mut cacheable_types = BTreeSet::new();
        for entry in &flattened {
            match entry {
                AbiEntry::Function(function) => {
                    cacheable_types.extend(
                        function
                            .inputs
                            .iter()
                            .map(|member| member.r#type.trim().to_owned()),
                    );
                    cacheable_types.extend(
                        function
                            .outputs
                            .iter()
                            .map(|member| member.r#type.trim().to_owned()),
                    );
                }
                AbiEntry::Struct(definition) => {
                    cacheable_types.insert(definition.name.clone());
                    cacheable_types.extend(
                        definition
                            .members
                            .iter()
                            .map(|member| member.r#type.trim().to_owned()),
                    );
                }
                AbiEntry::Enum(definition) => {
                    cacheable_types.insert(definition.name.clone());
                    cacheable_types.extend(
                        definition
                            .variants
                            .iter()
                            .map(|variant| variant.r#type.trim().to_owned()),
                    );
                }
                _ => {}
            }
        }
        Ok(Self {
            entries: flattened,
            type_indices,
            function_indices,
            cacheable_types,
            schema_results: Arc::new(RwLock::new(SchemaCache::new())),
        })
    }
    /// Parses a Cairo 1 ABI JSON array.
    pub fn from_json(json: &str) -> Result<Self, AbiError> {
        Self::new(serde_json::from_str(json).map_err(|e| error(e.to_string()))?)
    }
    /// Looks up a function, including functions declared in interfaces.
    pub fn function(&self, name: &str) -> Result<&AbiFunction, AbiError> {
        self.function_indices
            .get(name)
            .and_then(|index| match &self.entries[*index] {
                AbiEntry::Function(function) => Some(function),
                _ => None,
            })
            .ok_or_else(|| error(format!("unknown function: {name}")))
    }
    /// Validates and serializes positional arguments.
    pub fn encode_inputs(&self, name: &str, values: &[AbiValue]) -> Result<Vec<Felt>, AbiError> {
        self.encode_inputs_with_schema_budget(
            name,
            values,
            &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK),
        )
    }
    fn encode_inputs_with_schema_budget(
        &self,
        name: &str,
        values: &[AbiValue],
        schema: &mut SchemaBudget,
    ) -> Result<Vec<Felt>, AbiError> {
        schema.charge_text(name.len())?;
        schema.charge_owned(name.len())?;
        let function = self.function(name)?;
        if function.inputs.len() != values.len() {
            return Err(error(format!(
                "wrong argument count for {name}: expected {}, got {}",
                function.inputs.len(),
                values.len()
            )));
        }
        let mut output = vec![];
        for (field, value) in function.inputs.iter().zip(values) {
            self.validate_type(&field.r#type, schema)?;
            self.encode(&field.r#type, value, &mut output, 0, schema)?;
        }
        Ok(output)
    }
    /// Decodes all outputs, rejecting truncated and trailing return data.
    pub fn decode_outputs(&self, name: &str, data: &[Felt]) -> Result<Vec<AbiValue>, AbiError> {
        self.decode_outputs_with_schema_budget(
            name,
            data,
            &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK),
        )
    }
    fn decode_outputs_with_schema_budget(
        &self,
        name: &str,
        data: &[Felt],
        schema: &mut SchemaBudget,
    ) -> Result<Vec<AbiValue>, AbiError> {
        schema.charge_text(name.len())?;
        schema.charge_owned(name.len())?;
        let mut data = data;
        let mut budget = 1_000_000;
        let values = self
            .function(name)?
            .outputs
            .iter()
            .map(|o| {
                self.validate_type(&o.r#type, schema)?;
                self.decode(&o.r#type, &mut data, 0, &mut budget, schema)
            })
            .collect::<Result<_, _>>()?;
        if !data.is_empty() {
            return Err(error("trailing return data"));
        }
        Ok(values)
    }
    /// Serializes a standalone ABI type.
    pub fn encode_value(&self, ty: &str, value: &AbiValue) -> Result<Vec<Felt>, AbiError> {
        let mut schema = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        self.validate_type(ty, &mut schema)?;
        let mut out = vec![];
        self.encode(ty, value, &mut out, 0, &mut schema)?;
        Ok(out)
    }
    /// Decodes a standalone ABI type, consuming only the required prefix.
    pub fn decode_value(&self, ty: &str, data: &mut &[Felt]) -> Result<AbiValue, AbiError> {
        let mut schema = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        self.validate_type(ty, &mut schema)?;
        self.decode(ty, data, 0, &mut 1_000_000, &mut schema)
    }
    // Validate the schema independently of values, so empty arrays and unselected enum
    // variants cannot hide unsupported types. Each type is visited once, allowing recursive
    // named schemas without revisiting cycles; value depth/node limits still apply separately.
    fn validate_type(&self, ty: &str, budget: &mut SchemaBudget) -> Result<(), AbiError> {
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
        let result =
            self.validate_type_graph(ty, &mut std::collections::BTreeSet::new(), 0, budget);
        if !budget.exceeded && self.cacheable_types.contains(ty) {
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
    ) -> Result<(), AbiError> {
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
    fn encode(
        &self,
        ty: &str,
        value: &AbiValue,
        out: &mut Vec<Felt>,
        depth: usize,
        schema: &mut SchemaBudget,
    ) -> Result<(), AbiError> {
        schema.charge_text(ty.len().saturating_mul(4))?;
        schema.charge_owned(ty.len().saturating_add(2 * std::mem::size_of::<Felt>()))?;
        if depth > 64 {
            return Err(error("ABI nesting exceeds 64"));
        }
        let ty = ty.trim();
        if let Some(inner) = ty.strip_prefix('@') {
            return self.encode(inner, value, out, depth + 1, schema);
        }
        if scalar_bits(ty).is_some() {
            if let AbiValue::Felt(f) = value {
                validate_scalar(ty, *f)?;
                out.push(*f);
                return Ok(());
            }
        } else if ty == "core::integer::u256" {
            if let AbiValue::Struct(fields) = value {
                if fields.len() != 2 {
                    return Err(error("u256 requires low and high limbs"));
                }
                for name in ["low", "high"] {
                    let limb = fields
                        .get(name)
                        .ok_or_else(|| error("u256 requires low and high limbs"))?;
                    self.encode("core::integer::u128", limb, out, depth + 1, schema)?;
                }
                return Ok(());
            }
        } else if ty == "core::bool" {
            if let AbiValue::Bool(v) = value {
                out.push(Felt::from(u8::from(*v)));
                return Ok(());
            }
        } else if ty == "core::byte_array::ByteArray" {
            if let AbiValue::Bytes(bytes) = value {
                schema.charge_owned(
                    (bytes.len() / 31)
                        .saturating_add(3)
                        .saturating_mul(2 * std::mem::size_of::<Felt>()),
                )?;
                out.push(Felt::from(bytes.len() / 31));
                let (chunks, tail) = bytes.as_chunks::<31>();
                for c in chunks {
                    out.push(Felt::from_bytes_be_slice(c));
                }
                out.push(Felt::from_bytes_be_slice(tail));
                out.push(Felt::from(tail.len()));
                return Ok(());
            }
        } else if let Some(inner) = array_inner(ty) {
            if let AbiValue::Sequence(vs) = value {
                out.push(Felt::from(vs.len()));
                for v in vs {
                    self.encode(inner, v, out, depth + 1, schema)?;
                }
                return Ok(());
            }
        } else if let Some(types) = tuple_types(ty)? {
            if let AbiValue::Sequence(vs) = value {
                if vs.len() != types.clone().count() {
                    return Err(error("wrong tuple length"));
                }
                for (t, v) in types.zip(vs) {
                    self.encode(t, v, out, depth + 1, schema)?;
                }
                return Ok(());
            }
        } else {
            if let Some(entry) = self.type_indices.get(ty).map(|index| &self.entries[*index]) {
                match entry {
                    AbiEntry::Struct(s) if s.name == ty => {
                        if let AbiValue::Struct(fields) = value {
                            if fields.len() != s.members.len() {
                                return Err(error("wrong struct fields"));
                            }
                            for m in &s.members {
                                schema.charge_text(m.name.len())?;
                                schema.charge_owned(m.name.len())?;
                                self.encode(
                                    &m.r#type,
                                    fields.get(&m.name).ok_or_else(|| {
                                        error(format!("missing field: {}", m.name))
                                    })?,
                                    out,
                                    depth + 1,
                                    schema,
                                )?;
                            }
                            return Ok(());
                        }
                        return Err(error("expected struct"));
                    }
                    AbiEntry::Enum(e) if e.name == ty => {
                        if let AbiValue::Enum { variant, value } = value {
                            let mut selected = None;
                            for (index, candidate) in e.variants.iter().enumerate() {
                                schema.charge_text(
                                    candidate.name.len().saturating_add(variant.len()),
                                )?;
                                if candidate.name == *variant {
                                    selected = Some((index, candidate));
                                    break;
                                }
                            }
                            let (i, v) = selected.ok_or_else(|| error("unknown enum variant"))?;
                            out.push(Felt::from(i));
                            return self.encode(&v.r#type, value, out, depth + 1, schema);
                        }
                        return Err(error("expected enum"));
                    }
                    _ => {}
                }
            }
            return Err(error(format!("unsupported type: {ty}")));
        }
        Err(error(format!("wrong value for {ty}")))
    }
    fn decode(
        &self,
        ty: &str,
        data: &mut &[Felt],
        depth: usize,
        budget: &mut usize,
        schema: &mut SchemaBudget,
    ) -> Result<AbiValue, AbiError> {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| error("decoded values exceed one million nodes"))?;
        schema.charge_text(ty.len().saturating_mul(4))?;
        schema.charge_owned(ty.len().saturating_add(2 * std::mem::size_of::<AbiValue>()))?;
        if depth > 64 {
            return Err(error("ABI nesting exceeds 64"));
        }
        let ty = ty.trim();
        if let Some(inner) = ty.strip_prefix('@') {
            return self.decode(inner, data, depth + 1, budget, schema);
        }
        if scalar_bits(ty).is_some() {
            let f = take(data)?;
            validate_scalar(ty, f)?;
            return Ok(AbiValue::Felt(f));
        }
        if ty == "core::integer::u256" {
            let mut fields = BTreeMap::new();
            for name in ["low", "high"] {
                schema.charge_owned(name.len() + std::mem::size_of::<String>())?;
                fields.insert(
                    name.to_owned(),
                    self.decode("core::integer::u128", data, depth + 1, budget, schema)?,
                );
            }
            return Ok(AbiValue::Struct(fields));
        }
        if ty == "core::bool" {
            return match take(data)? {
                f if f == Felt::ZERO => Ok(AbiValue::Bool(false)),
                f if f == Felt::ONE => Ok(AbiValue::Bool(true)),
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
            *budget = budget
                .checked_sub(words)
                .ok_or_else(|| error("decoded values exceed one million nodes"))?;
            let pending_len = length(data[n + 1])?;
            let pending_word = data[n].to_bytes_be();
            if pending_len > 30 || pending_word[..32 - pending_len].iter().any(|b| *b != 0) {
                return Err(error("invalid ByteArray pending word"));
            }
            let capacity = n
                .checked_mul(31)
                .and_then(|size| size.checked_add(pending_len))
                .ok_or_else(|| error("ByteArray size overflow"))?;
            schema.charge_owned(capacity)?;
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
            return Ok(AbiValue::Bytes(bytes));
        }
        if let Some(inner) = array_inner(ty) {
            let n = length(take(data)?)?; // Bound work even for zero-sized types.
            if n > 1_000_000 {
                return Err(error("array exceeds one million items"));
            }
            let mut values = Vec::new();
            for _ in 0..n {
                values.push(self.decode(inner, data, depth + 1, budget, schema)?);
            }
            return Ok(AbiValue::Sequence(values));
        }
        if let Some(types) = tuple_types(ty)? {
            return types
                .map(|t| self.decode(t, data, depth + 1, budget, schema))
                .collect::<Result<Vec<_>, _>>()
                .map(AbiValue::Sequence);
        }
        if let Some(entry) = self.type_indices.get(ty).map(|index| &self.entries[*index]) {
            match entry {
                AbiEntry::Struct(s) if s.name == ty => {
                    let mut values = BTreeMap::new();
                    for m in &s.members {
                        schema.charge_text(m.name.len())?;
                        schema.charge_owned(
                            m.name.len().saturating_add(std::mem::size_of::<String>()),
                        )?;
                        values.insert(
                            m.name.clone(),
                            self.decode(&m.r#type, data, depth + 1, budget, schema)?,
                        );
                    }
                    return Ok(AbiValue::Struct(values));
                }
                AbiEntry::Enum(e) if e.name == ty => {
                    let index = length(take(data)?)?;
                    let v = e
                        .variants
                        .get(index)
                        .ok_or_else(|| error("invalid enum discriminant"))?;
                    schema.charge_owned(v.name.len())?;
                    return Ok(AbiValue::Enum {
                        variant: v.name.clone(),
                        value: Box::new(self.decode(&v.r#type, data, depth + 1, budget, schema)?),
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
fn validate_scalar(ty: &str, value: Felt) -> Result<(), AbiError> {
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
fn tuple_types(ty: &str) -> Result<Option<TupleTypes<'_>>, AbiError> {
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
fn take(data: &mut &[Felt]) -> Result<Felt, AbiError> {
    let (first, rest) = data
        .split_first()
        .ok_or_else(|| error("truncated ABI data"))?;
    *data = rest;
    Ok(*first)
}
fn length(value: Felt) -> Result<usize, AbiError> {
    usize::try_from(value).map_err(|_| error("length or discriminant does not fit usize"))
}

/// A contract instance whose functions are described by a runtime Cairo 1 ABI.
#[derive(Debug, Clone)]
pub struct Contract<P> {
    /// Contract address.
    pub address: Felt,
    /// Runtime ABI.
    pub abi: ContractAbi,
    /// Provider used for read calls.
    pub provider: P,
}
impl<P> Contract<P> {
    /// Attaches an ABI and provider to an address without making network requests.
    pub const fn new(address: Felt, abi: ContractAbi, provider: P) -> Self {
        Self {
            address,
            abi,
            provider,
        }
    }
    /// Builds a validated account call, suitable for multicalls or offline signing.
    pub fn populate(
        &self,
        name: &str,
        args: &[AbiValue],
    ) -> Result<starknet_rust_core::types::Call, AbiError> {
        self.populate_with_schema_budget(name, args, &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK))
    }
    fn populate_with_schema_budget(
        &self,
        name: &str,
        args: &[AbiValue],
        schema: &mut SchemaBudget,
    ) -> Result<starknet_rust_core::types::Call, AbiError> {
        let calldata = self
            .abi
            .encode_inputs_with_schema_budget(name, args, schema)?;
        Ok(starknet_rust_core::types::Call {
            to: self.address,
            selector: get_selector_from_name(name).map_err(|e| error(e.to_string()))?,
            calldata,
        })
    }
    /// Builds a transaction builder using the account's nonce, fee, simulation and signing APIs.
    pub fn invoke<'a, A: starknet_rust_accounts::Account>(
        &self,
        account: &'a A,
        name: &str,
        args: &[AbiValue],
    ) -> Result<starknet_rust_accounts::ExecutionV3<'a, A>, AbiError> {
        Ok(account.execute_v3(vec![self.populate(name, args)?]))
    }
}
impl<P: starknet_rust_providers::Provider> Contract<P> {
    /// Calls a view entrypoint and decodes the returned ABI values. External functions must use invoke.
    pub async fn call(
        &self,
        name: &str,
        args: &[AbiValue],
        block: starknet_rust_core::types::BlockId,
    ) -> Result<Vec<AbiValue>, ContractCallError> {
        if !matches!(
            self.abi
                .function(name)
                .map_err(ContractCallError::Abi)?
                .state_mutability,
            starknet_rust_core::types::contract::StateMutability::View
        ) {
            return Err(ContractCallError::Abi(error("function is not marked view")));
        }
        let mut schema = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        let call = self
            .populate_with_schema_budget(name, args, &mut schema)
            .map_err(ContractCallError::Abi)?;
        let result = self
            .provider
            .call(
                starknet_rust_core::types::FunctionCall {
                    contract_address: call.to,
                    entry_point_selector: call.selector,
                    calldata: call.calldata,
                },
                block,
            )
            .await
            .map_err(ContractCallError::Provider)?;
        self.abi
            .decode_outputs_with_schema_budget(name, &result, &mut schema)
            .map_err(ContractCallError::Abi)
    }
}
/// A provider failure or invalid ABI call/response.
#[derive(Debug)]
pub enum ContractCallError {
    /// Invalid ABI/value/response.
    Abi(AbiError),
    /// RPC failure.
    Provider(starknet_rust_providers::ProviderError),
}
impl fmt::Display for ContractCallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Abi(e) => e.fmt(f),
            Self::Provider(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for ContractCallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Abi(e) => e,
            Self::Provider(e) => e,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_enum_encoding_charges_variant_name_search_work() {
        let names: Vec<_> = (0..4)
            .map(|index| format!("v{index}{}", "x".repeat(64)))
            .collect();
        let variants: Vec<_> = names
            .iter()
            .map(|name| serde_json::json!({"name":name,"type":"()"}))
            .collect();
        let abi = ContractAbi::from_json(
            &serde_json::json!([{"type":"enum","name":"E","variants":variants}]).to_string(),
        )
        .unwrap();
        let value = AbiValue::Sequence(vec![
            AbiValue::Enum {
                variant: names[3].clone(),
                value: Box::new(AbiValue::Sequence(vec![]))
            };
            3
        ]);
        let root = "core::array::Array::<E>";
        assert_eq!(
            abi.encode_value(root, &value).unwrap(),
            vec![Felt::from(3u64); 4]
        );
        let mut resources = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        resources.text = 500;
        assert_eq!(
            abi.encode(root, &value, &mut vec![], 0, &mut resources)
                .unwrap_err()
                .to_string(),
            "ABI type text exceeds work budget"
        );
        assert!(resources.exceeded);
    }

    #[test]
    fn byte_output_limit_is_checked_before_byte_array_encoding_allocation() {
        let abi = ContractAbi::from_json("[]").unwrap();
        let mut budget = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        budget.owned = 100;
        let mut output = vec![];
        assert_eq!(
            abi.encode(
                "core::byte_array::ByteArray",
                &AbiValue::Bytes(vec![7; 512]),
                &mut output,
                0,
                &mut budget
            )
            .unwrap_err()
            .to_string(),
            "ABI logical allocation exceeds byte budget"
        );
        assert_eq!(output, [] as [Felt; 0]);
        assert!(budget.exceeded);
    }
    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn cloned_abis_share_cache_capacity_and_count_concurrent_root_once() {
        let abi = ContractAbi::from_json(r#"[{"type":"struct","name":"S","members":[]}]"#).unwrap();
        let initial = abi.schema_results.read().unwrap().remaining;
        std::thread::scope(|scope| {
            for _ in 0..8 {
                let cloned = abi.clone();
                scope.spawn(move || {
                    cloned
                        .validate_type("S", &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK))
                        .unwrap();
                });
            }
        });
        let cache = abi.schema_results.read().unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(initial - cache.remaining, "S".len() + 128);
    }

    #[test]
    fn text_exhaustion_and_cached_diagnostic_copy_cannot_poison_structural_results() {
        let unknown = "Unknown".repeat(64);
        let json = serde_json::json!([{"type":"struct","name":"S","members":[{"name":"field","type":unknown}]}]).to_string();
        let codec = ContractAbi::from_json(&json).unwrap();
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
            let codec = ContractAbi::from_json(&json).unwrap();
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
                matches!(codec.decode_value(&root, &mut data.as_slice()).unwrap(), AbiValue::Sequence(values) if values.len() == 4)
            );
            let mut resources = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
            resources.owned = 512;
            assert_eq!(
                codec
                    .decode(&root, &mut data.as_slice(), 0, &mut 100, &mut resources)
                    .unwrap_err()
                    .to_string(),
                "ABI logical allocation exceeds byte budget"
            );
            assert!(resources.exceeded);
            assert!(
                matches!(codec.decode_value(&root, &mut data.as_slice()).unwrap(), AbiValue::Sequence(values) if values.len() == 4)
            );
        }
    }
    #[test]
    fn repeated_borrowed_tuple_parsing_obeys_text_work_limit() {
        let json = "[]".to_owned();
        let codec = ContractAbi::from_json(&json).unwrap();
        let root = format!("core::array::Array::<((),{}())>", " ".repeat(512));
        let data = [Felt::from(3u64)];
        assert!(
            matches!(codec.decode_value(&root, &mut data.as_slice()).unwrap(), AbiValue::Sequence(values) if values.len() == 3)
        );
        let mut resources = SchemaBudget::new(DEFAULT_SCHEMA_WORK);
        resources.text = 5_000;
        assert_eq!(
            codec
                .decode(&root, &mut data.as_slice(), 0, &mut 100, &mut resources)
                .unwrap_err()
                .to_string(),
            "ABI type text exceeds work budget"
        );
        assert!(resources.exceeded);
        assert!(
            matches!(codec.decode_value(&root, &mut data.as_slice()).unwrap(), AbiValue::Sequence(values) if values.len() == 3)
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
        let codec = ContractAbi::from_json(&json).unwrap();
        codec.schema_results.write().unwrap().remaining = 0;
        let root = "S".to_owned();
        let data: [Felt; 0] = [];
        for _ in 0..2 {
            assert_eq!(
                codec.decode_value(&root, &mut data.as_slice()).unwrap(),
                AbiValue::Struct(BTreeMap::new())
            );
        }
        assert_eq!(codec.schema_results.read().unwrap().len(), 0);
    }

    #[test]
    fn distinct_roots_share_schema_work_and_exhaustion_does_not_poison_cache() {
        let members: Vec<_> = (0..32)
            .map(|i| serde_json::json!({"name":format!("f{i}"),"type":"()"}))
            .collect();
        let mut entries =
            vec![serde_json::json!({"type":"struct","name":"Large","members":members})];
        for i in 0..4 {
            entries.push(serde_json::json!({"type":"struct","name":format!("Wrapper{i}"),"members":[{"name":"shared","type":"Large"}]}));
        }
        let inputs: Vec<_> = (0..4).map(|i| serde_json::json!({"name":format!("arg{i}"),"type":format!("core::array::Array::<Wrapper{i}>")})).collect();
        let outputs: Vec<_> = inputs
            .iter()
            .map(|v| serde_json::json!({"type":v["type"]}))
            .collect();
        entries.push(serde_json::json!({"type":"function","name":"f","inputs":inputs,"outputs":outputs,"state_mutability":"view"}));
        let json = serde_json::to_string(&entries).unwrap();
        let values = vec![AbiValue::Sequence(vec![]); 4];
        // Each root needs over 64 visits/edges, despite encoding a single zero felt.
        // A per-root budget would incorrectly let all four roots through.
        for encode in [true, false] {
            let abi = ContractAbi::from_json(&json).unwrap();
            let mut budget = SchemaBudget::new(100);
            let result = if encode {
                abi.encode_inputs_with_schema_budget("f", &values, &mut budget)
                    .map(|_| ())
            } else {
                abi.decode_outputs_with_schema_budget("f", &[Felt::ZERO; 4], &mut budget)
                    .map(|_| ())
            };
            assert_eq!(
                result.unwrap_err().to_string(),
                "ABI schema validation exceeds work budget"
            );
            assert_eq!(budget.remaining, 0);
            assert!(budget.exceeded);
            let cache = abi.schema_results.read().unwrap();
            assert_eq!(cache.len(), 1);
            assert!(cache.values().all(Result::is_ok));
            drop(cache);
            assert_eq!(
                abi.encode_inputs("f", &values).unwrap(),
                vec![Felt::ZERO; 4]
            );
            assert_eq!(abi.decode_outputs("f", &[Felt::ZERO; 4]).unwrap(), values);
        }
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
    fn empty_struct(name: &str) -> AbiEntry {
        AbiEntry::Struct(starknet_rust_core::types::contract::AbiStruct {
            name: name.into(),
            members: vec![],
        })
    }
    #[test]
    fn interface_flattening_preserves_order_and_enforces_its_depth_boundary() {
        let abi = ContractAbi::new(vec![
            empty_struct("Before"),
            nested_interfaces(empty_struct("Leaf"), 64),
            empty_struct("After"),
        ])
        .unwrap();
        let names: Vec<_> = abi
            .entries
            .iter()
            .map(|entry| match entry {
                AbiEntry::Struct(definition) => definition.name.as_str(),
                _ => panic!("unexpected flattened entry"),
            })
            .collect();
        assert_eq!(names, vec!["Before", "Leaf", "After"]);
        assert_eq!(
            ContractAbi::new(vec![nested_interfaces(empty_struct("Leaf"), 65)])
                .unwrap_err()
                .to_string(),
            "ABI interface nesting exceeds 64"
        );
        let empty = AbiEntry::Interface(starknet_rust_core::types::contract::AbiInterface {
            name: "Empty".into(),
            items: vec![],
        });
        assert_eq!(
            ContractAbi::new(vec![nested_interfaces(empty, 64)])
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
                    .map(|_| nested_interfaces(empty_struct("Leaf"), 20_000))
                    .collect();
                assert_eq!(
                    ContractAbi::new(entries).unwrap_err().to_string(),
                    "ABI interface nesting exceeds 64"
                );
            })
            .unwrap()
            .join()
            .unwrap();
    }
    #[derive(Debug)]
    struct MockTransport;
    #[cfg_attr(not(target_arch = "wasm32"), async_trait::async_trait)]
    #[cfg_attr(target_arch = "wasm32", async_trait::async_trait(?Send))]
    impl starknet_rust_providers::jsonrpc::JsonRpcTransport for MockTransport {
        type Error = serde_json::Error;
        async fn send_request<
            P: serde::Serialize + Send + Sync,
            R: serde::de::DeserializeOwned + Send,
        >(
            &self,
            method: starknet_rust_providers::jsonrpc::JsonRpcMethod,
            params: P,
        ) -> Result<starknet_rust_providers::jsonrpc::JsonRpcResponse<R>, Self::Error> {
            assert!(matches!(
                method,
                starknet_rust_providers::jsonrpc::JsonRpcMethod::Call
            ));
            let params = serde_json::to_value(params)?;
            assert_eq!(params["request"]["contract_address"], "0x3");
            assert_eq!(params["request"]["calldata"], serde_json::json!(["0x1"]));
            assert_eq!(params["block_id"], serde_json::json!({"block_number":42}));
            serde_json::from_value(serde_json::json!({"id":1,"result":["0x1"]}))
        }
        async fn send_requests<
            R: AsRef<[starknet_rust_providers::ProviderRequestData]> + Send + Sync,
        >(
            &self,
            _: R,
        ) -> Result<
            Vec<starknet_rust_providers::jsonrpc::JsonRpcResponse<serde_json::Value>>,
            Self::Error,
        > {
            panic!("unexpected batch")
        }
    }
    #[tokio::test]
    async fn read_call_uses_provider_and_decodes_output() {
        let abi = ContractAbi::from_json(r#"[{"type":"function","name":"is_owner","inputs":[{"name":"address","type":"core::felt252"}],"outputs":[{"type":"core::bool"}],"state_mutability":"view"}]"#).unwrap();
        let c = Contract::new(
            Felt::THREE,
            abi,
            starknet_rust_providers::JsonRpcClient::new(MockTransport),
        );
        assert_eq!(
            c.call(
                "is_owner",
                &[AbiValue::Felt(Felt::ONE)],
                starknet_rust_core::types::BlockId::Number(42)
            )
            .await
            .unwrap(),
            vec![AbiValue::Bool(true)]
        );
    }
    fn abi() -> ContractAbi {
        ContractAbi::from_json(r#"[{"type":"struct","name":"core::integer::u256","members":[{"name":"low","type":"core::integer::u128"},{"name":"high","type":"core::integer::u128"}]},{"type":"enum","name":"Choice","variants":[{"name":"None","type":"()"},{"name":"Some","type":"core::integer::u256"}]},{"type":"interface","name":"I","items":[{"type":"function","name":"transfer","inputs":[{"name":"to","type":"core::starknet::contract_address::ContractAddress"},{"name":"amount","type":"core::integer::u256"}],"outputs":[{"type":"core::bool"}],"state_mutability":"external"}]}]"#).unwrap()
    }
    #[test]
    fn arbitrary_standalone_type_names_do_not_grow_the_schema_cache() {
        let abi = ContractAbi::from_json(r#"[{"type":"struct","name":"Empty","members":[]},{"type":"function","name":"consume","inputs":[{"name":"values","type":"core::array::Array::<Empty>"}],"outputs":[],"state_mutability":"external"}]"#).unwrap();
        for index in 0..1_000 {
            assert!(
                abi.encode_value(&format!("Unknown{index}"), &AbiValue::Sequence(vec![]))
                    .is_err()
            );
            let ty = format!("core::array::Array::<Unknown{index}>");
            assert!(abi.decode_value(&ty, &mut [Felt::ZERO].as_slice()).is_err());
        }
        assert!(abi.schema_results.read().unwrap().is_empty());
        for _ in 0..2 {
            abi.encode_inputs("consume", &[AbiValue::Sequence(vec![])])
                .unwrap();
        }
        assert_eq!(abi.schema_results.read().unwrap().len(), 1);
    }
    #[test]
    fn cached_recursive_schema_errors_remain_errors_after_clone() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<ContractAbi>();
        let abi = ContractAbi::from_json(r#"[{"type":"struct","name":"Node","members":[{"name":"children","type":"core::array::Array::<Node>"},{"name":"invalid","type":"Unknown"}]}]"#).unwrap();
        let empty = AbiValue::Sequence(vec![]);
        for current in [&abi, &abi.clone()] {
            for ty in ["core::array::Array::<Node>", "Node"] {
                assert!(current.encode_value(ty, &empty).is_err());
                assert!(
                    current
                        .decode_value(ty, &mut [Felt::ZERO].as_slice())
                        .is_err()
                );
            }
        }
        assert_eq!(abi.schema_results.read().unwrap().len(), 2);
    }
    #[test]
    fn indexed_function_and_type_namespaces_can_overlap() {
        let abi = ContractAbi::from_json(r#"[{"type":"struct","name":"Shared","members":[{"name":"value","type":"core::felt252"}]},{"type":"function","name":"Shared","inputs":[{"name":"value","type":"Shared"}],"outputs":[{"type":"Shared"}],"state_mutability":"view"}]"#).unwrap();
        let value = AbiValue::Struct(BTreeMap::from([(
            "value".into(),
            AbiValue::Felt(Felt::THREE),
        )]));
        assert_eq!(
            abi.encode_inputs("Shared", std::slice::from_ref(&value))
                .unwrap(),
            vec![Felt::THREE]
        );
        assert_eq!(
            abi.decode_outputs("Shared", &[Felt::THREE]).unwrap(),
            vec![value]
        );
        let message = abi.encode_inputs("Shared", &[]).unwrap_err().to_string();
        assert_eq!(
            message,
            "wrong argument count for Shared: expected 1, got 0"
        );
    }
    #[test]
    fn builtin_u256_roundtrips_without_an_abi_struct_declaration() {
        let abi = ContractAbi::from_json("[]").unwrap();
        let limbs = [Felt::from(u128::MAX), Felt::ONE];
        let value = AbiValue::Struct(BTreeMap::from([
            ("low".into(), AbiValue::Felt(limbs[0])),
            ("high".into(), AbiValue::Felt(limbs[1])),
        ]));
        assert_eq!(
            abi.encode_value("core::integer::u256", &value).unwrap(),
            limbs
        );
        assert_eq!(
            abi.decode_value("core::integer::u256", &mut limbs.as_slice())
                .unwrap(),
            value
        );
        for index in [0, 1] {
            let mut bad = limbs;
            bad[index] = Felt::from(u128::MAX) + Felt::ONE;
            assert!(
                abi.decode_value("core::integer::u256", &mut bad.as_slice())
                    .is_err()
            );
            let bad_value = AbiValue::Struct(BTreeMap::from([
                ("low".into(), AbiValue::Felt(bad[0])),
                ("high".into(), AbiValue::Felt(bad[1])),
            ]));
            assert!(abi.encode_value("core::integer::u256", &bad_value).is_err());
        }
        assert!(
            abi.decode_value("core::integer::u256", &mut &limbs[..1])
                .is_err()
        );
        assert!(
            abi.encode_value("core::integer::u256", &AbiValue::Struct(BTreeMap::new()))
                .is_err()
        );
    }
    #[test]
    fn declared_builtin_schemas_are_validated_before_encoding_or_decoding() {
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
            let abi =
                ContractAbi::from_json(&serde_json::json!([declaration]).to_string()).unwrap();
            let value = match ty {
                "core::integer::u256" => AbiValue::Struct(BTreeMap::from([
                    ("low".into(), AbiValue::Felt(Felt::ZERO)),
                    ("high".into(), AbiValue::Felt(Felt::ZERO)),
                ])),
                "core::bool" => AbiValue::Bool(false),
                "core::felt252" => AbiValue::Felt(Felt::ZERO),
                _ => AbiValue::Bytes(vec![]),
            };
            for _ in 0..2 {
                assert_eq!(
                    abi.encode_value(ty, &value).unwrap_err().to_string(),
                    expected
                );
                let input = [Felt::ZERO; 3];
                let mut data = input.as_slice();
                assert_eq!(
                    abi.decode_value(ty, &mut data).unwrap_err().to_string(),
                    expected
                );
                assert_eq!(data, input.as_slice());
                assert_eq!(
                    abi.encode_value(
                        &format!("core::array::Array::<{ty}>"),
                        &AbiValue::Sequence(vec![])
                    )
                    .unwrap_err()
                    .to_string(),
                    expected
                );
            }
        }
    }
    #[test]
    fn valid_declared_builtins_keep_their_special_wire_encodings() {
        let abi = ContractAbi::from_json(r#"[{"type":"enum","name":"core::bool","variants":[{"name":"False","type":"()"},{"name":"True","type":"()"}]},{"type":"struct","name":"core::byte_array::ByteArray","members":[{"name":"data","type":"core::array::Array::<core::bytes_31::bytes31>"},{"name":"pending_word","type":"core::felt252"},{"name":"pending_word_len","type":"core::integer::u32"}]}]"#).unwrap();
        for (ty, value, wire) in [
            ("core::bool", AbiValue::Bool(true), vec![Felt::ONE]),
            (
                "core::byte_array::ByteArray",
                AbiValue::Bytes(vec![b'a']),
                vec![Felt::ZERO, Felt::from(b'a'), Felt::ONE],
            ),
        ] {
            assert_eq!(abi.encode_value(ty, &value).unwrap(), wire);
            let mut data = wire.as_slice();
            assert_eq!(abi.decode_value(ty, &mut data).unwrap(), value);
            assert_eq!(data, [] as [Felt; 0]);
        }
    }
    #[test]
    fn explicit_array_span_tuple_and_unit_declarations_cannot_bypass_schema_checks() {
        let cases = [
            (
                "core::array::Array::<core::felt252>",
                AbiValue::Sequence(vec![]),
            ),
            (
                "core::array::Span::<core::felt252>",
                AbiValue::Sequence(vec![]),
            ),
            (
                "(core::felt252, core::bool)",
                AbiValue::Sequence(vec![AbiValue::Felt(Felt::ZERO), AbiValue::Bool(false)]),
            ),
            ("()", AbiValue::Sequence(vec![])),
        ];
        let expected: Vec<_> = cases
            .iter()
            .map(|(ty, _)| {
                (
                    *ty,
                    Some("duplicate ABI struct member".to_owned()),
                    Some("duplicate ABI struct member".to_owned()),
                )
            })
            .collect();
        let mut actual = vec![];
        for (ty, value) in cases {
            let abi = ContractAbi::from_json(&serde_json::json!([{"type":"struct","name":ty,"members":[{"name":"same","type":"()"},{"name":"same","type":"()"}]}]).to_string()).unwrap();
            actual.push((
                ty,
                abi.encode_value(ty, &value)
                    .err()
                    .map(|error| error.to_string()),
                abi.decode_value(ty, &mut [Felt::ZERO; 3].as_slice())
                    .err()
                    .map(|error| error.to_string()),
            ));
        }
        assert_eq!(actual, expected);
    }
    #[test]
    fn contract_populates_u256_in_cairo_order() {
        let c = Contract::new(Felt::THREE, abi(), ());
        let amount = AbiValue::Struct(BTreeMap::from([
            ("high".into(), AbiValue::Felt(Felt::TWO)),
            ("low".into(), AbiValue::Felt(Felt::ONE)),
        ]));
        let call = c
            .populate("transfer", &[AbiValue::Felt(Felt::THREE), amount])
            .unwrap();
        assert_eq!(call.calldata, vec![Felt::THREE, Felt::ONE, Felt::TWO]);
        assert_eq!(call.selector, get_selector_from_name("transfer").unwrap());
        assert_eq!(
            c.abi.decode_outputs("transfer", &[Felt::ONE]).unwrap(),
            vec![AbiValue::Bool(true)]
        );
    }
    #[test]
    fn nested_array_tuple_enum_roundtrip() {
        let a = abi();
        let v = AbiValue::Sequence(vec![
            AbiValue::Sequence(vec![AbiValue::Felt(Felt::ONE), AbiValue::Bool(true)]),
            AbiValue::Sequence(vec![AbiValue::Felt(Felt::TWO), AbiValue::Bool(false)]),
        ]);
        let ty = "core::array::Array::<(core::felt252, core::bool)>";
        let encoded = a.encode_value(ty, &v).unwrap();
        let mut input = encoded.as_slice();
        assert_eq!(a.decode_value(ty, &mut input).unwrap(), v);
        assert_eq!(input, []);
        let v = AbiValue::Enum {
            variant: "None".into(),
            value: Box::new(AbiValue::Sequence(vec![])),
        };
        assert_eq!(a.encode_value("Choice", &v).unwrap(), vec![Felt::ZERO]);
    }
    #[test]
    fn empty_arrays_and_spans_validate_their_complete_element_schema() {
        let a = abi();
        for ty in [
            "core::array::Array::<Unknown>",
            "core::array::Span::<Unknown>",
            "core::array::Array::<core::array::Array::<Unknown>>",
            "core::array::Array::<(core::felt252, Unknown)>",
            "core::array::Array::<core::integer::i128>",
        ] {
            assert!(
                a.encode_value(ty, &AbiValue::Sequence(vec![])).is_err(),
                "{ty}"
            );
            assert!(
                a.decode_value(ty, &mut [Felt::ZERO].as_slice()).is_err(),
                "{ty}"
            );
        }
        for ty in [
            "core::array::Array::<core::felt252>",
            "core::array::Span::<core::felt252>",
        ] {
            assert_eq!(
                a.encode_value(ty, &AbiValue::Sequence(vec![])).unwrap(),
                vec![Felt::ZERO]
            );
            assert_eq!(
                a.decode_value(ty, &mut [Felt::ZERO].as_slice()).unwrap(),
                AbiValue::Sequence(vec![])
            );
        }
        let function = ContractAbi::from_json(r#"[{"type":"function","name":"f","inputs":[{"name":"items","type":"core::array::Array::<Unknown>"}],"outputs":[{"type":"core::array::Span::<Unknown>"}],"state_mutability":"view"}]"#).unwrap();
        assert!(
            function
                .encode_inputs("f", &[AbiValue::Sequence(vec![])])
                .is_err()
        );
        assert!(function.decode_outputs("f", &[Felt::ZERO]).is_err());
    }
    #[test]
    fn recursive_type_validation_checks_all_sibling_fields_and_enum_variants() {
        let valid = ContractAbi::from_json(r#"[{"type":"struct","name":"Node","members":[{"name":"children","type":"core::array::Array::<Node>"},{"name":"value","type":"core::felt252"}]}]"#).unwrap();
        let node = AbiValue::Struct(BTreeMap::from([
            ("children".into(), AbiValue::Sequence(vec![])),
            ("value".into(), AbiValue::Felt(Felt::THREE)),
        ]));
        assert_eq!(
            valid.encode_value("Node", &node).unwrap(),
            vec![Felt::ZERO, Felt::THREE]
        );
        assert_eq!(
            valid
                .decode_value("Node", &mut [Felt::ZERO, Felt::THREE].as_slice())
                .unwrap(),
            node
        );
        let invalid = ContractAbi::from_json(r#"[{"type":"struct","name":"Node","members":[{"name":"children","type":"core::array::Array::<Node>"},{"name":"value","type":"Unknown"}]},{"type":"enum","name":"Choice","variants":[{"name":"None","type":"()"},{"name":"Some","type":"Unknown"}]}]"#).unwrap();
        for ty in ["core::array::Array::<Node>", "core::array::Span::<Choice>"] {
            assert!(
                invalid
                    .encode_value(ty, &AbiValue::Sequence(vec![]))
                    .is_err()
            );
            assert!(
                invalid
                    .decode_value(ty, &mut [Felt::ZERO].as_slice())
                    .is_err()
            );
        }
        let empty_variant = AbiValue::Enum {
            variant: "None".into(),
            value: Box::new(AbiValue::Sequence(vec![])),
        };
        assert!(invalid.encode_value("Choice", &empty_variant).is_err());
    }
    #[test]
    fn duplicate_struct_members_never_produce_a_lossy_success() {
        let a = ContractAbi::from_json(r#"[{"type":"struct","name":"Bad","members":[{"name":"x","type":"core::integer::u8"},{"name":"x","type":"core::integer::u8"}]},{"type":"function","name":"f","inputs":[],"outputs":[{"type":"Bad"}],"state_mutability":"view"},{"type":"enum","name":"BadEnum","variants":[{"name":"A","type":"core::integer::u8"},{"name":"A","type":"core::integer::u8"}]}]"#).unwrap();
        let data = [Felt::ONE, Felt::TWO];
        let mut input = data.as_slice();
        assert!(a.decode_value("Bad", &mut input).is_err());
        assert_eq!(input, data.as_slice());
        assert!(a.decode_outputs("f", &data).is_err());
        assert!(a.decode_value("BadEnum", &mut data.as_slice()).is_err());
        assert!(
            a.encode_value(
                "BadEnum",
                &AbiValue::Enum {
                    variant: "A".into(),
                    value: Box::new(AbiValue::Felt(Felt::TWO))
                }
            )
            .is_err()
        );
        assert!(
            a.encode_value("core::array::Array::<Bad>", &AbiValue::Sequence(vec![]))
                .is_err()
        );
    }
    #[test]
    fn aggregate_budget_bounds_nested_zero_sized_array_expansion() {
        let a = abi();
        let data = [Felt::TWO, Felt::from(6u8), Felt::from(6u8)];
        assert!(
            a.decode(
                "core::array::Array::<core::array::Array::<()>>",
                &mut data.as_slice(),
                0,
                &mut 10,
                &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK),
            )
            .is_err()
        );
    }
    #[test]
    fn rejects_invalid_data() {
        let a = abi();
        assert!(
            a.encode_value("core::integer::u8", &AbiValue::Felt(Felt::from(256u32)))
                .is_err()
        );
        assert!(a.decode_outputs("transfer", &[Felt::TWO]).is_err());
        assert!(
            a.decode_outputs("transfer", &[Felt::ONE, Felt::ZERO])
                .is_err()
        );
        assert!(a.decode_outputs("transfer", &[]).is_err());
        assert!(a.encode_inputs("transfer", &[]).is_err());
        assert!(
            a.encode_value("unknown", &AbiValue::Felt(Felt::ZERO))
                .is_err()
        );
    }
    #[test]
    fn byte_array_roundtrip_and_malformed_tail() {
        let a = abi();
        for n in [0, 1, 30, 31, 32, 62] {
            let v = AbiValue::Bytes(vec![255; n]);
            let encoded = a.encode_value("core::byte_array::ByteArray", &v).unwrap();
            assert_eq!(
                a.decode_value("core::byte_array::ByteArray", &mut encoded.as_slice())
                    .unwrap(),
                v
            );
        }
        assert!(
            a.decode_value(
                "core::byte_array::ByteArray",
                &mut [Felt::ZERO, Felt::ONE, Felt::ZERO].as_slice()
            )
            .is_err()
        );
        assert!(
            a.decode_value(
                "core::byte_array::ByteArray",
                &mut [Felt::ZERO, Felt::ZERO, Felt::from(32u8)].as_slice()
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
                let decoder =
                    ContractAbi::from_json(&serde_json::json!([declaration]).to_string()).unwrap();
                for root in [ty.to_owned(), format!("core::array::Array::<{ty}>")] {
                    for _ in 0..2 {
                        assert_eq!(
                            decoder
                                .encode_value(&root, &AbiValue::Sequence(vec![]))
                                .unwrap_err()
                                .to_string(),
                            expected
                        );
                        let input = [Felt::ZERO; 3];
                        let mut data = input.as_slice();
                        assert_eq!(
                            decoder
                                .decode_value(&root, &mut data)
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
                AbiValue::Sequence(vec![AbiValue::Felt(Felt::THREE)]),
                vec![Felt::ONE, Felt::THREE],
            ),
            (
                "core::array::Span::<core::felt252>",
                AbiValue::Sequence(vec![AbiValue::Felt(Felt::THREE)]),
                vec![Felt::ONE, Felt::THREE],
            ),
            (
                "(core::felt252, core::bool)",
                AbiValue::Sequence(vec![AbiValue::Felt(Felt::THREE), AbiValue::Bool(true)]),
                vec![Felt::THREE, Felt::ONE],
            ),
            ("()", AbiValue::Sequence(vec![]), vec![]),
        ] {
            let declaration = serde_json::json!({"type":"struct","name":ty,"members":[]});
            let decoder =
                ContractAbi::from_json(&serde_json::json!([declaration]).to_string()).unwrap();
            assert_eq!(decoder.encode_value(ty, &value).unwrap(), wire);
            let mut data = wire.as_slice();
            assert_eq!(decoder.decode_value(ty, &mut data).unwrap(), value);
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
                ContractAbi::from_json(&serde_json::json!([declaration]).to_string()).unwrap();
            for root in [ty.to_owned(), format!("core::array::Array::<{ty}>")] {
                assert_eq!(
                    decoder
                        .encode_value(&root, &AbiValue::Sequence(vec![]))
                        .unwrap_err()
                        .to_string(),
                    "unsupported type: Unknown"
                );
                let input = [Felt::ZERO; 3];
                let mut data = input.as_slice();
                assert_eq!(
                    decoder
                        .decode_value(&root, &mut data)
                        .unwrap_err()
                        .to_string(),
                    "unsupported type: Unknown"
                );
                assert_eq!(data, input.as_slice());
            }
        }
        let declaration = serde_json::json!({"type":"struct","name":"core::integer::u128","members":[{"name":"bad","type":"Unknown"}]});
        let decoder =
            ContractAbi::from_json(&serde_json::json!([declaration]).to_string()).unwrap();
        assert_eq!(
            decoder
                .encode_value(
                    "core::integer::u256",
                    &AbiValue::Struct(BTreeMap::from([
                        ("low".into(), AbiValue::Felt(Felt::ZERO)),
                        ("high".into(), AbiValue::Felt(Felt::ZERO))
                    ]))
                )
                .unwrap_err()
                .to_string(),
            "unsupported type: Unknown"
        );
        let mut input = [Felt::ZERO; 2].as_slice();
        assert_eq!(
            decoder
                .decode_value("core::integer::u256", &mut input)
                .unwrap_err()
                .to_string(),
            "unsupported type: Unknown"
        );
    }
    #[test]
    fn compiler_span_snapshots_preserve_array_wire_encoding() {
        let artifact: serde_json::Value = serde_json::from_str(include_str!("../../starknet-rust-core/test-data/raw_gateway_responses/get_class_by_hash/3_cairo_1.txt")).unwrap();
        let entries: Vec<AbiEntry> =
            serde_json::from_str(artifact["abi"].as_str().unwrap()).unwrap();
        let entries = entries.into_iter().filter(|entry| matches!(entry, AbiEntry::Struct(s) if s.name.starts_with("core::array::Span::<"))).collect();
        let codec = ContractAbi::new(entries).unwrap();
        let span = "core::array::Span::<core::felt252>";
        let nested = "core::array::Span::<core::array::Span::<core::felt252>>";
        for (ty, wire, value) in [
            (span, vec![Felt::ZERO], AbiValue::Sequence(vec![])),
            (
                span,
                vec![Felt::ONE, Felt::from(7_u64)],
                AbiValue::Sequence(vec![AbiValue::Felt(Felt::from(7_u64))]),
            ),
            (nested, vec![Felt::ZERO], AbiValue::Sequence(vec![])),
            (
                nested,
                vec![Felt::TWO, Felt::ONE, Felt::from(7_u64), Felt::ZERO],
                AbiValue::Sequence(vec![
                    AbiValue::Sequence(vec![AbiValue::Felt(Felt::from(7_u64))]),
                    AbiValue::Sequence(vec![]),
                ]),
            ),
            (
                "core::array::Array::<core::array::Span::<core::felt252>>",
                vec![Felt::ZERO],
                AbiValue::Sequence(vec![]),
            ),
            (
                "@core::array::Array::<core::felt252>",
                vec![Felt::ONE, Felt::from(7_u64)],
                AbiValue::Sequence(vec![AbiValue::Felt(Felt::from(7_u64))]),
            ),
        ] {
            assert_eq!(codec.encode_value(ty, &value).unwrap(), wire);
            let mut input = wire.as_slice();
            assert_eq!(codec.decode_value(ty, &mut input).unwrap(), value);
            assert_eq!(input, []);
        }
    }
    #[test]
    fn snapshots_validate_underlying_and_explicit_declarations() {
        let codec = ContractAbi::new(vec![]).unwrap();
        for ty in [
            "@Unknown",
            "core::array::Array::<@Unknown>",
            "core::array::Span::<@Unknown>",
        ] {
            let mut input = [Felt::ZERO].as_slice();
            assert_eq!(
                codec.decode_value(ty, &mut input).unwrap_err().to_string(),
                "unsupported type: Unknown"
            );
        }
        for name in ["@core::felt252", "core::felt252"] {
            let entries: Vec<AbiEntry> = serde_json::from_value(serde_json::json!([{"type":"struct","name":name,"members":[{"name":"bad","type":"Unknown"}]}])).unwrap();
            let codec = ContractAbi::new(entries).unwrap();
            let ty = "@core::felt252";
            let mut input = [Felt::ZERO].as_slice();
            assert_eq!(
                codec.decode_value(ty, &mut input).unwrap_err().to_string(),
                "unsupported type: Unknown"
            );
        }
    }
    #[test]
    fn byte_array_words_share_budget_before_payload_allocation() {
        let codec = ContractAbi::new(vec![]).unwrap();
        let wire = [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO];
        let mut input = wire.as_slice();
        let mut budget = 3usize;
        assert_eq!(
            codec
                .decode(
                    "core::byte_array::ByteArray",
                    &mut input,
                    0,
                    &mut budget,
                    &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK)
                )
                .unwrap(),
            AbiValue::Bytes(vec![0; 31])
        );
        assert_eq!(budget, 0);
        let mut input = wire.as_slice();
        let mut budget = 2usize;
        assert!(
            codec
                .decode(
                    "core::byte_array::ByteArray",
                    &mut input,
                    0,
                    &mut budget,
                    &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK)
                )
                .unwrap_err()
                .to_string()
                .contains("node")
        );
        assert_eq!(input.len(), 3); // Only the length prefix was consumed.

        let mut input = [Felt::ZERO].as_slice();
        let mut budget = 3usize;
        assert_eq!(
            codec
                .decode(
                    "core::byte_array::ByteArray",
                    &mut input,
                    0,
                    &mut budget,
                    &mut SchemaBudget::new(DEFAULT_SCHEMA_WORK)
                )
                .unwrap_err()
                .to_string(),
            "truncated ByteArray"
        );
    }
}
