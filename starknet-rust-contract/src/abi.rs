//! Runtime Cairo 1 ABI values and serialization.
use starknet_rust_core::{
    types::{
        Felt,
        contract::{AbiEntry, AbiFunction},
    },
    utils::get_selector_from_name,
};
use std::{collections::BTreeMap, fmt};

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

/// A runtime Cairo 1 ABI. Unsupported types fail explicitly rather than being treated as felts.
#[derive(Debug, Clone)]
pub struct ContractAbi {
    entries: Vec<AbiEntry>,
    type_indices: BTreeMap<String, usize>,
    function_indices: BTreeMap<String, usize>,
}
impl ContractAbi {
    /// Creates an ABI, expanding interface entries. Duplicates within the function namespace or ordinary type namespace are rejected; functions and types may share a name.
    pub fn new(entries: Vec<AbiEntry>) -> Result<Self, AbiError> {
        fn flatten(entries: Vec<AbiEntry>, out: &mut Vec<AbiEntry>) {
            for e in entries {
                match e {
                    AbiEntry::Interface(i) => flatten(i.items, out),
                    e => out.push(e),
                }
            }
        }
        let mut flattened = vec![];
        flatten(entries, &mut flattened);
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
        Ok(Self {
            entries: flattened,
            type_indices,
            function_indices,
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
            self.validate_type(&field.r#type)?;
            self.encode(&field.r#type, value, &mut output, 0)?;
        }
        Ok(output)
    }
    /// Decodes all outputs, rejecting truncated and trailing return data.
    pub fn decode_outputs(&self, name: &str, data: &[Felt]) -> Result<Vec<AbiValue>, AbiError> {
        let mut data = data;
        let mut budget = 1_000_000;
        let values = self
            .function(name)?
            .outputs
            .iter()
            .map(|o| {
                self.validate_type(&o.r#type)?;
                self.decode(&o.r#type, &mut data, 0, &mut budget)
            })
            .collect::<Result<_, _>>()?;
        if !data.is_empty() {
            return Err(error("trailing return data"));
        }
        Ok(values)
    }
    /// Serializes a standalone ABI type.
    pub fn encode_value(&self, ty: &str, value: &AbiValue) -> Result<Vec<Felt>, AbiError> {
        self.validate_type(ty)?;
        let mut out = vec![];
        self.encode(ty, value, &mut out, 0)?;
        Ok(out)
    }
    /// Decodes a standalone ABI type, consuming only the required prefix.
    pub fn decode_value(&self, ty: &str, data: &mut &[Felt]) -> Result<AbiValue, AbiError> {
        self.validate_type(ty)?;
        self.decode(ty, data, 0, &mut 1_000_000)
    }
    // Validate the schema independently of values, so empty arrays and unselected enum
    // variants cannot hide unsupported types. Each type is visited once, allowing recursive
    // named schemas without revisiting cycles; value depth/node limits still apply separately.
    fn validate_type(&self, ty: &str) -> Result<(), AbiError> {
        self.validate_type_graph(ty, &mut std::collections::BTreeSet::new(), 0)
    }
    fn validate_type_graph(
        &self,
        ty: &str,
        seen: &mut std::collections::BTreeSet<String>,
        depth: usize,
    ) -> Result<(), AbiError> {
        if depth > 64 {
            return Err(error("ABI type nesting exceeds 64"));
        }
        let ty = ty.trim();
        if !seen.insert(ty.to_owned()) {
            return Ok(());
        }
        if scalar_bits(ty).is_some()
            || matches!(
                ty,
                "core::bool" | "core::byte_array::ByteArray" | "core::integer::u256"
            )
        {
            return Ok(());
        }
        if let Some(inner) = array_inner(ty) {
            return self.validate_type_graph(inner, seen, depth + 1);
        }
        if let Some(types) = tuple_types(ty)? {
            for ty in types {
                self.validate_type_graph(ty, seen, depth + 1)?;
            }
            return Ok(());
        }
        if let Some(entry) = self.type_indices.get(ty).map(|index| &self.entries[*index]) {
            match entry {
                AbiEntry::Struct(s) if s.name == ty => {
                    let mut names = std::collections::BTreeSet::new();
                    for member in &s.members {
                        if !names.insert(&member.name) {
                            return Err(error("duplicate ABI struct member"));
                        }
                        self.validate_type_graph(&member.r#type, seen, depth + 1)?;
                    }
                    return Ok(());
                }
                AbiEntry::Enum(e) if e.name == ty => {
                    let mut names = std::collections::BTreeSet::new();
                    for variant in &e.variants {
                        if !names.insert(&variant.name) {
                            return Err(error("duplicate ABI enum variant"));
                        }
                        self.validate_type_graph(&variant.r#type, seen, depth + 1)?;
                    }
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(error(format!("unsupported type: {ty}")))
    }
    fn encode(
        &self,
        ty: &str,
        value: &AbiValue,
        out: &mut Vec<Felt>,
        depth: usize,
    ) -> Result<(), AbiError> {
        if depth > 64 {
            return Err(error("ABI nesting exceeds 64"));
        }
        let ty = ty.trim();
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
                    self.encode("core::integer::u128", limb, out, depth + 1)?;
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
                    self.encode(inner, v, out, depth + 1)?;
                }
                return Ok(());
            }
        } else if let Some(types) = tuple_types(ty)? {
            if let AbiValue::Sequence(vs) = value {
                if vs.len() != types.len() {
                    return Err(error("wrong tuple length"));
                }
                for (t, v) in types.iter().zip(vs) {
                    self.encode(t, v, out, depth + 1)?;
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
                                self.encode(
                                    &m.r#type,
                                    fields.get(&m.name).ok_or_else(|| {
                                        error(format!("missing field: {}", m.name))
                                    })?,
                                    out,
                                    depth + 1,
                                )?;
                            }
                            return Ok(());
                        }
                        return Err(error("expected struct"));
                    }
                    AbiEntry::Enum(e) if e.name == ty => {
                        if let AbiValue::Enum { variant, value } = value {
                            let (i, v) = e
                                .variants
                                .iter()
                                .enumerate()
                                .find(|(_, v)| v.name == *variant)
                                .ok_or_else(|| error("unknown enum variant"))?;
                            out.push(Felt::from(i));
                            return self.encode(&v.r#type, value, out, depth + 1);
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
    ) -> Result<AbiValue, AbiError> {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| error("decoded values exceed one million nodes"))?;
        if depth > 64 {
            return Err(error("ABI nesting exceeds 64"));
        }
        let ty = ty.trim();
        if scalar_bits(ty).is_some() {
            let f = take(data)?;
            validate_scalar(ty, f)?;
            return Ok(AbiValue::Felt(f));
        }
        if ty == "core::integer::u256" {
            let mut fields = BTreeMap::new();
            for name in ["low", "high"] {
                fields.insert(
                    name.to_owned(),
                    self.decode("core::integer::u128", data, depth + 1, budget)?,
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
            return Ok(AbiValue::Bytes(bytes));
        }
        if let Some(inner) = array_inner(ty) {
            let n = length(take(data)?)?; // Bound work even for zero-sized types.
            if n > 1_000_000 {
                return Err(error("array exceeds one million items"));
            }
            let mut values = Vec::new();
            for _ in 0..n {
                values.push(self.decode(inner, data, depth + 1, budget)?);
            }
            return Ok(AbiValue::Sequence(values));
        }
        if let Some(types) = tuple_types(ty)? {
            return types
                .iter()
                .map(|t| self.decode(t, data, depth + 1, budget))
                .collect::<Result<Vec<_>, _>>()
                .map(AbiValue::Sequence);
        }
        if let Some(entry) = self.type_indices.get(ty).map(|index| &self.entries[*index]) {
            match entry {
                AbiEntry::Struct(s) if s.name == ty => {
                    let mut values = BTreeMap::new();
                    for m in &s.members {
                        values.insert(
                            m.name.clone(),
                            self.decode(&m.r#type, data, depth + 1, budget)?,
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
                    return Ok(AbiValue::Enum {
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
fn tuple_types(ty: &str) -> Result<Option<Vec<&str>>, AbiError> {
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
        let calldata = self.abi.encode_inputs(name, args)?;
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
        let call = self.populate(name, args).map_err(ContractCallError::Abi)?;
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
            .decode_outputs(name, &result)
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
    #[derive(Debug)]
    struct MockTransport;
    #[async_trait::async_trait]
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
                &mut 10
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
}
