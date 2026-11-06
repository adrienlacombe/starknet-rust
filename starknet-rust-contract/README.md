# Types for smart contract deployment and interaction

## Runtime Cairo 1 ABI contracts

`ContractAbi::from_json` accepts compiler Cairo 1 ABI arrays, including interface functions.
`Contract::new(address, abi, provider)` attaches the ABI without network access. Use `populate`
for validated multicall calldata, `call` for decoded view results, or
`contract.invoke(&account, name, args)?.estimate_fee().await` / `.send().await` for writes.

Values are explicit `AbiValue`s: `Felt`, `Bool`, `Sequence` (array/tuple), `Struct` (named fields),
`Enum` (variant and payload), and `Bytes` (ByteArray). Unsigned scalar widths are checked;
struct field order comes from the ABI rather than the map's iteration order. `u256` is represented
by its ABI struct's `low` and `high` u128 fields. Arrays/Span, tuples, structs, enums and ByteArray
can be nested. Unit payloads are `Sequence(vec![])`.

This API does not generate compile-time Rust bindings. Cairo 0 ABIs, signed integers, fixed arrays,
and Cairo wrapper types not declared as structs/enums in the ABI are currently unsupported and
return `AbiError`. It rejects unknown functions, wrong arguments, invalid scalars, truncated and
trailing return data. Recursive value decoding has a depth limit of 64 and arrays a one-million
item limit, with a shared one-million-node decoded-value budget to bound zero-sized nested arrays;
only load ABIs you intend to interact with.

Schema validation runs independently of values, so empty arrays/Span and unselected enum variants
cannot hide unsupported types. Recursive named schemas are checked once per type, including all
fields/variants; runtime value depth and aggregate-node limits still apply.

Duplicate ordinary struct-member or enum-variant names are rejected during schema validation,
preventing lossy or ambiguous decoded values.

Each public encode/decode operation also has a separate one-million-unit schema-work budget,
shared across all argument or output roots, including both phases of a contract view call. Graph visits and declaration edges consume this
budget even for empty arrays; completed root validations are cached. Exceptionally complex cold
schemas may hit this resource cap. Exhaustion is never cached as an invalid schema; a later call starts with a fresh budget.

Operations additionally enforce independent 64 MiB allowances for logical owned storage and
type-text work. Logical accounting includes value/container slots, copied identifiers and
diagnostics, ByteArray/encoded buffers, and schema temporaries; it is not an exact allocator
or process-memory measurement. Type text is charged before repeated parsing or name searches.
Tuple fields are traversed with a borrowed iterator, without eager per-value field vectors.
The immutable loaded ABI/indexes and caller-owned input values/felts form the storage baseline
outside these allowances.
Completed schema-cache entries have a separate shared 64 MiB logical capacity; a full cache
skips optional insertions while valid decoding continues. Resource failures are not cached.
Contract view calls share allowances across encoding and decoding. Very large valid cold schemas
or outputs may reach these private resource caps.
