# Types for smart contract deployment and interaction

## ABI event decoding

Construct `events::EventDecoder::from_json(abi_json, "my_contract::Event")` with the full Cairo 1/2
ABI and its root event name. `decoder.decode(&event)` returns the emitting address, nested enum
variant path, leaf event type and a map of decoded fields. `decode_from(receipt.events(), address)`
filters a receipt to one contract before decoding, preserving event order.

Cairo 2 nested enum selectors and flat enum paths are expanded from the ABI; key and data fields
are decoded from their respective streams. Cairo 1 untyped events use their short-name selector.
The value decoder supports felts, unsigned integer/address widths, bool, arrays/Span, tuples,
ordinary ABI structs/enums and ByteArray. Unknown selectors, ambiguous/cyclic routes, invalid
scalars, truncation and trailing keys/data fail explicitly. Depth is limited to 64; arrays are
limited to one million items.

Cairo 0 ABIs, signed integers, fixed arrays and nested event-enum _struct members_ are currently
unsupported. Nested/flat enum routing from the selected root is supported. This API does not
subscribe to events or generate compile-time Rust event types.
