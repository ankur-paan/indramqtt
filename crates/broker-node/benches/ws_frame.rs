// The WS frame sampler's single source of truth is `tests/bench_ws_frame`
// (the path the M1-01 spec BENCH line names). Cargo only builds bench
// targets under this directory, so this target includes that file; it is
// compiled and run by `cargo test -p broker-node --bench ws_frame --
// --ignored`. Keep all codec and sampling logic in the included file.
include!("../../../tests/bench_ws_frame");
