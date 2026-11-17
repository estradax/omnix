# Context-cost benchmark

Compares how many bytes / estimated tokens enter the model context when (A) all upstream MCP tool
definitions are loaded directly versus (B) the agent talks to the omnix gateway (3 tools: search, describe, execute).

## Reproduce

    cargo test --test bench -- --ignored --nocapture      # full run, writes target/bench-report.md
    cargo test --test bench benchmark_smoke               # fast sanity (2 servers x 5 tools, 50 records)

Fully offline and deterministic (byte counts): servers are `src/bin/mock_many.rs` with a hand-written
seeded PRNG (seed 42, server name mixed in), config lives in a temp dir (`HOME` and `OMNIX_CONFIG_DIR` set,
environment cleared for the gateway process). Only wall-clock numbers vary between runs.

## Setup

5 servers (`s1`..`s5`) x 20 generated tools (2-8 params: string/integer/boolean/enum/array/nested object,
20-60 word descriptions) + 2 working tools each (`list_records`, `get_record`) = 110 tools.

Task: "list 500 records from s1, keep those with status == 'active', return the count and the first 3 names."

- Direct: tools/list of every server as `{name, description, input_schema}` (names namespaced `sN__tool`), plus the
  `list_records` call and its FULL result (500 records, ~270 bytes each) entering context.
- Gateway: the gateway's 3 tool definitions, plus real `search`, `describe`, `execute` calls (arguments and results as
  serialized content blocks). The JS filters server-side; only the small answer returns.
- Correctness: the gateway answer must equal the direct computation (asserted).

## What is and is not measured

- Measured: bytes of tool definitions and of tool-call arguments/results; chars/4 token estimate; wall-clock (informational).
- Token estimate is APPROXIMATE (chars/4). To use a real tokenizer, replace `est_tokens` in `tests/bench.rs`.
- NOT measured: model quality, whether a model finds the right tool via search, number of model turns/latency
  (the gateway flow needs 3 calls vs 1 in the scripted flow; a real model may need more or fewer), prompt caching effects.
- Real MCP clients may lazy-load or defer tool definitions, which shrinks the direct "definitions" cost.
  The definitions-only ratio is reported separately; the task-flow row (intermediate result stays out of context) is
  independent of that.
- The task is deliberately favorable to code mode (large intermediate result). Tasks with small results gain only from definitions.
- Search query and the single describe call are scripted, not model-chosen.

## Results (debug build, 5 x 20 generated tools = 110 tools, 500 records)

Tokens ~ chars/4.

| Row | Direct bytes | Gateway bytes | Ratio | Direct ~tok | Gateway ~tok | Ratio |
|---|---:|---:|---:|---:|---:|---:|
| Definitions only | 105940 | 839 | 126.3x | 26485 | 210 | 126.1x |
| Task flow | 135351 | 1359 | 99.6x | 33839 | 342 | 98.9x |
| Total | 241291 | 2198 | 109.8x | 60324 | 552 | 109.3x |

Answer (both): `{"count":214,"first3":["Person 0003","Person 0006","Person 0007"]}`.
Gateway cold start (spawn + initialize + tools/list, 5 upstreams, debug build): about 1.1 s. Whole test about 1.6 s.
