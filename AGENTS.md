# Agent instructions for PacketBreaker

Read README.md, docs/ARCHITECTURE.md, docs/DECISIONS.md and docs/VALIDATION.md before changing
code. These rules apply to every task in this repository.

## Product rules

- Every number and finding is traceable to concrete frames: file, frame number and display filters.
- Never present a guess as a measurement. When evidence is insufficient, the result is `unknown`
  with an explicit reason.
- tshark is the only protocol dissector. Heavy work runs in DuckDB SQL, not in per-packet Python.
- No outbound network calls, telemetry or CDN assets. The server binds to 127.0.0.1 only.
- Never commit real or third-party captures. `demo/` stays gitignored.

## Test design rules (mandatory)

1. **Distractors.** Every fixture must contain wrong answers that the code could pick: at least two
   candidate devices or hops, and a fault location parametrized across devices AND links.
2. **Negative tests first.** For every detector, write the false-positive cases before
   implementing it: capture misses, legitimate endpoint behaviour, missing capture points, clock
   uncertainty. Each must produce `unknown` or no finding.
3. **Naive-implementation check.** For each new detector, state in the PR which trivial wrong
   implementation the tests would catch (for example "always blame the first middlebox" or
   "assume loss in every bucket"), and show that the tests fail against it.
4. **Realistic patterns.** No fixture where the signal is perfectly regular. Use intermittent and
   random events, IP ID zero/constant, IPv6 and concurrent flows.
5. **Never weaken an assertion to make a test pass.** If the behaviour is uncertain, the expected
   result is `unknown` with a reason.
6. **Speed.** The default `pytest` run stays under 2 minutes. Large real-tshark matrices are marked
   `@pytest.mark.slow`; CI runs them on one job only.

## Git workflow

- Work on a feature branch, one commit per item, push after each commit.
- Open a PR at the end and get the full CI matrix green. Never push to `main` directly and never
  enable auto-merge; the owner reviews and merges.
- Update ARCHITECTURE.md, DECISIONS.md and VALIDATION.md with each part. Report what works, what is
  approximate and the known limitations, then stop and wait for review.
