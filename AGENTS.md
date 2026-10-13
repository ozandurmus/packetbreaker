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
6. **Speed.** Aim for a default `pytest` run under 2 minutes locally. Large real-tshark matrices are
   marked `@pytest.mark.slow`; CI runs them on one job only. Timing budgets are advisory: never
   spend a task chasing a wall-clock budget unless the task is explicitly about test speed.

## Working efficiently (mandatory)

Time and credits are limited. Every task is time-boxed to **60 minutes** of work unless the prompt
says otherwise.

1. **Targeted tests while developing.** Run only the tests for the files you change. Run the full
   fast suite **once**, at the end, before opening the PR.
2. **CI: push once, check once.** Open the PR and read the CI result once.
   - A real test failure in your change: fix it, then push again.
   - Timing budgets, runner noise, flaky infrastructure or anything unrelated to your change:
     do NOT fix it. Report it in one line and stop.
   - Never poll CI in a loop and never re-run jobs hoping for green.
3. **No unrequested work.** No benchmarks, refactors, extra features or "proof" re-runs unless
   the prompt asks for them.
4. **Stuck rule.** If the same problem has taken more than 15 minutes, stop and report what you
   tried and what you need. Do not keep experimenting.
5. **Report format.** At most 10 lines: what changed, the test result, the CI result, open
   issues. No long narratives.

## Git workflow

- Work on a feature branch, one commit per item, push after each commit.
- Open a PR at the end and get the full CI matrix green. Never push to `main` directly and never
  enable auto-merge; the owner reviews and merges.
- Update ARCHITECTURE.md, DECISIONS.md and VALIDATION.md with each part. Report what works, what is
  approximate and the known limitations, then stop and wait for review.
