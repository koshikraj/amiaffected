# Evaluation cases for AIA-2026-0001

Maintainer material. Never installed, never read by a check. Each case is a
`.json` file; `.pem` files are its inputs. `expected.verdict` is the
advisory verdict assuming every other coverage item was read and matched
nothing, so a single store decides the case. Grading is manual: run an
agent against the case input, compare its report with `report_contains`.
