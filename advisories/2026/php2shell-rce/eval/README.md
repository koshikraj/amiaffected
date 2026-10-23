# Evaluation cases for AIA-2026-0002

Maintainer material. Never installed, never read by a check. Each case is a
`.json` file whose `captured_output` is the transcript an agent would see from
one or more blocks of advisory.md. `expected.verdict` is the advisory verdict
assuming every other required coverage item was read to its `done` line and
found nothing, so one block decides the case. Grading is manual: run an agent
against the case input, compare its report with `report_contains`.

The distribution cases exist because the comparator is the trap here: a fixed
Ubuntu or EL package still prints the old upstream number from `php -v`, and
an agent that compares that number with floor-php-upstream reports a fixed
host as affected, or an unfixed Sury or Remi build as fixed.
