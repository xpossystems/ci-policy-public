# Mandatory development gates

These are hard requirements for every new feature or function in this repository,
regardless of size or language. Apply them to delegated work too.

1. **TDD first:** define expected behavior, write meaningful failing tests, and run
   them to confirm the intended failure before implementation. Implement the
   minimum, then refactor with tests green. Tests added afterward are not TDD.
2. **Unit tests:** cover normal behavior, boundaries, invalid inputs, and errors.
3. **Integration tests:** exercise actual affected component boundaries. Fully
   mocked boundary tests do not replace integration coverage.
4. **Break testing and pentesting:** after implementation, use malformed input,
   failure injection, edge cases, retries/concurrency where relevant, and abuse
   cases. Perform hands-on feature-scoped security tests for applicable authentication,
   authorization, isolation, injection, and exposure surfaces. Static scans alone
   are not pentesting. Use owned or explicitly authorized local/test/staging targets
   and test data; this does not authorize destructive production or third-party tests.
5. **Fix and retest:** repair findings, add regressions, and rerun affected unit,
   integration, break, and security checks until passing.
6. **Completion:** do not declare complete with a required check missing or failing,
   or an unresolved finding. Report commands/results, scope, findings/fixes, and
   limitations. State access/environment blockers and keep the work incomplete.

Finish implementation, tests, and review before asking for push or merge approval.
Do not push or merge to main without explicit user approval. An explicit request
to push or merge the current work provides that approval; do not ask again.
Never bypass required checks or weaken CI protections to complete a feature.
