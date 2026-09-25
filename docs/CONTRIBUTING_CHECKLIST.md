# Contribution Checklist

Before opening a pull request:

- Run the relevant backend tests.
- Run the evaluation harness when detection logic changes.
- Run the frontend typecheck/build when UI code changes.
- Keep secrets out of source control; use environment variables.
- Preserve the project's deterministic risk-scoring and evidence-sufficiency invariants.
- Update documentation when behavior or configuration changes.
