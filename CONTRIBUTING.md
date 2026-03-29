# Contributing

1. Add `check_*()` method to the appropriate auditor class in `modules/`.
2. Use `self.finding()` with: `cid`, `title`, `sev`, `cat`, `desc`, `items`, `remed`, `refs`, `cis`.
3. Check ID format: `OCI-{CATEGORY}-{NNN}` (e.g., `OCI-IAM-011`, `OCI-NET-011`).
4. Map to CIS OCI Foundation Benchmark v2.0 section where applicable.
5. Add sample data to `sample_data/` to test the new check.
6. Update `README.md` and `CLAUDE.md` with the new check.
