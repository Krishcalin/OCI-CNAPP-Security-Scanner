# CLAUDE.md -- OCI CNAPP Security Scanner

## Project Overview

A Python-based Cloud-Native Application Protection Platform (CNAPP) scanner for Oracle Cloud Infrastructure. Performs offline security assessment by analyzing OCI CLI JSON configuration exports against the CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0, OCI security best practices, and industry frameworks. Covers CSPM, CIEM, CWPP, KSPM, IaC, and CIS Benchmark compliance in a single tool.

**Repository**: https://github.com/Krishcalin/OCI-CNAPP-Security-Scanner
**License**: MIT
**Python**: 3.8+ (stdlib only, zero external dependencies)
**Version**: 1.0.0

## Repository Structure

```
OCI-CNAPP-Security-Scanner/
├── oci_scanner.py                  # Main entry point, CLI, MODULE_MAP
├── modules/
│   ├── __init__.py
│   ├── base.py                     # DataLoader, BaseAuditor, FILE_MAP
│   ├── cspm_core.py               # IamPolicyAuditor, NetworkVcnAuditor,
│   │                              # ComputeAuditor, StorageAuditor
│   ├── cspm_ciem.py               # DatabaseAuditor, LoggingAuditAuditor,
│   │                              # CloudGuardAuditor
│   ├── cwpp_iac.py                # OkeSecurityAuditor, VaultKmsAuditor,
│   │                              # WafEdgeAuditor, BastionAuditor,
│   │                              # IacSecurityAuditor, CisBenchmarkAuditor
│   └── report_generator.py        # ReportGenerator (HTML dashboard)
├── sample_data/                    # 35 demo OCI config JSON exports
├── docs/
│   └── banner.svg
├── LICENSE
├── CLAUDE.md
└── README.md
```

## Architecture

```
oci_scanner.py
  ├─ banner()                       # Console ASCII banner
  ├─ MODULE_MAP                     # dict mapping module name -> (label, AuditorClass)
  └─ main()
       ├─ argparse (--data-dir, --output, --severity, --modules, --config, --version)
       ├─ DataLoader(data_dir).load_all()      # Load all JSON files via FILE_MAP
       ├─ for each module:
       │    AuditorClass(data, baseline).run_all_checks()  -> list[dict]
       ├─ severity filter
       └─ ReportGenerator(findings, meta).generate(output)  # HTML report
```

### Data Flow

```
OCI CLI JSON exports  -->  DataLoader (FILE_MAP)  -->  dict[str, Any]
                                                          |
                    BaseAuditor._unwrap(key)  <-----------+
                         |
                   AuditorClass.run_all_checks()
                         |
                   list[Finding dict]
                         |
                   ReportGenerator  -->  HTML Dashboard
```

## Key Classes

### BaseAuditor (`modules/base.py`)

Base class for all auditor modules. Provides:

- `SEVERITY_CRITICAL`, `SEVERITY_HIGH`, `SEVERITY_MEDIUM`, `SEVERITY_LOW` -- severity constants
- `__init__(self, data, baseline)` -- receives loaded config data and optional baseline overrides
- `finding(cid, title, sev, cat, desc, items, remed, refs, cis, details, remediation, references)` -- creates a finding dict and appends to `self.findings`
- `run_all_checks()` -- abstract method, each auditor overrides this
- `gb(k, d)` -- get baseline value with default
- `_unwrap(key)` -- extracts data for a key, handling OCI CLI `{"data": [...]}` envelope format

### DataLoader (`modules/base.py`)

- `__init__(self, data_dir)` -- sets data directory path
- `load_all()` -- iterates FILE_MAP, loads each JSON file, returns `dict[str, Any]`
- Supports multiple filenames per key (tries each in order, uses first found)
- Uses `utf-8-sig` encoding to handle BOM

### ReportGenerator (`modules/report_generator.py`)

- `__init__(self, findings, meta)` -- receives findings list and scan metadata
- `generate(output_path)` -- generates interactive HTML dashboard with:
  - Severity breakdown (CRITICAL/HIGH/MEDIUM/LOW counts)
  - Category grouping
  - Detailed findings with affected items
  - OCI branding

## Module Inventory (13 modules, 76 checks)

| Module | Auditor Class | Check ID Prefix | Checks | Category |
|--------|--------------|-----------------|--------|----------|
| `iam` | `IamPolicyAuditor` | `OCI-IAM-` | 10 | CSPM |
| `network` | `NetworkVcnAuditor` | `OCI-NET-` | 10 | CSPM |
| `compute` | `ComputeAuditor` | `OCI-COMP-` | 8 | CSPM |
| `storage` | `StorageAuditor` | `OCI-STOR-` | 6 | CSPM |
| `database` | `DatabaseAuditor` | `OCI-DB-` | 6 | CSPM |
| `logging` | `LoggingAuditAuditor` | `OCI-LOG-` | 6 | CSPM |
| `cloudguard` | `CloudGuardAuditor` | `OCI-CG-` | 5 | CSPM |
| `oke` | `OkeSecurityAuditor` | `OCI-OKE-` | 8 | CWPP/KSPM |
| `vault` | `VaultKmsAuditor` | `OCI-KMS-` | 5 | Encryption |
| `waf` | `WafEdgeAuditor` | `OCI-WAF-` | 4 | CWPP |
| `bastion` | `BastionAuditor` | `OCI-BAST-` | 4 | CWPP |
| `iac` | `IacSecurityAuditor` | `OCI-IAC-` | 3 | IaC |
| `cis` | `CisBenchmarkAuditor` | `OCI-CIS-` | 1 | Compliance |

## FILE_MAP

The `FILE_MAP` dict in `modules/base.py` maps logical data keys to candidate JSON filenames. Each key maps to a list of possible filenames (tried in order). Categories:

| Key Group | Keys | Primary Files |
|-----------|------|---------------|
| IAM & Policies | `iam_users`, `iam_groups`, `iam_policies`, `iam_api_keys`, `iam_auth_tokens`, `compartments`, `identity_providers`, `tenancy_config`, `password_policy` | `iam_users.json`, `iam_groups.json`, `iam_policies.json`, `iam_api_keys.json`, `iam_auth_tokens.json`, `compartments.json`, `identity_providers.json`, `tenancy_config.json`, `password_policy.json` |
| Networking | `vcns`, `security_lists`, `network_security_groups`, `nsg_rules`, `subnets`, `internet_gateways`, `drg_attachments`, `route_tables`, `service_gateways` | `vcns.json`, `security_lists.json`, `network_security_groups.json`, `nsg_rules.json`, `subnets.json`, `internet_gateways.json`, `drg_attachments.json`, `route_tables.json`, `service_gateways.json` |
| Compute | `instances`, `boot_volumes`, `images`, `vnic_attachments` | `instances.json`, `boot_volumes.json`, `images.json`, `vnic_attachments.json` |
| Object Storage | `buckets`, `preauthenticated_requests` | `buckets.json`, `preauthenticated_requests.json` |
| Database | `autonomous_databases`, `db_systems`, `mysql_db_systems` | `autonomous_databases.json`, `db_systems.json`, `mysql_db_systems.json` |
| Logging & Audit | `audit_config`, `log_groups`, `service_connectors`, `events_rules`, `alarms` | `audit_config.json`, `log_groups.json`, `service_connectors.json`, `events_rules.json`, `alarms.json` |
| Cloud Guard | `cloud_guard_config`, `cloud_guard_targets`, `cloud_guard_detectors`, `cloud_guard_problems`, `security_zones` | `cloud_guard_config.json`, `cloud_guard_targets.json`, `cloud_guard_detectors.json`, `cloud_guard_problems.json`, `security_zones.json` |
| OKE | `oke_clusters`, `oke_node_pools` | `oke_clusters.json`, `oke_node_pools.json` |
| Vault & KMS | `vaults`, `vault_keys` | `vaults.json`, `vault_keys.json` |
| WAF & LB | `waf_policies`, `load_balancers` | `waf_policies.json`, `load_balancers.json` |
| Bastion | `bastions`, `bastion_sessions` | `bastions.json`, `bastion_sessions.json` |
| IaC | `terraform_state`, `terraform_plan` | `terraform.tfstate`, `terraform_plan.json` |

## CLI Reference

```bash
# Run all checks against sample data
python oci_scanner.py --data-dir ./sample_data --output report.html

# Run specific modules
python oci_scanner.py --data-dir ./exports --modules iam network compute oke

# Filter by severity
python oci_scanner.py --data-dir ./exports --severity HIGH

# Use baseline config for custom thresholds
python oci_scanner.py --data-dir ./exports --config baseline.json

# Show version
python oci_scanner.py --version
```

## MODULE_MAP (`oci_scanner.py`)

```python
MODULE_MAP = {
    "iam":        ("CSPM: IAM & Policies",       IamPolicyAuditor),
    "network":    ("CSPM: Networking & VCN",      NetworkVcnAuditor),
    "compute":    ("CSPM: Compute",               ComputeAuditor),
    "storage":    ("CSPM: Object Storage",        StorageAuditor),
    "database":   ("CSPM: Database Security",     DatabaseAuditor),
    "logging":    ("CSPM: Logging & Audit",       LoggingAuditAuditor),
    "cloudguard": ("CSPM: Cloud Guard",           CloudGuardAuditor),
    "oke":        ("CWPP/KSPM: OKE Kubernetes",   OkeSecurityAuditor),
    "vault":      ("Encryption: Vault & KMS",     VaultKmsAuditor),
    "waf":        ("CWPP: WAF & Edge Security",   WafEdgeAuditor),
    "bastion":    ("CWPP: Bastion Security",      BastionAuditor),
    "iac":        ("IaC: Terraform Security",     IacSecurityAuditor),
    "cis":        ("Compliance: CIS OCI Benchmark", CisBenchmarkAuditor),
}
```

## CIS OCI Foundations Benchmark v2.0 Mapping

| CIS Section | Topic | Module | Check IDs |
|-------------|-------|--------|-----------|
| 1.1 | Root Compartment & Policy | `iam` | OCI-IAM-001, OCI-IAM-009 |
| 1.2 | Broad Policies | `iam` | OCI-IAM-003 |
| 1.3 | User/Group Management | `iam` | OCI-IAM-006 |
| 1.4 | Admin Group | `iam` | OCI-IAM-008 |
| 1.5 | Password Policy | `iam` | OCI-IAM-010 |
| 1.7 | MFA Enforcement | `iam` | OCI-IAM-002 |
| 1.8 | API Key Rotation | `iam` | OCI-IAM-004 |
| 1.9 | Auth Token Rotation | `iam` | OCI-IAM-005 |
| 1.10 | KMS Key Rotation | `vault` | OCI-KMS-001 |
| 1.12 | Federation | `iam` | OCI-IAM-007 |
| 2.1-2.7 | Networking & VCN | `network` | OCI-NET-001 to OCI-NET-006, OCI-NET-009 |
| 3.1-3.6 | Compute Security | `compute` | OCI-COMP-001 to OCI-COMP-004, OCI-COMP-006, OCI-COMP-007 |
| 4.1-4.8 | Logging, Audit, Cloud Guard | `logging`, `cloudguard` | OCI-LOG-001 to OCI-LOG-005, OCI-CG-001 to OCI-CG-003 |
| 5.1-5.4 | Object Storage | `storage` | OCI-STOR-001, OCI-STOR-002, OCI-STOR-004, OCI-STOR-005 |

## Finding Dict Schema

Each finding is a dict with:

```python
{
    "check_id":         "OCI-IAM-001",         # Unique check identifier
    "title":            "Resources in root...", # Short title
    "severity":         "CRITICAL",             # CRITICAL | HIGH | MEDIUM | LOW
    "category":         "IAM & Policies",       # Module category
    "description":      "...",                  # Detailed description
    "affected_items":   ["item1", "item2"],     # List of affected resource identifiers
    "affected_count":   2,                      # len(affected_items)
    "remediation":      "...",                  # Fix recommendation
    "references":       ["https://..."],        # Reference URLs
    "cis_benchmark":    "1.1",                  # CIS section (empty if not mapped)
    "details":          {},                     # Additional structured data
    "timestamp":        "2026-03-29T..."        # ISO 8601 timestamp
}
```

## Conventions

### Offline JSON Analysis
- The scanner never connects to any live OCI environment
- All data is read from local JSON files exported via the OCI CLI
- The `DataLoader` handles the standard OCI CLI `{"data": [...]}` response envelope via `_unwrap()`

### OCI CLI Envelope Format
- OCI CLI commands return JSON with a `"data"` key wrapping the actual payload
- `BaseAuditor._unwrap(key)` extracts the inner data, handling both enveloped and raw formats

### Severity Levels
- **CRITICAL** -- immediate risk, exploitable, data exposure (e.g., public buckets, SSH open to internet)
- **HIGH** -- significant risk, should be fixed promptly (e.g., no backups, overly broad policies)
- **MEDIUM** -- moderate risk, hardening recommendation (e.g., missing encryption, missing boot integrity)
- **LOW** -- informational, best practice (e.g., replication not configured, log groups not organized)

### Check ID Format
- `OCI-{MODULE}-{NNN}` where MODULE is `IAM`, `NET`, `COMP`, `STOR`, `DB`, `LOG`, `CG`, `OKE`, `KMS`, `WAF`, `BAST`, `IAC`, or `CIS`
- Numbers are zero-padded to 3 digits (001-010)

### HTML Report
- Generated by `ReportGenerator` in `modules/report_generator.py`
- OCI branding with interactive dashboard
- Severity breakdown, category grouping, detailed findings with affected items
- Falls back to JSON output if `report_generator` module is unavailable

### Module Source Layout
- `cspm_core.py` -- IAM, Network, Compute, Storage (first 4 CSPM modules)
- `cspm_ciem.py` -- Database, Logging, Cloud Guard (remaining CSPM modules)
- `cwpp_iac.py` -- OKE, Vault, WAF, Bastion, IaC, CIS (CWPP + Encryption + IaC + Compliance)

### Baseline Config
- Optional JSON file passed via `--config` flag
- Allows overriding default thresholds (e.g., max admin group size, max API key age)
- Accessed via `BaseAuditor.gb(key, default)` method

## Development Guidelines

### Adding a New Check

1. Add a method to the appropriate auditor class (e.g., `check_new_thing` in `IamPolicyAuditor`)
2. Call it from `run_all_checks()` in the correct order
3. Use `self._unwrap("key")` to get the data
4. Use `self.finding(cid, title, sev, cat, desc, ...)` to emit findings
5. Follow the check ID pattern: `OCI-{MODULE}-{NNN}`
6. Update `MODULE_MAP` if adding a new module

### Adding a New Data Source

1. Add the filename mapping to `FILE_MAP` in `modules/base.py`
2. Add a sample file to `sample_data/` with representative data
3. Reference the key via `self._unwrap("new_key")` in the auditor

## Related Projects

| Project | Repo |
|---------|------|
| GCP CNAPP Security Scanner | [GCP-CNAPP-Security-Scanner](https://github.com/Krishcalin/GCP-CNAPP-Security-Scanner) |
| AWS CloudFormation + Terraform IaC | [AWS-Security-Scanner](https://github.com/Krishcalin/AWS-Security-Scanner) |
| Static Application Security Testing | [Static-Application-Security-Testing](https://github.com/Krishcalin/Static-Application-Security-Testing) |
| Kubernetes KSPM | [Kubernetes-KSPM](https://github.com/Krishcalin/Kubernetes-Security-Posture-Management) |
| AI Security Posture Management | [AI-Secure-Posture-Management](https://github.com/Krishcalin/AI-Secure-Posture-Management) |
