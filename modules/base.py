"""Base Auditor and OCI Configuration Data Loader for CNAPP Scanner."""
import json, datetime
from pathlib import Path
from typing import Dict, List, Any

class BaseAuditor:
    SEVERITY_CRITICAL="CRITICAL"; SEVERITY_HIGH="HIGH"; SEVERITY_MEDIUM="MEDIUM"; SEVERITY_LOW="LOW"
    def __init__(self, data, baseline=None):
        self.data=data; self.baseline=baseline or {}; self.findings=[]
    def finding(self, cid, title, sev, cat, desc, items=None, remed="", refs=None, cis=None, details=None, remediation=None, references=None):
        f={"check_id":cid,"title":title,"severity":sev,"category":cat,"description":desc,
           "affected_items":items or [],"affected_count":len(items) if items else 0,
           "remediation":remediation or remed,"references":references or refs or [],"cis_benchmark":cis or "",
           "details":details or {},"timestamp":datetime.datetime.now().isoformat()}
        self.findings.append(f); return f
    def run_all_checks(self)->List[Dict]: raise NotImplementedError
    def gb(self,k,d): return self.baseline.get(k,d)
    def _unwrap(self, key):
        """Get data for key, unwrapping OCI CLI {'data': [...]} envelope."""
        d=self.data.get(key)
        if d is None: return []
        if isinstance(d,dict): return d.get("data",d) if "data" in d else d
        return d if isinstance(d,list) else []

FILE_MAP={
    # IAM & Policies
    "iam_users":              ["iam_users.json","users.json"],
    "iam_groups":             ["iam_groups.json","groups.json"],
    "iam_policies":           ["iam_policies.json","policies.json"],
    "iam_api_keys":           ["iam_api_keys.json","api_keys.json"],
    "iam_auth_tokens":        ["iam_auth_tokens.json","auth_tokens.json"],
    "compartments":           ["compartments.json"],
    "identity_providers":     ["identity_providers.json","federation.json"],
    "tenancy_config":         ["tenancy_config.json","tenancy.json"],
    "password_policy":        ["password_policy.json","authentication_policy.json"],
    # Networking
    "vcns":                   ["vcns.json","virtual_cloud_networks.json"],
    "security_lists":         ["security_lists.json"],
    "network_security_groups":["network_security_groups.json","nsgs.json"],
    "nsg_rules":              ["nsg_rules.json","nsg_security_rules.json"],
    "subnets":                ["subnets.json"],
    "internet_gateways":      ["internet_gateways.json","igws.json"],
    "drg_attachments":        ["drg_attachments.json"],
    "route_tables":           ["route_tables.json"],
    "service_gateways":       ["service_gateways.json"],
    # Compute
    "instances":              ["instances.json","compute_instances.json"],
    "boot_volumes":           ["boot_volumes.json"],
    "images":                 ["images.json","custom_images.json"],
    "vnic_attachments":       ["vnic_attachments.json"],
    # Object Storage
    "buckets":                ["buckets.json","object_storage_buckets.json"],
    "preauthenticated_requests":["preauthenticated_requests.json","pars.json"],
    # Database
    "autonomous_databases":   ["autonomous_databases.json","adb.json"],
    "db_systems":             ["db_systems.json","database_systems.json"],
    "mysql_db_systems":       ["mysql_db_systems.json"],
    # Logging & Audit
    "audit_config":           ["audit_config.json","audit_configuration.json"],
    "log_groups":             ["log_groups.json"],
    "service_connectors":     ["service_connectors.json"],
    "events_rules":           ["events_rules.json","event_rules.json"],
    "alarms":                 ["alarms.json","monitoring_alarms.json"],
    # Cloud Guard
    "cloud_guard_config":     ["cloud_guard_config.json"],
    "cloud_guard_targets":    ["cloud_guard_targets.json"],
    "cloud_guard_detectors":  ["cloud_guard_detectors.json"],
    "cloud_guard_problems":   ["cloud_guard_problems.json"],
    "security_zones":         ["security_zones.json"],
    # OKE / Kubernetes
    "oke_clusters":           ["oke_clusters.json","kubernetes_clusters.json"],
    "oke_node_pools":         ["oke_node_pools.json","node_pools.json"],
    # Vault & KMS
    "vaults":                 ["vaults.json"],
    "vault_keys":             ["vault_keys.json","kms_keys.json"],
    # WAF & Load Balancer
    "waf_policies":           ["waf_policies.json"],
    "load_balancers":         ["load_balancers.json"],
    # Bastion
    "bastions":               ["bastions.json"],
    "bastion_sessions":       ["bastion_sessions.json"],
    # IaC
    "terraform_state":        ["terraform.tfstate","terraform_state.json"],
    "terraform_plan":         ["terraform_plan.json","tfplan.json"],
    # CIS v3.1.0 additions
    "customer_secret_keys":   ["customer_secret_keys.json","secret_keys.json"],
    "tag_defaults":           ["tag_defaults.json"],
    "notification_topics":    ["notification_topics.json","topics.json"],
    "block_volumes":          ["block_volumes.json","volumes.json"],
    "file_systems":           ["file_systems.json","file_storage.json"],
}

class DataLoader:
    def __init__(self, data_dir):
        self.data_dir=Path(data_dir); self._data={}
    def load_all(self):
        for key,fnames in FILE_MAP.items():
            for fn in fnames:
                fp=self.data_dir/fn
                if fp.exists():
                    print(f"    Loading {fn}...")
                    try:
                        with open(fp,"r",encoding="utf-8-sig") as f: self._data[key]=json.load(f)
                    except Exception as e: print(f"    [WARN] {e}"); self._data[key]=None
                    break
            else: self._data[key]=None
        loaded=sum(1 for v in self._data.values() if v is not None)
        print(f"    Loaded: {loaded}/{len(FILE_MAP)} config files")
        return self._data
