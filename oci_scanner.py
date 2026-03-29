#!/usr/bin/env python3
"""
OCI CNAPP Security Scanner
=============================
Cloud-Native Application Protection Platform for Oracle Cloud Infrastructure.
CSPM . CIEM . CWPP . IaC . KSPM . CIS Benchmark

Usage:
    python oci_scanner.py --data-dir ./sample_data --output report.html
    python oci_scanner.py --data-dir ./exports --modules iam network compute oke
"""
import argparse,json,sys,datetime
from pathlib import Path
from modules.base import DataLoader
from modules.cspm_core import IamPolicyAuditor,NetworkVcnAuditor,ComputeAuditor,StorageAuditor
from modules.cspm_ciem import DatabaseAuditor,LoggingAuditAuditor,CloudGuardAuditor
from modules.cwpp_iac import (OkeSecurityAuditor,VaultKmsAuditor,WafEdgeAuditor,
    BastionAuditor,IacSecurityAuditor,CisBenchmarkAuditor)

try: from modules.report_generator import ReportGenerator
except ImportError: ReportGenerator=None

__version__="1.0.0"

def banner():
    print(r"""
  +=========================================================================+
  |   OCI CNAPP Security Scanner v1.0                                       |
  |   Cloud-Native Application Protection Platform                          |
  |                                                                         |
  |   CSPM . CIEM . CWPP . KSPM . IaC . CIS Benchmark                     |
  |   IAM . VCN . Compute . Storage . DB . OKE . Vault . WAF . Bastion    |
  +=========================================================================+
    """)

MODULE_MAP={
    "iam":       ("CSPM: IAM & Policies",IamPolicyAuditor),
    "network":   ("CSPM: Networking & VCN",NetworkVcnAuditor),
    "compute":   ("CSPM: Compute",ComputeAuditor),
    "storage":   ("CSPM: Object Storage",StorageAuditor),
    "database":  ("CSPM: Database Security",DatabaseAuditor),
    "logging":   ("CSPM: Logging & Audit",LoggingAuditAuditor),
    "cloudguard":("CSPM: Cloud Guard",CloudGuardAuditor),
    "oke":       ("CWPP/KSPM: OKE Kubernetes",OkeSecurityAuditor),
    "vault":     ("Encryption: Vault & KMS",VaultKmsAuditor),
    "waf":       ("CWPP: WAF & Edge Security",WafEdgeAuditor),
    "bastion":   ("CWPP: Bastion Security",BastionAuditor),
    "iac":       ("IaC: Terraform Security",IacSecurityAuditor),
    "cis":       ("Compliance: CIS OCI Benchmark",CisBenchmarkAuditor),
}

def main():
    banner()
    parser=argparse.ArgumentParser(description="OCI CNAPP Security Scanner")
    parser.add_argument("--data-dir",required=True,help="Path to directory with OCI CLI JSON exports")
    parser.add_argument("--output",default="oci_security_report.html",help="Output report filename")
    parser.add_argument("--severity",choices=["CRITICAL","HIGH","MEDIUM","LOW","ALL"],default="ALL",
                        help="Minimum severity filter")
    parser.add_argument("--modules",nargs="+",choices=list(MODULE_MAP.keys())+["all"],default=["all"],
                        help="Modules to run (default: all)")
    parser.add_argument("--config",default=None,help="Baseline config JSON file")
    parser.add_argument("--version",action="version",version=f"OCI CNAPP Security Scanner v{__version__}")
    args=parser.parse_args()
    data_dir=Path(args.data_dir)
    if not data_dir.exists(): print(f"[ERROR] Not found: {data_dir}"); sys.exit(1)
    print("[*] Loading OCI configuration data...")
    data=DataLoader(data_dir).load_all()
    baseline={}
    if args.config:
        with open(args.config) as f: baseline=json.load(f)
    run=list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings=[]
    for mod in run:
        if mod not in MODULE_MAP: continue
        label,cls=MODULE_MAP[mod]
        print(f"[*] Running {label}...")
        findings=cls(data,baseline).run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")
    sev={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    if args.severity!="ALL":
        t=sev.get(args.severity,3)
        all_findings=[f for f in all_findings if sev.get(f["severity"],3)<=t]
    meta={"scan_time":datetime.datetime.now().isoformat(),"data_directory":str(data_dir),
          "modules_run":run,"severity_filter":args.severity,
          "platform":"Oracle Cloud Infrastructure","version":__version__}
    print(f"\n[*] Generating report: {args.output}")
    if ReportGenerator: ReportGenerator(all_findings,meta).generate(args.output)
    else:
        with open(args.output.replace(".html",".json"),"w") as f:
            json.dump({"findings":all_findings,"meta":meta},f,indent=2)
    c=sum(1 for f in all_findings if f["severity"]=="CRITICAL")
    h=sum(1 for f in all_findings if f["severity"]=="HIGH")
    m=sum(1 for f in all_findings if f["severity"]=="MEDIUM")
    l=sum(1 for f in all_findings if f["severity"]=="LOW")
    print(f"\n{'='*71}")
    print(f"  SCAN COMPLETE -- {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {c}  |  HIGH: {h}  |  MEDIUM: {m}  |  LOW: {l}")
    print(f"  Report: {args.output}")
    print(f"{'='*71}\n")

if __name__=="__main__": main()
