"""CWPP/IaC Auditors: OKE, Vault & KMS, WAF, Bastion, Terraform IaC, CIS Benchmark."""
import json, re
from datetime import datetime, timezone
from typing import List, Dict
from .base import BaseAuditor


class OkeSecurityAuditor(BaseAuditor):
    """OCI OKE / Kubernetes security checks (8 checks, OCI-OKE-001 to OCI-OKE-008)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_public_api_endpoint()
        self.check_network_policies()
        self.check_pod_security()
        self.check_rbac_iam_integration()
        self.check_node_secure_boot()
        self.check_workload_identity()
        self.check_image_validation()
        self.check_node_auto_upgrade()
        return self.findings

    def _clusters(self):
        return [c for c in self._unwrap("oke_clusters")
                if c.get("lifecycle-state", c.get("lifecycleState", "")) == "ACTIVE"]

    def check_public_api_endpoint(self):
        clusters = self._clusters()
        if not clusters: return
        public = []
        for c in clusters:
            name = c.get("name", c.get("display-name", c.get("displayName", "")))
            ep_cfg = c.get("endpoint-config", c.get("endpointConfig", {})) or {}
            is_public = ep_cfg.get("is-public-ip-enabled", ep_cfg.get("isPublicIpEnabled", True))
            if is_public:
                public.append(name)
        if public:
            self.finding("OCI-OKE-001", "Public API endpoint", self.SEVERITY_HIGH,
                "OKE / Kubernetes",
                f"{len(public)} OKE cluster(s) have public Kubernetes API endpoints, exposing the control plane to the internet.",
                items=public[:20],
                remed="Configure private API endpoints for OKE clusters. Use Bastion or VPN for kubectl access.")

    def check_network_policies(self):
        clusters = self._clusters()
        if not clusters: return
        no_np = []
        for c in clusters:
            name = c.get("name", c.get("display-name", c.get("displayName", "")))
            options = c.get("options", c.get("clusterPodNetworkOptions", {})) or {}
            # Check for Calico/network policy support
            net_config = c.get("cluster-pod-network-options", options)
            cni = ""
            if isinstance(net_config, list):
                for opt in net_config:
                    cni = opt.get("cni-type", opt.get("cniType", ""))
            elif isinstance(net_config, dict):
                cni = net_config.get("cni-type", net_config.get("cniType", ""))
            # OCI_VCN_IP_NATIVE supports network policies, FLANNEL_OVERLAY requires Calico addon
            network_policy_capable = "VCN_IP_NATIVE" in cni.upper() if cni else False
            if not network_policy_capable:
                no_np.append(f"{name} (CNI: {cni or 'unknown'})")
        if no_np:
            self.finding("OCI-OKE-002", "Network policies not enforced", self.SEVERITY_HIGH,
                "OKE / Kubernetes",
                f"{len(no_np)} OKE cluster(s) may not support Kubernetes Network Policies for pod-to-pod segmentation.",
                items=no_np[:20],
                remed="Use VCN-Native Pod Networking CNI for native network policy support, or install Calico for flannel-based clusters.")

    def check_pod_security(self):
        clusters = self._clusters()
        if not clusters: return
        no_pss = []
        for c in clusters:
            name = c.get("name", c.get("display-name", c.get("displayName", "")))
            options = c.get("options", {}) or {}
            admission = options.get("admission-controller-options",
                                   options.get("admissionControllerOptions", {})) or {}
            pss_enabled = admission.get("is-pod-security-policy-enabled",
                                       admission.get("isPodSecurityPolicyEnabled", False))
            if not pss_enabled:
                no_pss.append(name)
        if no_pss:
            self.finding("OCI-OKE-003", "Pod security standards not applied", self.SEVERITY_MEDIUM,
                "OKE / Kubernetes",
                f"{len(no_pss)} OKE cluster(s) do not have Pod Security admission controls configured.",
                items=no_pss[:20],
                remed="Enable Pod Security Standards (PSS) via PodSecurity admission controller. Apply 'restricted' or 'baseline' profiles.")

    def check_rbac_iam_integration(self):
        clusters = self._clusters()
        if not clusters: return
        no_iam = []
        for c in clusters:
            name = c.get("name", c.get("display-name", c.get("displayName", "")))
            ctype = c.get("type", "").upper()
            # ENHANCED_CLUSTER supports workload identity/IAM; BASIC_CLUSTER does not
            if ctype == "BASIC_CLUSTER":
                no_iam.append(f"{name} (type: BASIC_CLUSTER, no OCI IAM RBAC)")
        if no_iam:
            self.finding("OCI-OKE-004", "RBAC not integrated with OCI IAM", self.SEVERITY_HIGH,
                "OKE / Kubernetes",
                f"{len(no_iam)} OKE cluster(s) do not have RBAC integrated with OCI IAM for centralized access control.",
                items=no_iam[:20],
                remed="Configure Kubernetes RBAC to map to OCI IAM groups and policies for centralized access management.")

    def check_node_secure_boot(self):
        pools = self._unwrap("oke_node_pools")
        if not pools: return
        no_sb = []
        for p in pools:
            state = p.get("lifecycle-state", p.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            name = p.get("name", p.get("display-name", p.get("displayName", "")))
            node_cfg = p.get("node-config-details", p.get("nodeConfigDetails", {})) or {}
            pc = node_cfg.get("node-pool-pod-network-option-details",
                             node_cfg.get("platform-config", {})) or {}
            # Check for shielded instance on worker nodes
            sb = pc.get("is-secure-boot-enabled", pc.get("isSecureBootEnabled", False))
            if not sb:
                no_sb.append(name)
        if no_sb:
            self.finding("OCI-OKE-005", "Node pool without secure boot", self.SEVERITY_MEDIUM,
                "OKE / Kubernetes",
                f"{len(no_sb)} OKE node pool(s) do not have Shielded Instance (Secure Boot) enabled on worker nodes.",
                items=no_sb[:20],
                remed="Enable Shielded Instances with Secure Boot for OKE node pools to prevent unauthorized boot modifications.")

    def check_workload_identity(self):
        clusters = self._clusters()
        if not clusters: return
        no_wi = []
        for c in clusters:
            name = c.get("name", c.get("display-name", c.get("displayName", "")))
            options = c.get("options", {}) or {}
            wi = options.get("is-workload-identity-enabled",
                           c.get("is-workload-identity-enabled",
                           c.get("isWorkloadIdentityEnabled", False)))
            if not wi:
                no_wi.append(name)
        if no_wi:
            self.finding("OCI-OKE-006", "Workload identity not configured", self.SEVERITY_HIGH,
                "OKE / Kubernetes",
                f"{len(no_wi)} OKE cluster(s) do not have Workload Identity enabled for pod-level IAM integration.",
                items=no_wi[:20],
                remed="Enable OKE Workload Identity to allow pods to authenticate to OCI services using Kubernetes service accounts.")

    def check_image_validation(self):
        clusters = self._clusters()
        if not clusters: return
        no_iv = []
        for c in clusters:
            name = c.get("name", c.get("display-name", c.get("displayName", "")))
            options = c.get("options", {}) or {}
            img_policy = options.get("image-policy-config",
                                   c.get("imagePolicyConfig", {})) or {}
            enabled = img_policy.get("is-policy-enabled",
                                   img_policy.get("isPolicyEnabled", False))
            if not enabled:
                no_iv.append(name)
        if no_iv:
            self.finding("OCI-OKE-007", "Image validation not enabled", self.SEVERITY_MEDIUM,
                "OKE / Kubernetes",
                f"{len(no_iv)} OKE cluster(s) do not enforce container image signature validation.",
                items=no_iv[:20],
                remed="Enable image verification policies to ensure only signed and trusted container images are deployed.")

    def check_node_auto_upgrade(self):
        pools = self._unwrap("oke_node_pools")
        if not pools: return
        no_upgrade = []
        for p in pools:
            state = p.get("lifecycle-state", p.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            name = p.get("name", p.get("display-name", p.get("displayName", "")))
            auto = p.get("node-config-details", p.get("nodeConfigDetails", {})) or {}
            is_auto = auto.get("is-pv-encryption-in-transit-enabled",
                              p.get("is-auto-upgrade-enabled",
                              p.get("isAutoUpgradeEnabled", False)))
            k8s_ver = p.get("kubernetes-version", p.get("kubernetesVersion", ""))
            cluster_ver = ""
            clusters = self._unwrap("oke_clusters")
            for c in clusters:
                cid = c.get("id", "")
                if cid == p.get("cluster-id", p.get("clusterId", "")):
                    cluster_ver = c.get("kubernetes-version", c.get("kubernetesVersion", ""))
                    break
            if k8s_ver and cluster_ver and k8s_ver != cluster_ver:
                no_upgrade.append(f"{name}: node {k8s_ver} vs cluster {cluster_ver}")
            elif not p.get("is-auto-upgrade-enabled", p.get("isAutoUpgradeEnabled", False)):
                no_upgrade.append(f"{name}: auto-upgrade disabled")
        if no_upgrade:
            self.finding("OCI-OKE-008", "Node auto-upgrade disabled", self.SEVERITY_MEDIUM,
                "OKE / Kubernetes",
                f"{len(no_upgrade)} OKE node pool(s) have auto-upgrade disabled or are running mismatched Kubernetes versions.",
                items=no_upgrade[:20],
                remed="Enable node pool auto-upgrade to keep worker nodes aligned with the cluster Kubernetes version.")


class VaultKmsAuditor(BaseAuditor):
    """OCI Vault & KMS security checks (5 checks, OCI-KMS-001 to OCI-KMS-005)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_key_rotation()
        self.check_cmek_usage()
        self.check_vault_replication()
        self.check_key_access_policies()
        self.check_hsm_protection()
        return self.findings

    def check_key_rotation(self):
        keys = self._unwrap("vault_keys")
        if not keys: return
        no_rotation = []
        now = datetime.now(timezone.utc)
        for k in keys:
            state = k.get("lifecycle-state", k.get("lifecycleState", ""))
            if state not in ("ENABLED", "ACTIVE"): continue
            name = k.get("display-name", k.get("displayName", ""))
            # Check current key version creation time
            current_ver = k.get("current-key-version", k.get("currentKeyVersion", ""))
            created = k.get("time-created", k.get("timeCreated", ""))
            try:
                ct = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age = (now - ct).days
                if age > 365:
                    no_rotation.append(f"{name}: key created {age} days ago, no rotation detected")
            except (ValueError, TypeError):
                no_rotation.append(f"{name}: unable to determine key age")
        if no_rotation:
            self.finding("OCI-KMS-001", "Vault keys without rotation", self.SEVERITY_HIGH,
                "Vault & KMS",
                f"{len(no_rotation)} encryption key(s) have not been rotated. Keys should be rotated periodically.",
                items=no_rotation[:20],
                remed="Enable automatic key rotation or manually rotate keys. Navigate to Vault > Key > Rotate Key.",
                refs=["CIS OCI 1.10"], cis="1.10")

    def check_cmek_usage(self):
        keys = self._unwrap("vault_keys")
        buckets = self._unwrap("buckets")
        bvs = self._unwrap("boot_volumes")
        adbs = self._unwrap("autonomous_databases")
        if not keys:
            resources = []
            if buckets: resources.append(f"{len(buckets)} bucket(s)")
            if bvs: resources.append(f"{len(bvs)} boot volume(s)")
            if adbs: resources.append(f"{len(adbs)} database(s)")
            if resources:
                self.finding("OCI-KMS-002", "Customer-managed keys not used", self.SEVERITY_MEDIUM,
                    "Vault & KMS",
                    "No Vault keys found. Resources are using Oracle-managed encryption only.",
                    items=resources,
                    remed="Create a Vault and master encryption keys. Assign customer-managed keys to sensitive resources.")
        else:
            # Keys exist but check if resources are actually using them
            no_cmek = []
            for b in buckets:
                if not b.get("kms-key-id", b.get("kmsKeyId", "")):
                    no_cmek.append(f"Bucket: {b.get('name', b.get('display-name', ''))}")
            for bv in bvs:
                if not bv.get("kms-key-id", bv.get("kmsKeyId", "")):
                    no_cmek.append(f"Boot Volume: {bv.get('display-name', bv.get('displayName', ''))}")
            for db in adbs:
                if not db.get("kms-key-id", db.get("kmsKeyId", "")):
                    no_cmek.append(f"ADB: {db.get('display-name', db.get('displayName', ''))}")
            if no_cmek:
                self.finding("OCI-KMS-002", "Customer-managed keys not used", self.SEVERITY_MEDIUM,
                    "Vault & KMS",
                    f"{len(no_cmek)} resource(s) use Oracle-managed encryption despite Vault keys being available.",
                    items=no_cmek[:20],
                    remed="Assign customer-managed encryption keys from OCI Vault to all sensitive resources.")

    def check_vault_replication(self):
        vaults = self._unwrap("vaults")
        if not vaults: return
        no_rep = []
        for v in vaults:
            state = v.get("lifecycle-state", v.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            name = v.get("display-name", v.get("displayName", ""))
            replicas = v.get("replica-details", v.get("replicaDetails"))
            if not replicas:
                no_rep.append(name)
        if no_rep:
            self.finding("OCI-KMS-003", "Vault not replicated", self.SEVERITY_LOW,
                "Vault & KMS",
                f"{len(no_rep)} vault(s) are not replicated across regions for disaster recovery.",
                items=no_rep[:20],
                remed="Enable cross-region vault replication for critical encryption keys to ensure DR capability.")

    def check_key_access_policies(self):
        policies = self._unwrap("iam_policies")
        if not policies: return
        broad_kms = []
        for p in policies:
            name = p.get("name", p.get("display-name", ""))
            stmts = p.get("statements", [])
            for s in stmts:
                sl = s.lower() if isinstance(s, str) else ""
                if ("manage" in sl or "use" in sl) and ("keys" in sl or "vaults" in sl or "key-delegate" in sl):
                    if "in tenancy" in sl and "where" not in sl:
                        broad_kms.append(f"{name}: {s[:120]}")
        if broad_kms:
            self.finding("OCI-KMS-004", "Overly broad key access policies", self.SEVERITY_HIGH,
                "Vault & KMS",
                f"{len(broad_kms)} policy statement(s) grant broad access to Vault/KMS resources.",
                items=broad_kms[:20],
                remed="Scope KMS policies to specific compartments and key OCIDs. Separate key management from key usage permissions.")

    def check_hsm_protection(self):
        keys = self._unwrap("vault_keys")
        if not keys: return
        software_keys = []
        for k in keys:
            state = k.get("lifecycle-state", k.get("lifecycleState", ""))
            if state not in ("ENABLED", "ACTIVE"): continue
            protection = k.get("protection-mode", k.get("protectionMode", "SOFTWARE"))
            if protection.upper() == "SOFTWARE":
                name = k.get("display-name", k.get("displayName", ""))
                software_keys.append(f"{name} (protection: SOFTWARE)")
        if software_keys:
            self.finding("OCI-KMS-005", "HSM protection level not used", self.SEVERITY_MEDIUM,
                "Vault & KMS",
                f"{len(software_keys)} key(s) use software protection instead of HSM. HSM provides FIPS 140-2 Level 3 hardware protection.",
                items=software_keys[:20],
                remed="Create keys with HSM protection mode for enhanced security. Use Dedicated KMS for single-tenant HSM requirements.")


class WafEdgeAuditor(BaseAuditor):
    """OCI WAF & Edge security checks (4 checks, OCI-WAF-001 to OCI-WAF-004)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_lb_without_waf()
        self.check_waf_rules_enabled()
        self.check_rate_limiting()
        self.check_custom_rules()
        return self.findings

    def check_lb_without_waf(self):
        lbs = self._unwrap("load_balancers")
        wafs = self._unwrap("waf_policies")
        if not lbs: return
        # Build set of LBs protected by WAF
        waf_protected = set()
        for w in wafs:
            targets = w.get("backend-type", "")
            lb_id = w.get("load-balancer-id", w.get("loadBalancerId", ""))
            if lb_id: waf_protected.add(lb_id)
            # Also check web-app-firewalls with LB references
            actions = w.get("actions", [])
            for a in actions:
                ref = a.get("load-balancer-id", "")
                if ref: waf_protected.add(ref)
        unprotected = []
        for lb in lbs:
            state = lb.get("lifecycle-state", lb.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            lb_id = lb.get("id", "")
            name = lb.get("display-name", lb.get("displayName", ""))
            if lb_id not in waf_protected:
                unprotected.append(name)
        if unprotected:
            self.finding("OCI-WAF-001", "Load balancers without WAF policy", self.SEVERITY_HIGH,
                "WAF & Edge Security",
                f"{len(unprotected)} load balancer(s) are not protected by a Web Application Firewall policy.",
                items=unprotected[:20],
                remed="Create WAF policies and attach them to load balancers to protect web applications from OWASP Top 10 attacks.")

    def check_waf_rules_enabled(self):
        wafs = self._unwrap("waf_policies")
        if not wafs: return
        disabled_rules = []
        for w in wafs:
            name = w.get("display-name", w.get("displayName", ""))
            # Handle both flat protection-rules and nested request-protection.rules
            rules = w.get("protection-rules", w.get("protectionRules", []))
            if not rules:
                rp = w.get("request-protection", w.get("requestProtection", {})) or {}
                rules = rp.get("rules", [])
            total = len(rules) if isinstance(rules, list) else 0
            active = 0
            if isinstance(rules, list):
                for r in rules:
                    action = r.get("action", "").upper()
                    is_enabled = r.get("is-enabled", r.get("isEnabled", True))
                    if action in ("BLOCK", "DETECT") or is_enabled:
                        active += 1
            if total > 0 and active < total / 2:
                disabled_rules.append(f"{name}: {active}/{total} rules active")
        if disabled_rules:
            self.finding("OCI-WAF-002", "WAF protection rules not enabled", self.SEVERITY_MEDIUM,
                "WAF & Edge Security",
                "WAF policies have a majority of protection rules disabled.",
                items=disabled_rules[:20],
                remed="Enable protection rules in WAF policies, especially for SQL injection, XSS, and command injection categories.")

    def check_rate_limiting(self):
        wafs = self._unwrap("waf_policies")
        if not wafs: return
        no_rl = []
        for w in wafs:
            name = w.get("display-name", w.get("displayName", ""))
            rl_rules = w.get("rate-limiting", w.get("requestRateLimiting", {}))
            rules = rl_rules.get("rules", []) if isinstance(rl_rules, dict) else []
            if not rules:
                no_rl.append(name)
        if no_rl:
            self.finding("OCI-WAF-003", "No rate limiting configured", self.SEVERITY_MEDIUM,
                "WAF & Edge Security",
                f"{len(no_rl)} WAF policy(ies) do not have rate limiting rules configured.",
                items=no_rl[:20],
                remed="Configure rate limiting rules to protect against brute-force attacks and DDoS at the application layer.")

    def check_custom_rules(self):
        wafs = self._unwrap("waf_policies")
        if not wafs: return
        no_custom = []
        for w in wafs:
            name = w.get("display-name", w.get("displayName", ""))
            custom = w.get("custom-protection-rules", w.get("customProtectionRules", []))
            if not custom:
                no_custom.append(name)
        if no_custom and len(no_custom) == len(wafs):
            self.finding("OCI-WAF-004", "No custom WAF rules", self.SEVERITY_LOW,
                "WAF & Edge Security",
                "No custom WAF protection rules are defined. Custom rules provide application-specific threat detection.",
                items=no_custom[:10],
                remed="Create custom protection rules tailored to your application's specific attack surface and threat model.")


class BastionAuditor(BaseAuditor):
    """OCI Bastion security checks (4 checks, OCI-BAST-001 to OCI-BAST-004)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_bastion_service_used()
        self.check_session_limits()
        self.check_bastion_audit_logging()
        self.check_direct_ssh_public()
        return self.findings

    def check_bastion_service_used(self):
        bastions = self._unwrap("bastions")
        instances = self._unwrap("instances")
        if not instances: return
        # Check if any instances exist but no bastion service
        running = [i for i in instances
                   if i.get("lifecycle-state", i.get("lifecycleState", "")) == "RUNNING"]
        if running and not bastions:
            self.finding("OCI-BAST-001", "Bastion service not used", self.SEVERITY_HIGH,
                "Bastion Security",
                f"{len(running)} compute instance(s) running but no OCI Bastion service configured for secure access.",
                items=[i.get("display-name", i.get("displayName", "")) for i in running[:10]],
                remed="Create an OCI Bastion to provide time-limited, audited SSH/RDP access to private instances without public IPs.")

    def check_session_limits(self):
        bastions = self._unwrap("bastions")
        if not bastions: return
        long_ttl = []
        for b in bastions:
            state = b.get("lifecycle-state", b.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            name = b.get("name", b.get("display-name", b.get("displayName", "")))
            max_ttl = b.get("max-session-ttl-in-seconds",
                           b.get("maxSessionTtlInSeconds", 10800))
            threshold = self.gb("bastion_max_ttl", 10800)  # 3 hours default
            if max_ttl > threshold:
                hours = max_ttl / 3600
                long_ttl.append(f"{name}: max TTL {hours:.1f}h (threshold: {threshold/3600:.1f}h)")
        if long_ttl:
            self.finding("OCI-BAST-002", "Session limits too permissive", self.SEVERITY_MEDIUM,
                "Bastion Security",
                "Bastion session TTL exceeds the recommended maximum duration.",
                items=long_ttl[:20],
                remed="Reduce bastion max session TTL to 3 hours or less. Enforce just-in-time access with short sessions.")

    def check_bastion_audit_logging(self):
        bastions = self._unwrap("bastions")
        sessions = self._unwrap("bastion_sessions")
        if not bastions: return
        # Check if bastion sessions are being tracked
        if bastions and not sessions:
            names = [b.get("name", b.get("display-name", b.get("displayName", "")))
                    for b in bastions
                    if b.get("lifecycle-state", b.get("lifecycleState", "")) == "ACTIVE"]
            if names:
                self.finding("OCI-BAST-003", "Bastion sessions not audit-logged", self.SEVERITY_MEDIUM,
                    "Bastion Security",
                    "No bastion session data available for audit. Ensure bastion activity is logged.",
                    items=names[:20],
                    remed="Verify that OCI Audit service captures bastion session events. Export audit logs to SIEM for monitoring.")

    def check_direct_ssh_public(self):
        instances = self._unwrap("instances")
        sls = self._unwrap("security_lists")
        bastions = self._unwrap("bastions")
        if not instances or not sls: return
        # Check for instances with public IPs and SSH open
        ssh_open = False
        for sl in sls:
            ingress = sl.get("ingress-security-rules", sl.get("ingressSecurityRules", []))
            for rule in ingress:
                src = rule.get("source", "")
                proto = str(rule.get("protocol", ""))
                if src == "0.0.0.0/0" and proto == "6":
                    tcp = rule.get("tcp-options", rule.get("tcpOptions", {}))
                    dport = tcp.get("destination-port-range", tcp.get("destinationPortRange", {}))
                    if dport.get("min", 0) <= 22 <= dport.get("max", 0):
                        ssh_open = True
                        break
            if ssh_open: break
        if not ssh_open: return
        public_instances = []
        for i in instances:
            state = i.get("lifecycle-state", i.get("lifecycleState", ""))
            if state != "RUNNING": continue
            if i.get("public-ip", i.get("publicIp")):
                public_instances.append(i.get("display-name", i.get("displayName", "")))
        has_bastion = any(b.get("lifecycle-state", b.get("lifecycleState", "")) == "ACTIVE"
                        for b in bastions) if bastions else False
        if public_instances and not has_bastion:
            self.finding("OCI-BAST-004", "Direct SSH via public IP detected", self.SEVERITY_CRITICAL,
                "Bastion Security",
                f"{len(public_instances)} instance(s) are accessible via SSH over public IPs with no Bastion service in use.",
                items=public_instances[:20],
                remed="Deploy OCI Bastion service. Remove public IPs from instances and restrict SSH in security lists to Bastion subnet.")


class IacSecurityAuditor(BaseAuditor):
    """OCI Terraform / IaC security checks (3 checks, OCI-IAC-001 to OCI-IAC-003)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_terraform_state_misconfig()
        self.check_terraform_plan_deletions()
        self.check_terraform_state_local()
        return self.findings

    def check_terraform_state_misconfig(self):
        state = self.data.get("terraform_state")
        if not state: return
        if not isinstance(state, dict): return
        issues = []
        resources = state.get("resources", [])
        for r in resources:
            rtype = r.get("type", "")
            for inst in r.get("instances", []):
                attrs = inst.get("attributes", {})
                # Check for public access patterns
                if attrs.get("public-access-type", attrs.get("publicAccessType", "")) != "NoPublicAccess":
                    if "bucket" in rtype.lower():
                        issues.append(f"{rtype}: public bucket detected")
                # Check for overly permissive security rules
                src = attrs.get("source", "")
                if src == "0.0.0.0/0":
                    issues.append(f"{rtype}: rule with source 0.0.0.0/0")
                # Check for missing encryption
                if "kms_key_id" in attrs and not attrs.get("kms_key_id"):
                    issues.append(f"{rtype}: no KMS key assigned")
        if issues:
            self.finding("OCI-IAC-001", "Terraform state misconfigurations", self.SEVERITY_HIGH,
                "Terraform / IaC",
                f"{len(issues)} potential misconfiguration(s) found in Terraform state.",
                items=issues[:20],
                remed="Review Terraform state for security issues. Update Terraform configurations and apply corrected plans.")

    def check_terraform_plan_deletions(self):
        plan = self.data.get("terraform_plan")
        if not plan or not isinstance(plan, dict): return
        changes = plan.get("resource_changes", [])
        deletions = []
        for c in changes:
            change = c.get("change", {})
            actions = change.get("actions", [])
            if "delete" in actions:
                addr = c.get("address", c.get("type", "unknown"))
                deletions.append(addr)
        if deletions:
            self.finding("OCI-IAC-002", "Terraform plan resource deletions", self.SEVERITY_MEDIUM,
                "Terraform / IaC",
                f"Terraform plan includes {len(deletions)} resource deletion(s). Review before applying.",
                items=deletions[:20],
                remed="Review planned deletions carefully. Ensure no critical resources are being destroyed unintentionally.")

    def check_terraform_state_local(self):
        state = self.data.get("terraform_state")
        if not state: return
        if not isinstance(state, dict): return
        backend = state.get("backend", {})
        btype = backend.get("type", "local") if isinstance(backend, dict) else "local"
        if btype == "local":
            self.finding("OCI-IAC-003", "Terraform state stored locally", self.SEVERITY_MEDIUM,
                "Terraform / IaC",
                "Terraform state file is using local backend. State should be stored remotely for team collaboration and security.",
                items=["Backend type: local"],
                remed="Configure remote backend using OCI Object Storage or Terraform Cloud. Enable state locking and encryption.")


class CisBenchmarkAuditor(BaseAuditor):
    """CIS OCI Foundation Benchmark v2.0 summary assessment."""

    CIS_SECTIONS = {
        "1": "Identity and Access Management",
        "2": "Networking",
        "3": "Compute",
        "4": "Logging and Monitoring",
        "5": "Storage",
    }

    def run_all_checks(self) -> List[Dict]:
        self.check_cis_summary()
        return self.findings

    def check_cis_summary(self):
        # Count available data for each CIS section
        section_coverage = {}
        # Section 1: IAM
        iam_data = sum(1 for k in ["iam_users", "iam_groups", "iam_policies",
                                    "iam_api_keys", "iam_auth_tokens", "compartments",
                                    "identity_providers", "password_policy"]
                       if self.data.get(k) is not None)
        section_coverage["1"] = f"{iam_data}/8 config files loaded"
        # Section 2: Networking
        net_data = sum(1 for k in ["vcns", "security_lists", "network_security_groups",
                                    "subnets", "internet_gateways", "drg_attachments",
                                    "route_tables", "service_gateways"]
                       if self.data.get(k) is not None)
        section_coverage["2"] = f"{net_data}/8 config files loaded"
        # Section 3: Compute
        comp_data = sum(1 for k in ["instances", "boot_volumes", "images"]
                        if self.data.get(k) is not None)
        section_coverage["3"] = f"{comp_data}/3 config files loaded"
        # Section 4: Logging
        log_data = sum(1 for k in ["audit_config", "log_groups", "service_connectors",
                                    "events_rules", "alarms", "cloud_guard_config"]
                       if self.data.get(k) is not None)
        section_coverage["4"] = f"{log_data}/6 config files loaded"
        # Section 5: Storage
        stor_data = sum(1 for k in ["buckets", "preauthenticated_requests"]
                        if self.data.get(k) is not None)
        section_coverage["5"] = f"{stor_data}/2 config files loaded"

        items = []
        for sec, name in self.CIS_SECTIONS.items():
            items.append(f"Section {sec} ({name}): {section_coverage.get(sec, 'N/A')}")

        self.finding("OCI-CIS-001",
            "CIS OCI Foundation Benchmark v2.0 assessment summary", self.SEVERITY_LOW,
            "CIS Benchmark",
            "Summary of data coverage for CIS Oracle Cloud Infrastructure Foundations Benchmark v2.0 sections.",
            items=items,
            remed="Export all required OCI CLI configuration data for comprehensive CIS benchmark assessment.",
            refs=["CIS OCI Foundation Benchmark v2.0"],
            cis="All")
