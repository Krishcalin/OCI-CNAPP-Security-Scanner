"""CSPM Core Auditors: IAM & Policies, Networking & VCN, Compute, Object Storage."""
import re
from datetime import datetime, timezone
from typing import List, Dict
from .base import BaseAuditor


class IamPolicyAuditor(BaseAuditor):
    """OCI IAM & Policy security checks (20 checks, OCI-IAM-001 to OCI-IAM-020)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_root_compartment_resources()
        self.check_mfa_enforcement()
        self.check_broad_policy_statements()
        self.check_api_key_age()
        self.check_auth_token_rotation()
        self.check_users_not_in_groups()
        self.check_federation_configured()
        self.check_admin_group_size()
        self.check_tenancy_wide_policies()
        self.check_password_policy()
        self.check_admin_group_protection()
        self.check_password_expiry()
        self.check_password_reuse()
        self.check_secret_key_rotation()
        self.check_admin_api_keys()
        self.check_user_email()
        self.check_instance_principal()
        self.check_storage_admin_delete()
        self.check_credentials_unused()
        self.check_multiple_api_keys()
        return self.findings

    def check_root_compartment_resources(self):
        comps = self._unwrap("compartments")
        if not comps: return
        root_resources = []
        for c in comps:
            cid = c.get("compartment-id", c.get("compartmentId", ""))
            name = c.get("name", c.get("display-name", ""))
            # Root compartment resources have compartment-id equal to tenancy OCID
            if c.get("lifecycle-state", c.get("lifecycleState", "")) == "ACTIVE":
                # If this is a sub-compartment of root with resources flagged
                if c.get("is-root", False) or "root" in name.lower():
                    continue
                if c.get("defined-tags", c.get("definedTags", {})).get("has-resources", False):
                    root_resources.append(f"{name} ({cid[:40]}...)")
        # Also check tenancy config for root compartment resource indicators
        tenancy = self.data.get("tenancy_config")
        if tenancy:
            t = tenancy.get("data", tenancy) if isinstance(tenancy, dict) else tenancy
            if isinstance(t, dict):
                root_res = t.get("root-compartment-resources", [])
                if isinstance(root_res, list):
                    root_resources.extend(root_res)
        if root_resources:
            self.finding("OCI-IAM-001", "Resources in root compartment", self.SEVERITY_CRITICAL,
                "IAM & Policies",
                "Production resources should not reside in the root compartment. Use sub-compartments for resource isolation and policy scoping.",
                items=root_resources[:20],
                remed="Move resources to dedicated sub-compartments. Create a compartment hierarchy matching your organizational structure.",
                refs=["CIS OCI 1.1"], cis="1.1")

    def check_mfa_enforcement(self):
        users = self._unwrap("iam_users")
        if not users: return
        no_mfa = []
        for u in users:
            state = u.get("lifecycle-state", u.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            mfa = u.get("is-mfa-activated", u.get("isMfaActivated", False))
            if not mfa:
                no_mfa.append(u.get("name", u.get("description", "unknown")))
        if no_mfa:
            self.finding("OCI-IAM-002", "MFA not enforced for IAM users", self.SEVERITY_CRITICAL,
                "IAM & Policies",
                f"{len(no_mfa)} active IAM user(s) do not have MFA enabled. Multi-factor authentication is essential for protecting against credential compromise.",
                items=no_mfa[:20],
                remed="Enable MFA for all IAM users. Navigate to Identity > Users > User Details > Enable MFA.",
                refs=["CIS OCI 1.7"], cis="1.7")

    def check_broad_policy_statements(self):
        policies = self._unwrap("iam_policies")
        if not policies: return
        broad = []
        for p in policies:
            name = p.get("name", p.get("display-name", ""))
            stmts = p.get("statements", [])
            for s in stmts:
                sl = s.lower() if isinstance(s, str) else ""
                if "manage all-resources" in sl and "where" not in sl:
                    broad.append(f"{name}: {s[:120]}")
        if broad:
            self.finding("OCI-IAM-003", "Overly broad policy statements", self.SEVERITY_HIGH,
                "IAM & Policies",
                "Policy statements granting 'manage all-resources' without conditions violate least-privilege principle.",
                items=broad[:20],
                remed="Scope policies to specific resource types and compartments. Use conditions (where clauses) to limit scope.",
                refs=["CIS OCI 1.2"], cis="1.2")

    def check_api_key_age(self):
        keys = self._unwrap("iam_api_keys")
        if not keys: return
        old_keys = []
        now = datetime.now(timezone.utc)
        for k in keys:
            state = k.get("lifecycle-state", k.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            created = k.get("time-created", k.get("timeCreated", ""))
            if not created: continue
            try:
                ct = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age = (now - ct).days
                if age > 90:
                    uid = k.get("user-id", k.get("userId", ""))[:30]
                    fp = k.get("fingerprint", k.get("key-id", ""))[:20]
                    old_keys.append(f"user={uid}... key={fp}... ({age} days)")
            except (ValueError, TypeError):
                pass
        if old_keys:
            self.finding("OCI-IAM-004", "API keys older than 90 days", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(old_keys)} API signing key(s) exceed the 90-day rotation threshold.",
                items=old_keys[:20],
                remed="Rotate API keys every 90 days. Generate a new key pair and deactivate the old key.",
                refs=["CIS OCI 1.8"], cis="1.8")

    def check_auth_token_rotation(self):
        tokens = self._unwrap("iam_auth_tokens")
        if not tokens: return
        old = []
        now = datetime.now(timezone.utc)
        for t in tokens:
            state = t.get("lifecycle-state", t.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            created = t.get("time-created", t.get("timeCreated", ""))
            if not created: continue
            try:
                ct = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age = (now - ct).days
                if age > 90:
                    desc = t.get("description", t.get("token-id", ""))[:40]
                    old.append(f"{desc} ({age} days)")
            except (ValueError, TypeError):
                pass
        if old:
            self.finding("OCI-IAM-005", "Auth tokens not rotated", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(old)} auth token(s) are older than 90 days.",
                items=old[:20],
                remed="Regenerate auth tokens every 90 days. Delete unused tokens immediately.",
                refs=["CIS OCI 1.9"], cis="1.9")

    def check_users_not_in_groups(self):
        users = self._unwrap("iam_users")
        groups = self._unwrap("iam_groups")
        if not users: return
        # Build set of user IDs that belong to at least one group
        grouped_users = set()
        for g in groups:
            members = g.get("members", g.get("user-ids", []))
            if isinstance(members, list):
                for m in members:
                    if isinstance(m, dict):
                        grouped_users.add(m.get("user-id", m.get("userId", "")))
                    else:
                        grouped_users.add(str(m))
        ungrouped = []
        for u in users:
            if u.get("lifecycle-state", u.get("lifecycleState", "")) != "ACTIVE": continue
            uid = u.get("id", u.get("user-id", ""))
            if uid and uid not in grouped_users:
                ungrouped.append(u.get("name", u.get("description", uid[:30])))
        if ungrouped:
            self.finding("OCI-IAM-006", "Users not in groups", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"{len(ungrouped)} IAM user(s) are not assigned to any group. Group-based access control simplifies policy management.",
                items=ungrouped[:20],
                remed="Assign all users to appropriate groups. Apply policies to groups, not individual users.",
                refs=["CIS OCI 1.3"], cis="1.3")

    def check_federation_configured(self):
        providers = self._unwrap("identity_providers")
        if not providers:
            self.finding("OCI-IAM-007", "No federation configured", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                "No identity provider federation is configured. Federation with enterprise IdP (SAML/OIDC) centralizes identity management.",
                remed="Configure federation with your enterprise identity provider (Azure AD, Okta, etc.) via Identity > Federation.",
                refs=["CIS OCI 1.12"], cis="1.12")

    def check_admin_group_size(self):
        groups = self._unwrap("iam_groups")
        if not groups: return
        for g in groups:
            name = g.get("name", g.get("display-name", "")).lower()
            if "admin" not in name: continue
            members = g.get("members", g.get("user-ids", []))
            count = len(members) if isinstance(members, list) else 0
            threshold = self.gb("admin_group_max", 5)
            if count > threshold:
                member_names = []
                for m in members[:20]:
                    if isinstance(m, dict):
                        member_names.append(m.get("name", m.get("user-id", "")[:30]))
                    else:
                        member_names.append(str(m)[:30])
                self.finding("OCI-IAM-008", "Admin group has excessive members", self.SEVERITY_HIGH,
                    "IAM & Policies",
                    f"The '{g.get('name', 'Administrators')}' group has {count} members (threshold: {threshold}). Limit admin access to reduce blast radius.",
                    items=member_names,
                    remed="Review admin group membership. Remove unnecessary members and use just-in-time access.",
                    refs=["CIS OCI 1.4"], cis="1.4")

    def check_tenancy_wide_policies(self):
        policies = self._unwrap("iam_policies")
        if not policies: return
        tenancy_wide = []
        for p in policies:
            name = p.get("name", p.get("display-name", ""))
            stmts = p.get("statements", [])
            for s in stmts:
                sl = s.lower() if isinstance(s, str) else ""
                if "in tenancy" in sl and ("manage" in sl or "use" in sl):
                    if "all-resources" in sl or "all resources" in sl:
                        tenancy_wide.append(f"{name}: {s[:120]}")
        if tenancy_wide:
            self.finding("OCI-IAM-009", "Policy allows all-resources in tenancy", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(tenancy_wide)} policy statement(s) grant tenancy-wide resource access. This violates compartment isolation.",
                items=tenancy_wide[:20],
                remed="Scope policies to specific compartments instead of tenancy. Use 'in compartment <name>' instead of 'in tenancy'.",
                refs=["CIS OCI 1.1"], cis="1.1")

    def check_password_policy(self):
        pp = self.data.get("password_policy")
        if not pp:
            self.finding("OCI-IAM-010", "No password policy configured", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                "No authentication/password policy configuration found. Password complexity and expiration should be enforced.",
                remed="Configure password policy under Identity > Authentication Settings. Require minimum length 14, complexity, and 365-day expiration.",
                refs=["CIS OCI 1.5"], cis="1.5")
            return
        d = pp.get("data", pp) if isinstance(pp, dict) else pp
        if isinstance(d, dict):
            issues = []
            pwd = d.get("password-policy", d.get("passwordPolicy", d))
            if isinstance(pwd, dict):
                minlen = pwd.get("minimum-password-length", pwd.get("minimumPasswordLength", 0))
                if minlen < 14:
                    issues.append(f"Minimum length {minlen} (recommended: 14)")
                if not pwd.get("is-uppercase-characters-required", pwd.get("isUppercaseCharactersRequired", True)):
                    issues.append("Uppercase characters not required")
                if not pwd.get("is-special-characters-required", pwd.get("isSpecialCharactersRequired", True)):
                    issues.append("Special characters not required")
            if issues:
                self.finding("OCI-IAM-010", "No password policy configured", self.SEVERITY_MEDIUM,
                    "IAM & Policies",
                    "Password policy does not meet security requirements.",
                    items=issues,
                    remed="Update password policy: minimum 14 characters, require uppercase, lowercase, numeric, and special characters.",
                    refs=["CIS OCI 1.5"], cis="1.5")

    # ── CIS OCI v3.1.0 IAM additions (OCI-IAM-011 to OCI-IAM-020) ──

    def check_admin_group_protection(self):
        """OCI-IAM-011 (CIS 1.3): IAM admins cannot update Administrators group."""
        policies = self._unwrap("iam_policies")
        if not policies: return
        unsafe = []
        for p in policies:
            name = p.get("name", p.get("display-name", ""))
            stmts = p.get("statements", [])
            for s in stmts:
                sl = s.lower() if isinstance(s, str) else ""
                if ("use users in tenancy" in sl or "use groups in tenancy" in sl):
                    if "where target.group.name != 'administrators'" not in sl.replace('"', "'"):
                        unsafe.append(f"{name}: {s[:120]}")
        if unsafe:
            self.finding("OCI-IAM-011", "IAM admins can update Administrators group", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(unsafe)} policy statement(s) allow user/group management without excluding the Administrators group.",
                items=unsafe[:20],
                remed="Add condition \"where target.group.name != 'Administrators'\" to policies granting 'use users' or 'use groups' in tenancy.",
                refs=["CIS OCI 1.3"], cis="1.3")

    def check_password_expiry(self):
        """OCI-IAM-012 (CIS 1.5): Password policy expires within 365 days."""
        pp = self.data.get("password_policy")
        if not pp: return
        d = pp.get("data", pp) if isinstance(pp, dict) else pp
        if not isinstance(d, dict): return
        pwd = d.get("password-policy", d.get("passwordPolicy", d))
        if not isinstance(pwd, dict): return
        expires = pwd.get("expires-after-days", pwd.get("expiresAfterDays",
                 pwd.get("password-expiration-days", pwd.get("passwordExpirationDays", None))))
        if expires is None:
            self.finding("OCI-IAM-012", "Password expiration not configured", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                "Password expiration is not configured. Passwords should expire within 365 days.",
                items=["No expiration policy set"],
                remed="Configure password expiration to 365 days or less under Identity > Authentication Settings.",
                refs=["CIS OCI 1.5"], cis="1.5")
        elif expires > 365:
            self.finding("OCI-IAM-012", "Password expiration exceeds 365 days", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"Password expiration is set to {expires} days, which exceeds the 365-day CIS recommendation.",
                items=[f"Current expiration: {expires} days (recommended: <= 365)"],
                remed="Reduce password expiration to 365 days or less under Identity > Authentication Settings.",
                refs=["CIS OCI 1.5"], cis="1.5")

    def check_password_reuse(self):
        """OCI-IAM-013 (CIS 1.6): Password policy prevents reuse (>= 24)."""
        pp = self.data.get("password_policy")
        if not pp: return
        d = pp.get("data", pp) if isinstance(pp, dict) else pp
        if not isinstance(d, dict): return
        pwd = d.get("password-policy", d.get("passwordPolicy", d))
        if not isinstance(pwd, dict): return
        remembered = pwd.get("previous-passwords-remembered", pwd.get("previousPasswordsRemembered",
                    pwd.get("num-previous-passwords-blocked", pwd.get("numPreviousPasswordsBlocked", 0))))
        if remembered < 24:
            self.finding("OCI-IAM-013", "Password reuse prevention insufficient", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"Password policy remembers {remembered} previous passwords. CIS requires at least 24 to prevent reuse.",
                items=[f"Current: {remembered} passwords remembered (recommended: >= 24)"],
                remed="Set 'previous passwords remembered' to at least 24 under Identity > Authentication Settings.",
                refs=["CIS OCI 1.6"], cis="1.6")

    def check_secret_key_rotation(self):
        """OCI-IAM-014 (CIS 1.9): Customer secret keys rotate every 90 days."""
        keys = self._unwrap("customer_secret_keys")
        if not keys: return
        old_keys = []
        now = datetime.now(timezone.utc)
        for k in keys:
            state = k.get("lifecycle-state", k.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            created = k.get("time-created", k.get("timeCreated", ""))
            if not created: continue
            try:
                ct = datetime.fromisoformat(created.replace("Z", "+00:00"))
                age = (now - ct).days
                if age > 90:
                    uid = k.get("user-id", k.get("userId", ""))[:30]
                    desc = k.get("display-name", k.get("displayName", k.get("id", "")))[:30]
                    old_keys.append(f"user={uid}... key={desc} ({age} days)")
            except (ValueError, TypeError):
                pass
        if old_keys:
            self.finding("OCI-IAM-014", "Customer secret keys older than 90 days", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(old_keys)} customer secret key(s) exceed the 90-day rotation threshold.",
                items=old_keys[:20],
                remed="Rotate customer secret keys every 90 days. Generate a new key and deactivate the old one.",
                refs=["CIS OCI 1.9"], cis="1.9")

    def check_admin_api_keys(self):
        """OCI-IAM-015 (CIS 1.12): API keys not created for tenancy admin users."""
        keys = self._unwrap("iam_api_keys")
        groups = self._unwrap("iam_groups")
        if not keys or not groups: return
        # Build set of user IDs in admin groups
        admin_user_ids = set()
        for g in groups:
            gname = g.get("name", g.get("display-name", "")).lower()
            if "admin" not in gname: continue
            members = g.get("members", g.get("user-ids", []))
            if isinstance(members, list):
                for m in members:
                    if isinstance(m, dict):
                        admin_user_ids.add(m.get("user-id", m.get("userId", "")))
                    else:
                        admin_user_ids.add(str(m))
        admin_with_keys = []
        seen = set()
        for k in keys:
            state = k.get("lifecycle-state", k.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            uid = k.get("user-id", k.get("userId", ""))
            if uid in admin_user_ids and uid not in seen:
                seen.add(uid)
                fp = k.get("fingerprint", k.get("key-id", ""))[:20]
                admin_with_keys.append(f"admin user={uid[:30]}... key={fp}...")
        if admin_with_keys:
            self.finding("OCI-IAM-015", "API keys on tenancy admin users", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(admin_with_keys)} tenancy admin user(s) have API keys. Admin users should use console or federation, not API keys.",
                items=admin_with_keys[:20],
                remed="Remove API keys from admin users. Use federation/SSO for admin access and Instance Principals for automation.",
                refs=["CIS OCI 1.12"], cis="1.12")

    def check_user_email(self):
        """OCI-IAM-016 (CIS 1.13): All IAM users have valid email."""
        users = self._unwrap("iam_users")
        if not users: return
        no_email = []
        for u in users:
            state = u.get("lifecycle-state", u.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            email = u.get("email", u.get("emailAddress", ""))
            if not email or not email.strip():
                name = u.get("name", u.get("description", u.get("id", "")[:30]))
                no_email.append(name)
        if no_email:
            self.finding("OCI-IAM-016", "IAM users without valid email", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"{len(no_email)} active IAM user(s) do not have a valid email address configured.",
                items=no_email[:20],
                remed="Set a valid email address for all IAM users for password recovery and security notifications.",
                refs=["CIS OCI 1.13"], cis="1.13")

    def check_instance_principal(self):
        """OCI-IAM-017 (CIS 1.14): Instance Principal authentication used."""
        policies = self._unwrap("iam_policies")
        instances = self._unwrap("instances")
        has_instance_principal = False
        for p in policies:
            stmts = p.get("statements", [])
            for s in stmts:
                sl = s.lower() if isinstance(s, str) else ""
                if "request.principal" in sl or "dynamic-group" in sl:
                    has_instance_principal = True
                    break
            if has_instance_principal: break
        running = [i for i in instances
                   if i.get("lifecycle-state", i.get("lifecycleState", "")) == "RUNNING"]
        if not has_instance_principal and running:
            self.finding("OCI-IAM-017", "Instance Principal not used", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"{len(running)} running instance(s) found but no Instance Principal (dynamic group) policies detected. "
                "Instances may be using stored credentials instead of Instance Principal for OCI API access.",
                items=[i.get("display-name", i.get("displayName", "")) for i in running[:20]],
                remed="Create dynamic groups and policies for Instance Principal authentication. Remove stored API keys from instances.",
                refs=["CIS OCI 1.14"], cis="1.14")

    def check_storage_admin_delete(self):
        """OCI-IAM-018 (CIS 1.15): Storage admins cannot delete resources."""
        policies = self._unwrap("iam_policies")
        if not policies: return
        unsafe = []
        for p in policies:
            name = p.get("name", p.get("display-name", ""))
            stmts = p.get("statements", [])
            for s in stmts:
                sl = s.lower() if isinstance(s, str) else ""
                if ("manage object-family" in sl or "manage buckets" in sl or
                        "manage objects" in sl or "manage volumes" in sl or
                        "manage file-family" in sl):
                    if "request.permission!=" not in sl.replace(" ", "") or "*_delete" not in sl.lower():
                        unsafe.append(f"{name}: {s[:120]}")
        if unsafe:
            self.finding("OCI-IAM-018", "Storage admins can delete resources", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"{len(unsafe)} policy statement(s) grant storage management without restricting delete permissions.",
                items=unsafe[:20],
                remed="Add condition \"where request.permission != '*_DELETE'\" to storage admin policies to prevent accidental or malicious deletion.",
                refs=["CIS OCI 1.15"], cis="1.15")

    def check_credentials_unused(self):
        """OCI-IAM-019 (CIS 1.16): Credentials unused 45+ days disabled."""
        users = self._unwrap("iam_users")
        if not users: return
        stale = []
        now = datetime.now(timezone.utc)
        for u in users:
            state = u.get("lifecycle-state", u.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            name = u.get("name", u.get("description", u.get("id", "")[:30]))
            # Check last successful login
            last_login = u.get("last-successful-login-time", u.get("lastSuccessfulLoginTime", ""))
            created = u.get("time-created", u.get("timeCreated", ""))
            reference_date = last_login or created
            if not reference_date: continue
            try:
                ref_dt = datetime.fromisoformat(reference_date.replace("Z", "+00:00"))
                idle_days = (now - ref_dt).days
                if idle_days > 45:
                    stale.append(f"{name}: idle {idle_days} days (last activity: {reference_date[:10]})")
            except (ValueError, TypeError):
                pass
        if stale:
            self.finding("OCI-IAM-019", "Credentials unused for 45+ days", self.SEVERITY_HIGH,
                "IAM & Policies",
                f"{len(stale)} active IAM user(s) have not logged in for over 45 days. Stale credentials increase attack surface.",
                items=stale[:20],
                remed="Disable or remove IAM users who have not logged in for 45+ days. Implement an automated credential lifecycle policy.",
                refs=["CIS OCI 1.16"], cis="1.16")

    def check_multiple_api_keys(self):
        """OCI-IAM-020 (CIS 1.17): Only one active API key per user."""
        keys = self._unwrap("iam_api_keys")
        if not keys: return
        from collections import defaultdict
        user_keys = defaultdict(list)
        for k in keys:
            state = k.get("lifecycle-state", k.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            uid = k.get("user-id", k.get("userId", ""))
            fp = k.get("fingerprint", k.get("key-id", ""))[:20]
            if uid:
                user_keys[uid].append(fp)
        multi = []
        for uid, fps in user_keys.items():
            if len(fps) > 1:
                multi.append(f"user={uid[:30]}...: {len(fps)} active keys")
        if multi:
            self.finding("OCI-IAM-020", "Multiple active API keys per user", self.SEVERITY_MEDIUM,
                "IAM & Policies",
                f"{len(multi)} user(s) have more than one active API key. Each user should have only one active key to simplify rotation.",
                items=multi[:20],
                remed="Remove redundant API keys. Maintain only one active API key per user and rotate regularly.",
                refs=["CIS OCI 1.17"], cis="1.17")


class NetworkVcnAuditor(BaseAuditor):
    """OCI Networking & VCN security checks (12 checks, OCI-NET-001 to OCI-NET-012)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_default_security_list_egress()
        self.check_ssh_open()
        self.check_rdp_open()
        self.check_nsg_permissive()
        self.check_flow_logs()
        self.check_internet_gateway()
        self.check_drg_configured()
        self.check_route_tables()
        self.check_service_gateway()
        self.check_icmp_unrestricted()
        self.check_nsg_ssh_open()
        self.check_nsg_rdp_open()
        return self.findings

    def _get_security_rules(self):
        """Extract all security list ingress/egress rules."""
        sls = self._unwrap("security_lists")
        return sls

    def check_default_security_list_egress(self):
        sls = self._get_security_rules()
        if not sls: return
        permissive = []
        for sl in sls:
            name = sl.get("display-name", sl.get("displayName", ""))
            egress = sl.get("egress-security-rules", sl.get("egressSecurityRules", []))
            for rule in egress:
                dest = rule.get("destination", "")
                proto = str(rule.get("protocol", ""))
                if dest == "0.0.0.0/0" and proto == "all":
                    permissive.append(f"{name}: egress all to 0.0.0.0/0")
                    break
        if permissive:
            self.finding("OCI-NET-001", "Default security list allows all egress", self.SEVERITY_HIGH,
                "Networking & VCN",
                "Security list(s) permit unrestricted outbound traffic to all destinations.",
                items=permissive[:20],
                remed="Restrict egress rules to only required destinations and ports. Remove 'all protocols to 0.0.0.0/0' rules.",
                refs=["CIS OCI 2.1"], cis="2.1")

    def check_ssh_open(self):
        sls = self._get_security_rules()
        if not sls: return
        exposed = []
        for sl in sls:
            name = sl.get("display-name", sl.get("displayName", ""))
            ingress = sl.get("ingress-security-rules", sl.get("ingressSecurityRules", []))
            for rule in ingress:
                src = rule.get("source", "")
                proto = str(rule.get("protocol", ""))
                if src in ("0.0.0.0/0", "::/0") and proto == "6":
                    tcp = rule.get("tcp-options", rule.get("tcpOptions", {}))
                    dport = tcp.get("destination-port-range", tcp.get("destinationPortRange", {}))
                    mn = dport.get("min", 0)
                    mx = dport.get("max", 0)
                    if mn <= 22 <= mx:
                        exposed.append(f"{name}: SSH (port 22) from {src}")
        if exposed:
            self.finding("OCI-NET-002", "SSH open to 0.0.0.0/0", self.SEVERITY_CRITICAL,
                "Networking & VCN",
                "Security list(s) allow SSH access from any source IP. This exposes instances to brute-force and unauthorized access.",
                items=exposed[:20],
                remed="Restrict SSH to specific CIDR blocks or use OCI Bastion service for secure access.",
                refs=["CIS OCI 2.2"], cis="2.2")

    def check_rdp_open(self):
        sls = self._get_security_rules()
        if not sls: return
        exposed = []
        for sl in sls:
            name = sl.get("display-name", sl.get("displayName", ""))
            ingress = sl.get("ingress-security-rules", sl.get("ingressSecurityRules", []))
            for rule in ingress:
                src = rule.get("source", "")
                proto = str(rule.get("protocol", ""))
                if src in ("0.0.0.0/0", "::/0") and proto == "6":
                    tcp = rule.get("tcp-options", rule.get("tcpOptions", {}))
                    dport = tcp.get("destination-port-range", tcp.get("destinationPortRange", {}))
                    mn = dport.get("min", 0)
                    mx = dport.get("max", 0)
                    if mn <= 3389 <= mx:
                        exposed.append(f"{name}: RDP (port 3389) from {src}")
        if exposed:
            self.finding("OCI-NET-003", "RDP open to 0.0.0.0/0", self.SEVERITY_CRITICAL,
                "Networking & VCN",
                "Security list(s) allow RDP access from any source IP.",
                items=exposed[:20],
                remed="Restrict RDP to specific CIDR blocks or disable RDP access entirely. Use Bastion service for remote access.",
                refs=["CIS OCI 2.3"], cis="2.3")

    def check_nsg_permissive(self):
        nsgs = self._unwrap("network_security_groups")
        nsg_rules = self._unwrap("nsg_rules")
        if not nsgs and not nsg_rules: return
        permissive = []
        # Check NSG rules data
        rules_to_check = nsg_rules if nsg_rules else []
        # Also check inline rules in NSGs
        for nsg in nsgs:
            name = nsg.get("display-name", nsg.get("displayName", ""))
            inline_rules = nsg.get("rules", nsg.get("security-rules", []))
            for rule in inline_rules:
                direction = rule.get("direction", "").upper()
                src = rule.get("source", "")
                proto = str(rule.get("protocol", ""))
                if direction == "INGRESS" and src == "0.0.0.0/0" and proto == "all":
                    permissive.append(f"NSG '{name}': allows all ingress from 0.0.0.0/0")
        for rule in rules_to_check:
            direction = rule.get("direction", "").upper()
            src = rule.get("source", "")
            proto = str(rule.get("protocol", ""))
            nsg_id = rule.get("network-security-group-id", "")[:30]
            if direction == "INGRESS" and src == "0.0.0.0/0" and proto == "all":
                permissive.append(f"NSG {nsg_id}...: allows all ingress from 0.0.0.0/0")
        if permissive:
            self.finding("OCI-NET-004", "NSG rules overly permissive", self.SEVERITY_HIGH,
                "Networking & VCN",
                "Network Security Group(s) contain rules allowing all traffic from any source.",
                items=permissive[:20],
                remed="Restrict NSG rules to specific ports and source CIDRs required by the application.",
                refs=["CIS OCI 2.4"], cis="2.4")

    def check_flow_logs(self):
        subnets = self._unwrap("subnets")
        log_groups = self._unwrap("log_groups")
        if not subnets: return
        no_logs = []
        # Build set of subnet OCIDs that have flow logs enabled
        logged_subnets = set()
        for lg in log_groups:
            logs = lg.get("logs", [])
            for log in logs:
                cfg = log.get("configuration", {})
                src = cfg.get("source", {})
                if src.get("source-type", "") == "OCISERVICE" and "flowlogs" in src.get("service", "").lower():
                    res = src.get("resource", "")
                    if res: logged_subnets.add(res)
        for s in subnets:
            name = s.get("display-name", s.get("displayName", ""))
            sid = s.get("id", "")
            state = s.get("lifecycle-state", s.get("lifecycleState", ""))
            if state != "AVAILABLE": continue
            # Check if subnet has flow logs via is-flow-log-enabled field or log_groups
            flow_enabled = s.get("is-flow-log-enabled", s.get("isFlowLogEnabled"))
            if flow_enabled is False or (flow_enabled is None and sid not in logged_subnets):
                no_logs.append(f"{name} ({sid[:30]}...)")
        if no_logs:
            self.finding("OCI-NET-005", "Subnets without VCN flow logs", self.SEVERITY_HIGH,
                "Networking & VCN",
                f"{len(no_logs)} subnet(s) do not have VCN flow logs enabled for network traffic visibility.",
                items=no_logs[:20],
                remed="Enable VCN flow logs on all subnets. Navigate to Networking > VCN > Subnet > Enable Flow Logs.",
                refs=["CIS OCI 2.5"], cis="2.5")

    def check_internet_gateway(self):
        igws = self._unwrap("internet_gateways")
        if not igws: return
        enabled = []
        for igw in igws:
            state = igw.get("lifecycle-state", igw.get("lifecycleState", ""))
            if state != "AVAILABLE": continue
            is_enabled = igw.get("is-enabled", igw.get("isEnabled", True))
            if is_enabled:
                name = igw.get("display-name", igw.get("displayName", ""))
                vcn = igw.get("vcn-id", igw.get("vcnId", ""))[:30]
                enabled.append(f"{name} (VCN: {vcn}...)")
        if enabled:
            self.finding("OCI-NET-006", "Internet gateway on sensitive VCN", self.SEVERITY_MEDIUM,
                "Networking & VCN",
                f"{len(enabled)} internet gateway(s) are enabled. Review whether public internet access is required for each VCN.",
                items=enabled[:20],
                remed="Remove or disable internet gateways on VCNs hosting sensitive workloads. Use NAT or service gateways instead.",
                refs=["CIS OCI 2.6"], cis="2.6")

    def check_drg_configured(self):
        drgs = self._unwrap("drg_attachments")
        vcns = self._unwrap("vcns")
        if not vcns: return
        if not drgs:
            vcn_names = [v.get("display-name", v.get("displayName", "")) for v in vcns[:10]]
            self.finding("OCI-NET-007", "DRG not configured", self.SEVERITY_LOW,
                "Networking & VCN",
                "No Dynamic Routing Gateway attachments found. DRG is required for VCN peering and on-premises connectivity.",
                items=vcn_names,
                remed="Create a DRG and attach it to VCNs that require cross-VCN or on-premises connectivity.",
                refs=[], cis="")

    def check_route_tables(self):
        rts = self._unwrap("route_tables")
        if not rts: return
        issues = []
        for rt in rts:
            name = rt.get("display-name", rt.get("displayName", ""))
            rules = rt.get("route-rules", rt.get("routeRules", []))
            if not rules:
                issues.append(f"{name}: empty route table (no rules)")
        if issues:
            self.finding("OCI-NET-008", "Route table misconfigurations", self.SEVERITY_MEDIUM,
                "Networking & VCN",
                "Route table(s) have configuration issues.",
                items=issues[:20],
                remed="Review route tables and ensure routes point to valid targets (IGW, NAT, DRG, service gateway).")

    def check_service_gateway(self):
        sgws = self._unwrap("service_gateways")
        vcns = self._unwrap("vcns")
        if not vcns: return
        if not sgws:
            self.finding("OCI-NET-009", "Service gateway not used", self.SEVERITY_MEDIUM,
                "Networking & VCN",
                "No service gateways found. Service gateways enable private access to Oracle services without traversing the internet.",
                remed="Create service gateways in VCNs that access Oracle services (Object Storage, Autonomous DB). Route traffic via service gateway.",
                refs=["CIS OCI 2.7"], cis="2.7")

    def check_icmp_unrestricted(self):
        sls = self._get_security_rules()
        if not sls: return
        exposed = []
        for sl in sls:
            name = sl.get("display-name", sl.get("displayName", ""))
            ingress = sl.get("ingress-security-rules", sl.get("ingressSecurityRules", []))
            for rule in ingress:
                src = rule.get("source", "")
                proto = str(rule.get("protocol", ""))
                if src == "0.0.0.0/0" and proto == "1":
                    exposed.append(f"{name}: ICMP from 0.0.0.0/0")
        if exposed:
            self.finding("OCI-NET-010", "Unrestricted ICMP ingress", self.SEVERITY_MEDIUM,
                "Networking & VCN",
                "Security list(s) allow ICMP from any source. This can be used for network reconnaissance.",
                items=exposed[:20],
                remed="Restrict ICMP to specific source CIDRs and ICMP types (e.g., type 3 code 4 for path MTU discovery).")

    # ── CIS OCI v3.1.0 NSG additions (OCI-NET-011 to OCI-NET-012) ──

    def _collect_nsg_ingress_rules(self):
        """Collect all NSG ingress rules from both NSG objects and standalone rules."""
        nsgs = self._unwrap("network_security_groups")
        nsg_rules = self._unwrap("nsg_rules")
        rules = []
        # Build NSG name lookup
        nsg_names = {}
        for nsg in nsgs:
            nsg_id = nsg.get("id", "")
            nsg_names[nsg_id] = nsg.get("display-name", nsg.get("displayName", nsg_id[:30]))
            for rule in nsg.get("rules", nsg.get("security-rules", [])):
                direction = rule.get("direction", "").upper()
                if direction == "INGRESS":
                    rules.append((nsg_names[nsg_id], rule))
        for rule in nsg_rules:
            direction = rule.get("direction", "").upper()
            if direction == "INGRESS":
                nsg_id = rule.get("network-security-group-id", rule.get("networkSecurityGroupId", ""))
                name = nsg_names.get(nsg_id, nsg_id[:30])
                rules.append((name, rule))
        return rules

    def check_nsg_ssh_open(self):
        """OCI-NET-011 (CIS 2.3): NSG ingress from 0.0.0.0/0 to port 22."""
        ingress = self._collect_nsg_ingress_rules()
        if not ingress: return
        exposed = []
        for nsg_name, rule in ingress:
            src = rule.get("source", "")
            proto = str(rule.get("protocol", ""))
            if src not in ("0.0.0.0/0", "::/0"): continue
            if proto == "6":  # TCP
                tcp = rule.get("tcp-options", rule.get("tcpOptions", {})) or {}
                dport = tcp.get("destination-port-range", tcp.get("destinationPortRange", {})) or {}
                mn = dport.get("min", 0)
                mx = dport.get("max", 0)
                if mn <= 22 <= mx:
                    exposed.append(f"NSG '{nsg_name}': SSH (port 22) from {src}")
            elif proto == "all":
                exposed.append(f"NSG '{nsg_name}': all protocols (incl. SSH) from {src}")
        if exposed:
            self.finding("OCI-NET-011", "NSG allows SSH from 0.0.0.0/0", self.SEVERITY_CRITICAL,
                "Networking & VCN",
                f"{len(exposed)} NSG rule(s) allow SSH (TCP/22) ingress from any source IP.",
                items=exposed[:20],
                remed="Restrict NSG SSH rules to specific CIDR blocks. Use OCI Bastion service for secure remote access.",
                refs=["CIS OCI 2.3"], cis="2.3")

    def check_nsg_rdp_open(self):
        """OCI-NET-012 (CIS 2.4): NSG ingress from 0.0.0.0/0 to port 3389."""
        ingress = self._collect_nsg_ingress_rules()
        if not ingress: return
        exposed = []
        for nsg_name, rule in ingress:
            src = rule.get("source", "")
            proto = str(rule.get("protocol", ""))
            if src not in ("0.0.0.0/0", "::/0"): continue
            if proto == "6":  # TCP
                tcp = rule.get("tcp-options", rule.get("tcpOptions", {})) or {}
                dport = tcp.get("destination-port-range", tcp.get("destinationPortRange", {})) or {}
                mn = dport.get("min", 0)
                mx = dport.get("max", 0)
                if mn <= 3389 <= mx:
                    exposed.append(f"NSG '{nsg_name}': RDP (port 3389) from {src}")
            elif proto == "all":
                exposed.append(f"NSG '{nsg_name}': all protocols (incl. RDP) from {src}")
        if exposed:
            self.finding("OCI-NET-012", "NSG allows RDP from 0.0.0.0/0", self.SEVERITY_CRITICAL,
                "Networking & VCN",
                f"{len(exposed)} NSG rule(s) allow RDP (TCP/3389) ingress from any source IP.",
                items=exposed[:20],
                remed="Restrict NSG RDP rules to specific CIDR blocks or disable RDP entirely. Use Bastion service for remote access.",
                refs=["CIS OCI 2.4"], cis="2.4")


class ComputeAuditor(BaseAuditor):
    """OCI Compute security checks (8 checks, OCI-COMP-001 to OCI-COMP-008)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_secure_boot()
        self.check_measured_boot()
        self.check_transit_encryption()
        self.check_public_ips()
        self.check_legacy_images()
        self.check_boot_volume_cmek()
        self.check_imds_v1()
        self.check_monitoring_agent()
        return self.findings

    def _instances(self):
        return [i for i in self._unwrap("instances")
                if i.get("lifecycle-state", i.get("lifecycleState", "")) == "RUNNING"]

    def check_secure_boot(self):
        instances = self._instances()
        if not instances: return
        no_sb = []
        for i in instances:
            pc = i.get("platform-config", i.get("platformConfig", {})) or {}
            if not pc.get("is-secure-boot-enabled", pc.get("isSecureBootEnabled", False)):
                no_sb.append(i.get("display-name", i.get("displayName", "")))
        if no_sb:
            self.finding("OCI-COMP-001", "Shielded Instance Secure Boot disabled", self.SEVERITY_MEDIUM,
                "Compute",
                f"{len(no_sb)} instance(s) do not have Secure Boot enabled. Secure Boot prevents unauthorized boot loaders.",
                items=no_sb[:20],
                remed="Enable Shielded Instance features (Secure Boot) when launching new instances. Existing instances require recreation.",
                refs=["CIS OCI 3.1"], cis="3.1")

    def check_measured_boot(self):
        instances = self._instances()
        if not instances: return
        no_mb = []
        for i in instances:
            pc = i.get("platform-config", i.get("platformConfig", {})) or {}
            if not pc.get("is-measured-boot-enabled", pc.get("isMeasuredBootEnabled", False)):
                no_mb.append(i.get("display-name", i.get("displayName", "")))
        if no_mb:
            self.finding("OCI-COMP-002", "Measured Boot disabled", self.SEVERITY_MEDIUM,
                "Compute",
                f"{len(no_mb)} instance(s) do not have Measured Boot / vTPM enabled.",
                items=no_mb[:20],
                remed="Enable Measured Boot with vTPM when launching new instances for firmware integrity verification.",
                refs=["CIS OCI 3.2"], cis="3.2")

    def check_transit_encryption(self):
        instances = self._instances()
        if not instances: return
        no_enc = []
        for i in instances:
            lo = i.get("launch-options", i.get("launchOptions", {})) or {}
            if not lo.get("is-pv-encryption-in-transit-enabled", lo.get("isPvEncryptionInTransitEnabled", False)):
                no_enc.append(i.get("display-name", i.get("displayName", "")))
        if no_enc:
            self.finding("OCI-COMP-003", "In-transit encryption disabled", self.SEVERITY_HIGH,
                "Compute",
                f"{len(no_enc)} instance(s) do not have in-transit encryption enabled for boot/block volumes.",
                items=no_enc[:20],
                remed="Enable in-transit encryption when launching instances. Use paravirtualized attachments with encryption.",
                refs=["CIS OCI 3.3"], cis="3.3")

    def check_public_ips(self):
        instances = self._instances()
        vnics = self._unwrap("vnic_attachments")
        if not instances: return
        public = []
        # Check VNIC attachments for public IPs
        public_vnic_ids = set()
        for v in vnics:
            vnic = v.get("vnic", v)
            if vnic.get("public-ip", vnic.get("publicIp")):
                iid = v.get("instance-id", v.get("instanceId", ""))
                public_vnic_ids.add(iid)
        for i in instances:
            iid = i.get("id", "")
            name = i.get("display-name", i.get("displayName", ""))
            # Check direct public-ip field or VNIC attachments
            if i.get("public-ip", i.get("publicIp")) or iid in public_vnic_ids:
                public.append(name)
        if public:
            self.finding("OCI-COMP-004", "Instances with public IPs", self.SEVERITY_HIGH,
                "Compute",
                f"{len(public)} instance(s) have public IP addresses assigned, directly exposing them to the internet.",
                items=public[:20],
                remed="Remove public IPs from instances. Use load balancers, NAT gateways, or Bastion service for external access.",
                refs=["CIS OCI 3.4"], cis="3.4")

    def check_legacy_images(self):
        instances = self._instances()
        images = self._unwrap("images")
        if not instances: return
        # Build map of deprecated/legacy image IDs
        legacy_images = set()
        for img in images:
            state = img.get("lifecycle-state", img.get("lifecycleState", ""))
            os_name = img.get("operating-system", img.get("operatingSystem", "")).lower()
            os_ver = img.get("operating-system-version", img.get("operatingSystemVersion", ""))
            if state == "DEPRECATED" or state == "DISABLED":
                legacy_images.add(img.get("id", ""))
            # Flag known EOL versions
            if "oracle linux" in os_name and os_ver:
                try:
                    major = int(str(os_ver).split(".")[0])
                    if major < 7:
                        legacy_images.add(img.get("id", ""))
                except (ValueError, IndexError):
                    pass
        legacy = []
        for i in instances:
            src = i.get("source-details", i.get("sourceDetails", {})) or {}
            img_id = src.get("image-id", src.get("imageId", ""))
            if not img_id:
                img_id = i.get("image-id", i.get("imageId", ""))
            if img_id in legacy_images:
                legacy.append(f"{i.get('display-name', '')} (image: {img_id[:30]}...)")
        if legacy:
            self.finding("OCI-COMP-005", "Legacy images in use", self.SEVERITY_MEDIUM,
                "Compute",
                f"{len(legacy)} instance(s) are running deprecated or end-of-life OS images.",
                items=legacy[:20],
                remed="Migrate instances to supported OS images. Oracle Linux 8+ or 9+ is recommended.")

    def check_boot_volume_cmek(self):
        bvs = self._unwrap("boot_volumes")
        if not bvs: return
        no_cmek = []
        for bv in bvs:
            state = bv.get("lifecycle-state", bv.get("lifecycleState", ""))
            if state != "AVAILABLE": continue
            kms_id = bv.get("kms-key-id", bv.get("kmsKeyId", ""))
            if not kms_id:
                name = bv.get("display-name", bv.get("displayName", ""))
                no_cmek.append(name)
        if no_cmek:
            self.finding("OCI-COMP-006", "Boot volumes without customer-managed keys", self.SEVERITY_MEDIUM,
                "Compute",
                f"{len(no_cmek)} boot volume(s) use Oracle-managed encryption instead of customer-managed keys.",
                items=no_cmek[:20],
                remed="Use OCI Vault customer-managed keys (CMK) for boot volume encryption for enhanced key control.",
                refs=["CIS OCI 3.5"], cis="3.5")

    def check_imds_v1(self):
        instances = self._instances()
        if not instances: return
        v1 = []
        for i in instances:
            opts = i.get("instance-options", i.get("instanceOptions", {})) or {}
            # are-legacy-imds-endpoints-disabled = false means IMDSv1 is available
            legacy_disabled = opts.get("are-legacy-imds-endpoints-disabled",
                                       opts.get("areLegacyImdsEndpointsDisabled", True))
            if not legacy_disabled:
                v1.append(i.get("display-name", i.get("displayName", "")))
        if v1:
            self.finding("OCI-COMP-007", "Instance Metadata Service v1 in use", self.SEVERITY_HIGH,
                "Compute",
                f"{len(v1)} instance(s) have legacy IMDS v1 endpoints enabled. IMDSv1 is vulnerable to SSRF-based credential theft.",
                items=v1[:20],
                remed="Disable legacy IMDS endpoints. Set 'are-legacy-imds-endpoints-disabled' to true for all instances.",
                refs=["CIS OCI 3.6"], cis="3.6")

    def check_monitoring_agent(self):
        instances = self._instances()
        if not instances: return
        no_mon = []
        for i in instances:
            agent = i.get("agent-config", i.get("agentConfig", {})) or {}
            plugins = agent.get("plugins-config", agent.get("pluginsConfig", []))
            mon_enabled = False
            if isinstance(plugins, list):
                for p in plugins:
                    pname = p.get("name", "").lower()
                    if "monitoring" in pname or "management" in pname:
                        if p.get("desired-state", p.get("desiredState", "")) == "ENABLED":
                            mon_enabled = True
                            break
            if not mon_enabled:
                no_mon.append(i.get("display-name", i.get("displayName", "")))
        if no_mon:
            self.finding("OCI-COMP-008", "Monitoring agent not enabled", self.SEVERITY_LOW,
                "Compute",
                f"{len(no_mon)} instance(s) do not have the monitoring agent/plugin enabled.",
                items=no_mon[:20],
                remed="Enable the Compute Instance Monitoring plugin in the Oracle Cloud Agent configuration.")


class StorageAuditor(BaseAuditor):
    """OCI Object Storage security checks (8 checks, OCI-STOR-001 to OCI-STOR-008)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_public_buckets()
        self.check_versioning()
        self.check_lifecycle_policies()
        self.check_cmek()
        self.check_preauthenticated_requests()
        self.check_replication()
        self.check_block_volume_cmk()
        self.check_file_storage_cmk()
        return self.findings

    def _buckets(self):
        return self._unwrap("buckets")

    def check_public_buckets(self):
        buckets = self._buckets()
        if not buckets: return
        public = []
        for b in buckets:
            access = b.get("public-access-type", b.get("publicAccessType", "NoPublicAccess"))
            if access != "NoPublicAccess":
                name = b.get("name", b.get("display-name", ""))
                public.append(f"{name} (access: {access})")
        if public:
            self.finding("OCI-STOR-001", "Public buckets detected", self.SEVERITY_CRITICAL,
                "Object Storage",
                f"{len(public)} bucket(s) have public access enabled. Data may be exposed to the internet.",
                items=public[:20],
                remed="Set bucket access type to 'NoPublicAccess'. Use pre-authenticated requests or IAM policies for controlled access.",
                refs=["CIS OCI 5.1"], cis="5.1")

    def check_versioning(self):
        buckets = self._buckets()
        if not buckets: return
        no_ver = []
        for b in buckets:
            ver = b.get("versioning", b.get("objectVersioning", "Disabled"))
            if ver != "Enabled":
                no_ver.append(b.get("name", b.get("display-name", "")))
        if no_ver:
            self.finding("OCI-STOR-002", "Versioning not enabled", self.SEVERITY_MEDIUM,
                "Object Storage",
                f"{len(no_ver)} bucket(s) do not have object versioning enabled for data protection and recovery.",
                items=no_ver[:20],
                remed="Enable versioning on buckets containing important data. Navigate to Object Storage > Bucket > Edit > Enable Versioning.",
                refs=["CIS OCI 5.2"], cis="5.2")

    def check_lifecycle_policies(self):
        buckets = self._buckets()
        if not buckets: return
        no_lc = []
        for b in buckets:
            rules = b.get("lifecycle-rules", b.get("objectLifecyclePolicy", {}).get("items", []))
            if not rules:
                no_lc.append(b.get("name", b.get("display-name", "")))
        if no_lc:
            self.finding("OCI-STOR-003", "No lifecycle policies", self.SEVERITY_LOW,
                "Object Storage",
                f"{len(no_lc)} bucket(s) have no lifecycle policies for automatic archiving or deletion of old objects.",
                items=no_lc[:20],
                remed="Create lifecycle policies to transition old objects to Archive/Infrequent Access tiers or delete expired objects.")

    def check_cmek(self):
        buckets = self._buckets()
        if not buckets: return
        no_cmek = []
        for b in buckets:
            kms = b.get("kms-key-id", b.get("kmsKeyId", ""))
            if not kms:
                no_cmek.append(b.get("name", b.get("display-name", "")))
        if no_cmek:
            self.finding("OCI-STOR-004", "Buckets without customer-managed keys", self.SEVERITY_MEDIUM,
                "Object Storage",
                f"{len(no_cmek)} bucket(s) use Oracle-managed encryption. Customer-managed keys provide enhanced control.",
                items=no_cmek[:20],
                remed="Assign a Vault master encryption key to each bucket for customer-managed encryption.",
                refs=["CIS OCI 5.3"], cis="5.3")

    def check_preauthenticated_requests(self):
        pars = self._unwrap("preauthenticated_requests")
        if not pars: return
        now = datetime.now(timezone.utc)
        risky = []
        for p in pars:
            expiry = p.get("time-expires", p.get("timeExpires", ""))
            name = p.get("name", p.get("id", ""))[:40]
            access = p.get("access-type", p.get("accessType", ""))
            bucket = p.get("bucket-name", p.get("bucketName", ""))
            try:
                exp_dt = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
                ttl_days = (exp_dt - now).days
                if ttl_days > 30:
                    risky.append(f"{bucket}/{name}: {access}, expires in {ttl_days} days")
            except (ValueError, TypeError):
                risky.append(f"{bucket}/{name}: {access}, unknown expiry")
        if risky:
            self.finding("OCI-STOR-005", "Pre-authenticated requests review", self.SEVERITY_HIGH,
                "Object Storage",
                f"{len(risky)} pre-authenticated request(s) have long expiration times or broad access.",
                items=risky[:20],
                remed="Review and revoke unnecessary PARs. Set short expiration times and scope to specific objects.",
                refs=["CIS OCI 5.4"], cis="5.4")

    def check_replication(self):
        buckets = self._buckets()
        if not buckets: return
        no_rep = []
        for b in buckets:
            rep = b.get("replication-enabled", b.get("isReplicationEnabled", False))
            if not rep:
                no_rep.append(b.get("name", b.get("display-name", "")))
        if no_rep:
            self.finding("OCI-STOR-006", "Replication not configured", self.SEVERITY_LOW,
                "Object Storage",
                f"{len(no_rep)} bucket(s) do not have cross-region replication enabled for disaster recovery.",
                items=no_rep[:10],
                remed="Enable replication on buckets containing critical data for cross-region disaster recovery.")

    # ── CIS OCI v3.1.0 Storage additions (OCI-STOR-007 to OCI-STOR-008) ──

    def check_block_volume_cmk(self):
        """OCI-STOR-007 (CIS 5.2.1): Block volumes encrypted with CMK."""
        volumes = self._unwrap("block_volumes")
        if not volumes: return
        no_cmk = []
        for v in volumes:
            state = v.get("lifecycle-state", v.get("lifecycleState", ""))
            if state != "AVAILABLE": continue
            kms = v.get("kms-key-id", v.get("kmsKeyId", ""))
            if not kms:
                name = v.get("display-name", v.get("displayName", ""))
                no_cmk.append(name)
        if no_cmk:
            self.finding("OCI-STOR-007", "Block volumes without customer-managed keys", self.SEVERITY_MEDIUM,
                "Object Storage",
                f"{len(no_cmk)} block volume(s) use Oracle-managed encryption instead of customer-managed keys (CMK).",
                items=no_cmk[:20],
                remed="Assign a Vault master encryption key (CMK) to each block volume for customer-managed encryption.",
                refs=["CIS OCI 5.2.1"], cis="5.2.1")

    def check_file_storage_cmk(self):
        """OCI-STOR-008 (CIS 5.3.1): File storage encrypted with CMK."""
        filesystems = self._unwrap("file_systems")
        if not filesystems: return
        no_cmk = []
        for fs in filesystems:
            state = fs.get("lifecycle-state", fs.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            kms = fs.get("kms-key-id", fs.get("kmsKeyId", ""))
            if not kms:
                name = fs.get("display-name", fs.get("displayName", ""))
                no_cmk.append(name)
        if no_cmk:
            self.finding("OCI-STOR-008", "File storage without customer-managed keys", self.SEVERITY_MEDIUM,
                "Object Storage",
                f"{len(no_cmk)} file system(s) use Oracle-managed encryption instead of customer-managed keys (CMK).",
                items=no_cmk[:20],
                remed="Assign a Vault master encryption key (CMK) to each file system for customer-managed encryption.",
                refs=["CIS OCI 5.3.1"], cis="5.3.1")
