"""CSPM/CIEM Auditors: Database Security, Logging & Audit, Cloud Guard."""
from datetime import datetime, timezone
from typing import List, Dict
from .base import BaseAuditor


class DatabaseAuditor(BaseAuditor):
    """OCI Database security checks (6 checks, OCI-DB-001 to OCI-DB-006)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_adb_cmek()
        self.check_db_system_backups()
        self.check_mysql_private_endpoint()
        self.check_db_private_subnet()
        self.check_adb_iam_auth()
        self.check_db_patch_level()
        return self.findings

    def check_adb_cmek(self):
        adbs = self._unwrap("autonomous_databases")
        if not adbs: return
        no_cmek = []
        for db in adbs:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state not in ("AVAILABLE", "RUNNING"): continue
            kms = db.get("kms-key-id", db.get("kmsKeyId", ""))
            if not kms:
                name = db.get("display-name", db.get("displayName", ""))
                no_cmek.append(name)
        if no_cmek:
            self.finding("OCI-DB-001", "ADB without customer-managed encryption", self.SEVERITY_MEDIUM,
                "Database Security",
                f"{len(no_cmek)} Autonomous Database(s) use Oracle-managed encryption keys.",
                items=no_cmek[:20],
                remed="Configure Autonomous Database to use a customer-managed encryption key from OCI Vault.")

    def check_db_system_backups(self):
        dbs = self._unwrap("db_systems")
        if not dbs: return
        no_backup = []
        for db in dbs:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state not in ("AVAILABLE", "RUNNING", "PROVISIONING"): continue
            backup = db.get("db-backup-config", db.get("dbBackupConfig", {})) or {}
            auto_enabled = backup.get("auto-backup-enabled", backup.get("autoBackupEnabled", False))
            if not auto_enabled:
                name = db.get("display-name", db.get("displayName", ""))
                no_backup.append(name)
        if no_backup:
            self.finding("OCI-DB-002", "DB Systems without automated backups", self.SEVERITY_HIGH,
                "Database Security",
                f"{len(no_backup)} DB System(s) do not have automated backups enabled.",
                items=no_backup[:20],
                remed="Enable automated backups for all DB Systems. Set an appropriate retention period (minimum 30 days).")

    def check_mysql_private_endpoint(self):
        mysqls = self._unwrap("mysql_db_systems")
        if not mysqls: return
        public = []
        for db in mysqls:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state != "ACTIVE": continue
            # Check if MySQL has public endpoint
            is_public = db.get("is-publicly-accessible", db.get("isPubliclyAccessible", False))
            endpoints = db.get("endpoints", [])
            for ep in endpoints:
                if ep.get("modes", []) and ep.get("ip-address", ep.get("ipAddress", "")):
                    # Check if endpoint has public access
                    if ep.get("status", "") == "ACTIVE" and is_public:
                        name = db.get("display-name", db.get("displayName", ""))
                        public.append(f"{name} ({ep.get('ip-address', ep.get('ipAddress', ''))})")
                        break
            if is_public and not endpoints:
                name = db.get("display-name", db.get("displayName", ""))
                public.append(name)
        if public:
            self.finding("OCI-DB-003", "MySQL HeatWave without private endpoint", self.SEVERITY_HIGH,
                "Database Security",
                f"{len(public)} MySQL HeatWave instance(s) are publicly accessible.",
                items=public[:20],
                remed="Deploy MySQL HeatWave instances in private subnets. Disable public access and use Bastion or VPN for connectivity.")

    def check_db_private_subnet(self):
        dbs = self._unwrap("db_systems")
        adbs = self._unwrap("autonomous_databases")
        subnets = self._unwrap("subnets")
        # Build set of public subnet IDs
        public_subnets = set()
        for s in subnets:
            # Subnets with prohibitPublicIpOnVnic=false are public
            if not s.get("prohibit-public-ip-on-vnic", s.get("prohibitPublicIpOnVnic", True)):
                public_subnets.add(s.get("id", ""))
        exposed = []
        for db in dbs:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state not in ("AVAILABLE", "RUNNING"): continue
            sid = db.get("subnet-id", db.get("subnetId", ""))
            if sid in public_subnets:
                exposed.append(f"DB System: {db.get('display-name', db.get('displayName', ''))}")
        for db in adbs:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state != "AVAILABLE": continue
            sid = db.get("subnet-id", db.get("subnetId", ""))
            if sid and sid in public_subnets:
                exposed.append(f"ADB: {db.get('display-name', db.get('displayName', ''))}")
        if exposed:
            self.finding("OCI-DB-004", "Database not in private subnet", self.SEVERITY_HIGH,
                "Database Security",
                f"{len(exposed)} database(s) are deployed in public subnets, potentially exposing them to the internet.",
                items=exposed[:20],
                remed="Deploy databases in private subnets (prohibitPublicIpOnVnic=true). Use service gateways for Oracle service access.")

    def check_adb_iam_auth(self):
        adbs = self._unwrap("autonomous_databases")
        if not adbs: return
        no_iam = []
        for db in adbs:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state != "AVAILABLE": continue
            iam_auth = db.get("is-access-control-enabled", db.get("isAccessControlEnabled", False))
            if not iam_auth:
                no_iam.append(db.get("display-name", db.get("displayName", "")))
        if no_iam:
            self.finding("OCI-DB-005", "IAM authentication not enabled for ADB", self.SEVERITY_MEDIUM,
                "Database Security",
                f"{len(no_iam)} Autonomous Database(s) do not have access control (IAM authentication) enabled.",
                items=no_iam[:20],
                remed="Enable access control on Autonomous Database to restrict connections by IP/VCN and enable IAM-based authentication.")

    def check_db_patch_level(self):
        dbs = self._unwrap("db_systems")
        if not dbs: return
        outdated = []
        now = datetime.now(timezone.utc)
        for db in dbs:
            state = db.get("lifecycle-state", db.get("lifecycleState", ""))
            if state not in ("AVAILABLE", "RUNNING"): continue
            last_patch = db.get("last-patch-history-entry-id", db.get("lastPatchHistoryEntryId", ""))
            version = db.get("version", db.get("dbVersion", ""))
            # Check time since last maintenance
            maint_window = db.get("maintenance-window", db.get("maintenanceWindow", {})) or {}
            last_run = maint_window.get("time-of-last-run", maint_window.get("timeOfLastRun", ""))
            if last_run:
                try:
                    lr = datetime.fromisoformat(last_run.replace("Z", "+00:00"))
                    days_since = (now - lr).days
                    if days_since > 90:
                        name = db.get("display-name", db.get("displayName", ""))
                        outdated.append(f"{name}: v{version}, last patched {days_since} days ago")
                except (ValueError, TypeError):
                    pass
            elif not last_patch:
                name = db.get("display-name", db.get("displayName", ""))
                outdated.append(f"{name}: v{version}, no patch history")
        if outdated:
            self.finding("OCI-DB-006", "Database patch not current", self.SEVERITY_MEDIUM,
                "Database Security",
                f"{len(outdated)} DB System(s) may be running outdated patch levels.",
                items=outdated[:20],
                remed="Apply the latest database patches. Enable automatic maintenance windows for regular patching.")


class LoggingAuditAuditor(BaseAuditor):
    """OCI Logging & Audit checks (12 checks, OCI-LOG-001 to OCI-LOG-012)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_audit_retention()
        self.check_vcn_flow_logs()
        self.check_service_connector()
        self.check_events_rules()
        self.check_alarms()
        self.check_log_groups()
        self.check_default_tags()
        self.check_notification_topic()
        self.check_iam_vcn_event_rules()
        self.check_cloud_guard_notification()
        self.check_object_storage_write_logs()
        self.check_local_user_auth_notification()
        return self.findings

    def check_audit_retention(self):
        cfg = self.data.get("audit_config")
        if not cfg:
            self.finding("OCI-LOG-001", "Audit log retention below 365 days", self.SEVERITY_HIGH,
                "Logging & Audit",
                "Audit configuration not found. OCI Audit service should retain logs for at least 365 days.",
                remed="Configure audit log retention to 365 days via Identity > Audit > Retention Period.",
                refs=["CIS OCI 4.1"], cis="4.1")
            return
        d = cfg.get("data", cfg) if isinstance(cfg, dict) else cfg
        if isinstance(d, dict):
            retention = d.get("retention-period-days", d.get("retentionPeriodDays", 90))
            if retention < 365:
                self.finding("OCI-LOG-001", "Audit log retention below 365 days", self.SEVERITY_HIGH,
                    "Logging & Audit",
                    f"Audit log retention is set to {retention} days. Minimum 365 days is recommended for compliance.",
                    items=[f"Current retention: {retention} days (recommended: 365)"],
                    remed="Increase audit log retention to 365 days. Navigate to Identity > Audit > Retention Period.",
                    refs=["CIS OCI 4.1"], cis="4.1")

    def check_vcn_flow_logs(self):
        subnets = self._unwrap("subnets")
        log_groups = self._unwrap("log_groups")
        if not subnets: return
        # Check if any flow logs are configured
        has_flow_logs = False
        for lg in log_groups:
            logs = lg.get("logs", [])
            for log in logs:
                cfg = log.get("configuration", {})
                src = cfg.get("source", {})
                if "flowlogs" in src.get("service", "").lower():
                    has_flow_logs = True
                    break
            if has_flow_logs: break
        # Also check subnet-level flow log flags
        for s in subnets:
            if s.get("is-flow-log-enabled", s.get("isFlowLogEnabled", False)):
                has_flow_logs = True
                break
        if not has_flow_logs:
            subnet_names = [s.get("display-name", s.get("displayName", "")) for s in subnets
                           if s.get("lifecycle-state", s.get("lifecycleState", "")) == "AVAILABLE"]
            self.finding("OCI-LOG-002", "VCN flow logs not enabled", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No VCN flow logs are configured. Flow logs provide visibility into network traffic.",
                items=subnet_names[:20],
                remed="Enable VCN flow logs on all subnets for network traffic analysis and security monitoring.",
                refs=["CIS OCI 4.2"], cis="4.2")

    def check_service_connector(self):
        connectors = self._unwrap("service_connectors")
        if not connectors:
            self.finding("OCI-LOG-003", "Service connector not configured", self.SEVERITY_MEDIUM,
                "Logging & Audit",
                "No service connectors configured. Service Connector Hub enables log export to external SIEM, Object Storage, or Streaming.",
                remed="Create service connectors to export audit logs and other service logs to Object Storage or external SIEM.",
                refs=["CIS OCI 4.3"], cis="4.3")
            return
        active = [c for c in connectors
                  if c.get("lifecycle-state", c.get("lifecycleState", "")) == "ACTIVE"]
        if not active:
            self.finding("OCI-LOG-003", "Service connector not configured", self.SEVERITY_MEDIUM,
                "Logging & Audit",
                "No active service connectors found. All connectors are inactive or in error state.",
                items=[f"{c.get('display-name', '')}: {c.get('lifecycle-state', c.get('lifecycleState', ''))}"
                       for c in connectors[:10]],
                remed="Activate service connectors to ensure logs are exported to the target destination.",
                refs=["CIS OCI 4.3"], cis="4.3")

    def check_events_rules(self):
        rules = self._unwrap("events_rules")
        if not rules:
            self.finding("OCI-LOG-004", "Events rules not configured", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No OCI Events rules configured. Events rules enable automated responses to infrastructure changes.",
                remed="Create Events rules for critical operations: IAM changes, network modifications, instance launches, security list changes.",
                refs=["CIS OCI 4.4"], cis="4.4")
            return
        active = [r for r in rules
                  if r.get("lifecycle-state", r.get("lifecycleState", "")) == "ACTIVE"
                  and r.get("is-enabled", r.get("isEnabled", False))]
        if not active:
            self.finding("OCI-LOG-004", "Events rules not configured", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No active Events rules found. All rules are disabled or inactive.",
                items=[f"{r.get('display-name', '')}: disabled" for r in rules[:10]],
                remed="Enable Events rules for IAM, network, compute, and storage change notifications.",
                refs=["CIS OCI 4.4"], cis="4.4")

    def check_alarms(self):
        alarms = self._unwrap("alarms")
        if not alarms:
            self.finding("OCI-LOG-005", "No alarms configured", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No monitoring alarms configured. Alarms provide proactive notification of security-relevant metric changes.",
                remed="Create alarms for: high CPU/memory usage, unauthorized API calls, security list changes, failed login attempts.",
                refs=["CIS OCI 4.5"], cis="4.5")
            return
        enabled = [a for a in alarms
                   if a.get("is-enabled", a.get("isEnabled", False))]
        if not enabled:
            self.finding("OCI-LOG-005", "No alarms configured", self.SEVERITY_HIGH,
                "Logging & Audit",
                "All monitoring alarms are disabled.",
                items=[f"{a.get('display-name', '')}: disabled" for a in alarms[:10]],
                remed="Enable monitoring alarms for security-critical metrics.",
                refs=["CIS OCI 4.5"], cis="4.5")

    def check_log_groups(self):
        lgs = self._unwrap("log_groups")
        if not lgs: return
        # Check if logs are organized or all in default group
        default_only = all(
            "default" in lg.get("display-name", lg.get("displayName", "")).lower()
            for lg in lgs
        )
        if default_only and len(lgs) <= 1:
            self.finding("OCI-LOG-006", "Log groups not organized", self.SEVERITY_LOW,
                "Logging & Audit",
                "All logs are in the default log group. Organizing logs into purpose-specific groups improves manageability.",
                remed="Create dedicated log groups for different services/environments (e.g., audit-logs, vcn-flow-logs, application-logs).")

    # ── CIS OCI v3.1.0 Logging additions (OCI-LOG-007 to OCI-LOG-012) ──

    def check_default_tags(self):
        """OCI-LOG-007 (CIS 4.1): Default tags on resources."""
        tags = self._unwrap("tag_defaults")
        if not tags:
            self.finding("OCI-LOG-007", "Default tags not configured", self.SEVERITY_MEDIUM,
                "Logging & Audit",
                "No default tag rules found. Default tags should include the creator (iam.principal.name) for resource accountability.",
                remed="Create a default tag rule with value '${iam.principal.name}' to automatically tag resources with their creator.",
                refs=["CIS OCI 4.1"], cis="4.1")
            return
        has_principal_tag = False
        for t in tags:
            val = t.get("value", t.get("default-value", t.get("defaultValue", "")))
            if isinstance(val, str) and "${iam.principal.name}" in val.lower():
                has_principal_tag = True
                break
        if not has_principal_tag:
            self.finding("OCI-LOG-007", "Default tags missing creator identity", self.SEVERITY_MEDIUM,
                "Logging & Audit",
                "Default tags exist but none include '${iam.principal.name}' for creator tracking.",
                items=[f"Tag: {t.get('tag-definition-name', t.get('tagDefinitionName', ''))}: {t.get('value', '')}"
                       for t in tags[:10]],
                remed="Add a default tag rule with value '${iam.principal.name}' to track who created each resource.",
                refs=["CIS OCI 4.1"], cis="4.1")

    def check_notification_topic(self):
        """OCI-LOG-008 (CIS 4.2): Notification topic and subscription exists."""
        topics = self._unwrap("notification_topics")
        if not topics:
            self.finding("OCI-LOG-008", "No notification topics configured", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No OCI Notification Service topics found. Notification topics are required for event-driven alerting.",
                remed="Create at least one notification topic with active subscriptions (email, PagerDuty, Slack, etc.) for security alerts.",
                refs=["CIS OCI 4.2"], cis="4.2")
            return
        active_with_subs = []
        no_subs = []
        for t in topics:
            state = t.get("lifecycle-state", t.get("lifecycleState", ""))
            name = t.get("name", t.get("display-name", t.get("displayName", "")))
            if state != "ACTIVE":
                continue
            # Check for subscriptions
            sub_count = t.get("subscription-count", t.get("subscriptionCount",
                       len(t.get("subscriptions", []))))
            if sub_count and int(sub_count) > 0:
                active_with_subs.append(name)
            else:
                no_subs.append(name)
        if not active_with_subs:
            items = [f"{n}: no active subscriptions" for n in no_subs[:10]] if no_subs else ["No active topics found"]
            self.finding("OCI-LOG-008", "Notification topics without subscriptions", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No notification topics have active subscriptions. Alerts will not be delivered.",
                items=items,
                remed="Add subscriptions (email, HTTPS, PagerDuty, Slack) to notification topics to receive security alerts.",
                refs=["CIS OCI 4.2"], cis="4.2")

    def check_iam_vcn_event_rules(self):
        """OCI-LOG-009 (CIS 4.3-4.12): Event rules for IAM/VCN/NSG changes."""
        rules = self._unwrap("events_rules")
        if not rules: return
        # Collect all event types from active rules
        event_types = set()
        for r in rules:
            state = r.get("lifecycle-state", r.get("lifecycleState", ""))
            enabled = r.get("is-enabled", r.get("isEnabled", False))
            if state != "ACTIVE" or not enabled: continue
            condition = r.get("condition", r.get("conditionStr", ""))
            if isinstance(condition, str):
                condition_lower = condition.lower()
            elif isinstance(condition, dict):
                condition_lower = str(condition).lower()
            else:
                continue
            event_types.add(condition_lower)
        # Check for required event type categories
        all_conditions = " ".join(event_types)
        required_events = {
            "IAM group changes (CIS 4.3)": ["com.oraclecloud.identitycontrolplane.creategroup",
                                              "com.oraclecloud.identitycontrolplane.deletegroup",
                                              "com.oraclecloud.identitycontrolplane.updategroup"],
            "IAM policy changes (CIS 4.4)": ["com.oraclecloud.identitycontrolplane.createpolicy",
                                               "com.oraclecloud.identitycontrolplane.deletepolicy",
                                               "com.oraclecloud.identitycontrolplane.updatepolicy"],
            "IAM user changes (CIS 4.5)": ["com.oraclecloud.identitycontrolplane.createuser",
                                             "com.oraclecloud.identitycontrolplane.deleteuser",
                                             "com.oraclecloud.identitycontrolplane.updateuser"],
            "VCN changes (CIS 4.6)": ["com.oraclecloud.virtualnetwork.createvcn",
                                        "com.oraclecloud.virtualnetwork.deletevcn",
                                        "com.oraclecloud.virtualnetwork.updatevcn"],
            "Route table changes (CIS 4.7)": ["com.oraclecloud.virtualnetwork.createroutetable",
                                                "com.oraclecloud.virtualnetwork.deleteroutetable",
                                                "com.oraclecloud.virtualnetwork.updateroutetable"],
            "Security list changes (CIS 4.8)": ["com.oraclecloud.virtualnetwork.createsecuritylist",
                                                  "com.oraclecloud.virtualnetwork.deletesecuritylist",
                                                  "com.oraclecloud.virtualnetwork.updatesecuritylist"],
            "NSG changes (CIS 4.9)": ["com.oraclecloud.virtualnetwork.changenetworksecuritygroup",
                                        "com.oraclecloud.virtualnetwork.createnetworksecuritygroup",
                                        "com.oraclecloud.virtualnetwork.deletenetworksecuritygroup",
                                        "com.oraclecloud.virtualnetwork.updatenetworksecuritygroup"],
            "Internet gateway changes (CIS 4.10)": ["com.oraclecloud.virtualnetwork.createinternetgateway",
                                                      "com.oraclecloud.virtualnetwork.deleteinternetgateway",
                                                      "com.oraclecloud.virtualnetwork.updateinternetgateway"],
        }
        missing = []
        for desc, event_list in required_events.items():
            found = any(evt.lower() in all_conditions for evt in event_list)
            # Also check for broad patterns like "identitycontrolplane" or "virtualnetwork"
            if not found:
                keyword = event_list[0].split(".")[2] if len(event_list[0].split(".")) > 2 else ""
                if keyword and keyword.lower() in all_conditions:
                    found = True
            if not found:
                missing.append(desc)
        if missing:
            self.finding("OCI-LOG-009", "Event rules missing for IAM/VCN changes", self.SEVERITY_HIGH,
                "Logging & Audit",
                f"{len(missing)} required event rule category(ies) are not configured for change monitoring.",
                items=missing[:20],
                remed="Create Events rules for all IAM and networking change events (groups, policies, users, VCNs, route tables, security lists, NSGs, internet gateways).",
                refs=["CIS OCI 4.3", "CIS OCI 4.4", "CIS OCI 4.5", "CIS OCI 4.6",
                       "CIS OCI 4.7", "CIS OCI 4.8", "CIS OCI 4.9", "CIS OCI 4.10"],
                cis="4.3-4.12")

    def check_cloud_guard_notification(self):
        """OCI-LOG-010 (CIS 4.15): Notification for Cloud Guard problems."""
        rules = self._unwrap("events_rules")
        if not rules:
            self.finding("OCI-LOG-010", "No Cloud Guard problem notifications", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No Events rules found. A rule for Cloud Guard problem detection events is required for timely alerting.",
                remed="Create an Events rule that triggers on Cloud Guard problem detected events and sends notifications to a subscribed topic.",
                refs=["CIS OCI 4.15"], cis="4.15")
            return
        has_cg_rule = False
        for r in rules:
            state = r.get("lifecycle-state", r.get("lifecycleState", ""))
            enabled = r.get("is-enabled", r.get("isEnabled", False))
            if state != "ACTIVE" or not enabled: continue
            condition = r.get("condition", r.get("conditionStr", ""))
            cond_str = str(condition).lower() if condition else ""
            if ("cloudguard" in cond_str or "cloud_guard" in cond_str or "cloud-guard" in cond_str) and \
               ("problem" in cond_str or "detected" in cond_str):
                has_cg_rule = True
                break
        if not has_cg_rule:
            self.finding("OCI-LOG-010", "No Cloud Guard problem notifications", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No Events rule detected for Cloud Guard problem notifications. Security findings may go unnoticed.",
                remed="Create an Events rule for 'com.oraclecloud.cloudguard.problemdetected' events with notification action to an active topic.",
                refs=["CIS OCI 4.15"], cis="4.15")

    def check_object_storage_write_logs(self):
        """OCI-LOG-011 (CIS 4.17): Object Storage write logging enabled."""
        lgs = self._unwrap("log_groups")
        if not lgs:
            self.finding("OCI-LOG-011", "Object Storage write logging not enabled", self.SEVERITY_MEDIUM,
                "Logging & Audit",
                "No log groups found. Object Storage write logs should be enabled for data change auditing.",
                remed="Enable write logging for Object Storage buckets via log groups in the Logging service.",
                refs=["CIS OCI 4.17"], cis="4.17")
            return
        has_os_write_log = False
        for lg in lgs:
            logs = lg.get("logs", [])
            for log in logs:
                cfg = log.get("configuration", {})
                src = cfg.get("source", {})
                service = src.get("service", "").lower()
                category = src.get("category", src.get("log-type", "")).lower()
                if "objectstorage" in service or "object-storage" in service or "object_storage" in service:
                    if "write" in category:
                        has_os_write_log = True
                        break
            if has_os_write_log: break
        if not has_os_write_log:
            self.finding("OCI-LOG-011", "Object Storage write logging not enabled", self.SEVERITY_MEDIUM,
                "Logging & Audit",
                "No Object Storage write logs found in any log group. Write logs track data modifications for compliance auditing.",
                remed="Enable Object Storage write logging: Logging > Log Groups > Create Log > Service=Object Storage, Category=Write.",
                refs=["CIS OCI 4.17"], cis="4.17")

    def check_local_user_auth_notification(self):
        """OCI-LOG-012 (CIS 4.18): Notification for local OCI user authentication."""
        rules = self._unwrap("events_rules")
        if not rules:
            self.finding("OCI-LOG-012", "No local user authentication notifications", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No Events rules found. A rule for local user sign-on events is required to detect unauthorized local authentication.",
                remed="Create an Events rule for identity sign-on events (com.oraclecloud.identitycontrolplane.interactivelogin) with notification action.",
                refs=["CIS OCI 4.18"], cis="4.18")
            return
        has_signon_rule = False
        for r in rules:
            state = r.get("lifecycle-state", r.get("lifecycleState", ""))
            enabled = r.get("is-enabled", r.get("isEnabled", False))
            if state != "ACTIVE" or not enabled: continue
            condition = r.get("condition", r.get("conditionStr", ""))
            cond_str = str(condition).lower() if condition else ""
            if ("interactivelogin" in cond_str or "interactive-login" in cond_str or
                    "interactive_login" in cond_str or
                    ("identitycontrolplane" in cond_str and ("login" in cond_str or "signon" in cond_str or "sign-on" in cond_str))):
                has_signon_rule = True
                break
        if not has_signon_rule:
            self.finding("OCI-LOG-012", "No local user authentication notifications", self.SEVERITY_HIGH,
                "Logging & Audit",
                "No Events rule detected for local user sign-on events. Local authentication bypass of federation may go undetected.",
                remed="Create an Events rule for 'com.oraclecloud.identitycontrolplane.interactivelogin' with notification action to detect local user authentication.",
                refs=["CIS OCI 4.18"], cis="4.18")


class CloudGuardAuditor(BaseAuditor):
    """OCI Cloud Guard security checks (5 checks, OCI-CG-001 to OCI-CG-005)."""

    def run_all_checks(self) -> List[Dict]:
        self.check_cloud_guard_enabled()
        self.check_detector_recipes()
        self.check_responder_recipes()
        self.check_security_zones()
        self.check_unresolved_problems()
        return self.findings

    def check_cloud_guard_enabled(self):
        cfg = self.data.get("cloud_guard_config")
        if not cfg:
            self.finding("OCI-CG-001", "Cloud Guard not enabled", self.SEVERITY_CRITICAL,
                "Cloud Guard",
                "Cloud Guard configuration not found. Cloud Guard provides automated security monitoring and threat detection.",
                remed="Enable Cloud Guard in the OCI Console: Security > Cloud Guard > Enable.",
                refs=["CIS OCI 4.6"], cis="4.6")
            return
        d = cfg.get("data", cfg) if isinstance(cfg, dict) else cfg
        if isinstance(d, dict):
            status = d.get("status", d.get("lifecycleState", "")).upper()
            if status not in ("ENABLED", "ACTIVE"):
                self.finding("OCI-CG-001", "Cloud Guard not enabled", self.SEVERITY_CRITICAL,
                    "Cloud Guard",
                    f"Cloud Guard is in '{status}' state. It should be enabled for continuous security monitoring.",
                    items=[f"Status: {status}"],
                    remed="Enable Cloud Guard: Security > Cloud Guard > Enable.",
                    refs=["CIS OCI 4.6"], cis="4.6")

    def check_detector_recipes(self):
        detectors = self._unwrap("cloud_guard_detectors")
        if not detectors:
            self.finding("OCI-CG-002", "Detector recipes not configured", self.SEVERITY_HIGH,
                "Cloud Guard",
                "No Cloud Guard detector recipes found. Detector recipes define what security issues to monitor.",
                remed="Configure Cloud Guard detector recipes for configuration and activity monitoring.",
                refs=["CIS OCI 4.7"], cis="4.7")
            return
        active = [d for d in detectors
                  if d.get("lifecycle-state", d.get("lifecycleState", "")) == "ACTIVE"]
        # Check for both config and activity detectors
        types_found = set()
        for d in active:
            dtype = d.get("detector", d.get("detectorType", "")).upper()
            types_found.add(dtype)
        missing = []
        if "IAAS_CONFIGURATION_DETECTOR" not in types_found and "CONFIGURATION" not in types_found:
            missing.append("Configuration detector recipe")
        if "IAAS_ACTIVITY_DETECTOR" not in types_found and "ACTIVITY" not in types_found:
            missing.append("Activity detector recipe")
        if missing:
            self.finding("OCI-CG-002", "Detector recipes not configured", self.SEVERITY_HIGH,
                "Cloud Guard",
                "Cloud Guard is missing detector recipe types for comprehensive monitoring.",
                items=missing,
                remed="Add both Configuration and Activity detector recipes to Cloud Guard targets.",
                refs=["CIS OCI 4.7"], cis="4.7")

    def check_responder_recipes(self):
        targets = self._unwrap("cloud_guard_targets")
        if not targets: return
        no_responder = []
        for t in targets:
            name = t.get("display-name", t.get("displayName", ""))
            responders = t.get("target-responder-recipes", t.get("targetResponderRecipes", []))
            if not responders:
                no_responder.append(name)
        if no_responder:
            self.finding("OCI-CG-003", "Responder recipes not configured", self.SEVERITY_HIGH,
                "Cloud Guard",
                f"{len(no_responder)} Cloud Guard target(s) have no responder recipes for automated remediation.",
                items=no_responder[:20],
                remed="Configure responder recipes on Cloud Guard targets to enable automated or guided remediation.",
                refs=["CIS OCI 4.8"], cis="4.8")

    def check_security_zones(self):
        zones = self._unwrap("security_zones")
        if not zones:
            self.finding("OCI-CG-004", "Security zones not defined", self.SEVERITY_MEDIUM,
                "Cloud Guard",
                "No Security Zones configured. Security Zones enforce preventive security policies on compartments.",
                remed="Create Security Zones for compartments containing sensitive resources to enforce guardrails (e.g., no public buckets, encrypted volumes).")

    def check_unresolved_problems(self):
        problems = self._unwrap("cloud_guard_problems")
        if not problems: return
        critical_open = []
        high_open = []
        for p in problems:
            status = p.get("lifecycle-state", p.get("lifecycleState", "")).upper()
            if status in ("RESOLVED", "DISMISSED"): continue
            risk = p.get("risk-level", p.get("riskLevel", "")).upper()
            name = p.get("detector-rule-id-display-name",
                        p.get("detectorRuleIdDisplayName", p.get("id", "")))[:60]
            if risk == "CRITICAL":
                critical_open.append(f"CRITICAL: {name}")
            elif risk == "HIGH":
                high_open.append(f"HIGH: {name}")
        all_open = critical_open + high_open
        if all_open:
            self.finding("OCI-CG-005", "Unresolved Cloud Guard problems", self.SEVERITY_MEDIUM,
                "Cloud Guard",
                f"{len(critical_open)} critical and {len(high_open)} high-risk Cloud Guard problems remain unresolved.",
                items=all_open[:20],
                remed="Investigate and resolve open Cloud Guard problems. Prioritize CRITICAL findings first.")
