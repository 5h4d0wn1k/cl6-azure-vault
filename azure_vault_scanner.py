#!/usr/bin/env python3
"""CL6 — Azure Key Vault Scanner: Enumerate vaults, audit access policies, analyze certificates."""

import json
import hmac
import hashlib
import time
import urllib.request
import urllib.parse
import urllib.error
import base64
import os
import sys
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone


@dataclass
class Finding:
    severity: str
    category: str
    resource: str
    message: str

    def __str__(self):
        return f"[{self.severity}] {self.category} | {self.resource}: {self.message}"


class AzureAuthHelper:
    """Generate HMAC-SHA256 signatures for Azure management API requests."""

    @staticmethod
    def sign_request(method: str, url: str, body: str, key: str, key_id: str) -> Dict[str, str]:
        """Generate Authorization header for Azure management API."""
        date = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
        parsed = urllib.parse.urlparse(url)
        content_length = str(len(body)) if body else "0"
        content_type = "application/json" if body else ""

        string_to_sign = (
            f"{method}\n"
            f"{content_type}\n"
            f"{content_length}\n"
            f"x-ms-date:{date}\n"
            f"x-ms-version:2023-07-01\n"
            f"/{parsed.path.lstrip('/')}"
        )

        decoded_key = base64.b64decode(key)
        signature = base64.b64encode(
            hmac.new(decoded_key, string_to_sign.encode("utf-8"), hashlib.sha256).digest()
        ).decode("utf-8")

        return {
            "Authorization": f"SharedKey {key_id}:{signature}",
            "x-ms-date": date,
            "x-ms-version": "2023-07-01",
            "Content-Type": content_type,
            "Content-Length": content_length,
        }


class AzureRequestExecutor:
    """Execute signed HTTP requests against Azure Management API."""

    def __init__(self, subscription_id: str, token: str):
        self.subscription_id = subscription_id
        self.token = token
        self.base_url = "https://management.azure.com"
        self.api_version = "2023-07-01"

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def get(self, path: str, api_version: Optional[str] = None) -> Optional[Dict]:
        av = api_version or self.api_version
        separator = "&" if "?" in path else "?"
        url = f"{self.base_url}{path}{separator}api-version={av}"
        req = urllib.request.Request(url, headers=self._headers(), method="GET")
        return self._execute(req)

    def _execute(self, req: urllib.request.Request) -> Optional[Dict]:
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return {"error": True, "status": e.code, "message": body}
        except (urllib.error.URLError, OSError) as e:
            return {"error": True, "message": str(e)}

    def list_all_key_vaults(self) -> List[Dict]:
        path = f"/subscriptions/{self.subscription_id}/providers/Microsoft.KeyVault/vaults"
        result = self.get(path, "2023-07-01")
        if result and not result.get("error"):
            return result.get("value", [])
        return []

    def get_vault_details(self, vault_name: str) -> Optional[Dict]:
        path = (
            f"/subscriptions/{self.subscription_id}"
            f"/providers/Microsoft.KeyVault/vaults/{vault_name}"
        )
        return self.get(path, "2023-07-01")

    def list_vault_secrets(self, vault_name: str) -> List[Dict]:
        vault_url = f"https://{vault_name}.vault.azure.net"
        url = f"{vault_url}/secrets?api-version=7.4"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }, method="GET")
        result = self._execute(req)
        if result and not result.get("error"):
            return result.get("value", [])
        return []

    def list_vault_certificates(self, vault_name: str) -> List[Dict]:
        vault_url = f"https://{vault_name}.vault.azure.net"
        url = f"{vault_url}/certificates?api-version=7.4"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }, method="GET")
        result = self._execute(req)
        if result and not result.get("error"):
            return result.get("value", [])
        return []

    def list_vault_keys(self, vault_name: str) -> List[Dict]:
        vault_url = f"https://{vault_name}.vault.azure.net"
        url = f"{vault_url}/keys?api-version=7.4"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }, method="GET")
        result = self._execute(req)
        if result and not result.get("error"):
            return result.get("value", [])
        return []


class KeyVaultEnumerator:
    """Enumerate and catalog Azure Key Vaults."""

    def enumerate(self, executor: AzureRequestExecutor) -> Tuple[List[Dict], List[Finding]]:
        findings: List[Finding] = []
        vaults = executor.list_all_key_vaults()

        if not vaults:
            findings.append(Finding(
                severity="INFO",
                category="No Vaults Found",
                resource="Subscription",
                message="No Key Vaults found in subscription (or no access)",
            ))
            return vaults, findings

        findings.append(Finding(
            severity="INFO",
            category="Vault Enumeration",
            resource="Subscription",
            message=f"Found {len(vaults)} Key Vault(s)",
        ))

        for vault in vaults:
            name = vault.get("name", "unknown")
            props = vault.get("properties", {})
            tenant_id = props.get("tenantId", "")
            vault_uri = props.get("vaultUri", "")
            enable_soft_delete = props.get("enableSoftDelete", False)
            enable_purge_protection = props.get("enablePurgeProtection", False)
            sku = props.get("sku", {}).get("name", "")
            network_acls = props.get("networkAcls", {})

            if not enable_soft_delete:
                findings.append(Finding(
                    severity="HIGH",
                    category="Soft Delete Disabled",
                    resource=f"KeyVault/{name}",
                    message="Soft delete is disabled — secrets can be permanently deleted",
                ))

            if not enable_purge_protection:
                findings.append(Finding(
                    severity="HIGH",
                    category="No Purge Protection",
                    resource=f"KeyVault/{name}",
                    message="Purge protection is disabled — vault can be purged after soft delete",
                ))

            if sku and sku.lower() == "standard":
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Standard SKU",
                    resource=f"KeyVault/{name}",
                    message="Using Standard SKU — Premium SKU required for HSM-backed keys",
                ))

            default_action = network_acls.get("defaultAction", "Allow")
            if default_action == "Allow" and not network_acls.get("virtualNetworkRules"):
                findings.append(Finding(
                    severity="HIGH",
                    category="No Network Restrictions",
                    resource=f"KeyVault/{name}",
                    message="Network ACL default action is Allow with no virtual network rules",
                ))

            bypass = network_acls.get("bypass", "None")
            if bypass in ("AzureServices", "All"):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Azure Services Bypass",
                    resource=f"KeyVault/{name}",
                    message=f"Network ACL allows Azure services to bypass: {bypass}",
                ))

        return vaults, findings


class AccessPolicyAuditor:
    """Audit Key Vault access policies."""

    DANGEROUS_PERMS = {
        "all": "Full access to vault",
        "purge": "Can permanently delete vault contents",
        "delete": "Can delete secrets/keys/certificates",
        "set": "Can modify secrets/keys/certificates",
    }

    ALL_PERMISSIONS = [
        "get", "list", "set", "delete", "purge", "recover",
        "backup", "restore", "update", "import", "wrapkey",
        "unwrapkey", "sign", "verify", "encrypt", "decrypt",
    ]

    def audit(self, vault_details: Dict, vault_name: str) -> List[Finding]:
        findings: List[Finding] = []
        props = vault_details.get("properties", {})

        access_policies = props.get("accessPolicies", [])
        if not access_policies:
            findings.append(Finding(
                severity="INFO",
                category="No Access Policies",
                resource=f"KeyVault/{vault_name}",
                message="No access policies configured (uses RBAC mode or empty)",
            ))
            return findings

        for policy in access_policies:
            findings.extend(self._audit_single_policy(policy, vault_name))

        return findings

    def _audit_single_policy(self, policy: Dict, vault_name: str) -> List[Finding]:
        findings: List[Finding] = []
        tenant_id = policy.get("tenantId", "")
        object_id = policy.get("objectId", "")
        app_id = policy.get("applicationId", "")
        display_name = policy.get("displayName", object_id[:8] if object_id else "unknown")

        for perm_type in ("permissionsToSecrets", "permissionsToKeys",
                          "permissionsToCertificates", "permissionsToStorage"):
            perms = policy.get(perm_type, [])
            if not perms:
                continue

            resource_type = perm_type.replace("permissionsTo", "")
            for perm_group in perms:
                actions = perm_group.get("permissions", [])
                if isinstance(actions, str):
                    actions = [actions]

                if "all" in actions:
                    findings.append(Finding(
                        severity="HIGH",
                        category="Full Permission Granted",
                        resource=f"KeyVault/{vault_name}",
                        message=f"'{display_name}' has full {resource_type} access",
                    ))

                if "purge" in actions:
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="Purge Permission Granted",
                        resource=f"KeyVault/{vault_name}",
                        message=f"'{display_name}' can purge {resource_type} (permanent deletion)",
                    ))

                if "set" in actions and "delete" in actions and "purge" in actions:
                    findings.append(Finding(
                        severity="CRITICAL",
                        category="Full Lifecycle Control",
                        resource=f"KeyVault/{vault_name}",
                        message=f"'{display_name}' has full create/modify/delete/purge on {resource_type}",
                    ))

                scope_actions = {"get", "list"}
                if set(actions) - scope_actions and set(actions) != set(actions):
                    non_read = [a for a in actions if a not in scope_actions]
                    if len(non_read) >= 3:
                        findings.append(Finding(
                            severity="MEDIUM",
                            category="Broad Permissions",
                            resource=f"KeyVault/{vault_name}",
                            message=f"'{display_name}' has {len(non_read)} write permissions on {resource_type}",
                        ))

        return findings


class CertificateAnalyzer:
    """Analyze Key Vault certificates for security issues."""

    def analyze(self, executor: AzureRequestExecutor, vault_name: str) -> List[Finding]:
        findings: List[Finding] = []
        certificates = executor.list_vault_certificates(vault_name)

        for cert in certificates:
            cert_name = cert.get("name", "unknown")
            cert_props = cert.get("attributes", {})

            enabled = cert_props.get("enabled", True)
            if not enabled:
                findings.append(Finding(
                    severity="LOW",
                    category="Disabled Certificate",
                    resource=f"KeyVault/{vault_name}/cert/{cert_name}",
                    message="Certificate is disabled",
                ))

            expires = cert_props.get("expires", "")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    days_left = (exp_dt - now).days
                    if days_left < 0:
                        findings.append(Finding(
                            severity="HIGH",
                            category="Expired Certificate",
                            resource=f"KeyVault/{vault_name}/cert/{cert_name}",
                            message=f"Certificate expired {abs(days_left)} days ago",
                        ))
                    elif days_left < 30:
                        findings.append(Finding(
                            severity="MEDIUM",
                            category="Expiring Certificate",
                            resource=f"KeyVault/{vault_name}/cert/{cert_name}",
                            message=f"Certificate expires in {days_left} days",
                        ))
                except (ValueError, TypeError):
                    pass

            recovery = cert_props.get("recoveryLevel", "")
            if recovery in ("Purgeable", ""):
                if not recovery:
                    findings.append(Finding(
                        severity="MEDIUM",
                        category="No Recovery Level",
                        resource=f"KeyVault/{vault_name}/cert/{cert_name}",
                        message="Certificate has no recovery level set",
                    ))

        return findings


class SecretInventory:
    """Inventory Key Vault secrets with metadata."""

    def inventory(self, executor: AzureRequestExecutor, vault_name: str) -> Tuple[List[Dict], List[Finding]]:
        findings: List[Finding] = []
        secrets = executor.list_vault_secrets(vault_name)

        for secret in secrets:
            secret_name = secret.get("name", "unknown")
            attrs = secret.get("attributes", {})

            enabled = attrs.get("enabled", True)
            if not enabled:
                findings.append(Finding(
                    severity="LOW",
                    category="Disabled Secret",
                    resource=f"KeyVault/{vault_name}/secret/{secret_name}",
                    message="Secret is disabled but still exists",
                ))

            expires = attrs.get("expires", "")
            if expires:
                try:
                    exp_dt = datetime.fromisoformat(expires.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    days_left = (exp_dt - now).days
                    if days_left < 0:
                        findings.append(Finding(
                            severity="HIGH",
                            category="Expired Secret",
                            resource=f"KeyVault/{vault_name}/secret/{secret_name}",
                            message=f"Secret expired {abs(days_left)} days ago",
                        ))
                    elif days_left < 7:
                        findings.append(Finding(
                            severity="MEDIUM",
                            category="Expiring Secret",
                            resource=f"KeyVault/{vault_name}/secret/{secret_name}",
                            message=f"Secret expires in {days_left} days",
                        ))
                except (ValueError, TypeError):
                    pass

            updated = attrs.get("updated", attrs.get("created", ""))
            if updated:
                try:
                    updated_dt = datetime.fromisoformat(updated.replace("Z", "+00:00"))
                    now = datetime.now(timezone.utc)
                    days_since = (now - updated_dt).days
                    if days_since > 365:
                        findings.append(Finding(
                            severity="MEDIUM",
                            category="Stale Secret",
                            resource=f"KeyVault/{vault_name}/secret/{secret_name}",
                            message=f"Secret not updated in {days_since} days",
                        ))
                except (ValueError, TypeError):
                    pass

            recovery = attrs.get("recoveryLevel", "")
            if recovery in ("Purgeable", ""):
                findings.append(Finding(
                    severity="MEDIUM",
                    category="Purgeable Secret",
                    resource=f"KeyVault/{vault_name}/secret/{secret_name}",
                    message="Secret is purgeable (no recovery protection)",
                ))

        return secrets, findings


class KeyAnalyzer:
    """Analyze Key Vault keys."""

    def analyze(self, executor: AzureRequestExecutor, vault_name: str) -> Tuple[List[Dict], List[Finding]]:
        findings: List[Finding] = []
        keys = executor.list_vault_keys(vault_name)

        for key in keys:
            key_name = key.get("name", "unknown")
            key_attrs = key.get("attributes", {})
            kty = key.get("kty", "unknown")

            if kty in ("RSA", "RSA-HSM"):
                size = key.get("keySize", 0)
                if 0 < size < 2048:
                    findings.append(Finding(
                        severity="HIGH",
                        category="Weak Key Size",
                        resource=f"KeyVault/{vault_name}/key/{key_name}",
                        message=f"RSA key size is {size} bits (minimum 2048 recommended)",
                    ))
            elif kty in ("EC",):
                curve = key.get("crv", "")
                if curve in ("P-256K",):
                    findings.append(Finding(
                        severity="MEDIUM",
                        category="Legacy Curve",
                        resource=f"KeyVault/{vault_name}/key/{key_name}",
                        message=f"Using curve {curve} — consider P-256 or P-384",
                    ))

            enabled = key_attrs.get("enabled", True)
            if not enabled:
                findings.append(Finding(
                    severity="LOW",
                    category="Disabled Key",
                    resource=f"KeyVault/{vault_name}/key/{key_name}",
                    message="Key is disabled",
                ))

        return keys, findings


class AzureVaultScanner:
    """Main scanner orchestrator."""

    def __init__(self, subscription_id: str, token: str):
        self.executor = AzureRequestExecutor(subscription_id, token)
        self.enumerator = KeyVaultEnumerator()
        self.policy_auditor = AccessPolicyAuditor()
        self.cert_analyzer = CertificateAnalyzer()
        self.secret_inventory = SecretInventory()
        self.key_analyzer = KeyAnalyzer()

    def scan(self) -> Tuple[List[Dict], List[Finding]]:
        all_findings: List[Finding] = []

        vaults, enum_findings = self.enumerator.enumerate(self.executor)
        all_findings.extend(enum_findings)

        for vault in vaults:
            vault_name = vault.get("name", "unknown")
            details = self.executor.get_vault_details(vault_name)
            if details and not details.get("error"):
                all_findings.extend(self.policy_auditor.audit(details, vault_name))

            all_findings.extend(self.cert_analyzer.analyze(self.executor, vault_name))
            _, secret_findings = self.secret_inventory.inventory(self.executor, vault_name)
            all_findings.extend(secret_findings)
            _, key_findings = self.key_analyzer.analyze(self.executor, vault_name)
            all_findings.extend(key_findings)

        return vaults, all_findings

    def print_report(self, vaults: List[Dict], findings: List[Finding]):
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        sorted_findings = sorted(findings, key=lambda f: severity_order.get(f.severity, 5))

        print("\n" + "=" * 70)
        print("  CL6 — Azure Key Vault Scanner Report")
        print("=" * 70)

        print(f"\n  Vaults discovered: {len(vaults)}")
        for v in vaults:
            print(f"    - {v.get('name', 'unknown')}")

        if not sorted_findings:
            print("\n  No findings detected.\n")
            return

        counts = {}
        for f in sorted_findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        print("\n  Summary:")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if sev in counts:
                print(f"    {sev}: {counts[sev]}")
        print(f"    TOTAL: {len(sorted_findings)}")
        print()

        for f in sorted_findings:
            print(f"  {f}")

        print("\n" + "=" * 70 + "\n")


class OfflineVaultAuditor:
    """Static audit of realistic Azure Key Vault fixtures (no Azure access).

    Reuses the same detection semantics as the live auditors (soft delete,
    purge protection, network ACLs, access-policy permissions, certificate
    expiry, secret staleness/purgeability, weak keys) but reads vault state
    from a JSON fixture instead of the Azure management/data APIs.
    """

    def audit(self, vaults) -> List[Finding]:
        findings: List[Finding] = []
        for vault in vaults:
            name = vault.get("name", "unknown")
            props = vault.get("properties", {})
            findings.extend(self._audit_vault_props(name, props))
            findings.extend(AccessPolicyAuditor().audit({"properties": props}, name))
            findings.extend(self._audit_certificates(name, props.get("certificates", [])))
            findings.extend(self._audit_secrets(name, props.get("secrets", [])))
            findings.extend(self._audit_keys(name, props.get("keys", [])))
        return findings

    def _audit_vault_props(self, name, props):
        findings = []
        enable_soft_delete = props.get("enableSoftDelete", False)
        enable_purge_protection = props.get("enablePurgeProtection", False)
        sku = props.get("sku", {}).get("name", "")
        network_acls = props.get("networkAcls", {})

        if not enable_soft_delete:
            findings.append(Finding("HIGH", "Soft Delete Disabled",
                                    f"KeyVault/{name}",
                                    "Soft delete is disabled — secrets can be permanently deleted"))
        if not enable_purge_protection:
            findings.append(Finding("HIGH", "No Purge Protection",
                                    f"KeyVault/{name}",
                                    "Purge protection is disabled — vault can be purged after soft delete"))
        if sku and sku.lower() == "standard":
            findings.append(Finding("MEDIUM", "Standard SKU",
                                    f"KeyVault/{name}",
                                    "Using Standard SKU — Premium SKU required for HSM-backed keys"))
        default_action = network_acls.get("defaultAction", "Allow")
        if default_action == "Allow" and not network_acls.get("virtualNetworkRules"):
            findings.append(Finding("HIGH", "No Network Restrictions",
                                    f"KeyVault/{name}",
                                    "Network ACL default action is Allow with no virtual network rules"))
        bypass = network_acls.get("bypass", "None")
        if bypass in ("AzureServices", "All"):
            findings.append(Finding("MEDIUM", "Azure Services Bypass",
                                    f"KeyVault/{name}",
                                    f"Network ACL allows Azure services to bypass: {bypass}"))
        return findings

    def _audit_certificates(self, name, certs):
        findings = []
        for cert in certs or []:
            cert_name = cert.get("name", "unknown")
            attrs = cert.get("attributes", {})
            enabled = attrs.get("enabled", True)
            if not enabled:
                findings.append(Finding("LOW", "Disabled Certificate",
                                        f"KeyVault/{name}/cert/{cert_name}",
                                        "Certificate is disabled"))
            expires = attrs.get("expires", "")
            if expires:
                days_left = _days_until(expires)
                if days_left is not None:
                    if days_left < 0:
                        findings.append(Finding("HIGH", "Expired Certificate",
                                                f"KeyVault/{name}/cert/{cert_name}",
                                                f"Certificate expired {abs(days_left)} days ago"))
                    elif days_left < 30:
                        findings.append(Finding("MEDIUM", "Expiring Certificate",
                                                f"KeyVault/{name}/cert/{cert_name}",
                                                f"Certificate expires in {days_left} days"))
            recovery = attrs.get("recoveryLevel", "")
            if recovery in ("Purgeable", ""):
                findings.append(Finding("MEDIUM", "No Recovery Level",
                                        f"KeyVault/{name}/cert/{cert_name}",
                                        "Certificate has no recovery level set"))
        return findings

    def _audit_secrets(self, name, secrets):
        findings = []
        for secret in secrets or []:
            secret_name = secret.get("name", "unknown")
            attrs = secret.get("attributes", {})
            enabled = attrs.get("enabled", True)
            if not enabled:
                findings.append(Finding("LOW", "Disabled Secret",
                                        f"KeyVault/{name}/secret/{secret_name}",
                                        "Secret is disabled but still exists"))
            expires = attrs.get("expires", "")
            if expires:
                days_left = _days_until(expires)
                if days_left is not None:
                    if days_left < 0:
                        findings.append(Finding("HIGH", "Expired Secret",
                                                f"KeyVault/{name}/secret/{secret_name}",
                                                f"Secret expired {abs(days_left)} days ago"))
                    elif days_left < 7:
                        findings.append(Finding("MEDIUM", "Expiring Secret",
                                                f"KeyVault/{name}/secret/{secret_name}",
                                                f"Secret expires in {days_left} days"))
            recovery = attrs.get("recoveryLevel", "")
            if recovery in ("Purgeable", ""):
                findings.append(Finding("MEDIUM", "Purgeable Secret",
                                        f"KeyVault/{name}/secret/{secret_name}",
                                        "Secret is purgeable (no recovery protection)"))
        return findings

    def _audit_keys(self, name, keys):
        findings = []
        for key in keys or []:
            key_name = key.get("name", "unknown")
            kty = key.get("kty", "unknown")
            if kty in ("RSA", "RSA-HSM"):
                size = key.get("keySize", 0)
                if 0 < size < 2048:
                    findings.append(Finding("HIGH", "Weak Key Size",
                                            f"KeyVault/{name}/key/{key_name}",
                                            f"RSA key size is {size} bits (minimum 2048 recommended)"))
            elif kty == "EC":
                curve = key.get("crv", "")
                if curve == "P-256K":
                    findings.append(Finding("MEDIUM", "Legacy Curve",
                                            f"KeyVault/{name}/key/{key_name}",
                                            f"Using curve {curve} — consider P-256 or P-384"))
            enabled = key.get("attributes", {}).get("enabled", True)
            if not enabled:
                findings.append(Finding("LOW", "Disabled Key",
                                        f"KeyVault/{name}/key/{key_name}",
                                        "Key is disabled"))
        return findings


def _days_until(iso) -> Optional[int]:
    try:
        exp_dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        return (exp_dt - datetime.now(timezone.utc)).days
    except (ValueError, TypeError):
        return None


def load_vault_fixtures(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except OSError as exc:
        raise FileNotFoundError(f"Fixtures file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in fixtures file {path}: {exc}") from exc
    if isinstance(data, dict):
        val = data.get("vaults", data.get("resources", []))
        return val
    if isinstance(data, list):
        return data
    raise ValueError(f"Unsupported fixture structure in {path}")


def findings_to_json_offline(vaults, findings):
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    crit_high = counts.get("CRITICAL", 0) + counts.get("HIGH", 0)
    return {
        "tool": "CL6-AzureKeyVaultOfflineAuditor",
        "mode": "offline-fixture",
        "vault_count": len(vaults),
        "finding_count": len(findings),
        "critical_high_count": crit_high,
        "summary": counts,
        "vaults": [v.get("name") for v in vaults],
        "findings": [
            {
                "severity": f.severity,
                "category": f.category,
                "resource": f.resource,
                "message": f.message,
                "remediation": _azure_remediation(f.category),
            }
            for f in sorted(findings, key=lambda x: severity_order.get(x.severity, 5))
        ],
    }


def _azure_remediation(category):
    table = {
        "Soft Delete Disabled": "Enable soft delete on the vault to protect against accidental deletion.",
        "No Purge Protection": "Enable purge protection to prevent permanent destruction after soft delete.",
        "Standard SKU": "Upgrade to Premium SKU if HSM-backed key requirements are needed.",
        "No Network Restrictions": "Set network ACL defaultAction to Deny and allow only required virtual networks/IPs.",
        "Azure Services Bypass": "Remove AzureServices/All bypass unless explicitly required.",
        "Expired Certificate": "Renew or remove the certificate; track expiry in your change process.",
        "Expiring Certificate": "Schedule renewal before the certificate expires.",
        "No Recovery Level": "Enable recover/purge protection on the certificate.",
        "Disabled Certificate": "Remove the disabled certificate from the vault.",
        "Expired Secret": "Rotate the secret and purge its old versions.",
        "Expiring Secret": "Rotate the secret before its scheduled expiry.",
        "Purgeable Secret": "Enable soft delete / purge protection on the vault.",
        "Disabled Secret": "Remove the disabled secret from the vault.",
        "Weak Key Size": "Regenerate the RSA key with at least 2048 bits.",
        "Legacy Curve": "Use P-256 or P-384 curves instead of P-256K.",
        "Disabled Key": "Remove the disabled key from the vault.",
        "No Access Policies": "Confirm vault uses RBAC; otherwise define least-privilege access policies.",
        "Vault Enumeration": "No action — informational.",
        "No Vaults Found": "No action — informational.",
    }
    return table.get(category, "Review and harden the affected Key Vault configuration.")


def print_offline_report(vaults, findings):
    print("\n" + "=" * 64)
    print("  CL6 — Azure Key Vault Offline Audit")
    print("=" * 64)
    print(f"  Vaults audited: {len(vaults)}")
    print(f"  Findings:       {len(findings)}")
    print("=" * 64)
    counts = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev in counts:
            print(f"    {sev:9s}: {counts[sev]}")
    print()
    for f in findings:
        print(f"  [{f.severity:8s}] {f.category} | {f.resource}")
        print(f"      {f.message}")
        print(f"      Fix: {_azure_remediation(f.category)}")
    print("\n" + "=" * 64 + "\n")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CL6 — Azure Key Vault Scanner")
    parser.add_argument("--subscription-id", help="Azure subscription ID (live mode, your own at runtime only)")
    parser.add_argument("--token", help="Azure Bearer token (live mode)")
    parser.add_argument("--demo", action="store_true",
                        help="Run offline demo against bundled fixture (no Azure access)")
    parser.add_argument("--fixtures", default="",
                        help="Path to Key Vault state fixtures JSON (offline audit)")
    parser.add_argument("--output", "-o", default="", help="JSON output file")
    parser.add_argument("--exit-code-on-findings", action="store_true",
                        help="Exit 2 when CRITICAL/HIGH findings exist (CI-friendly)")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))

    if args.demo or args.fixtures or not (args.subscription_id and args.token):
        fixture = args.fixtures or os.path.join(base_dir, "fixtures", "vaults.json")
        if not os.path.isfile(fixture):
            print(f"[!] Fixture not found: {fixture}. Run --demo from the repo root.", file=sys.stderr)
            return 1
        print(f"[*] Offline mode — auditing fixtures: {fixture}")
        try:
            vaults = load_vault_fixtures(fixture)
        except (FileNotFoundError, ValueError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1
        findings = OfflineVaultAuditor().audit(vaults)
        print_offline_report(vaults, findings)
        report = findings_to_json_offline(vaults, findings)
        output = args.output or os.path.join(base_dir, "reports", "cl6-report.json")
        write_report(report, output)
        if args.exit_code_on_findings and report["critical_high_count"] > 0:
            return 2
        return 0

    scanner = AzureVaultScanner(args.subscription_id, args.token)
    vaults, findings = scanner.scan()
    scanner.print_report(vaults, findings)
    if args.output:
        report = findings_to_json_offline(vaults, findings)
        write_report(report, args.output)
    critical = sum(1 for f in findings if f.severity == "CRITICAL")
    if args.exit_code_on_findings and (critical > 0 or
                                       any(f.severity == "HIGH" for f in findings)):
        return 2
    return 0


def write_report(report, output_path):
    parent = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(parent, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, sort_keys=True)
    print(f"[+] JSON report written to {output_path}")


if __name__ == "__main__":
    sys.exit(main())
