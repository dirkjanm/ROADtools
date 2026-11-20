import datetime
from sqlalchemy import inspect as sa_inspect
from roadtools.roadlib.metadef.database import (
    AgentIdentityMetadata,
    Application,
    AppRoleAssignment,
    FederatedIdentityCredential,
    OAuth2PermissionGrant,
    ServicePrincipal,
)
from roadtools.roadrecon.gather import extract_agent_metadata_from_sp

SEVERITY_WEIGHTS = {
    "Critical": 4,
    "High": 3,
    "Medium": 2,
    "Low": 1,
    "Informational": 0,
}

WEIGHT_TO_SEVERITY = {v: k for k, v in SEVERITY_WEIGHTS.items()}

TIER0_APP_ROLES = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod",
    "Policy.ReadWrite.PermissionGrant",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.ReadWrite.AzureResources",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedEligibilitySchedule.ReadWrite.AzureADGroup",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
    "User.ReadWrite.All",
    "UserAuthenticationMethod.ReadWrite.All",
    "Organization.ReadWrite.All",
    "EntitlementManagement.ReadWrite.All",
    " TrustFrameworkKeySet.ReadWrite.All",
    "TrustFrameworkKeySet.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
}

TIER0_DIRECTORY_ROLES = {
    "Global Administrator",
    "Company Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Hybrid Identity Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Conditional Access Administrator",
    "Authentication Administrator",
    "Security Administrator",
    "User Administrator",
    "Groups Administrator",
    "Intune Administrator",
    "Partner Tier2 Support",
    "Directory Synchronization Accounts",
}

TIER0_AZURE_ROLES = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Role Based Access Control Administrator",
    "Key Vault Administrator",
    "Managed Identity Operator",
    "Virtual Machine Administrator Login",
}

M365_DATA_PREFIXES = (
    "Mail.",
    "MailboxSettings.",
    "Calendars.",
    "Contacts.",
    "Files.",
    "Sites.",
    "Notes.",
    "Chat.",
    "ChatMessage.",
    "ChannelMessage.",
    "Team.",
    "TeamsAppInstallation.",
    "TeamsTab.",
    "OnlineMeetings.",
    "OnlineMeetingTranscript.",
    "CallRecords.",
    "People.",
    "Presence.",
    "Tasks.",
    "AiEnterpriseInteraction.",
    "Copilot.",
    "Bookings.",
    "ExternalItem.",
    "ExternalConnection.",
    "eDiscovery.",
    "ThreatHunting.",
    "SecurityActions.",
    "SecurityEvents.",
    "SecurityIncident.",
)

M365_DATA_SCOPES = {
    "Mail.Read",
    "Mail.ReadBasic",
    "Mail.ReadBasic.All",
    "Mail.ReadWrite",
    "Mail.Send",
    "MailboxSettings.Read",
    "MailboxSettings.ReadWrite",
    "Calendars.Read",
    "Calendars.ReadWrite",
    "Contacts.Read",
    "Contacts.ReadWrite",
    "Files.Read",
    "Files.Read.All",
    "Files.ReadWrite",
    "Files.ReadWrite.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Sites.Manage.All",
    "Sites.FullControl.All",
    "Sites.Selected",
    "Chat.Read",
    "Chat.ReadBasic",
    "Chat.ReadWrite",
    "Chat.Read.All",
    "Chat.ReadWrite.All",
    "ChannelMessage.Read.All",
    "ChannelMessage.Send",
    "ChannelMessage.ReadWrite",
    "People.Read",
    "People.Read.All",
    "AiEnterpriseInteraction.Read",
    "AiEnterpriseInteraction.Read.All",
    "AiEnterpriseInteraction.ReadWrite.All",
    "Copilot.Read",
    "Copilot.Read.All",
    "Copilot.ReadWrite.All",
    "Bookings.Read.All",
    "Bookings.ReadWrite.All",
    "ExternalItem.Read.All",
    "ExternalItem.ReadWrite.All",
    "OnlineMeetingTranscript.Read.All",
}


def is_m365_data_scope(perm_name: str) -> bool:
    if not perm_name:
        return False
    if perm_name in M365_DATA_SCOPES:
        return True
    return any(perm_name.startswith(prefix) for prefix in M365_DATA_PREFIXES)


def is_tier0_permission(perm_name: str) -> bool:
    if not perm_name:
        return False
    return perm_name in TIER0_APP_ROLES


def _parse_iso_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime.datetime):
        if value.tzinfo is not None:
            return value.astimezone(datetime.timezone.utc).replace(tzinfo=None)
        return value
    if not isinstance(value, str):
        return None
    s = value.strip()
    if not s:
        return None
    if s.endswith("Z"):
        s = s[:-1]
    if "+" in s[10:]:
        s = s[: s.rfind("+")]
    elif "-" in s[19:]:
        s = s[: s.rfind("-")]
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(s[:26], fmt)
        except ValueError:
            continue
    return None


def _analyze_credentials(pw_creds, key_creds, now_utc=None):
    if now_utc is None:
        now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    pw_list = pw_creds if isinstance(pw_creds, list) else []
    key_list = key_creds if isinstance(key_creds, list) else []
    secrets_count = len(pw_list)
    certs_count = len(key_list)
    expired_count = 0
    long_lived_count = 0
    max_expiry_days = 0

    for cred in list(pw_list) + list(key_list):
        if not isinstance(cred, dict):
            continue
        end_dt = _parse_iso_datetime(cred.get("endDate") or cred.get("endDateTime"))
        start_dt = _parse_iso_datetime(cred.get("startDate") or cred.get("startDateTime"))
        if end_dt:
            delta_days = (end_dt - now_utc).days
            if delta_days < 0:
                expired_count += 1
            else:
                if delta_days > max_expiry_days:
                    max_expiry_days = delta_days
                if delta_days > 365:
                    long_lived_count += 1
                elif start_dt and (end_dt - start_dt).days > 365:
                    long_lived_count += 1

    parts = []
    if secrets_count:
        parts.append(f"{secrets_count} secret(s)")
    if certs_count:
        parts.append(f"{certs_count} cert(s)")
    if expired_count:
        parts.append(f"{expired_count} expired")
    if long_lived_count:
        parts.append(f"{long_lived_count} long-lived (>365d)")

    return {
        "secretsCount": secrets_count,
        "certsCount": certs_count,
        "expiredCredentialsCount": expired_count,
        "longLivedCredentialsCount": long_lived_count,
        "maxExpiryDays": max_expiry_days,
        "credentialSummary": ", ".join(parts) if parts else "No secrets or certificates",
    }


def evaluate_fic_risk(fic, app_display_name: str = "") -> dict:
    if isinstance(fic, dict):
        fic_id = fic.get("id")
        app_obj_id = fic.get("applicationObjectId")
        app_id = fic.get("appId")
        name = fic.get("name") or ""
        issuer = (fic.get("issuer") or "").strip()
        subject = (fic.get("subject") or "").strip() if fic.get("subject") is not None else ""
        description = fic.get("description")
        audiences = fic.get("audiences") or []
        claims_expr = fic.get("claimsMatchingExpression")
    else:
        fic_id = getattr(fic, "id", None)
        app_obj_id = getattr(fic, "applicationObjectId", None)
        app_id = getattr(fic, "appId", None)
        name = getattr(fic, "name", "") or ""
        issuer = (getattr(fic, "issuer", "") or "").strip()
        subj_attr = getattr(fic, "subject", None)
        subject = subj_attr.strip() if isinstance(subj_attr, str) else ""
        description = getattr(fic, "description", None)
        audiences = getattr(fic, "audiences", None) or []
        claims_expr = getattr(fic, "claimsMatchingExpression", None)

    reasons = []
    severity = "Low"
    issuer_lower = issuer.lower()
    subject_lower = subject.lower()

    has_claims_expr = bool(claims_expr and (isinstance(claims_expr, dict) and claims_expr.get("value") or isinstance(claims_expr, str)))

    # Critical (4) checks
    if not issuer or issuer_lower.startswith("http://"):
        severity = "Critical"
        reasons.append("Insecure or missing OIDC issuer URL (non-HTTPS)")

    if not subject and not has_claims_expr:
        severity = "Critical"
        reasons.append("Empty OIDC subject without a claimsMatchingExpression constraint")
    elif subject == "*" or subject.endswith(":*") or subject.endswith("/*") or "*" in subject:
        severity = "Critical"
        reasons.append(f"Wildcard OIDC subject '{subject}' allows broad token exchange spoofing")

    # High (3) checks
    if "token.actions.githubusercontent.com" in issuer_lower:
        if "pull_request" in subject_lower:
            if SEVERITY_WEIGHTS[severity] < SEVERITY_WEIGHTS["High"]:
                severity = "High"
            reasons.append("GitHub Actions OIDC subject trusts pull_request workflow triggers (fork PR risk)")
        elif ":ref:refs/heads/" not in subject_lower and ":ref:refs/tags/" not in subject_lower and ":environment:" not in subject_lower:
            if SEVERITY_WEIGHTS[severity] < SEVERITY_WEIGHTS["High"]:
                severity = "High"
            reasons.append("GitHub Actions OIDC subject lacks explicit branch (:ref:refs/heads/), tag, or environment (:environment:) constraint")

    if subject_lower.startswith("system:serviceaccount:default:") or subject_lower == "system:serviceaccount:default":
        if SEVERITY_WEIGHTS[severity] < SEVERITY_WEIGHTS["High"]:
            severity = "High"
        reasons.append(f"Kubernetes OIDC subject trusts the 'default' namespace ({subject})")

    if has_claims_expr and isinstance(claims_expr, dict):
        expr_val = str(claims_expr.get("value", ""))
        if "*" in expr_val:
            if SEVERITY_WEIGHTS[severity] < SEVERITY_WEIGHTS["High"]:
                severity = "High"
            reasons.append(f"Flexible claimsMatchingExpression uses wildcard matching ({expr_val})")

    if not reasons:
        reasons.append("Pinned OIDC subject and HTTPS issuer")

    return {
        "id": fic_id,
        "applicationObjectId": app_obj_id,
        "appId": app_id,
        "applicationDisplayName": app_display_name or "",
        "name": name,
        "issuer": issuer,
        "subject": subject,
        "description": description,
        "audiences": audiences if isinstance(audiences, list) else [audiences],
        "claimsMatchingExpression": claims_expr,
        "riskLevel": severity,
        "severityWeight": SEVERITY_WEIGHTS[severity],
        "riskReasons": reasons,
    }


def analyze_nhi_posture(dbsession) -> dict:
    bind = dbsession.get_bind()
    inspector = sa_inspect(bind)
    existing_tables = set(inspector.get_table_names())

    fic_table_present = "FederatedIdentityCredentials" in existing_tables
    agent_meta_table_present = "AgentIdentityMetadatas" in existing_tables
    az_roles_table_present = (
        "AZroleAssignments" in existing_tables
        and "AZroleDefinitions" in existing_tables
        and "lnk_az_roleassignment_serviceprincipal" in existing_tables
    )
    az_eligible_table_present = (
        "AZroleEligibilityScheduleInstances" in existing_tables
        and "AZroleDefinitions" in existing_tables
        and "lnk_az_roleassignment_eligible_serviceprincipal" in existing_tables
    )
    pim_table_present = (
        "PIMgovernanceRoleAssignments" in existing_tables
        and "PIMgovernanceRoleDefinitions" in existing_tables
        and "lnk_pim_roleassignment_subjectserviceprincipal" in existing_tables
    )

    collection_status = "collected" if (fic_table_present and agent_meta_table_present) else "derived_from_legacy_db"

    all_sps = dbsession.query(ServicePrincipal).all() if "ServicePrincipals" in existing_tables else []
    all_apps = dbsession.query(Application).all() if "Applications" in existing_tables else []
    all_approles = dbsession.query(AppRoleAssignment).all() if "AppRoleAssignments" in existing_tables else []
    all_oauth2 = dbsession.query(OAuth2PermissionGrant).all() if "OAuth2PermissionGrants" in existing_tables else []
    all_fics = dbsession.query(FederatedIdentityCredential).all() if fic_table_present else []
    all_agent_metas = dbsession.query(AgentIdentityMetadata).all() if agent_meta_table_present else []

    sp_by_id = {sp.objectId: sp for sp in all_sps if sp.objectId}
    app_by_obj_id = {a.objectId: a for a in all_apps if a.objectId}
    app_by_appid = {a.appId: a for a in all_apps if a.appId}
    agent_meta_by_sp_id = {m.objectId: m for m in all_agent_metas if m.objectId}

    # Build role lookup map for resource ServicePrincipals: (resource_sp_objectId, role_id) -> role_value
    resource_approle_map = {}
    for sp in all_sps:
        if isinstance(sp.appRoles, list):
            for ar_def in sp.appRoles:
                if isinstance(ar_def, dict) and ar_def.get("id"):
                    val = ar_def.get("value") or ar_def.get("displayName") or ar_def["id"]
                    resource_approle_map[(sp.objectId, ar_def["id"])] = val

    # Index AppRoleAssignments by principalId
    approles_by_principal = {}
    for ar in all_approles:
        if not ar.principalId:
            continue
        if ar.id == "00000000-0000-0000-0000-000000000000":
            continue
        role_name = resource_approle_map.get((ar.resourceId, ar.id))
        if not role_name:
            role_name = ar.id or "UnknownAppRole"
        approles_by_principal.setdefault(ar.principalId, []).append(role_name)

    # Index OAuth2PermissionGrants by clientId (ServicePrincipal.objectId)
    oauth2_by_client = {}
    for grant in all_oauth2:
        if not grant.clientId or not grant.scope:
            continue
        scopes = [s.strip() for s in str(grant.scope).split(" ") if s.strip()]
        oauth2_by_client.setdefault(grant.clientId, []).extend(scopes)

    # Index FICs by applicationObjectId and appId
    fics_by_app_obj_id = {}
    fics_by_appid = {}
    evaluated_fics = []
    findings = []

    for fic in all_fics:
        parent_app = app_by_obj_id.get(fic.applicationObjectId) or app_by_appid.get(fic.appId)
        app_name = parent_app.displayName if parent_app and parent_app.displayName else (fic.appId or "Unknown Application")
        fic_eval = evaluate_fic_risk(fic, app_name)
        evaluated_fics.append(fic_eval)
        if fic.applicationObjectId:
            fics_by_app_obj_id.setdefault(fic.applicationObjectId, []).append(fic_eval)
        if fic.appId:
            fics_by_appid.setdefault(fic.appId, []).append(fic_eval)

        if fic_eval["severityWeight"] >= SEVERITY_WEIGHTS["High"]:
            findings.append({
                "id": f"NHI-FIC-{fic.id}",
                "severity": fic_eval["riskLevel"],
                "severityWeight": fic_eval["severityWeight"],
                "category": "FederatedCredentialTrust",
                "principalObjectId": fic.applicationObjectId or fic.id,
                "principalType": "Application",
                "principalName": app_name,
                "appId": fic.appId,
                "title": f"High-Risk Federated Identity Credential '{fic.name}' on {app_name}",
                "detail": "; ".join(fic_eval["riskReasons"]),
                "recommendation": "Restrict the OIDC subject claim to an explicit branch, tag, or production environment and enforce HTTPS on a verified issuer.",
                "evidence": {
                    "credentialId": fic.id,
                    "credentialName": fic.name,
                    "issuer": fic.issuer,
                    "subject": fic.subject,
                },
            })

    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    agents_out = []
    workloads_out = []
    tier0_nhi_ids = set()
    ownerless_nhi_ids = set()

    for sp in all_sps:
        # Skip Microsoft 1st party resource SPs unless they have explicit agent metadata or custom credentials/FICs
        app_match = app_by_appid.get(sp.appId) if sp.appId else None
        sp_fics = []
        if app_match and app_match.objectId in fics_by_app_obj_id:
            sp_fics = fics_by_app_obj_id[app_match.objectId]
        elif sp.appId and sp.appId in fics_by_appid:
            sp_fics = fics_by_appid[sp.appId]

        agent_meta = agent_meta_by_sp_id.get(sp.objectId)
        heuristic_meta = None
        if not agent_meta:
            heuristic_meta = extract_agent_metadata_from_sp(sp.as_dict(), collection_source="heuristic")

        is_first_party = bool(sp.microsoftFirstParty) or (
            sp.appOwnerTenantId in ("f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47")
            and not app_match
            and not agent_meta
            and not heuristic_meta
        )

        # Resolve permissions
        assigned_approles = sorted(set(approles_by_principal.get(sp.objectId, [])))
        delegated_scopes = sorted(set(oauth2_by_client.get(sp.objectId, [])))

        # Also check if any permissions match AI/Copilot scopes to promote to agent
        all_perms = sorted(set(assigned_approles + delegated_scopes))
        m365_perms = [p for p in all_perms if is_m365_data_scope(p)]
        tier0_app_perms = [p for p in all_perms if is_tier0_permission(p)]

        if not agent_meta and not heuristic_meta:
            if any(p.startswith(("AiEnterpriseInteraction.", "Copilot.")) for p in all_perms):
                heuristic_meta = {
                    "objectId": sp.objectId,
                    "appId": sp.appId,
                    "agentCategory": "M365DeclarativeAgent",
                    "executionMode": "Autonomous" if any(p in assigned_approles for p in all_perms) else "Interactive",
                    "blueprintId": sp.applicationTemplateId,
                    "sponsorUserIds": [],
                    "m365Scopes": m365_perms,
                    "mcpTools": [],
                    "collectionSource": "heuristic",
                }

        # Owners (combine SP owners + backing Application owners)
        owner_names = []
        owner_ids = set()
        for u in getattr(sp, "ownerUsers", []) or []:
            if u.objectId not in owner_ids:
                owner_ids.add(u.objectId)
                owner_names.append(u.userPrincipalName or u.displayName or u.objectId)
        for osp in getattr(sp, "ownerServicePrincipals", []) or []:
            if osp.objectId not in owner_ids:
                owner_ids.add(osp.objectId)
                owner_names.append(osp.displayName or osp.objectId)
        if app_match:
            for u in getattr(app_match, "ownerUsers", []) or []:
                if u.objectId not in owner_ids:
                    owner_ids.add(u.objectId)
                    owner_names.append(u.userPrincipalName or u.displayName or u.objectId)
            for osp in getattr(app_match, "ownerServicePrincipals", []) or []:
                if osp.objectId not in owner_ids:
                    owner_ids.add(osp.objectId)
                    owner_names.append(osp.displayName or osp.objectId)

        # Directory roles
        dir_roles = []
        for dr in getattr(sp, "memberOfRole", []) or []:
            if dr.displayName:
                dir_roles.append(dr.displayName)
        if pim_table_present:
            try:
                for pim_ra in getattr(sp, "pimRoleAssignments", []) or []:
                    if pim_ra.roleDefinition and pim_ra.roleDefinition.displayName:
                        rname = pim_ra.roleDefinition.displayName
                        if rname not in dir_roles:
                            dir_roles.append(rname)
            except Exception:
                pass

        # Azure RBAC roles
        azure_roles = []
        if az_roles_table_present:
            try:
                for az_ra in getattr(sp, "azRoleAssignments", []) or []:
                    if az_ra.role and az_ra.role.role_name:
                        if az_ra.role.role_name not in azure_roles:
                            azure_roles.append(az_ra.role.role_name)
            except Exception:
                pass
        if az_eligible_table_present:
            try:
                for az_el in getattr(sp, "azEligibleRoleAssignments", []) or []:
                    if az_el.role and az_el.role.role_name:
                        if az_el.role.role_name not in azure_roles:
                            azure_roles.append(az_el.role.role_name)
            except Exception:
                pass

        tier0_dir = [r for r in dir_roles if r in TIER0_DIRECTORY_ROLES]
        tier0_az = [r for r in azure_roles if r in TIER0_AZURE_ROLES]
        tier0_combined = sorted(set(tier0_app_perms + tier0_dir + tier0_az))

        # Combine credentials on SP and backing Application
        combined_pw = list(sp.passwordCredentials or []) + (list(app_match.passwordCredentials or []) if app_match else [])
        combined_keys = list(sp.keyCredentials or []) + (list(app_match.keyCredentials or []) if app_match else [])
        cred_info = _analyze_credentials(combined_pw, combined_keys, now_utc=now_utc)

        is_agent = bool(agent_meta or heuristic_meta)

        if is_first_party and not is_agent and not tier0_combined and not sp_fics and cred_info["secretsCount"] == 0 and cred_info["certsCount"] == 0:
            # Skip unprivileged built-in Microsoft first-party resource SPs
            continue

        owners_count = len(owner_ids)
        if owners_count == 0:
            ownerless_nhi_ids.add(sp.objectId)
        if tier0_combined:
            tier0_nhi_ids.add(sp.objectId)

        risk_reasons = []
        max_weight = SEVERITY_WEIGHTS["Low"]

        if is_agent:
            meta_src = agent_meta.as_dict() if agent_meta else heuristic_meta
            agent_category = meta_src.get("agentCategory") or "CustomAIAgent"
            execution_mode = meta_src.get("executionMode") or "Unknown"
            if execution_mode == "Unknown" and assigned_approles:
                execution_mode = "Autonomous"
            blueprint_id = meta_src.get("blueprintId") or sp.applicationTemplateId
            sponsor_ids = meta_src.get("sponsorUserIds") or []
            explicit_m365 = meta_src.get("m365Scopes") or []
            merged_m365 = sorted(set(m365_perms + explicit_m365))
            mcp_tools = meta_src.get("mcpTools") or []

            if owners_count == 0 and not sponsor_ids:
                owner_count_effective = 0
            else:
                owner_count_effective = max(owners_count, len(sponsor_ids))

            if tier0_combined:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Critical"])
                reason = f"Agent holds Tier-0 administrative privileges: {', '.join(tier0_combined)}"
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-AGENT-TIER0-{sp.objectId}",
                    "severity": "Critical",
                    "severityWeight": SEVERITY_WEIGHTS["Critical"],
                    "category": "AgentTier0Privilege",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"{agent_category} '{sp.displayName}' holds Tier-0 privileges",
                    "detail": reason,
                    "recommendation": "Remove Tier-0 directory/Graph permissions from the AI agent and enforce least-privilege scoped roles.",
                    "evidence": {
                        "agentCategory": agent_category,
                        "executionMode": execution_mode,
                        "tier0Roles": tier0_combined,
                    },
                })

            high_write_m365 = [s for s in merged_m365 if "ReadWrite" in s or "Send" in s or "FullControl" in s or "Manage" in s]
            if execution_mode == "Autonomous" and high_write_m365:
                weight = SEVERITY_WEIGHTS["Critical"] if owner_count_effective == 0 else SEVERITY_WEIGHTS["High"]
                sev_label = WEIGHT_TO_SEVERITY[weight]
                max_weight = max(max_weight, weight)
                reason = f"Autonomous agent has broad M365 write/send blast radius ({', '.join(high_write_m365)})" + (" with no assigned owner/sponsor" if owner_count_effective == 0 else "")
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-AGENT-M365WRITE-{sp.objectId}",
                    "severity": sev_label,
                    "severityWeight": weight,
                    "category": "AgentM365BlastRadius",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"Autonomous {agent_category} '{sp.displayName}' with M365 Write/Send permissions",
                    "detail": reason,
                    "recommendation": "Scope M365 permissions to delegated interactive user context or restrict to specific Exchange/SharePoint sites and assign an explicit sponsor.",
                    "evidence": {
                        "executionMode": execution_mode,
                        "m365WriteScopes": high_write_m365,
                        "ownersCount": owner_count_effective,
                    },
                })
            elif merged_m365:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Medium"])
                risk_reasons.append(f"Accesses M365 organizational data scopes: {', '.join(merged_m365)}")

            if owner_count_effective == 0:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["High"] if execution_mode == "Autonomous" else SEVERITY_WEIGHTS["Medium"])
                reason = "Orphaned AI agent without human owner or sponsor accountability"
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-AGENT-ORPHAN-{sp.objectId}",
                    "severity": "High" if execution_mode == "Autonomous" else "Medium",
                    "severityWeight": SEVERITY_WEIGHTS["High"] if execution_mode == "Autonomous" else SEVERITY_WEIGHTS["Medium"],
                    "category": "AgentGovernance",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"Ownerless {agent_category} '{sp.displayName}'",
                    "detail": reason,
                    "recommendation": "Assign an accountable human sponsor or owner in Microsoft Entra Agent ID governance.",
                    "evidence": {"agentCategory": agent_category, "executionMode": execution_mode},
                })

            if app_match and app_match.availableToOtherTenants:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["High"])
                reason = "Multi-tenant Agent application registration allows cross-tenant instantiation"
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-AGENT-MULTITENANT-{sp.objectId}",
                    "severity": "High",
                    "severityWeight": SEVERITY_WEIGHTS["High"],
                    "category": "AgentMultiTenancy",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"Multi-tenant {agent_category} '{sp.displayName}'",
                    "detail": reason,
                    "recommendation": "Restrict internal enterprise AI agents to single-tenant registration unless published as a verified commercial offering.",
                    "evidence": {"availableToOtherTenants": True},
                })

            if cred_info["longLivedCredentialsCount"] > 0:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Medium"])
                risk_reasons.append(f"{cred_info['longLivedCredentialsCount']} long-lived secret/certificate credential(s) (>365 days)")

            for f_eval in sp_fics:
                if f_eval["severityWeight"] >= SEVERITY_WEIGHTS["High"]:
                    max_weight = max(max_weight, f_eval["severityWeight"])
                    risk_reasons.extend(f_eval["riskReasons"])

            if not risk_reasons:
                risk_reasons.append("Standard interactive agent posture")

            agents_out.append({
                "objectId": sp.objectId,
                "appId": sp.appId,
                "applicationObjectId": app_match.objectId if app_match else None,
                "displayName": sp.displayName or sp.appDisplayName or sp.objectId,
                "agentCategory": agent_category,
                "executionMode": execution_mode,
                "blueprintId": blueprint_id,
                "sponsorUserIds": sponsor_ids,
                "mcpTools": mcp_tools,
                "m365Scopes": merged_m365,
                "graphAppRoles": assigned_approles,
                "oauth2Scopes": delegated_scopes,
                "tier0Roles": tier0_combined,
                "directoryRoles": dir_roles,
                "azureRoles": azure_roles,
                "ownersCount": owner_count_effective,
                "ownerNames": owner_names or sponsor_ids,
                "hasSecrets": cred_info["secretsCount"] > 0,
                "hasCerts": cred_info["certsCount"] > 0,
                "federatedCredentialsCount": len(sp_fics),
                "accountEnabled": bool(sp.accountEnabled) if sp.accountEnabled is not None else True,
                "riskLevel": WEIGHT_TO_SEVERITY[max_weight],
                "severityWeight": max_weight,
                "riskReasons": risk_reasons,
            })
        else:
            # Classify Managed Identity or Workload App
            sp_type = sp.servicePrincipalType or "Application"
            alt_names = " ".join(str(x).lower() for x in (sp.alternativeNames or []))
            mi_res_id = sp.managedIdentityResourceId or ""
            if sp_type == "ManagedIdentity" or bool(mi_res_id):
                if "isexplicit=true" in alt_names or "/providers/microsoft.managedidentity/userassignedidentities/" in mi_res_id.lower():
                    nhi_type = "UserAssignedManagedIdentity"
                else:
                    nhi_type = "SystemManagedIdentity"
            elif app_match and app_match.availableToOtherTenants:
                nhi_type = "MultiTenantWorkloadApp"
            else:
                nhi_type = "SingleTenantWorkloadApp"

            if tier0_combined:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Critical"])
                reason = f"Workload holds Tier-0 administrative privileges: {', '.join(tier0_combined)}"
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-WORKLOAD-TIER0-{sp.objectId}",
                    "severity": "Critical",
                    "severityWeight": SEVERITY_WEIGHTS["Critical"],
                    "category": "WorkloadTier0Privilege",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"{nhi_type} '{sp.displayName}' holds Tier-0 privileges",
                    "detail": reason,
                    "recommendation": "Replace broad Tier-0 permissions with least-privilege roles or Administrative Unit scoped assignments.",
                    "evidence": {
                        "nhiType": nhi_type,
                        "tier0Roles": tier0_combined,
                    },
                })

            if cred_info["secretsCount"] > 0 and (tier0_combined or m365_perms):
                max_weight = max(max_weight, SEVERITY_WEIGHTS["High"])
                reason = f"Privileged workload uses static password secrets ({cred_info['secretsCount']}) instead of workload federation or certificates"
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-WORKLOAD-SECRET-{sp.objectId}",
                    "severity": "High",
                    "severityWeight": SEVERITY_WEIGHTS["High"],
                    "category": "CredentialHygiene",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"Privileged workload '{sp.displayName}' authenticates with client secrets",
                    "detail": reason,
                    "recommendation": "Migrate from static client secrets to Federated Identity Credentials (OIDC) or Managed Identities.",
                    "evidence": {
                        "secretsCount": cred_info["secretsCount"],
                        "maxExpiryDays": cred_info["maxExpiryDays"],
                    },
                })

            if cred_info["longLivedCredentialsCount"] > 0 or cred_info["expiredCredentialsCount"] > 0:
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Medium"])
                reason = f"Credential hygiene issue: {cred_info['credentialSummary']}"
                risk_reasons.append(reason)
                findings.append({
                    "id": f"NHI-WORKLOAD-CREDHYGIENE-{sp.objectId}",
                    "severity": "Medium",
                    "severityWeight": SEVERITY_WEIGHTS["Medium"],
                    "category": "CredentialHygiene",
                    "principalObjectId": sp.objectId,
                    "principalType": "ServicePrincipal",
                    "principalName": sp.displayName or sp.objectId,
                    "appId": sp.appId,
                    "title": f"Expired or long-lived credentials on '{sp.displayName}'",
                    "detail": reason,
                    "recommendation": "Remove expired credentials and rotate secrets/certificates with lifetimes exceeding 365 days.",
                    "evidence": cred_info,
                })

            if owners_count == 0 and nhi_type not in ("SystemManagedIdentity", "UserAssignedManagedIdentity"):
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Medium"] if (tier0_combined or m365_perms) else SEVERITY_WEIGHTS["Low"])
                risk_reasons.append("No assigned application or service principal owner")

            for f_eval in sp_fics:
                if f_eval["severityWeight"] >= SEVERITY_WEIGHTS["High"]:
                    max_weight = max(max_weight, f_eval["severityWeight"])
                    risk_reasons.extend(f_eval["riskReasons"])

            if not risk_reasons:
                risk_reasons.append("Standard workload identity posture")

            workloads_out.append({
                "objectId": sp.objectId,
                "appId": sp.appId,
                "applicationObjectId": app_match.objectId if app_match else None,
                "displayName": sp.displayName or sp.appDisplayName or sp.objectId,
                "nhiType": nhi_type,
                "servicePrincipalType": sp_type,
                "managedIdentityResourceId": sp.managedIdentityResourceId,
                "accountEnabled": bool(sp.accountEnabled) if sp.accountEnabled is not None else True,
                "secretsCount": cred_info["secretsCount"],
                "certsCount": cred_info["certsCount"],
                "federatedCredentialsCount": len(sp_fics),
                "expiredCredentialsCount": cred_info["expiredCredentialsCount"],
                "longLivedCredentialsCount": cred_info["longLivedCredentialsCount"],
                "maxExpiryDays": cred_info["maxExpiryDays"],
                "credentialSummary": cred_info["credentialSummary"],
                "privilegedRoles": sorted(set(tier0_combined + dir_roles + azure_roles + assigned_approles)),
                "m365Scopes": m365_perms,
                "ownersCount": owners_count,
                "ownerNames": owner_names,
                "riskLevel": WEIGHT_TO_SEVERITY[max_weight],
                "severityWeight": max_weight,
                "riskReasons": risk_reasons,
            })

    # Sort agents, workloads, federated credentials, and findings deterministically by severityWeight desc
    agents_out.sort(key=lambda x: (-x["severityWeight"], (x["displayName"] or "").lower(), x["objectId"]))
    workloads_out.sort(key=lambda x: (-x["severityWeight"], (x["displayName"] or "").lower(), x["objectId"]))
    evaluated_fics.sort(key=lambda x: (-x["severityWeight"], (x["applicationDisplayName"] or "").lower(), x["id"] or ""))
    findings.sort(key=lambda x: (-x["severityWeight"], (x["principalName"] or "").lower(), x["id"]))

    total_sys_mi = sum(1 for w in workloads_out if w["nhiType"] == "SystemManagedIdentity")
    total_user_mi = sum(1 for w in workloads_out if w["nhiType"] == "UserAssignedManagedIdentity")
    total_mi = total_sys_mi + total_user_mi
    total_workload_apps = len(workloads_out) - total_mi
    total_autonomous_agents = sum(1 for a in agents_out if a["executionMode"] == "Autonomous")

    sev_counts = {k: 0 for k in SEVERITY_WEIGHTS}
    for f in findings:
        if f["severity"] in sev_counts:
            sev_counts[f["severity"]] += 1

    summary = {
        "totalNhIs": len(agents_out) + len(workloads_out),
        "totalAgents": len(agents_out),
        "totalAutonomousAgents": total_autonomous_agents,
        "totalManagedIdentities": total_mi,
        "totalSystemManagedIdentities": total_sys_mi,
        "totalUserAssignedManagedIdentities": total_user_mi,
        "totalWorkloadApps": total_workload_apps,
        "totalFederatedCredentials": len(evaluated_fics),
        "tier0PrivilegedNhIs": len(tier0_nhi_ids),
        "ownerlessNhIs": len(ownerless_nhi_ids),
        "criticalFindingsCount": sev_counts["Critical"],
        "highFindingsCount": sev_counts["High"],
        "mediumFindingsCount": sev_counts["Medium"],
        "lowFindingsCount": sev_counts["Low"],
        "informationalFindingsCount": sev_counts["Informational"],
        "collectionStatus": collection_status,
        "federatedCredentialsTablePresent": fic_table_present,
        "agentMetadataTablePresent": agent_meta_table_present,
    }

    return {
        "summary": summary,
        "agents": agents_out,
        "workloads": workloads_out,
        "federatedCredentials": evaluated_fics,
        "findings": findings,
    }
