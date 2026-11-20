import datetime
import re
from urllib.parse import urlparse
from sqlalchemy import func, inspect as sa_inspect, or_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import selectinload
from roadtools.roadlib.metadef.database import (
    AgentIdentityMetadata,
    Application,
    AZroleAssignment,
    AZroleEligibilityScheduleInstance,
    AppRoleAssignment,
    FederatedIdentityCredential,
    NhiCollectionState,
    OAuth2PermissionGrant,
    PIMgovernanceRoleAssignment,
    ServicePrincipal,
    User,
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
    max_expiry_days = None

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
                if max_expiry_days is None or delta_days > max_expiry_days:
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


_EXPR_REFERENCES_SUB = re.compile(r"""claims\[\s*['"]sub['"]\s*\]""", re.I)
_EXPR_CLAUSE = re.compile(r"^claims\[\s*'([^']+)'\s*\]\s*(eq|matches)\s*'([^']*)'$", re.I)
_EXPR_SUB_EQ = re.compile(r"""claims\[\s*['"]sub['"]\s*\]\s*eq\s*['"]([^'"]*)['"]""", re.I)
_EXPR_LITERAL =re.compile(r"'[^']*'")
_EXPR_CONNECTOR = re.compile(r"\s*\b(and|or)\b\s*", re.I)
_UNPARSEABLE = "unparseable expression, cannot confirm subject restriction"


_GITHUB_ORG_PINNED = re.compile(r"^repo:[^*?/:]+/")


def _strip_outer_parens(text: str) -> str:
    """Strip balanced outer parentheses; `text` has quoted literals already masked."""
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        for i, ch in enumerate(text):
            depth += (ch == "(") - (ch == ")")
            if depth == 0 and i < len(text) - 1:
                return text  # first '(' closes before the end: not an outer pair
        text = text[1:-1].strip()
    return text


def _grade_claims_expression(expr_val: str, issuer: str = ""):
    """Fail-closed grading of a flexible-FIC claimsMatchingExpression.

    Microsoft Learn (flexible FIC, languageVersion 1) documents ONLY `eq`, `matches` (`*`/`?`
    wildcards) and `and`; comparands are single-quoted. Anything else (`or`, `!=`, `not`,
    startswith/contains, bare literals) is not in the documented grammar, so it is graded
    conservatively rather than assumed safe. Returns a list of (severity, reason).
    """
    out = []
    norm = re.sub(r"\s+", " ", expr_val.replace('"', "'")).strip()
    if norm.strip("' ") == "*":
        return [("Critical", f"claimsMatchingExpression matches every subject ({expr_val})")]
    literals = []
    masked = _EXPR_LITERAL.sub(lambda m: literals.append(m.group(0)) or f"@@{len(literals) - 1}@@", norm)
    masked = _strip_outer_parens(masked)
    github = (urlparse(issuer).hostname or "").lower() == "token.actions.githubusercontent.com"
    parts = _EXPR_CONNECTOR.split(masked)
    clauses = [parts[i] for i in range(0, len(parts), 2)]
    connectors = [parts[i].lower() for i in range(1, len(parts), 2)]

    def restore(text):
        return re.sub(r"@@(\d+)@@", lambda m: literals[int(m.group(1))], text).strip()

    any_sub = bool(_EXPR_REFERENCES_SUB.search(norm))
    unparseable = False
    for raw in clauses:
        c = restore(raw)
        m = _EXPR_CLAUSE.match(c)
        if m:
            claim, op, val = m.group(1).lower(), m.group(2).lower(), m.group(3)
            if claim == "sub" and op == "matches" and val and set(val) <= set("*?"):
                out.append(("Critical", f"claimsMatchingExpression matches every subject ({expr_val})"))
            elif github and claim == "sub" and op == "matches" and set("*?") & set(val) \
                    and not _GITHUB_ORG_PINNED.match(val):
                # shared public issuer: an unpinned org/repo lets any repository in any org get a token
                out.append(("Critical", f"claimsMatchingExpression wildcard does not pin the GitHub org/repo on a shared public issuer ({expr_val})"))
            elif op == "matches" and "*" in val and claim == "sub":
                out.append(("High", f"Flexible claimsMatchingExpression uses wildcard matching ({expr_val})"))
            continue
        cl = c.lower()
        if re.fullmatch(r"true|1|'([^']*)' eq '\1'", cl):
            out.append(("Critical", f"claimsMatchingExpression contains an always-true clause ({expr_val})"))
        elif "!=" in c or re.search(r"\bnot\b|\bne\b", cl):
            out.append(("Critical", f"claimsMatchingExpression uses negation, which can match any other subject ({expr_val})"))
        elif re.search(r"startswith|endswith|contains", cl) and "''" in c:
            out.append(("Critical", f"claimsMatchingExpression uses an empty-string prefix/contains match ({expr_val})"))
        else:
            unparseable = True
    if "or" in connectors:
        out.append(("High", f"claimsMatchingExpression uses 'or', so the subject constraint can be bypassed by another clause ({expr_val})"))
    if not any_sub:
        out.append(("Critical", f"claimsMatchingExpression does not constrain the subject claim ({expr_val})"))
    if unparseable:
        out.append(("Medium", f"claimsMatchingExpression: {_UNPARSEABLE} ({expr_val})"))
    return out


KNOWN_ISSUER_HOST_PATTERNS = tuple(re.compile(p) for p in (
    r"token\.actions\.githubusercontent\.com",
    r"vstoken\.actions\.githubusercontent\.com",
    r"vstoken\.dev\.azure\.com",
    r"app\.vstoken\.visualstudio\.com",
    r"accounts\.google\.com",
    r"container\.googleapis\.com",
    r"oidc\.eks\.[a-z0-9-]+\.amazonaws\.com",
    r"[a-z0-9-]+\.oic\.prod-aks\.azure\.com",
    r"login\.microsoftonline\.com",
    r"sts\.windows\.net",
    r"gitlab\.com",
    r"app\.terraform\.io",
    r"oidc\.circleci\.com",
    r"api\.bitbucket\.org",
))


def _is_known_issuer(issuer: str) -> bool:
    parsed = urlparse(issuer)
    if "@" in parsed.netloc:  # userinfo trick: https://evil@known-host/ must not pass the allowlist
        return False
    host = (parsed.hostname or "").lower()
    return any(p.fullmatch(host) for p in KNOWN_ISSUER_HOST_PATTERNS)


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

    if isinstance(claims_expr, dict):
        expr_val = str(claims_expr.get("value") or "").strip()
    elif isinstance(claims_expr, str):
        expr_val = claims_expr.strip()
    else:
        expr_val = ""
    has_claims_expr = bool(expr_val)
    expr_lower = expr_val.lower()

    def bump(level):
        nonlocal severity
        if SEVERITY_WEIGHTS[level] > SEVERITY_WEIGHTS[severity]:
            severity = level

    # Issuer checks
    if not issuer or issuer_lower.startswith("http://") or not issuer_lower.startswith("https://"):
        bump("Critical")
        reasons.append("Insecure or missing OIDC issuer URL (non-HTTPS)")
    elif not _is_known_issuer(issuer):
        bump("Medium")
        reasons.append(f"Federated credential trusts an unrecognised issuer '{issuer}' (not a known CI/CD, cloud or Kubernetes OIDC provider)")

    # Subject / expression checks
    literal_asterisk = False
    if has_claims_expr:
        for level, reason in _grade_claims_expression(expr_val, issuer):
            bump(level)
            reasons.append(reason)
    elif not subject:
        bump("Critical")
        reasons.append("Empty OIDC subject without a claimsMatchingExpression constraint")
    elif "*" in subject:
        # Plain subjects are compared literally (Microsoft Learn: explicit matching); only
        # claimsMatchingExpression 'matches' supports wildcards.
        literal_asterisk = True
        bump("Medium")
        reasons.append(
            f"Subject '{subject}' contains a literal asterisk, not a wildcard; likely misconfiguration "
            "(use a flexible federated credential for wildcard matching)")

    target_lower = subject_lower or expr_lower
    is_github_issuer = (_is_known_issuer(issuer)
                        and (urlparse(issuer).hostname or "").lower() == "token.actions.githubusercontent.com")
    if not literal_asterisk and is_github_issuer and target_lower:
        if "pull_request" in target_lower:
            bump("High")
            reasons.append("GitHub Actions OIDC subject trusts pull_request workflow triggers (fork PR risk)")
        elif ":ref:refs/heads/" not in target_lower and ":ref:refs/tags/" not in target_lower and ":environment:" not in target_lower:
            bump("High")
            reasons.append("GitHub Actions OIDC subject lacks explicit branch (:ref:refs/heads/), tag, or environment (:environment:) constraint")

    for cand in [subject] + _EXPR_SUB_EQ.findall(expr_val):
        cl = cand.strip().lower()
        if cl.startswith("system:serviceaccount:default:") or cl == "system:serviceaccount:default":
            bump("High")
            reasons.append(f"Kubernetes OIDC subject trusts the 'default' namespace ({cand})")

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


COLLECTION_STATUSES = ("collected", "skipped", "failed", "uncollected")


def _rel_available(model, attr, existing_tables):
    secondary = getattr(model, attr).property.secondary
    return secondary is None or secondary.name in existing_tables


def _sp_load_options(tables, pim_ok, az_ok, az_eligible_ok):
    opts = [selectinload(getattr(ServicePrincipal, a))
            for a in ("ownerUsers", "ownerServicePrincipals", "memberOfRole")
            if _rel_available(ServicePrincipal, a, tables)]
    if pim_ok:
        opts.append(selectinload(ServicePrincipal.pimRoleAssignments)
                    .selectinload(PIMgovernanceRoleAssignment.roleDefinition))
    if az_ok:
        opts.append(selectinload(ServicePrincipal.azRoleAssignments).selectinload(AZroleAssignment.role))
    if az_eligible_ok:
        opts.append(selectinload(ServicePrincipal.azEligibleRoleAssignments)
                    .selectinload(AZroleEligibilityScheduleInstance.role))
    return opts


def _resolve_sponsors(dbsession, sponsor_ids, existing_tables, cache, gap):
    """Resolve sponsor ids against known Users (objectId or userPrincipalName).

    Returns (resolved, unresolved): resolved is a list of (userObjectId, name); unresolved is the
    list of raw ids that match no known user (placeholders such as 'none' land here and never
    count as ownership).
    """
    ids = [i for i in sponsor_ids if isinstance(i, str) and i]
    unresolved_raw = [i for i in sponsor_ids if not (isinstance(i, str) and i)]
    # objectId matches exactly; userPrincipalName matches case-insensitively (UPNs are case-insensitive).
    def lookup(i):
        return cache.get(("oid", i)) or cache.get(("upn", i.lower()))

    missing = [i for i in ids if lookup(i) is None]
    if missing and "Users" in existing_tables:
        try:
            for u in dbsession.query(User).filter(
                    or_(User.objectId.in_(missing),
                        func.lower(User.userPrincipalName).in_([m.lower() for m in missing]))).all():
                entry = (u.objectId, u.userPrincipalName or u.displayName or u.objectId)
                cache[("oid", u.objectId)] = entry
                if u.userPrincipalName:
                    cache[("upn", u.userPrincipalName.lower())] = entry
        except SQLAlchemyError as exc:
            dbsession.rollback()
            gap(f"sponsors unavailable ({type(exc).__name__}); sponsors treated as unresolved")
    resolved, unresolved = [], [str(i) for i in unresolved_raw]
    for i in ids:
        entry = lookup(i)
        if entry is None:
            unresolved.append(i)
        elif entry not in resolved:
            resolved.append(entry)
    return resolved, unresolved


def _source_state(dbsession, markers, source, table_present, model):
    marker = markers.get(source)
    if marker is not None and marker.status in COLLECTION_STATUSES:
        if marker.status == "collected" and not table_present:
            return "uncollected", marker.detail  # a 'collected' claim without its table is not trustworthy
        return marker.status, marker.detail
    detail = marker.detail if marker is not None else None
    if table_present and dbsession.query(model).first() is not None:
        return "collected", detail
    return "uncollected", detail


def federated_credentials_collected(dbsession) -> bool:
    """True only if FIC rows are trustworthy (same rule analyze_nhi_posture applies)."""
    tables = set(sa_inspect(dbsession.get_bind()).get_table_names())
    if "FederatedIdentityCredentials" not in tables:
        return False
    markers = {}
    if "NhiCollectionStates" in tables:
        try:
            markers = {m.source: m for m in dbsession.query(NhiCollectionState).all()}
        except SQLAlchemyError:
            dbsession.rollback()
    state, _ = _source_state(dbsession, markers, "federatedCredentials", True, FederatedIdentityCredential)
    return state == "collected"


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

    data_gaps = []

    def gap(message):
        if message not in data_gaps:
            data_gaps.append(message)

    def safe_read(label, fn, default):
        try:
            return fn()
        except SQLAlchemyError as exc:
            dbsession.rollback()
            gap(f"{label} unavailable ({type(exc).__name__})")
            return default

    markers = {}
    if "NhiCollectionStates" in existing_tables:
        markers = safe_read(
            "collectionStates",
            lambda: {m.source: m for m in dbsession.query(NhiCollectionState).all()},
            {})

    def source_state(source, table_present, model):
        return _source_state(dbsession, markers, source, table_present, model)

    fic_state, fic_detail = source_state("federatedCredentials", fic_table_present, FederatedIdentityCredential)
    meta_state, meta_detail = source_state("agentMetadata", agent_meta_table_present, AgentIdentityMetadata)
    fic_collected = fic_state == "collected"
    meta_collected = meta_state == "collected"
    collection_status = "collected" if fic_collected else "derived_from_legacy_db"
    if not fic_collected:
        gap(f"federatedCredentials not collected ({fic_state}); federated credential counts unknown")
    if not meta_collected:
        gap(f"agentMetadata not collected ({meta_state}); agents inferred heuristically")
        gap("agent sponsor data unavailable: agentMetadata not collected; "
            "ownerless/orphan counts for agents are an upper bound")
    if not pim_table_present:
        gap("pimRoles unavailable (PIM tables not collected)")
    if not (az_roles_table_present or az_eligible_table_present):
        gap("azureRoles unavailable (Azure RBAC tables not collected)")

    sp_options = _sp_load_options(existing_tables, pim_table_present, az_roles_table_present, az_eligible_table_present)
    app_options = [selectinload(getattr(Application, a)) for a in ("ownerUsers", "ownerServicePrincipals")
                   if _rel_available(Application, a, existing_tables)]

    def load_all(model, table, options):
        if table not in existing_tables:
            return []
        if options:
            try:
                return dbsession.query(model).options(*options).all()
            except SQLAlchemyError as exc:
                dbsession.rollback()
                gap(f"eagerLoading unavailable ({type(exc).__name__})")
        return dbsession.query(model).all()

    all_sps = load_all(ServicePrincipal, "ServicePrincipals", sp_options)
    all_apps = load_all(Application, "Applications", app_options)
    all_approles = dbsession.query(AppRoleAssignment).all() if "AppRoleAssignments" in existing_tables else []
    all_oauth2 = dbsession.query(OAuth2PermissionGrant).all() if "OAuth2PermissionGrants" in existing_tables else []
    # Never report FIC rows from a source that was not fully collected (no false zero / partial data).
    all_fics = dbsession.query(FederatedIdentityCredential).all() if (fic_table_present and fic_collected) else []
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

        if fic_eval["severityWeight"] >= SEVERITY_WEIGHTS["Medium"]:
            findings.append({
                "id": f"NHI-FIC-{fic.id}",
                "severity": fic_eval["riskLevel"],
                "severityWeight": fic_eval["severityWeight"],
                "category": "FederatedCredentialTrust",
                "principalObjectId": fic.applicationObjectId or fic.id,
                "principalType": "Application",
                "principalName": app_name,
                "appId": fic.appId,
                "title": f"{fic_eval['riskLevel']}-risk Federated Identity Credential '{fic.name}' on {app_name}",
                "detail": "; ".join(fic_eval["riskReasons"]),
                "recommendation": "Restrict the OIDC subject claim to an explicit branch, tag, or production environment and enforce HTTPS on a verified, recognised issuer.",
                "evidence": {
                    "credentialId": fic.id,
                    "credentialName": fic.name,
                    "issuer": fic.issuer,
                    "subject": fic.subject,
                },
            })

    now_utc = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    sponsor_cache = {}
    agents_out = []
    workloads_out = []
    tier0_nhi_ids = set()
    ownerless_nhi_ids = set()

    for sp in all_sps:
        # Skip Microsoft 1st party resource SPs unless they have explicit agent metadata or custom credentials/FICs
        app_match = app_by_appid.get(sp.appId) if sp.appId else None
        sp_fics = []
        if not fic_collected:
            pass
        elif app_match and app_match.objectId in fics_by_app_obj_id:
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
        # Tier-0 is derived from application permissions (app roles) only: delegated scopes are
        # bounded by the signed-in user's own rights and stay informational / blast-radius only.
        tier0_app_perms = [p for p in assigned_approles if is_tier0_permission(p)]

        # Assigned (app-role) M365 data / Tier-0 permissions drive findings; delegated scopes are
        # bounded by the signed-in user and stay informational in m365Scopes.
        m365_assigned = [p for p in assigned_approles if is_m365_data_scope(p)]

        if not agent_meta and not heuristic_meta:
            # Heuristic promotion only on APP-ROLE Copilot/AiEnterpriseInteraction permissions; a
            # delegated grant (or an unrelated app role) is not evidence of an autonomous agent.
            ai_app_roles = [p for p in assigned_approles
                            if p.startswith(("AiEnterpriseInteraction.", "Copilot."))]
            if ai_app_roles:
                heuristic_meta = {
                    "objectId": sp.objectId,
                    "appId": sp.appId,
                    "agentCategory": "M365DeclarativeAgent",
                    "executionMode": "Autonomous",
                    "blueprintId": sp.applicationTemplateId,
                    "sponsorUserIds": [],
                    # app-role scopes only: delegated scopes must not feed the write finding
                    "m365Scopes": m365_assigned,
                    "mcpTools": [],
                    "collectionSource": "heuristic",
                }

        # Owners (combine SP owners + backing Application owners); lazy loads can fail if the
        # owner link tables are missing, which is recorded as a data gap rather than crashing.
        owner_names = []
        owner_ids = set()
        owners_known = True
        for holder in (sp, app_match):
            if holder is None:
                continue
            for attr, name_of in (
                    ("ownerUsers", lambda o: o.userPrincipalName or o.displayName or o.objectId),
                    ("ownerServicePrincipals", lambda o: o.displayName or o.objectId)):
                if not _rel_available(type(holder), attr, existing_tables):
                    # link table absent: skip the load (no failing query, no rollback expiring every
                    # ORM instance) and treat ownership as unknown rather than 'ownerless'
                    owners_known = False
                    gap("owners unavailable (owner link tables not collected)")
                    continue
                rows = safe_read("owners", lambda h=holder, a=attr: list(getattr(h, a, None) or []), [])
                for o in rows:
                    if o.objectId not in owner_ids:
                        owner_ids.add(o.objectId)
                        owner_names.append(name_of(o))

        # Directory roles (active membership, PIM, Azure RBAC kept separate)
        direct_roles = []
        for dr in safe_read("directoryRoles", lambda sp=sp: list(getattr(sp, "memberOfRole", []) or []), []):
            if dr.displayName and dr.displayName not in direct_roles:
                direct_roles.append(dr.displayName)

        def collect_names(rows, name_of):
            names = []
            for row in rows:
                name = name_of(row)
                if name and name not in names:
                    names.append(name)
            return names

        pim_roles = []
        if pim_table_present:
            pim_roles = safe_read(
                "pimRoles",
                lambda sp=sp: collect_names(sp.pimRoleAssignments or [],
                                            lambda r: r.roleDefinition.displayName if r.roleDefinition else None),
                [])
        azure_roles = []
        if az_roles_table_present:
            azure_roles = safe_read(
                "azureRoles",
                lambda sp=sp: collect_names(sp.azRoleAssignments or [], lambda r: r.role.role_name if r.role else None),
                [])
        if az_eligible_table_present:
            for name in safe_read(
                    "azureRoles",
                    lambda sp=sp: collect_names(sp.azEligibleRoleAssignments or [],
                                                lambda r: r.role.role_name if r.role else None),
                    []):
                if name not in azure_roles:
                    azure_roles.append(name)
        dir_roles = direct_roles + [r for r in pim_roles if r not in direct_roles]

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

        owners_count = len(owner_ids) if (owners_known or owner_ids) else None
        if tier0_combined:
            tier0_nhi_ids.add(sp.objectId)

        risk_reasons = []
        max_weight = SEVERITY_WEIGHTS["Low"]

        if is_agent:
            meta_src = agent_meta.as_dict() if agent_meta else heuristic_meta
            agent_category = meta_src.get("agentCategory") or "CustomAIAgent"
            execution_mode = meta_src.get("executionMode") or "Unknown"
            if execution_mode == "Unknown" and any(
                    is_m365_data_scope(r) or is_tier0_permission(r) for r in assigned_approles):
                # app-only access to M365 data / Tier-0 means it acts without a signed-in user
                execution_mode = "Autonomous"
            blueprint_id = meta_src.get("blueprintId") or sp.applicationTemplateId
            sponsor_ids = meta_src.get("sponsorUserIds") or []
            explicit_m365 = meta_src.get("m365Scopes") or []
            merged_m365 = sorted(set(m365_perms + explicit_m365))  # informational (incl. delegated)
            write_basis_m365 = sorted(set(m365_assigned + explicit_m365))  # delegated scopes excluded
            mcp_tools = meta_src.get("mcpTools") or []

            # Only sponsors that resolve to a known user count toward ownership (placeholders such
            # as 'none' must not hide an orphaned agent); owners and sponsors are de-duplicated.
            resolved_sponsors, unresolved_sponsors = _resolve_sponsors(
                dbsession, sponsor_ids, existing_tables, sponsor_cache, gap)
            sponsor_names = [name for _, name in resolved_sponsors]
            owner_count_effective = len(owner_ids | {oid for oid, _ in resolved_sponsors})
            if owner_count_effective == 0 and not owners_known:
                owner_count_effective = None  # unknown: owner data unavailable and no sponsor resolved
            if owner_count_effective == 0:
                ownerless_nhi_ids.add(sp.objectId)
            if not agent_meta or meta_src.get("collectionSource") == "heuristic":
                risk_reasons.append(
                    "Classified as an AI agent heuristically (no Agent ID metadata collected); "
                    "execution mode and ownership are inferred")

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

            high_write_m365 = [s for s in write_basis_m365 if "ReadWrite" in s or "Send" in s or "FullControl" in s or "Manage" in s]
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
                detail = reason + (
                    "" if meta_collected else
                    ". Agent sponsor data unavailable (agentMetadata not collected); this is an upper bound")
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
                    "detail": detail,
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
                if f_eval["severityWeight"] >= SEVERITY_WEIGHTS["Medium"]:
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
                "directoryRoles": direct_roles,
                "pimRoles": pim_roles,
                "azureRoles": azure_roles,
                "ownersCount": owner_count_effective,
                "ownerNames": owner_names,
                "sponsorNames": sponsor_names,
                "sponsorsCount": len(resolved_sponsors),
                "unresolvedSponsors": unresolved_sponsors,
                "hasSecrets": cred_info["secretsCount"] > 0,
                "hasCerts": cred_info["certsCount"] > 0,
                "federatedCredentialsCount": len(sp_fics) if fic_collected else None,
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
            elif is_first_party:
                nhi_type = "FirstPartyMicrosoft"
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

            if cred_info["secretsCount"] > 0 and (tier0_combined or m365_assigned):
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

            is_managed_identity = nhi_type in ("SystemManagedIdentity", "UserAssignedManagedIdentity")
            if owners_count == 0 and not is_managed_identity:  # None (unknown) is never 'ownerless'
                ownerless_nhi_ids.add(sp.objectId)
                max_weight = max(max_weight, SEVERITY_WEIGHTS["Medium"] if (tier0_combined or m365_assigned) else SEVERITY_WEIGHTS["Low"])
                risk_reasons.append("No assigned application or service principal owner")

            for f_eval in sp_fics:
                if f_eval["severityWeight"] >= SEVERITY_WEIGHTS["Medium"]:
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
                "nhiCategory": "ManagedIdentity" if is_managed_identity else "WorkloadApp",
                "servicePrincipalType": sp_type,
                "managedIdentityResourceId": sp.managedIdentityResourceId,
                "accountEnabled": bool(sp.accountEnabled) if sp.accountEnabled is not None else True,
                "secretsCount": cred_info["secretsCount"],
                "certsCount": cred_info["certsCount"],
                "federatedCredentialsCount": len(sp_fics) if fic_collected else None,
                "expiredCredentialsCount": cred_info["expiredCredentialsCount"],
                "longLivedCredentialsCount": cred_info["longLivedCredentialsCount"],
                "maxExpiryDays": cred_info["maxExpiryDays"],
                "credentialSummary": cred_info["credentialSummary"],
                "privilegedRoles": sorted(set(tier0_combined + dir_roles + azure_roles + assigned_approles)),
                "directoryRoles": direct_roles,
                "pimRoles": pim_roles,
                "azureRoles": azure_roles,
                "graphAppRoles": assigned_approles,
                "tier0Roles": tier0_combined,
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
        "totalFederatedCredentials": len(evaluated_fics) if fic_collected else None,
        "totalFirstPartyMicrosoftNhIs": sum(1 for w in workloads_out if w["nhiType"] == "FirstPartyMicrosoft"),
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
        "federatedCredentialsCollected": fic_collected,
        "agentMetadataCollected": meta_collected,
        "federatedCredentialsCollectionStatus": fic_state,
        "agentMetadataCollectionStatus": meta_state,
        "federatedCredentialsCollectionDetail": fic_detail,
        "agentMetadataCollectionDetail": meta_detail,
        "severityBreakdown": dict(sev_counts),
        "topFindings": findings[:5],
        "dataGaps": data_gaps,
    }

    return {
        "summary": summary,
        "agents": agents_out,
        "workloads": workloads_out,
        "federatedCredentials": evaluated_fics,
        "findings": findings,
    }
