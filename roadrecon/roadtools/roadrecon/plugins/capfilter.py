'''
CAP recon plugin
Copyright 2026 - MIT License
'''
from rich.console import Console
from rich.table import Table
import json
import argparse
import base64
import zlib
from roadtools.roadlib.metadef.database import ServicePrincipal, User, Policy, Application, Group, DirectoryRole
import roadtools.roadlib.metadef.database as database

# Required property - plugin description
DESCRIPTION = '''
Parse Conditional Access policies
'''


class CapFilterPlugin():
    """
    Conditional Access Policy filter plugin
    """

    ADMIN_APPS = {
        "797f4846-ba00-4fd7-ba43-dac1f8f63013",  # Azure Portal
        "00000007-0000-0ff1-ce00-000000000000",  # Microsoft 365 Admin Center
        "1b730954-1685-4b74-9bfd-dac224a7b894",  # Entra ID / Azure AD Admin Center
        "497effe9-df71-4043-a8bb-14cf78c4b63b",  # Exchange Admin Center
        "9bc3ab49-b65d-410a-85ad-de819febfddc",  # SharePoint Admin Center
        "12128f48-ec9e-42f0-b203-ea49fb6af367",  # Teams Admin Center
        "80ccca67-54bd-44ab-8625-4b79c4dc7775",  # Security & Compliance / Purview
        "d4ebce55-015a-49b5-a083-c84d1797ae8c",  # Intune / Endpoint Manager
        "1950a258-227b-4e31-a9cf-717495945fc2"   # Power Platform Admin
    }

    OFFICE365_APPS = {
        "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
        "00000002-0000-0ff1-ce00-000000000000",  # Exchange Online
        "00000003-0000-0ff1-ce00-000000000000",  # SharePoint Online
        "1fec8e78-bce4-4aaf-ab1b-5451cc387264",  # Microsoft Teams
        "00000006-0000-0ff1-ce00-000000000000",  # Office 365 Portal / Office.com
        "ab9b8c07-8f02-4f72-87fa-80105867a763",  # OneDrive Sync
        "00000005-0000-0ff1-ce00-000000000000",  # Yammer
        "00000004-0000-0ff1-ce00-000000000000",  # Skype for Business Online
        "4b233688-031c-404b-9a80-a4f3f2351f90",  # Outlook Web
        "c9a559d2-7aab-4f13-a6ed-e7e9c52aec87",  # Microsoft Forms
        "871c010f-5e61-4fb1-83ac-98610a7e9110",  # Power BI
        "66375f6b-983f-4c2c-9701-d680650f588f"   # Planner
    }

    def __init__(self, session):
        self.session = session
        self.console = Console()

    # -------------------------------------------------------------------------
    # Database helpers
    # -------------------------------------------------------------------------

    def _get_group(self, gid):
        if isinstance(gid, list):
            return self.session.query(Group).filter(Group.objectId.in_(gid)).all()
        return self.session.query(Group).filter(Group.objectId == gid).first()

    def _get_application(self, aid):
        if isinstance(aid, list):
            res = self.session.query(Application).filter(Application.appId.in_(aid)).all()
            if len(res) != len(aid):
                return self.session.query(ServicePrincipal).filter(ServicePrincipal.appId.in_(aid)).all()
            return res
        else:
            res = self.session.query(Application).filter(Application.appId == aid).first()
            if res is None:
                return self.session.query(ServicePrincipal).filter(ServicePrincipal.appId == aid).first()
            return res

    def _get_user(self, uid):
        if isinstance(uid, list):
            return self.session.query(User).filter(User.objectId.in_(uid)).all()
        return self.session.query(User).filter(User.objectId == uid).first()

    def _get_serviceprincipal(self, uid):
        if isinstance(uid, list):
            return self.session.query(ServicePrincipal).filter(ServicePrincipal.objectId.in_(uid)).all()
        return self.session.query(ServicePrincipal).filter(ServicePrincipal.objectId == uid).first()

    def _get_serviceprincipalrule(self, rule):
        if isinstance(rule, list):
            return [', '.join(rule)]
        return [rule]

    def _get_role(self, rid):
        if isinstance(rid, list):
            return self.session.query(DirectoryRole).filter(DirectoryRole.roleTemplateId.in_(rid)).all()
        return self.session.query(DirectoryRole).filter(DirectoryRole.roleTemplateId == rid).first()

    # -------------------------------------------------------------------------
    # Translation helpers
    # -------------------------------------------------------------------------

    def _translate_guestsexternal(self, value):
        return [value['GuestOrExternalUserTypes']]

    def _translate_authstrength(self, authstrengthguid):
        built_in = {
            '00000000-0000-0000-0000-000000000002': 'Multi-factor authentication',
            '00000000-0000-0000-0000-000000000003': 'Passwordless MFA',
            '00000000-0000-0000-0000-000000000004': 'Phishing-resistant MFA'
        }
        return built_in.get(
            authstrengthguid,
            f"Unknown authentication strength policy: {authstrengthguid} (probably custom)"
        )

    def _translate_clienttype(self, client):
        if client in ['EasSupported', 'EasUnsupported']:
            return 'Exchange ActiveSync'
        if client in ['OtherLegacy', 'LegacySmtp', 'LegacyPop', 'LegacyImap', 'LegacyMapi', 'LegacyOffice']:
            return 'Legacy Clients'
        if client == 'Native':
            return 'Mobile and Desktop clients'
        return client

    def _translate_locations(self, locs):
        out = []
        # Old format: KnownNetworkPolicies
        policies = self.session.query(Policy).filter(Policy.policyType == 6).all()
        for policy in policies:
            for pdetail in policy.policyDetail:
                detaildata = json.loads(pdetail)
                if (
                        'KnownNetworkPolicies' in detaildata
                        and detaildata['KnownNetworkPolicies']['NetworkId'] in locs
                ):
                    out.append(detaildata['KnownNetworkPolicies']['NetworkName'])
        # New format: policyIdentifier
        for loc in locs:
            policies = self.session.query(Policy).filter(
                Policy.policyType == 6,
                Policy.policyIdentifier == loc
            ).all()
            for policy in policies:
                out.append(policy.displayName)
        return out

    # -------------------------------------------------------------------------
    # Condition parsers
    # -------------------------------------------------------------------------

    def _parse_ucrit(self, crit):
        funct = {
            'Applications': self._get_application,
            'Users': self._get_user,
            'Groups': self._get_group,
            'Roles': self._get_role,
            'ServicePrincipals': self._get_serviceprincipal,
            'ServicePrincipalFilterRule': self._get_serviceprincipalrule,
            'GuestsOrExternalUsers': self._translate_guestsexternal
        }
        ot = ''
        for ctype, clist in crit.items():
            if 'All' in clist:
                ot += 'All users'
                break
            if 'None' in clist:
                ot += 'Nobody'
                break
            if 'Guests' in clist:
                ot += 'Guest users'
            try:
                objects = funct[ctype](clist)
            except KeyError:
                raise Exception('Unsupported criterium type: {0}'.format(ctype))
            if not objects:
                if 'Guests' not in clist:
                    ot += 'Unknown object(s) {0}'.format(', '.join(clist))
                continue
            if ctype == 'Users':
                ot += 'Users: '
                ot += ', '.join([uobj.displayName for uobj in objects])
            elif ctype == 'ServicePrincipals':
                ot += 'Service Principals: '
                ot += ', '.join([uobj.displayName for uobj in objects])
            elif ctype == 'Groups':
                ot += 'Users in groups: '
                ot += ', '.join([uobj.displayName for uobj in objects])
            elif ctype == 'Roles':
                ot += 'Users in roles: '
                ot += ', '.join([uobj.displayName for uobj in objects])
            elif ctype == 'GuestsOrExternalUsers':
                ot += 'Guests or external user types: '
                ot += ', '.join(objects)
            elif ctype == 'ServicePrincipalFilterRule':
                ot += 'Service Principals matching the following filter: '
                ot += ', '.join(objects)
            else:
                raise Exception('Unsupported criterium type: {0}'.format(ctype))
        return ot

    def _parse_appcrit(self, crit, service_principals):
        is_concerned = False
        ot = ''
        for ctype, clist in crit.items():
            if ctype == 'Acrs':
                ot += 'Action: '
                ot += ', '.join(clist)
            elif ctype == 'NetworkAccess':
                ot += 'Network access: '
                ot += ', '.join([f"{action}: {target}" for action, target in clist.items()])
            else:
                if 'All' in clist:
                    ot += 'All resources'
                    is_concerned = True
                    break
                if 'None' in clist:
                    ot += 'None'
                    is_concerned = False
                    break
                if 'Office365' in clist:
                    ot += 'All Office 365 applications '
                    if service_principals:
                        for sp in service_principals:
                            if sp.objectId in self.OFFICE365_APPS:
                                is_concerned = True
                if 'MicrosoftAdminPortals' in clist:
                    ot += 'All Microsoft Admin Portals '
                    if service_principals:
                        for sp in service_principals:
                            if sp.objectId in self.ADMIN_APPS:
                                is_concerned = True
                objects = self._get_application(clist)
                if objects:
                    if ctype == 'Applications':
                        ot += 'Resources:\n'
                        for uobj in objects:
                            ot += uobj.displayName + '\n'
                            if service_principals:
                                for sp in service_principals:
                                    if uobj.objectId == sp.objectId:
                                        is_concerned = True
        return ot, is_concerned

    def _parse_platform(self, cond, platform_filter=None):
        platform_match = False
        try:
            pcond = cond['DevicePlatforms']
        except KeyError:
            return '', True

        ot = ''
        for icrit in pcond['Include']:
            if 'All' in icrit['DevicePlatforms']:
                ot += '+[green]All platforms[/green]\n'
                platform_match = True
            else:
                for crit in icrit['DevicePlatforms']:
                    ot += f'+[green]{crit}[/green]\n'
                    if platform_filter == crit:
                        platform_match = True

        if 'Exclude' in pcond:
            for icrit in pcond['Exclude']:
                for crit in icrit['DevicePlatforms']:
                    ot += f'-[red]{crit}[/red]\n'
                    if platform_filter == crit:
                        platform_match = False

        if platform_filter is None:
            platform_match = True
        return ot, platform_match

    def _parse_devices(self, cond):
        try:
            pcond = cond['Devices']
        except KeyError:
            return ''
        ot = '[green]'
        for icrit in pcond['Include']:
            if 'DeviceStates' in icrit:
                ot += 'Device states: '
                ot += 'All' if 'All' in icrit['DeviceStates'] else ' '.join(icrit['DeviceStates'])
            if 'DeviceRule' in icrit:
                ot += 'Device rule: '
                ot += 'All devices' if 'All' in icrit['DeviceRule'] else icrit['DeviceRule']
        ot += '[/green]'

        if 'Exclude' in pcond:
            ot += '\n[red]'
            for icrit in pcond['Exclude']:
                if 'DeviceStates' in icrit:
                    ot += 'Device states: '
                    ot += 'All' if 'All' in icrit['DeviceStates'] else ' '.join(icrit['DeviceStates'])
                if 'DeviceRule' in icrit:
                    ot += 'Device rule: '
                    ot += 'All devices' if 'All' in icrit['DeviceRule'] else icrit['DeviceRule']
            ot += '[/red]'
        return ot

    def _parse_locationcrit(self, crit, location_filters, is_trusted=False):
        """
        Parse a single location criterion against the active location filters.

        location_filters: list of (identifier, is_trusted, match_by) tuples
            match_by = 'id'          -> compare against policyIdentifier / NetworkId
            match_by = 'displayname' -> compare against location display name
        """
        ot = ''
        is_concerned = False
        # True if at least one matched location is marked as trusted
        has_trusted_loc = any(trusted for _, trusted, _ in location_filters)

        for _, clist in crit.items():
            if 'AllTrusted' in clist:
                ot += 'All trusted locations'
                # Match if is_trusted flag is forced (-t) or at least one matched location is trusted
                if is_trusted or has_trusted_loc:
                    is_concerned = True
                break

            if 'All' in clist:
                ot += 'All locations'
                is_concerned = True
                break

            # Named locations: resolve display name for output, compare by id or displayname
            for loc in clist:
                names = self._translate_locations([loc])
                display = names[0] if names else loc
                ot += display + ', '

                for identifier, loc_trusted, match_by in location_filters:
                    if match_by == 'id' and loc == identifier:
                        is_concerned = True
                        break
                    if match_by == 'displayname' and display.lower() == identifier.lower():
                        is_concerned = True
                        break

        return ot, is_concerned

    def _parse_locations(self, cond, location_filters, is_trusted=False, location_filter_active=False):
        """
        Parse the Locations condition of a CAP policy.

        location_filter_active: True if --ip, --country or -l was explicitly provided.
            When False and no location_filters are set, the location condition is ignored
            (no filtering applied).
        """
        location_match = False
        try:
            lcond = cond['Locations']
        except KeyError:
            # No location condition in this policy -> always match
            return '', True

        ot = '[green]'
        for icrit in lcond['Include']:
            ot_res, is_concerned = self._parse_locationcrit(
                icrit, location_filters, is_trusted
            )
            ot += ot_res
            if is_concerned:
                location_match = True
        ot += '[/green]'

        if 'Exclude' in lcond:
            ot += '\n[red]'
            for icrit in lcond['Exclude']:
                ot_res, is_concerned = self._parse_locationcrit(
                    icrit, location_filters, is_trusted
                )
                ot += ot_res
                if is_concerned:
                    # Exclude takes priority: unset match if location is excluded
                    location_match = False
            ot += '[/red]'

        # If no location filter was requested, do not filter on location at all
        if not location_filter_active and not location_filters and not is_trusted:
            location_match = True

        return ot, location_match

    def _parse_signinrisks(self, cond):
        try:
            srcond = cond['SignInRisks']
        except KeyError:
            return ''
        ot = '[green]'
        for icrit in srcond['Include']:
            ot += ', '.join(icrit['SignInRisks'])
        ot += '[/green]'
        if 'Exclude' in srcond:
            ot += '\n[red]'
            for icrit in srcond['Exclude']:
                ot += ', '.join(icrit['SignInRisks'])
            ot += '[/red]'
        return ot

    def _parse_application(self, cond, service_principals):
        app_match = False
        try:
            ucond = cond['Applications']
        except KeyError:
            return '', True

        ot = '[green]'
        for icrit in ucond['Include']:
            ot_res, is_concerned = self._parse_appcrit(icrit, service_principals)
            ot += ot_res
            if is_concerned:
                app_match = True
        ot += '[/green]'

        ot += '[red]'
        if 'Exclude' in ucond:
            ot += '\n'
            for icrit in ucond['Exclude']:
                ot_res, is_concerned = self._parse_appcrit(icrit, service_principals)
                ot += ot_res
                if is_concerned:
                    app_match = False
        ot += '[/red]'

        if not service_principals:
            app_match = True
        return ot, app_match

    def _parse_authflows(self, cond):
        if 'AuthFlows' not in cond:
            return ''
        ucond = cond['AuthFlows']
        ot = 'Flows included: '
        for icrit in ucond['Include']:
            for _, clist in icrit.items():
                ot += ', '.join(clist)
        return ot

    def _parse_controls(self, controls):
        """
        Parse the Controls section of a CAP policy.

        Returns:
            display_str : human-readable string for the table
            groups      : list of groups, each group is a list of control strings
                          - AND between groups (all must be satisfied)
                          - OR within a group (any one is sufficient)

        Example:
            groups = [
                ['MFA'],
                ['Require compliant device', 'Require domain-joined device (Hybrid Azure AD)']
            ]
            -> MFA AND (compliant device OR domain-joined device)
        """
        CONTROL_LABELS = {
            'Mfa':                       'MFA',
            'Block':                     'Deny logon',
            'RequireCompliantDevice':    'Require compliant device',
            'RequireDomainJoinedDevice': 'Require domain-joined device (Hybrid Azure AD)',
            'RequireApprovedApp':        'Require approved client app',
            'RequireCompliantApp':       'Require app protection policy',
            'RequirePasswordChange':     'Require password change',
            'RequireAuthContext':        'Require authentication context',
        }

        if not controls:
            return '', []

        # Block is always standalone and takes priority
        for c in controls:
            if 'Control' in c and 'Block' in c['Control']:
                return 'Deny logon', [['Deny logon']]

        groups = []
        display_groups = []

        for c in controls:
            group_items = []

            if 'Control' in c:
                for ctrl in c['Control']:
                    label = CONTROL_LABELS.get(ctrl, ctrl)
                    group_items.append(label)

            if 'AuthStrengthIds' in c:
                for guid in c['AuthStrengthIds']:
                    group_items.append(self._translate_authstrength(guid))

            if group_items:
                groups.append(group_items)
                # Within a group: any one control is sufficient (OR)
                if len(group_items) == 1:
                    display_groups.append(group_items[0])
                else:
                    display_groups.append('any of [' + ' / '.join(group_items) + ']')

        if not groups:
            return '', []

        if len(display_groups) == 1:
            display_str = f'Requirements (any): {display_groups[0]}'
        else:
            # Multiple groups: all must be satisfied (AND between groups)
            display_str = 'Requirements (all): ' + ' AND '.join(display_groups)

        return display_str, groups

    def _parse_clients(self, cond, client_filter):
        client_match = False
        if 'ClientTypes' not in cond:
            return '', True
        ucond = cond['ClientTypes']
        ot = ''
        for icrit in ucond['Include']:
            for crit in icrit['ClientTypes']:
                client_type = self._translate_clienttype(crit)
                ot += f'+[green]{client_type}[/green]\n'
                if client_filter == client_type:
                    client_match = True
        if client_filter is None:
            client_match = True
        return ot, client_match

    def _parse_sessioncontrols(self, cond):
        if 'SessionControls' not in cond:
            return ''
        ucond = []
        for condition in cond['SessionControls']:
            if condition == 'SignInFrequency':
                siftype = cond.get('SignInFrequencyType')
                if not siftype:
                    ucond.append('SignInFrequency (Unknown setting)')
                elif siftype == 30:
                    ucond.append('SignInFrequency (Every time)')
                elif siftype == 10:
                    sifduration = cond.get('SignInFrequencyTimeSpan', '')
                    ucond.append(f'SignInFrequency (Every {sifduration})')
                else:
                    ucond.append(f'SignInFrequency (Unknown SIF type {siftype})')
            elif condition == 'PersistentBrowserSessionMode':
                pbmode = cond.get('PersistentBrowserSessionMode')
                ucond.append(f'PersistentBrowserSession: {pbmode}')
            else:
                ucond.append(condition)
        return ', '.join(ucond)

    def _parse_compressed_cidr(self, detail):
        if 'CompressedCidrIpRanges' not in detail:
            return ''
        compressed = detail['CompressedCidrIpRanges']
        b = base64.b64decode(compressed)
        cstr = zlib.decompress(b, -zlib.MAX_WBITS)
        return cstr.decode().split(",")

    def _parse_associated_policies(self, location_filters, condition_policy_list):
        """
        Return the list of policy display names that reference at least one
        of the matched locations (in Include or Exclude sections).

        location_filters: list of (identifier, is_trusted, match_by) tuples
        """
        found_pols = []
        for pol in condition_policy_list:
            if not pol.policyDetail:
                continue
            parsed = json.loads(pol.policyDetail[0])
            if not parsed.get('Conditions') or not parsed.get('Conditions').get('Locations'):
                continue
            cloc = parsed['Conditions']['Locations']

            pol_added = False
            for section in [cloc.get('Include', []), cloc.get('Exclude', [])]:
                if pol_added:
                    break
                for i in section:
                    if pol_added:
                        break
                    locs = i.get('Locations', [])
                    for identifier, loc_trusted, match_by in location_filters:
                        if match_by == 'id':
                            if identifier in locs or (loc_trusted and 'AllTrusted' in locs):
                                found_pols.append(pol.displayName)
                                pol_added = True
                                break
                        elif match_by == 'displayname':
                            names = self._translate_locations(locs)
                            if any(n.lower() == identifier.lower() for n in names):
                                found_pols.append(pol.displayName)
                                pol_added = True
                                break
        return found_pols

    # -------------------------------------------------------------------------
    # User-filter parsers
    # -------------------------------------------------------------------------

    def _filter_parse_ucrit(self, crit, user, include=True):
        is_concerned = False
        funct = {
            'Applications': self._get_application,
            'Users': self._get_user,
            'Groups': self._get_group,
            'Roles': self._get_role,
            'ServicePrincipals': self._get_serviceprincipal,
            'ServicePrincipalFilterRule': self._get_serviceprincipalrule,
            'GuestsOrExternalUsers': self._translate_guestsexternal
        }
        color_start = '+[green]' if include else '-[red]'
        color_end = '[/green]' if include else '[/red]'

        ot = ''
        for ctype, clist in crit.items():
            if 'All' in clist:
                ot += f'{color_start}All users{color_end}'
                is_concerned = True
                break
            if 'None' in clist:
                ot += 'Nobody'
                break
            if 'Guests' in clist:
                ot += 'Guest users'
            try:
                objects = funct[ctype](clist)
            except KeyError:
                raise Exception('Unsupported criterium type: {0}'.format(ctype))

            if not objects:
                continue

            if ctype == 'Users':
                for uobj in objects:
                    if user.objectId == uobj.objectId:
                        ot += f'{color_start}{uobj.displayName}{color_end}'
                        is_concerned = True

            elif ctype == 'ServicePrincipals':
                ot += 'Service Principals: '
                ot += ', '.join([uobj.displayName for uobj in objects])

            elif ctype == 'Groups':
                treated_groups = []
                for uobj in objects:
                    if uobj.objectId in treated_groups:
                        continue
                    for group in user.memberOf:
                        if group.objectId == uobj.objectId:
                            ot += f'{color_start}{uobj.displayName}{color_end}'
                            is_concerned = True
                            break
                        for nestedGroup in group.memberGroups:
                            if nestedGroup.objectId == uobj.objectId:
                                ot += f'{color_start}{group.displayName}>{uobj.displayName}{color_end}'
                                is_concerned = True
                                break
                    if is_concerned:
                        break
                    treated_groups.append(uobj.objectId)
                    for uobjsubgroups in uobj.memberGroups:
                        if uobjsubgroups.objectId in treated_groups:
                            continue
                        for group in user.memberOf:
                            if group.objectId == uobjsubgroups.objectId:
                                ot += f'{color_start}{uobj.displayName}>{uobjsubgroups.displayName}{color_end}'
                                is_concerned = True
                                break
                            for nestedGroup in group.memberGroups:
                                if nestedGroup.objectId == uobjsubgroups.objectId:
                                    ot += f'{color_start}{group.displayName}>{uobj.displayName}>{uobjsubgroups.displayName}{color_end}'
                                    is_concerned = True
                                    break
                        treated_groups.append(uobjsubgroups.objectId)
                    if is_concerned:
                        break

            elif ctype == 'Roles':
                for uobj in objects:
                    for role in user.memberOfRole:
                        if role.objectId == uobj.objectId:
                            ot += f'{color_start}{uobj.displayName}{color_end}'
                            is_concerned = True

            elif ctype == 'GuestsOrExternalUsers':
                ot += 'Guests or external user types: '
                ot += ', '.join(objects)

            elif ctype == 'ServicePrincipalFilterRule':
                ot += 'Service Principals matching the following filter: '
                ot += ', '.join(objects)

            else:
                raise Exception('Unsupported criterium type: {0}'.format(ctype))

        return ot, is_concerned

    def _filter_parse_who(self, cond, user):
        ucond = cond['Users']
        ot = ''
        cond_match = False

        if (
                len(ucond['Include']) == 1
                and 'Nobody' in self._parse_ucrit(ucond['Include'][0])
                and 'ServicePrincipals' in cond
        ):
            # Service principal-scoped policy
            spcond = cond['ServicePrincipals']
            for icrit in spcond['Include']:
                ot += self._parse_ucrit(icrit)
            if 'Exclude' in spcond:
                ot += '\nExcluding: '
                ot += ' '.join([self._parse_ucrit(icrit) for icrit in spcond['Exclude']])
        else:
            for icrit in ucond['Include']:
                result, is_concerned = self._filter_parse_ucrit(icrit, user, include=True)
                if result:
                    ot += result + '\n'
                if is_concerned:
                    cond_match = True
            if 'Exclude' in ucond:
                for icrit in ucond['Exclude']:
                    result, is_concerned = self._filter_parse_ucrit(icrit, user, include=False)
                    if result:
                        ot += result + '\n'
                    if is_concerned:
                        cond_match = False

        return ot, cond_match

    # -------------------------------------------------------------------------
    # Main entry point helpers
    # -------------------------------------------------------------------------

    def _resolve_user(self, user_filter_upn):
        """Return the User object matching the UPN filter, or None."""
        if user_filter_upn is None:
            return None
        user = self.session.query(User).filter(User.userPrincipalName.like(user_filter_upn)).first()
        if user is None:
            self.console.print('[red]User not found[/red]')
        return user

    def _resolve_service_principals(self, resources_filter, resources_id_filter):
        """Return the list of ServicePrincipal objects matching the resource filter."""
        service_principals = None
        if resources_id_filter is not None:
            service_principals = self.session.query(ServicePrincipal).filter(
                ServicePrincipal.appId.like(resources_id_filter)
            ).all()
        elif resources_filter is not None:
            service_principals = self.session.query(ServicePrincipal).filter(
                ServicePrincipal.displayName.like(resources_filter)
            ).all()
        if service_principals:
            for sp in service_principals:
                self.console.print(f'Filter by resource: {sp.displayName}')
        return service_principals

    def _find_matching_locations(self, ip_str=None, country_code=None):
        """
        Search all Named Locations and return a list of
        (location_name, policy_identifier, is_trusted, match_reason) tuples.

        Matching strategy:
        - ip_str only       : match on CIDR ranges
        - country_code only : match on CountryIsoCodes
        - both              : match on CIDR ranges OR CountryIsoCodes
        """
        import ipaddress

        ip = None
        if ip_str is not None:
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                self.console.print(f'[red]Invalid IP address: {ip_str}[/red]')
                return []

        if ip is None and country_code is None:
            self.console.print('[red]At least one of --ip or --country must be provided[/red]')
            return []

        matches = []

        for policy in self.session.query(Policy).filter(
                Policy.policyType == 6
        ).order_by(Policy.displayName):
            for pdetail in policy.policyDetail:
                detaildata = json.loads(pdetail)
                oldpolicy = 'KnownNetworkPolicies' in detaildata
                detail = detaildata['KnownNetworkPolicies'] if oldpolicy else json.loads(policy.policyDetail[0])

                if not detail:
                    continue

                categories = detail.get('Categories') or []
                is_trusted = 'trusted' in ', '.join(categories).lower()
                location_name = detail.get('NetworkName', policy.displayName) if oldpolicy else policy.displayName
                policy_identifier = detail.get('NetworkId') if oldpolicy else policy.policyIdentifier

                matched = False
                match_reason = ''

                # Check CIDR ranges (only if --ip was provided)
                if ip is not None:
                    cidrs = detail.get('CidrIpRanges') or [] if oldpolicy else (
                        self._parse_compressed_cidr(detail) or []
                    )
                    for cidr in cidrs:
                        cidr = cidr.strip()
                        if not cidr:
                            continue
                        try:
                            if ip in ipaddress.ip_network(cidr, strict=False):
                                matched = True
                                match_reason = f'CIDR {cidr}'
                                break
                        except ValueError:
                            continue

                # Check Country ISO codes (only if --country was provided)
                if not matched and country_code is not None:
                    country_codes = detail.get('CountryIsoCodes') or []
                    applies_to_unknown = detail.get('ApplyToUnknownCountry', False)

                    if country_code.upper() in country_codes:
                        matched = True
                        match_reason = f'Country {country_code.upper()}'
                    elif applies_to_unknown and ip is None:
                        # ApplyToUnknownCountry only relevant when no IP is provided
                        matched = True
                        match_reason = 'Unknown country (ApplyToUnknownCountry=True)'

                if matched:
                    matches.append((location_name, policy_identifier, is_trusted, match_reason))

        return matches

    def _build_cap_table(self):
        """Create and return the Rich table for CAP policies."""
        table = Table(
            show_header=True,
            header_style="b",
            title="Conditional Access Policies",
            show_lines=True
        )
        for col in [
            "Name", "Match", "Policy state", "Users", "Resources",
            "On platforms", "Device filter", "Using client", "At locations",
            "Sign-in risks", "Authentication flows", "Controls", "Session controls"
        ]:
            table.add_column(col)
        return table

    def _process_policy(self, policy, user, service_principals,
                        platform_filter, location_filters, is_trusted,
                        client_filter, match_reporting,
                        match_only, control_only,
                        location_filter_active,
                        cap_table):
        """
        Parse a single CAP policy and add a row to cap_table if applicable.
        Returns (row_added, controls_groups).
        controls_groups is None if the policy does not fully match.
        """
        detail = json.loads(policy.policyDetail[0])
        name = policy.displayName

        state = detail.get('State', '')
        display_name = name
        if state == 'Reporting':
            display_name += ' (Report only)'
        elif state != 'Enabled':
            display_name += ' (Disabled)'

        conditions = detail.get('Conditions')
        if conditions is None:
            return False, None

        who, user_match           = self._filter_parse_who(conditions, user)
        applications, app_match   = self._parse_application(conditions, service_principals)
        authflows                 = self._parse_authflows(conditions)
        platforms, platform_match = self._parse_platform(conditions, platform_filter)
        locations, location_match = self._parse_locations(
            conditions, location_filters, is_trusted,
            location_filter_active=location_filter_active
        )
        clients, client_match     = self._parse_clients(conditions, client_filter)
        signinrisks               = self._parse_signinrisks(conditions)
        sessioncontrols           = self._parse_sessioncontrols(detail)
        devices                   = self._parse_devices(conditions)
        controls_str, controls_groups = self._parse_controls(detail['Controls']) if 'Controls' in detail else ('', [])

        # Policy state styling
        status_match = True
        if state == 'Enabled':
            status_display = f'[green]{state}[/green]'
        elif state == 'Disabled':
            status_display = f'[red]{state}[/red]'
            status_match = False
        elif state == 'Reporting':
            status_display = f'[yellow]{state}[/yellow]'
            if not match_reporting:
                status_match = False
        else:
            status_display = state

        # Build match flags string
        match_flags = ''
        if user_match:     match_flags += '[U]'
        if platform_match: match_flags += '[P]'
        if client_match:   match_flags += '[C]'
        if app_match:      match_flags += '[R]'
        if location_match: match_flags += '[L]'

        match_condition = (
                user_match and platform_match and client_match
                and app_match and location_match and status_match
        )
        match_display = f'[green]{match_flags}[/green]' if match_condition else '[red]X[/red]'

        # Apply visibility filters
        show_row = True
        if match_only and not match_condition:
            show_row = False
        if control_only and controls_str == '':
            show_row = False

        if not show_row:
            return False, None

        cap_table.add_row(
            display_name, match_display, status_display,
            who, applications, platforms, devices, clients,
            locations, signinrisks, authflows, controls_str, sessioncontrols
        )

        # Return controls_groups only if policy fully matches
        return True, controls_groups if match_condition else None

    # -------------------------------------------------------------------------
    # Public main method
    # -------------------------------------------------------------------------

    def main(
            self,
            user_filter_upn=None,
            match_only=False,
            control_only=False,
            match_reporting=False,
            platform_filter=None,
            client_filter=None,
            resources_filter=None,
            resources_id_filter=None,
            location_filter=None,
            is_trusted=False,
            ip_filter=None,
            country_filter=None
    ):
        user = self._resolve_user(user_filter_upn)
        if user_filter_upn is not None and user is None:
            return

        service_principals    = self._resolve_service_principals(resources_filter, resources_id_filter)
        condition_policy_list = self.session.query(Policy).filter(Policy.policyType == 18).all()

        # --- Location / IP / Country resolution ---
        location_filters       = []
        location_filter_active = False

        # Manual location filter via -l / -t (lower priority, overridden by --ip / --country)
        if location_filter is not None:
            location_filters       = [(location_filter, is_trusted, 'displayname')]
            location_filter_active = True
        elif is_trusted:
            # -t alone without -l: force is_trusted flag without filtering on a specific location
            # is_trusted remains True, location_filter_active remains False
            pass

        # IP / Country resolution (higher priority, overrides -l / -t)
        if ip_filter is not None or country_filter is not None:
            location_filter_active = True
            location_filters       = []  # Reset: --ip / --country takes over

            if ip_filter is None and country_filter is not None:
                self.console.print(
                    f'[cyan]No IP provided — filtering on country code: '
                    f'{country_filter.upper()} only[/cyan]'
                )

            matches = self._find_matching_locations(
                ip_str=ip_filter,
                country_code=country_filter
            )

            if not matches:
                self.console.print(
                    f'[yellow]No named location found'
                    f'{f" for IP: {ip_filter}" if ip_filter else ""}'
                    f'{f" / country: {country_filter.upper()}" if country_filter else ""}'
                    f' — continuing with location=None, trusted=False[/yellow]'
                )
            else:
                label = ''
                if ip_filter:
                    label += f'IP {ip_filter}'
                if country_filter:
                    label += f'{" / " if ip_filter else ""}country {country_filter.upper()}'

                self.console.print(f'\n[cyan]{label} matches the following locations:[/cyan]')
                for loc_name, loc_id, loc_trusted, match_reason in matches:
                    trusted_label = '[green]trusted[/green]' if loc_trusted else '[red]not trusted[/red]'
                    self.console.print(
                        f'  - {loc_name} ({loc_id})'
                        f' — {trusted_label}'
                        f' — matched by: [cyan]{match_reason}[/cyan]'
                    )
                    location_filters.append((loc_id, loc_trusted, 'id'))

                if len(matches) > 1:
                    self.console.print(
                        f'[cyan]All {len(matches)} locations will be evaluated '
                        f'simultaneously (Microsoft behavior)[/cyan]'
                    )

        # Build and populate the CAP table
        cap_table  = self._build_cap_table()
        nb_results = 0

        # Collect all controls applied across matching policies
        applied = {
            'deny':             False,
            'mfa':              False,
            'compliant_device': False,
            'domain_joined':    False,
            'approved_app':     False,
            'app_protection':   False,
            'password_change':  False,
            'auth_context':     False,
            'session':          [],  # list of session control strings
            'auth_strength':    [],  # list of auth strength strings
            'any_of':           [],  # list of sets: controls where any one is sufficient
        }

        for policy in self.session.query(Policy).filter(
                Policy.policyType == 18
        ).order_by(Policy.displayName):
            added, matched_groups = self._process_policy(
                policy, user, service_principals,
                platform_filter, location_filters, is_trusted,
                client_filter, match_reporting,
                match_only, control_only,
                location_filter_active,
                cap_table
            )
            if added:
                nb_results += 1

            if matched_groups:
                for group in matched_groups:
                    if len(group) == 1:
                        # Single control in group: mandatory (AND)
                        ctrl = group[0]
                        if ctrl == 'Deny logon':
                            applied['deny'] = True
                        elif ctrl == 'MFA':
                            applied['mfa'] = True
                        elif ctrl == 'Require compliant device':
                            applied['compliant_device'] = True
                        elif ctrl == 'Require domain-joined device (Hybrid Azure AD)':
                            applied['domain_joined'] = True
                        elif ctrl == 'Require approved client app':
                            applied['approved_app'] = True
                        elif ctrl == 'Require app protection policy':
                            applied['app_protection'] = True
                        elif ctrl == 'Require password change':
                            applied['password_change'] = True
                        elif ctrl == 'Require authentication context':
                            applied['auth_context'] = True
                        elif any(s in ctrl for s in ['MFA', 'Passwordless', 'Phishing-resistant']):
                            # Auth strength counts as MFA-equivalent
                            if ctrl not in applied['auth_strength']:
                                applied['auth_strength'].append(ctrl)
                    else:
                        # Multiple controls in group: any one is sufficient (OR)
                        group_set = set(group)
                        if group_set not in applied['any_of']:
                            applied['any_of'].append(group_set)

                # Collect session controls from this matching policy
                detail = json.loads(policy.policyDetail[0])
                sc = self._parse_sessioncontrols(detail)
                if sc and sc not in applied['session']:
                    applied['session'].append(sc)

        # Build summary parts to check if there is anything to display
        summary_parts = []
        if applied['deny']:             summary_parts.append('deny')
        if applied['mfa']:              summary_parts.append('mfa')
        if applied['auth_strength']:    summary_parts.append('auth_strength')
        if applied['compliant_device']: summary_parts.append('compliant_device')
        if applied['domain_joined']:    summary_parts.append('domain_joined')
        if applied['approved_app']:     summary_parts.append('approved_app')
        if applied['app_protection']:   summary_parts.append('app_protection')
        if applied['password_change']:  summary_parts.append('password_change')
        if applied['auth_context']:     summary_parts.append('auth_context')

        # Display results
        if nb_results > 0:
            self.console.print(cap_table)

        label = user_filter_upn or ''

        if nb_results == 0:
            self.console.print(
                f'{label} : [green]FREEDOM !!!!![/green]'
            )
        elif summary_parts or applied['any_of'] or applied['session']:
            self.console.print(f'\n[bold]Applied controls for {label}:[/bold]')

            if applied['deny']:
                self.console.print('  [red]✗ Deny logon[/red]')
            if applied['mfa']:
                self.console.print('  [yellow]✓ MFA required[/yellow]')
            for strength in applied['auth_strength']:
                self.console.print(f'  [yellow]✓ {strength}[/yellow]')
            if applied['compliant_device']:
                self.console.print('  [yellow]✓ Compliant device required[/yellow]')
            if applied['domain_joined']:
                self.console.print('  [yellow]✓ Domain-joined device required (Hybrid Azure AD)[/yellow]')
            if applied['approved_app']:
                self.console.print('  [yellow]✓ Approved client app required[/yellow]')
            if applied['app_protection']:
                self.console.print('  [yellow]✓ App protection policy required[/yellow]')
            if applied['password_change']:
                self.console.print('  [yellow]✓ Password change required[/yellow]')
            if applied['auth_context']:
                self.console.print('  [yellow]✓ Authentication context required[/yellow]')

            # any_of groups: user can satisfy with any one control
            for group_set in applied['any_of']:
                self.console.print(
                    '  [yellow]✓ Any of: ' + ' / '.join(sorted(group_set)) + '[/yellow]'
                )

            for sc in applied['session']:
                self.console.print(f'  [cyan]⚙ Session: {sc}[/cyan]')
        else:
            self.console.print(f'\n{label} : [green]No controls applied[/green]')


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def add_args(parser):
    parser.add_argument('-u', '--upn',
                        action='store', default=None,
                        help='User principal name filter')
    parser.add_argument('-m', '--match',
                        action='store_true', default=False,
                        help='Show matching rules only')
    parser.add_argument('-c', '--control',
                        action='store_true', default=False,
                        help='Show control rules only')
    parser.add_argument('-r', '--reporting',
                        action='store_true', default=False,
                        help='Show reporting as a matching rule')
    parser.add_argument('-p', '--platform',
                        action='store', default=None,
                        choices=["Android", "iOS", "macOS", "Windows_Phone",
                                 "Windows", "Linux", "ChromeOS", "Unknown"],
                        help='Filter on a platform')
    parser.add_argument('-l', '--location',
                        action='store', default=None,
                        help='Filter on a location (by display name)')
    parser.add_argument('-t', '--trusted_location',
                        action='store_true', default=False,
                        help='Mark the location as trusted')
    parser.add_argument('--client',
                        action='store', default=None,
                        choices=["Browser", "Legacy Clients",
                                 "Exchange ActiveSync", "Mobile and Desktop clients"],
                        help='Filter on client type')
    parser.add_argument('--resource',
                        action='store', default=None,
                        help='Filter on resource display name')
    parser.add_argument('--resource_id',
                        action='store', default=None,
                        help='Filter on resource app ID')
    parser.add_argument('--ip',
                        action='store', default=None,
                        help='Filter on a source IP address (matched against CIDR ranges)')
    parser.add_argument('--country',
                        action='store', default=None,
                        metavar='ISO2',
                        help='ISO 3166-1 alpha-2 country code (e.g. NG, RU, FR) — can be used alone or combined with --ip')


def main(args=None):
    if args is None:
        parser = argparse.ArgumentParser(
            add_help=True,
            description='ROADrecon CAP analysis plugin',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )
        parser.add_argument('-d', '--database',
                            action='store', default='roadrecon.db',
                            help='Database file or SQLAlchemy URL')
        add_args(parser)
        args = parser.parse_args()

    db_url  = database.parse_db_argument(args.database)
    session = database.get_session(database.init(dburl=db_url))
    plugin  = CapFilterPlugin(session)
    plugin.main(
        user_filter_upn=args.upn,
        match_only=args.match,
        control_only=args.control,
        match_reporting=args.reporting,
        platform_filter=args.platform,
        client_filter=args.client,
        resources_filter=args.resource,
        resources_id_filter=args.resource_id,
        location_filter=args.location,
        is_trusted=args.trusted_location,
        ip_filter=args.ip,
        country_filter=args.country
    )


if __name__ == '__main__':
    main()
