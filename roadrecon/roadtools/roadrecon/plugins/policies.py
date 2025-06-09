'''
Conditional Access Policies parsing plugin
Contributed by Dirk-jan Mollema and Adrien Raulot (Fox-IT)
Uses code from ldapdomaindump under MIT license

The code here isn't very tidy, don't use it as a perfect example

Copyright 2020 - MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''
import json
import os
import codecs
import argparse
import pprint
import base64
import zlib
from html import escape
from roadtools.roadlib.metadef.database import ServicePrincipal, User, Policy, Application, Group, DirectoryRole
import roadtools.roadlib.metadef.database as database

# Required property - plugin description
DESCRIPTION = '''
Parse Conditional Access policies and export those to a file called caps.html
'''

STYLE_CSS = '''
tbody th {
    border: 1px solid #000;
}
tbody td {
    border: 1px solid #ababab;
    border-spacing: 0px;
    padding: 4px;
    border-collapse: collapse;
}
body {
    font-family: verdana;
}
table {
    font-size: 13px;
    border-collapse: collapse;
    width: 100%;
}
tbody tr:nth-child(odd) td {
    background-color: #eee;
}
tbody tr:hover td {
    background-color: lightblue;
}
thead td {
    font-size: 19px;
    font-weight: bold;
    padding: 10px 0px;
}
'''

class AccessPoliciesPlugin():
    """
    Conditional Access Policies parsing plugin
    """
    def __init__(self, session, file):
        self.session = session
        self.file = file

    def write_html(self, rel_outfile, body, genfunc=None, genargs=None, closeTable=True):
        outfile = os.path.join('.', rel_outfile)
        with codecs.open(outfile, 'w', 'utf8') as of:
            of.write('<!DOCTYPE html>\n<html>\n<head><meta charset="UTF-8">')
            #Include the style:
            of.write('<style type="text/css">')
            of.write(STYLE_CSS)
            of.write('</style>')
            of.write('</head><body>')
            #If the generator is not specified, we should write the HTML blob directly
            if genfunc is None:
                of.write(body)
            else:
                for tpart in genfunc(*genargs):
                    of.write(tpart)
            #Does the body contain an open table?
            if closeTable:
                of.write('</table>')
            of.write('</body></html>')

    def _get_group(self, gid):
        if isinstance(gid, list):
            return self.session.query(Group).filter(Group.objectId.in_(gid)).all()
        return self.session.query(Group).filter(Group.objectId == gid).first()

    def _get_application(self, aid):
        if isinstance(aid, list):
            res = self.session.query(Application).filter(Application.appId.in_(aid)).all()
            # if no result, query the ServicePrincipals
            if len(res) != len(aid):
                return self.session.query(ServicePrincipal).filter(ServicePrincipal.appId.in_(aid)).all()
            else:
                return res
        else:
            res = self.session.query(Application).filter(Application.appId == aid).first()
            # if no result, query the ServicePrincipals
            if res is None or len(res) == 0:
                return self.session.query(ServicePrincipal).filter(ServicePrincipal.appId == aid).first()

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

    def _print_object(self, obj):
        if obj is None:
            return
        if isinstance(obj, list):
            for objitem in obj:
                self._print_object(objitem)
        else:
            print('\t  ', end='')
            print(obj.objectId
                  + ': '
                  + obj.displayName
                  , end='')
            try:
                print(' (' + obj.appId + ')', end='')
                print(' (' + obj.objectType+ ')', end='')
            except:
                pass
            print()

    def _translate_guestsexternal(self, value):
        return [value['GuestOrExternalUserTypes'], ]

    def _translate_authstrength(self, authstrengthguid):
        built_in = {
            '00000000-0000-0000-0000-000000000002': 'Multi-factor authentication',
            '00000000-0000-0000-0000-000000000003': 'Passwordless MFA',
            '00000000-0000-0000-0000-000000000004': 'Phishing-resistant MFA'
        }
        try:
            return built_in[authstrengthguid]
        except KeyError:
            return f"Unknown authentication strengh policy: {authstrengthguid} (probably custom)"

    def _parse_ucrit(self, crit):
        funct = {
            'Applications' : self._get_application,
            'Users' : self._get_user,
            'Groups' : self._get_group,
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
            if len(objects) > 0:
                if ctype == 'Users':
                    ot += 'Users: '
                    ot += ', '.join([escape(uobj.displayName) for uobj in objects])
                elif ctype == 'ServicePrincipals':
                    ot += 'Service Principals: '
                    ot += ', '.join([escape(uobj.displayName) for uobj in objects])
                elif ctype == 'Groups':
                    ot += 'Users in groups: '
                    ot += ', '.join([escape(uobj.displayName) for uobj in objects])
                elif ctype == 'Roles':
                    ot += 'Users in roles: '
                    ot += ', '.join([escape(uobj.displayName) for uobj in objects])
                elif ctype == 'GuestsOrExternalUsers':
                    ot += 'Guests or external user types: '
                    ot += ', '.join([escape(uobj) for uobj in objects])
                elif ctype == 'ServicePrincipalFilterRule':
                    ot += 'Service Principals matching the following filter: '
                    ot += ', '.join([escape(sprule) for sprule in objects])
                else:
                    raise Exception('Unsupported criterium type: {0}'.format(ctype))
            else:
                if not 'Guests' in clist:
                    ot += 'Unknown object(s) {0}'.format(', '.join(clist))
                    print('Warning: Not all object IDs could be resolved for this policy')
        return ot

    def _parse_appcrit(self, crit):
        ot = ''
        for ctype, clist in crit.items():
            if ctype == 'Acrs':
                ot += 'Action: '
                ot += ', '.join([escape(action) for action in clist])
            elif ctype == 'NetworkAccess':
                # clist should be a dict, for example {"TrafficProfiles":"Internet"}
                ot += 'Network access: '
                ot += ', '.join([f"{escape(action)}: {escape(target)}" for action, target in clist.items()])
            else:
                if 'All' in clist:
                    ot += 'All resources'
                    break
                if 'None' in clist:
                    ot += 'None'
                    break
                if 'Office365' in clist:
                    ot += 'All Office 365 applications '
                if 'MicrosoftAdminPortals' in clist:
                    ot += 'All Microsoft Admin Portals '
                objects = self._get_application(clist)
                if objects is not None: 
                    if len(objects) > 0:
                        if ctype == 'Applications':
                            ot += 'Resources: '
                            ot += ', '.join([escape(uobj.displayName) for uobj in objects])
        return ot

    def _parse_platform(self, cond):
        try:
            pcond = cond['DevicePlatforms']
        except KeyError:
            return ''
        ot = '<strong>Including</strong>: '

        for icrit in pcond['Include']:
            if 'All' in icrit['DevicePlatforms']:
                ot += 'All platforms'
            else:
                ot += ', '.join(icrit['DevicePlatforms'])

        if 'Exclude' in pcond:
            ot += '\n<br /><strong>Excluding</strong>: '

            for icrit in pcond['Exclude']:
                ot += ', '.join(icrit['DevicePlatforms'])
        return ot

    def _parse_devices(self, cond):
        try:
            pcond = cond['Devices']
        except KeyError:
            return ''
        ot = '<strong>Including</strong>: '

        for icrit in pcond['Include']:
            if 'DeviceStates' in icrit.keys():
                ot += 'Device states: '
                if 'All' in icrit['DeviceStates']:
                    ot += 'All'
                else:
                    ot += ' '.join(icrit['DeviceStates'])
            if 'DeviceRule' in icrit.keys():
                ot += 'Device rule: '
                if 'All' in icrit['DeviceRule']:
                    ot += 'All devices'
                else:
                    ot += icrit['DeviceRule']

        if 'Exclude' in pcond:
            ot += '\n<br /><strong>Excluding</strong>: '

            for icrit in pcond['Exclude']:
                if 'DeviceStates' in icrit.keys():
                    ot += 'Device states: '
                    if 'All' in icrit['DeviceStates']:
                        ot += 'All'
                    else:
                        ot += ' '.join(icrit['DeviceStates'])
                if 'DeviceRule' in icrit.keys():
                    ot += 'Device rule: '
                    if 'All' in icrit['DeviceRule']:
                        ot += 'All devices'
                    else:
                        ot += icrit['DeviceRule']
        return ot

    def _parse_locations(self, cond):
        try:
            lcond = cond['Locations']
        except KeyError:
            return ''
        ot = '<strong>Including</strong>: '

        for icrit in lcond['Include']:
            ot += self._parse_locationcrit(icrit)

        if 'Exclude' in lcond:
            ot += '\n<br /><strong>Excluding</strong>: '

            for icrit in lcond['Exclude']:
                ot += self._parse_locationcrit(icrit)
        return ot

    def _parse_signinrisks(self, cond):
        try:
            srcond = cond['SignInRisks']
        except KeyError:
            return ''

        ot = '<strong>Including</strong>: '
        for icrit in srcond['Include']:
            ot += ', '.join([escape(crit) for crit in icrit['SignInRisks']])

        if 'Exclude' in srcond:
            ot += '\n<br /><strong>Excluding</strong>: '
            for icrit in srcond['Exclude']:
                ot += ', '.join([escape(crit) for crit in icrit['SignInRisks']])

        return ot

    def _parse_locationcrit(self, crit):
        ot = ''
        for ctype, clist in crit.items():
            if 'AllTrusted' in clist:
                ot += 'All trusted locations'
                break
            if 'All' in clist:
                ot += 'All locations'
                break
            objects = self._translate_locations(clist)
            ot += 'Locations: '
            ot += ', '.join([escape(uobj) for uobj in objects])
        return ot

    def _translate_locations(self, locs):
        policies = self.session.query(Policy).filter(Policy.policyType == 6).all()
        out = []
        # Not sure if there can be multiple
        for policy in policies:
            for pdetail in policy.policyDetail:
                detaildata = json.loads(pdetail)
                if 'KnownNetworkPolicies' in detaildata and detaildata['KnownNetworkPolicies']['NetworkId'] in locs:
                    out.append(detaildata['KnownNetworkPolicies']['NetworkName'])
        # New format
        for loc in locs:
            policies = self.session.query(Policy).filter(Policy.policyType == 6, Policy.policyIdentifier == loc).all()
            for policy in policies:
                out.append(policy.displayName)
        return out

    def _parse_who(self, cond):
        ucond = cond['Users']
        ot = '<strong>Including</strong>: '

        if len(ucond['Include']) == 1 and 'Nobody' in self._parse_ucrit(ucond['Include'][0]) and 'ServicePrincipals' in cond:
            # Service Principal policy
            spcond = cond['ServicePrincipals']
            for icrit in spcond['Include']:
                ot += self._parse_ucrit(icrit)

            if 'Exclude' in spcond:
                ot += '\n<br /><strong>Excluding</strong>: '
                otl = []
                for icrit in spcond['Exclude']:
                    otl.append(self._parse_ucrit(icrit))
                ot += '<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; '.join(otl)

        else:
            for icrit in ucond['Include']:
                ot += self._parse_ucrit(icrit)

            if 'Exclude' in ucond:
                ot += '\n<br /><strong>Excluding</strong>: '
                otl = []
                for icrit in ucond['Exclude']:
                    otl.append(self._parse_ucrit(icrit))
                ot += '<br />&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; '.join(otl)
        return ot

    def _parse_application(self, cond):
        ucond = cond['Applications']
        ot = '<strong>Including</strong>: '

        for icrit in ucond['Include']:
            ot += self._parse_appcrit(icrit)

        if 'Exclude' in ucond:
            ot += '\n<br /><strong>Excluding</strong>: '

            for icrit in ucond['Exclude']:
                ot += self._parse_appcrit(icrit)
        return ot

    def _parse_authflows(self, cond):
        if not 'AuthFlows' in cond:
            return ''
        ucond = cond['AuthFlows']
        ot = '<strong>Flows included</strong>: '

        for icrit in ucond['Include']:
            for _, clist in icrit.items():
                ot += escape(', '.join(clist))
        return ot

    def _parse_associated_polcies(self,location_object,is_trusted_location,condition_policy_list):
        found_pols = []

        for pol in condition_policy_list:
            if not pol.policyDetail:
                continue
            parsed = json.loads(pol.policyDetail[0])
            if not parsed.get('Conditions') or not parsed.get('Conditions').get('Locations'):
                continue

            cloc = parsed.get('Conditions').get('Locations')
            incl = cloc.get('Include') or []
            excl = cloc.get('Exclude') or []
            for i in incl:
                if location_object in i.get('Locations') or (is_trusted_location and "AllTrusted" in i.get('Locations')):
                    found_pols.append(escape(pol.displayName))

            for i in excl:
                if location_object in i.get('Locations') or (is_trusted_location and "AllTrusted" in i.get('Locations')):
                    found_pols.append(escape(pol.displayName))



        return found_pols


    def _parse_controls(self, controls):
        acontrols = []
        for c in controls:
            if 'Control' in c:
                acontrols.append(', '.join(c['Control']))
            if 'AuthStrengthIds' in c:
                acontrols.append(', '.join([self._translate_authstrength(authstrengthguid) for authstrengthguid in c['AuthStrengthIds']]))
        if 'Block' in acontrols:
            ot = '<strong>Deny logon</strong>'
            return ot
        if len(controls) > 1:
            ot = '<strong>Requirements (all)</strong>: '
        else:
            ot = '<strong>Requirements (any)</strong>: '
        ot += ', '.join(acontrols)
        return ot

    def _parse_clients(self, cond):
        if not 'ClientTypes' in cond:
            return ''
        ucond = cond['ClientTypes']
        ot = '<strong>Including</strong>: '

        for icrit in ucond['Include']:
            ot += ', '.join(list({escape(self._translate_clienttype(crit)) for crit in icrit['ClientTypes']}))

        return ot

    def _translate_clienttype(self, client):
        if client in ['EasSupported', 'EasUnsupported']:
            return 'Exchange ActiveSync'
        if client in ['OtherLegacy', 'LegacySmtp', 'LegacyPop', 'LegacyImap', 'LegacyMapi', 'LegacyOffice']:
            return 'Legacy Clients'
        if client == 'Native':
            return 'Mobile and Desktop clients'
        return client

    def _parse_sessioncontrols(self, cond):
        if not 'SessionControls' in cond:
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

    def _parse_compressed_cidr(self,detail):
        if not 'CompressedCidrIpRanges' in detail:
            return ''
        compressed = detail['CompressedCidrIpRanges']
        b = base64.b64decode(compressed)
        cstr = zlib.decompress(b, -zlib.MAX_WBITS)
        decoded_cidrs = escape(cstr.decode()).split(",")
        return decoded_cidrs


    def main(self, should_print=False):
        pp = pprint.PrettyPrinter(indent=4)
        ol = []
        oloc = []
        html = '<h1>Policies</h1><table>'
        condition_policy_list = self.session.query(Policy).filter(Policy.policyType == 18)
        for policy in self.session.query(Policy).filter(Policy.policyType == 18).order_by(Policy.displayName):
            out = {}
            out['name'] = escape(policy.displayName)
            if should_print:
                print()
                print('####################')
                print(policy.displayName)
                print(policy.objectId)
            detail = json.loads(policy.policyDetail[0])
            if detail['State'] == 'Reporting':
                out['name'] += ' (<i>Report only</i>)'
            elif detail['State'] != 'Enabled':
                out['name'] += ' (<i>Disabled</i>)'
            if should_print:
                pp.pprint(detail)
            try:
                conditions = detail['Conditions']
            except KeyError:
                conditions = None
            if conditions is None:
                if should_print:
                    print('Invalid policy - no conditions')
                continue
            out['who'] = self._parse_who(conditions)
            out['status'] = escape(detail['State'])
            out['applications'] = self._parse_application(conditions)
            out['authflows'] = self._parse_authflows(conditions)
            out['platforms'] = self._parse_platform(conditions)
            out['locations'] = self._parse_locations(conditions)
            out['clients'] = self._parse_clients(conditions)
            out['signinrisks'] = self._parse_signinrisks(conditions)
            out['sessioncontrols'] = self._parse_sessioncontrols(detail)
            out['devices'] = self._parse_devices(conditions)

            try:
                out['controls'] = self._parse_controls(detail['Controls'])
            except KeyError:
                out['controls'] = ''
            ol.append(out)
            if should_print:
                print('####################')



        for policy in self.session.query(Policy).filter(Policy.policyType == 6).order_by(Policy.displayName):
            loc = {}
            loc['name'] = escape(policy.displayName)
            if should_print:
                print()
                print('####################')
                print(policy.displayName)
                print(policy.objectId)
            detail = None
            oldpolicy = False

            for pdetail in policy.policyDetail:
                detaildata = json.loads(pdetail)
                if 'KnownNetworkPolicies' in detaildata:
                    detail = detaildata['KnownNetworkPolicies']
                    oldpolicy = True

            if not oldpolicy:
                # New format
                detail = json.loads(policy.policyDetail[0])

                if should_print:
                    pp.pprint(detail)
                if not detail:
                    continue

                loc['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
                loc['appliestounknowncountry'] = escape(str(detail.get("ApplyToUnknownCountry"))) if detail.get("ApplyToUnknownCountry") is not None else False
                loc['ipranges'] = "\n<br />".join(self._parse_compressed_cidr(detail))
                loc['categories'] = escape(", ".join(detail.get("Categories"))) if detail.get("Categories") is not None else ""
                loc['associated_policies'] = "\n<br />".join(self._parse_associated_polcies(policy.policyIdentifier,loc['trusted'],condition_policy_list))
                loc['country_codes'] =  escape(", ".join(detail.get("CountryIsoCodes"))) if detail.get("CountryIsoCodes") else None
                if should_print:
                    print(self._parse_compressed_cidr(detail))
            else:
                # Old format
                if should_print:
                    pp.pprint(detail)
                if not detail:
                    continue

                loc['name'] = escape(detail.get("NetworkName"))
                loc['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
                loc['appliestounknowncountry'] = escape(str(detail.get("ApplyToUnknownCountry"))) if detail.get("ApplyToUnknownCountry") is not None else False
                loc['ipranges'] = "\n<br />".join(detail.get('CidrIpRanges')) if detail.get("CidrIpRanges") else ""
                loc['categories'] = escape(", ".join(detail.get("Categories"))) if detail.get("Categories") is not None else ""
                loc['associated_policies'] = "\n<br />".join(self._parse_associated_polcies(detail.get('NetworkId'),loc['trusted'],condition_policy_list))
                loc['country_codes'] =  escape(", ".join(detail.get("CountryIsoCodes"))) if detail.get("CountryIsoCodes") else None


            oloc.append(loc)




        for out in ol:
            table = '<thead><tr><td colspan="2">{0}</td></tr></thead><tbody>'.format(out['name'])
            table += '<tr><td>Applies to</td><td>{0}</td></tr>'.format(out['who'])
            if out['status'] != 'Enabled':
                table += '<tr><td>Policy state</td><td>{0}</td></tr>'.format(out['status'])
            table += '<tr><td>Resources</td><td>{0}</td></tr>'.format(out['applications'])
            if out['platforms'] != '':
                table += '<tr><td>On platforms</td><td>{0}</td></tr>'.format(out['platforms'])
            if out['devices'] != '':
                table += '<tr><td>Device filter</td><td>{0}</td></tr>'.format(out['devices'])
            if out['clients'] != '':
                table += '<tr><td>Using clients</td><td>{0}</td></tr>'.format(out['clients'])
            if out['locations'] != '':
                table += '<tr><td>At locations</td><td>{0}</td></tr>'.format(out['locations'])
            if out['signinrisks'] != '':
                table += '<tr><td>Sign-in risks</td><td>{0}</td></tr>'.format(out['signinrisks'])
            if out['authflows'] != '':
                table += '<tr><td>Authentication flows</td><td>{0}</td></tr>'.format(out['authflows'])
            if out['controls'] != '':
                table += '<tr><td>Controls</td><td>{0}</td></tr>'.format(out['controls'])
            if out['sessioncontrols'] != '':
                table += '<tr><td>Session controls</td><td>{0}</td></tr>'.format(out['sessioncontrols'])
            table += '</tbody>'
            html += table
        html += '</table>'
        if len(oloc) > 0:
            html += "<h1>Named Locations</h1><table>"
            for loc in oloc:
                table = '<thead><tr><td colspan="2">{0}</td></tr></thead><tbody>'.format(loc['name'])
                table += '<tr><td>Trusted</td><td>{0}</td></tr>'.format(str(loc['trusted']))
                table += '<tr><td>Apply to unknown country</td><td>{0}</td></tr>'.format(loc['appliestounknowncountry'])
                table += '<tr><td>IP ranges</td><td>{0}</td></tr>'.format(loc['ipranges'])
                if(loc['categories']):
                    table += '<tr><td>Categories</td><td>{0}</td></tr>'.format(loc['categories'])

                if(loc['associated_policies']):
                    table += '<tr><td>Associated Policies</td><td>{0}</td></tr>'.format(loc['associated_policies'])

                if(loc['country_codes']):
                    table += '<tr><td>Country ISO Codes</td><td>{0}</td></tr>'.format(loc['country_codes'])

                table += "</tbody>"

                html += table 

            html += "</table>"
        self.write_html(self.file, html)
        print('Results written to {0}'.format(self.file))

def add_args(parser):
    parser.add_argument('-f',
                        '--file',
                        action='store',
                        help='Output file (default: caps.html)',
                        default='caps.html')
    parser.add_argument('-p',
                        '--print',
                        action='store_true',
                        help='Also print details to the console')
def main(args=None):
    if args is None:
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon policies to HTML plugin', formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('-d',
                            '--database',
                            action='store',
                            help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools',
                            default='roadrecon.db')
        add_args(parser)
        args = parser.parse_args()
    db_url = database.parse_db_argument(args.database)
    session = database.get_session(database.init(dburl=db_url))
    plugin = AccessPoliciesPlugin(session, args.file)
    plugin.main(args.print)

if __name__ == '__main__':
    main()
