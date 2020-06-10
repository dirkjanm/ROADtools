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
            if len(res) == 0:
                return self.session.query(ServicePrincipal).filter(ServicePrincipal.appId == aid).first()

    def _get_user(self, uid):
        if isinstance(uid, list):
            return self.session.query(User).filter(User.objectId.in_(uid)).all()
        return self.session.query(User).filter(User.objectId == uid).first()

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

    def _parse_ucrit(self, crit):
        funct = {
            'Applications' : self._get_application,
            'Users' : self._get_user,
            'Groups' : self._get_group,
            'Roles': self._get_role
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
                elif ctype == 'Groups':
                    ot += 'Users in groups: '
                    ot += ', '.join([escape(uobj.displayName) for uobj in objects])
                elif ctype == 'Roles':
                    ot += 'Users in roles: '
                    ot += ', '.join([escape(uobj.displayName) for uobj in objects])
                else:
                    raise Exception('Unsupported criterium type: {0}'.format(ctype))
            else:
                if not 'Guests' in clist:
                    raise Exception('Unmatched object(s): {0}'.format(','.join(clist)))
        return ot

    def _parse_appcrit(self, crit):
        ot = ''
        for ctype, clist in crit.items():
            if 'All' in clist:
                ot += 'All applications'
                break
            if 'Office365' in clist:
                ot += 'All Office 365 applications'
            objects = self._get_application(clist)
            if len(objects) > 0:
                if ctype == 'Applications':
                    ot += 'Applications: '
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

                if detaildata['KnownNetworkPolicies']['NetworkId'] in locs:
                    out.append(detaildata['KnownNetworkPolicies']['NetworkName'])
        return out

    def _parse_who(self, cond):
        ucond = cond['Users']
        ot = '<strong>Including</strong>: '

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

    def _parse_controls(self, controls):
        acontrols = [', '.join(c['Control']) for c in controls]
        if 'Block' in acontrols:
            ot = '<strong>Deny logon</strong>'
            return ot
        ot = '<strong>Requirements</strong>: '
        ot += ', '.join(acontrols)
        return ot

    def _parse_clients(self, cond):
        if not 'ClientTypes' in cond:
            return ''
        ucond = cond['ClientTypes']
        ot = '<strong>Including</strong>: '

        for icrit in ucond['Include']:
            ot += ', '.join([escape(crit) for crit in icrit['ClientTypes']])

        if 'Exclude' in ucond:
            ot += '\n<br /><strong>Excluding</strong>: '

            for icrit in ucond['Exclude']:
                ot += ', '.join([escape(crit) for crit in icrit['ClientTypes']])
        return ot

    def main(self, should_print=False):
        pp = pprint.PrettyPrinter(indent=4)
        ol = []
        html = '<table>'
        for policy in self.session.query(Policy).filter(Policy.policyType == 18):
            out = {}
            out['name'] = escape(policy.displayName)
            if should_print:
                print()
                print('####################')
                print(policy.displayName)
                print(policy.objectId)
            detail = json.loads(policy.policyDetail[0])
            if detail['State'] != 'Enabled':
                out['name'] += ' (<strong>Disabled</strong>)'
            if should_print:
                pp.pprint(detail)
            try:
                conditions = detail['Conditions']
            except KeyError:
                continue
            out['who'] = self._parse_who(conditions)
            out['applications'] = self._parse_application(conditions)
            out['platforms'] = self._parse_platform(conditions)
            out['locations'] = self._parse_locations(conditions)
            out['clients'] = self._parse_clients(conditions)

            try:
                controls = detail['Controls']
                out['controls'] = self._parse_controls(detail['Controls'])
            except KeyError:
                out['controls'] = ''
            ol.append(out)
            if should_print:
                print('####################')
        for out in ol:
            table = '<thead><tr><td colspan="2">{0}</td></tr></thead><tbody>'.format(out['name'])
            table += '<tr><td>Applies to</td><td>{0}</td></tr>'.format(out['who'])
            table += '<tr><td>Applications</td><td>{0}</td></tr>'.format(out['applications'])
            if out['platforms'] != '':
                table += '<tr><td>On platforms</td><td>{0}</td></tr>'.format(out['platforms'])
            if out['clients'] != '':
                table += '<tr><td>Using clients</td><td>{0}</td></tr>'.format(out['clients'])
            if out['locations'] != '':
                table += '<tr><td>At locations</td><td>{0}</td></tr>'.format(out['locations'])
            table += '<tr><td>Controls</td><td>{0}</td></tr>'.format(out['controls'])
            table += '</tbody>'
            html += table
        self.write_html(self.file, html)

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
