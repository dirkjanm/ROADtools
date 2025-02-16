'''
CAOptics importer plugin
Contributed by Alberto Verza (@acap4z) from NCC Group
Uses code from ldapdomaindump under MIT license

The code here isn't very tidy, don't use it as a perfect example

Copyright 2023 - MIT License

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
import csv
from sqlalchemy.orm.attributes import flag_modified
from roadtools.roadlib.metadef.database import ServicePrincipal, User, Policy, Application, Group, DirectoryRole
import roadtools.roadlib.metadef.database as database

# Required property - plugin description
DESCRIPTION = '''
Imports CAP MFA analysis from CAOptics, applies some post-processing rules and sets the MFA status for each user object
'''

# Constants
MFA_ENABLED = "Enabled"
MFA_CONDITIONAL = "Conditional"
MFA_DISABLED = "Disabled"
MFA_BLOCKED = "Blocked"
SCOPE_INDEX = 0
TERM_INDEX = 1
CONDITIONS_INDEX = 2
debug = False

def print_debug(msg):
    if debug:
        print("[DEBUG] %s" % msg)

def print_color(msg,color):
    print(color + msg + bcolors.ENDC)

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class CAOpticsImporterPlugin():
    """
    CAOptics importer plugin
    """
    def __init__(self, session, input_file, output_file):
        self.session = session
        self.input_file = input_file
        self.output_file = output_file
        self.permutations = {}
        self.expand_id_cache = {}

    def _get_group(self, gid):
        if isinstance(gid, list):
            return self.session.query(Group).filter(Group.objectId.in_(gid.lower())).all()
        return self.session.query(Group).filter(Group.objectId == gid.lower()).first()

    def _get_user(self, uid):
        return self.session.query(User).filter(User.objectId == uid.lower()).first()

    def _get_role(self, rid):
        if isinstance(rid, list):
            return self.session.query(DirectoryRole).filter(DirectoryRole.roleTemplateId.in_(rid.lower())).all()
        return self.session.query(DirectoryRole).filter(DirectoryRole.roleTemplateId == rid.lower()).first()


    def _expand_id(self, scope, root_invoke=False, resolved_ids = []):
        userlist = []
        # First call in the recursive chain.
        if root_invoke:
            # Python keeps this list even after the root call, so it must be cleared.
            resolved_ids.clear()
            # Return cache results and avoid all the recursive stuff.
            if scope in self.expand_id_cache.keys():
                return self.expand_id_cache[scope]
        # Loop check
        if scope in resolved_ids:
            return userlist
        # User ID
        user = self._get_user(scope)
        if user is not None:
            userlist.append(user.objectId)
            return userlist
        # Group ID and role ID
        group_or_role = self._get_group(scope)
        if group_or_role is None:
            group_or_role = self._get_role(scope)
        if group_or_role is not None:
            resolved_ids.append(scope)
            members = group_or_role.memberUsers
            for member in members:
                userlist.append(member.objectId)
            member_groups = group_or_role.memberGroups
            for group in member_groups:
                uids = self._expand_id(group.objectId, resolved_ids=resolved_ids)
                for uid in uids:
                    userlist.append(uid)
        #print("Unrolled from %s to %s" % (scope, userlist))
        # Cache results to avoid the _expand_id function for the given scope next time.
        self.expand_id_cache[scope] = userlist
        return userlist

    def _parse_row(self, row):
        if row[0] == "users":
            return
        # Determine all unrolled users in scope
        terminations = row[5]
        lineage = row[6].split("->")
        conditions = lineage[1:]
        scope = lineage[0].split(":")[1].strip()
        if ("-" in scope):
            users = self._expand_id(scope, root_invoke=True)
        else:
            users = [scope]
        #print_debug("Processing: %s" % lineage)
        #print_debug("Users in scope: %s" % len(users))
        for user in users:
            new_lineage = row[6].strip().replace(scope, user)
            if new_lineage in self.permutations:
                # Set no. of terminations
                self.permutations[new_lineage][TERM_INDEX] += int(terminations)
            else:
                self.permutations[new_lineage] = [user,int(terminations),conditions]
    
    def _update_all_users(self, mfa_status):
        all_users = self.session.query(User).all()
        if all_users is None:
            print("The database has no users. Please run 'roadrecon gather' first.")
            exit(-1)
        for user in all_users:
            user.strongAuthenticationDetail["CapMfaStatus"] = mfa_status
            flag_modified(user, "strongAuthenticationDetail")

    def _check_user_is_none(self, user, id):
        if user is None:
            print("There is a mismatch between the report IDs and the database IDs. " \
            "Please confirm that the CAOptics report and the ROADrecon database belong " \
            "to the same tenant. Unidentified ID: %s" % id)
            exit(-1)

    def _update_unterm_users(self, default_mfa_status):    
        for permutation in self.permutations.values():
            mfa_status = MFA_CONDITIONAL
            if permutation[TERM_INDEX] == 0:
                # Overrides mfa_status value to disabled if all conditions are unterminated.
                if len(permutation[CONDITIONS_INDEX]) <= 1:
                    mfa_status = MFA_DISABLED
                user_id = permutation[SCOPE_INDEX]
                if user_id == "All" or user_id == "GuestsOrExternalUsers":
                    continue
                user = self._get_user(user_id)
                self._check_user_is_none(user, user_id) 
                # If there is no MFA CAP by default, this additional step checks if a user
                # that was set as enabled must be updated to conditioned due to unterm cond.
                if default_mfa_status == 0:
                    current_mfa = user.strongAuthenticationDetail["CapMfaStatus"]
                    if current_mfa != MFA_ENABLED:
                        continue                 
                user.strongAuthenticationDetail["CapMfaStatus"] = mfa_status
                # print("User %s changed to %s" % (user.userPrincipalName,mfa_status))
                flag_modified(user, "strongAuthenticationDetail")

    # This function will be executed only when there is no MFA CAP by default.
    def _update_term_users(self):
        mfa_status = MFA_CONDITIONAL
        for permutation in self.permutations.values():
            # If permutation has terminations and no conditions, MFA is enabled.
            if permutation[TERM_INDEX] > 0:
                if len(permutation[CONDITIONS_INDEX]) <= 1:
                    mfa_status = MFA_ENABLED
                # If perm has terminations and conditions
                user_id = permutation[SCOPE_INDEX]
                if user_id == "All" or user_id == "GuestsOrExternalUsers":
                    continue
                user = self._get_user(user_id)
                self._check_user_is_none(user, user_id)
                user.strongAuthenticationDetail["CapMfaStatus"] = mfa_status
                flag_modified(user, "strongAuthenticationDetail")


    # Performs a search in the parsed permutations for a given user and returns all unterminated conditions.
    def _get_conditions(self,user):
        conditions = []
        for permutation in self.permutations.values():
            #print ("Term %s" % permutation)
            if permutation[TERM_INDEX] == 0 and permutation[SCOPE_INDEX] == user.objectId:
                conditions.append(permutation[CONDITIONS_INDEX])
        extra_conditions = user.strongAuthenticationDetail["CapMfaExtraConditions"]
        if len(extra_conditions) > 0:
            conditions.extend(extra_conditions)
        return conditions

    def _print_all_mfa(self):
        all_users = self.session.query(User).all()
        for user in all_users:
            color = bcolors.WARNING
            if user.strongAuthenticationDetail["CapMfaStatus"] == MFA_ENABLED:
                color = bcolors.OKGREEN
            elif user.strongAuthenticationDetail["CapMfaStatus"] == MFA_DISABLED:
                color = bcolors.FAIL
            print_color("%s\t%s" % (user.userPrincipalName,user.strongAuthenticationDetail["CapMfaStatus"]),color)

    def prettify_list(self, list_items):
        pretty_list = ''
        first = True
        for item in list_items:
            if first:
                pretty_list = "{0}".format(item)
                first = False
            else:
                pretty_list += "\n{0}".format(item)     
        return pretty_list  

    def _write_all_mfa_csv(self):
        all_users = self.session.query(User).all()
        with open(self.output_file, 'w', newline='') as csvfile:
            csvwriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            csvwriter.writerow(["User Principal Name","MFA Status", "MFA Bypass Conditions", "Blocking CAPs", "Afected by CAPs"])
            for user in all_users:
                mfa_status = user.strongAuthenticationDetail["CapMfaStatus"]
                conditions = ''  
                # Fill 'conditions' row only if MFA status is conditional
                if mfa_status == MFA_CONDITIONAL:
                    conditions = self._get_conditions(user)
                # Prettify lists
                pretty_cond = self.prettify_list(conditions)
                pretty_block = self.prettify_list(user.strongAuthenticationDetail["CapMfaBlockList"])
                pretty_cap = self.prettify_list(user.strongAuthenticationDetail["CapMfaList"])
                row = [user.userPrincipalName, mfa_status, pretty_cond, pretty_block, pretty_cap]
                csvwriter.writerow(row)


    ####
    # POST-PROCESSING FUNCTIONS
    ####

    def _policy_has_controls(self, policy_detail):
        controls = []
        try:
            controls = policy_detail['Controls']
        except (KeyError):
            print_debug("Policy without controls ignored (KeyError)")
            return False
        if len(controls) < 1:
            print_debug("Policy without controls ignored (Controls < 1)")
            return False
        else:
            return True       

    def _get_users_from_list(self, item_list):
        entities = ['Users','Groups','Roles']
        id_list = []
        users = []
        for item in item_list:
            for entity in entities:
                try:
                    id_list.extend(item[entity])
                except (KeyError):
                    continue
        for id in id_list:
            if id == "All":
                all_users = self.session.query(User).all()
                users = [user.objectId for user in all_users]
                break
            users.extend(self._expand_id(id, root_invoke=True))
        users = list(dict.fromkeys(users))
        return users


    def _get_affected_users(self, policy_detail):
        included_list = []
        try:
            included_list = policy_detail['Conditions']['Users']['Include']
        except (KeyError):
            return None
        excluded_list = []
        try:
            excluded_list = policy_detail['Conditions']['Users']['Exclude']
        except (KeyError):
            pass
        # Get only Users, Groups and Roles
        included_users = self._get_users_from_list(included_list)
        # Remove excluded users
        excluded_users = self._get_users_from_list(excluded_list)
        affected_users = list(set(included_users) - set(excluded_users))
        return affected_users

    def _clear_all_capmfa(self):
        all_users = self.session.query(User).all()
        if all_users is None:
            print("The database has no users. Please run 'roadrecon gather' first.")
            exit(-1)
        for user in all_users:
            user.strongAuthenticationDetail["CapMfaList"] = []
            user.strongAuthenticationDetail["CapMfaBlockList"] = []  
            user.strongAuthenticationDetail["CapMfaExtraConditions"] = []    
            flag_modified(user, "strongAuthenticationDetail")

    def _append_mfa_attr_list(self, affected_users, attr, value):
        for user_id in affected_users:
            user = self._get_user(user_id)
            user.strongAuthenticationDetail[attr].append(value)
            flag_modified(user, "strongAuthenticationDetail")         

    def _update_mfa_attr_list(self, affected_users, attr, value):
         for user_id in affected_users:
            user = self._get_user(user_id)
            user.strongAuthenticationDetail[attr] = value
            flag_modified(user, "strongAuthenticationDetail")    

    def _update_mfa_disabled_to_cond(self, affected_users):
        for user_id in affected_users:
            user = self._get_user(user_id)
            if user.strongAuthenticationDetail["CapMfaStatus"] == MFA_DISABLED:
                user.strongAuthenticationDetail["CapMfaStatus"] = MFA_CONDITIONAL
                flag_modified(user, "strongAuthenticationDetail") 

    def _is_blocking_policy(self, policy_detail):
        for c in policy_detail['Controls']:
            if 'Control' in c and any('Block' in control for control in c['Control']):
                return True 
        return False     

    def _check_extra_condition(self, conditions, affected_users, condition, display):
        try:
            cond = conditions[condition]
            self._update_mfa_disabled_to_cond(affected_users)
            self._append_mfa_attr_list(affected_users, "CapMfaExtraConditions", display)
        except KeyError:
            return     
       




    def main(self, should_print):

        # Read CSV report from CAOptics
        with open(self.input_file, newline='') as csvfile:
            csv_reader = csv.reader(csvfile, delimiter=',', quotechar='"')
            for row in csv_reader:
                self._parse_row(row)

        # Set default MFA status
        default_mfa_status = self.permutations["users:All ->"][TERM_INDEX]
        print_debug("MFA enabled by default: %s" % default_mfa_status)
        if default_mfa_status > 0:
            self._update_all_users(MFA_ENABLED)
        elif default_mfa_status == 0:
            self._update_all_users(MFA_DISABLED)
            # Users appearing in permutations with terminations are set to MFA enabled or conditional.
            self._update_term_users()           
        else:
            print("Invalid value read from default mfa rule (users:All ->). Make sure that CAOptics was launched with the '--allTerminations' flag.")
            return
        self._update_unterm_users(default_mfa_status)


        # POST-PROCESSING
        # The main goal is to fill mfa policies and conditions that are ignored by CAOptics:
        # - CAPs scoped to user actions and auth contexts.
        # - CAPs with ignored conditions (user-risk, sign-in risk, device filter, locations...)
        # - Block policies.
        self._clear_all_capmfa()
        for policy in self.session.query(Policy).filter(Policy.policyType == 18):
            print_debug("Policy: %s" % policy.displayName)
            detail = json.loads(policy.policyDetail[0])
            if detail['State'] == 'Enabled':
                #print_debug(str(detail))
                # Skip the policy if it has no controls
                if not self._policy_has_controls(detail):
                    continue
                # Users affected by the CAP
                affected_users = self._get_affected_users(detail)
                print_debug("Affected users: %s" % affected_users)
                # Skip the policy if it is not scoped to anyone
                if affected_users is None:
                    continue
                # Add CAP to the CAP list of all affected users
                self._append_mfa_attr_list(affected_users, "CapMfaList", policy.displayName)
                    
                # Add non-cloud scoped CAPs as 'conditional' to scoped users
                conditions = detail['Conditions']
                try:
                    for app in conditions['Applications']['Include']:
                        if 'Acrs' in app.keys():
                            #print_debug("Policy has Auth context.")
                            self._check_extra_condition(conditions, affected_users, "Applications", "Authentication Context (policy: {0})".format(policy.displayName))
                            break
                except (KeyError):
                    # Skip the policy if it is not scoped to any app or context
                    continue
                # Process CAPs with conditions ignored by CAOptics       
                # Filtered devices
                self._check_extra_condition(conditions, affected_users, "Devices", "Custom Device Filter (policy: {0})".format(policy.displayName))
                # User risk
                self._check_extra_condition(conditions, affected_users, "UserRisks", "User Risk (policy: {0})".format(policy.displayName))
                # Sign-in risk
                self._check_extra_condition(conditions, affected_users, "SignInRisks", "Sign-In Risk (policy: {0})".format(policy.displayName))
                # Locations
                # This one is tricky. While CAOptics ignores CAPs with the previous extra conditions completely, it actually
                # processes the "Location" CAPs but ignoring that condition. This may lead to "mfa enabled" false positives if
                # 'Location' is the only condition enabled in a policy.
                self._check_extra_condition(conditions, affected_users, "Locations", "Locations (policy: {0})".format(policy.displayName))
                # Process 'block' CAPs
                if self._is_blocking_policy(detail):
                    print_debug("The following users are blocked: %s" % str(affected_users))
                    self._append_mfa_attr_list(affected_users, "CapMfaBlockList", policy.displayName)

        # Write final MFA results to user objects in DB
        self.session.commit()

        if should_print:
            self._print_all_mfa()
        self._write_all_mfa_csv()
        #print(self.permutations)
        print_color('Results from {0} have been processed. Output report written into file {1}'.format(self.input_file,self.output_file),bcolors.OKBLUE)

def add_args(parser):
    parser.add_argument('-f',
                        '--input_file',
                        action='store',
                        help='Input file (default: report.csv)',
                        default='report.csv')
    parser.add_argument('-o',
                        '--output_file',
                        action='store',
                        help='Output file (default: output_report.csv)',
                        default='output_report.csv')
    parser.add_argument('-p',
                        '--print',
                        action='store_true',
                        help='Also print details to the console')
    parser.add_argument('-v',
                        '--verbose',
                        action='store_true',
                        help='Also print details to the console')
def main(args=None):
    if args is None:
        parser = argparse.ArgumentParser(add_help=True, description='CAOptics MFA results importer', formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('-d',
                            '--database',
                            action='store',
                            help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://host/roadtools',
                            default='roadrecon.db')
        add_args(parser)
        args = parser.parse_args()
    db_url = database.parse_db_argument(args.database)

    session = database.get_session(database.init(dburl=db_url))
    plugin = CAOpticsImporterPlugin(session, args.input_file, args.output_file)
    if args.verbose:
        global debug
        debug = True
    plugin.main(args.print)

if __name__ == '__main__':
    main()
