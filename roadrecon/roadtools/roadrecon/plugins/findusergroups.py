"""
File User Groups plugin
Contributed by Jason Lang

Copyright 2021 - MIT License

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
"""

import argparse
from pathlib import Path

from roadtools.roadlib.metadef.database import (User)
import roadtools.roadlib.metadef.database as database

# Required property - plugin description
DESCRIPTION = "Find users with group memberships matching search term."

class FindUsersInGroups():
    def __init__(self, session, searchterm, userlist=None):
        self.session = session
        self.searchterm = searchterm
        self.userlist = userlist

    def main(self):
        all_users = self.session.query(User).all()
        users = []

        if self.userlist:
            for upn in self.userlist:
                # I'm sure there's a faster way here...
                objuser = self.session.query(User).filter(User.userPrincipalName == upn).first()
                if objuser:
                    users.append(objuser)
        else:
            # Slooooow for large datasets
            users = all_users

        for user in users:
            groups = getattr(user, "memberOf")
            retgroups = []
            found = False
            if groups:
                for g in groups:
                    gname = getattr(g, 'displayName')
                    if self.searchterm.lower() in gname.lower():
                        found = True
                        retgroups.append(getattr(g, 'displayName'))

                if found:
                    print("{} - {}".format(getattr(user, 'userPrincipalName'), retgroups))
                   

def create_args_parser():
    parser = argparse.ArgumentParser(
        add_help=True,
        description=DESCRIPTION,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-d', '--database',
        action='store',
        help='Database file. Can be the local database name for SQLite, or an SQLAlchemy '
             'compatible URL such as postgresql+psycopg2://dirkjan@/roadtools',
        default='roadrecon.db'
    )

    add_args(parser)
    return parser


def add_args(parser):
    parser.add_argument(
        '-s', '--searchterm',
        help='Term to find matching groups. Wildcard searching done automatically. Default "admin"',
        default='admin'
    )
    parser.add_argument(
        '-u', '--userlistpath',
        help='Path to user list file. One UPN (user@domain.name) per line. Only users from this list with group membership matching the search term will be shown. Default search through all users (painfully slow).',
        default=None
    )


def main(args=None):
    if args is None:
        parser = create_args_parser()
        args = parser.parse_args()

    db_url = database.parse_db_argument(args.database)
    session = database.get_session(database.init(dburl=db_url))

    userlist = []
    if args.userlistpath:
        userfile = Path(args.userlistpath)
        if userfile.exists():
            with open(userfile, 'r') as infile:
                for line in infile:
                    userlist.append(line.rstrip('\n'))
    else:
        userlist = None

    plugin = FindUsersInGroups(session, args.searchterm, userlist)
    plugin.main()
    print("Done!")

if __name__ == '__main__':
    main()
