"""
ROAD2Timeline Plugin
Contributed by Ryan Marcotte Cobb (Secureworks)

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
"""
import argparse

from typing import Optional

import roadtools.roadlib.metadef.database as database

DESCRIPTION = "Timeline analysis of Azure AD objects"

def create_args_parser():
    parser = argparse.ArgumentParser(
        # TODO: Remove?
        #add_help=True,
        description=DESCRIPTION,
        # TODO: Remove?
        #formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '-d', '--database',
        action='store',
        help='Database file. Can be the local database name for SQLite, or an SQLAlchemy '
             'compatible URL such as postgresql+psycopg2://dirkjan@/roadtools',
        default='roadrecon.db'
    )
    return parser


def add_args(parser: argparse.ArgumentParser):
    parser.add_argument(
        '-f', '--file',
        action='store',
        help='File containing string templates to translate Azure AD objects into a timeline \
            entry. Defaults to `road2timeline.yaml`',
        default='road2timeline.yaml'
    )


def main(args: Optional[argparse.Namespace] = None):
    if args is None:
        parser = create_args_parser()
        args = parser.parse_args()

    db_url = database.parse_db_argument(args.database)
    session = database.get_session(database.init(dburl=db_url))

    pass

if __name__ == '__main__':
    main()