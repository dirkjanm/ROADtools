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
import logging
import yaml
import sqlalchemy

import pandas as pd
import numpy as np
import roadtools.roadlib.metadef.database as database

from pathlib import Path
from typing import Dict, Optional

DESCRIPTION = "Timeline analysis of Azure AD objects"

logger = logging.getLogger(__name__)

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
        '-t', '--template-file',
        action='store',
        help='File containing string templates to translate Azure AD objects into a timeline \
            entry. Defaults to `road2timeline.yaml` in the current working directory.',
        default='road2timeline.yaml'
    )
    parser.add_argument(
        '-f', '--output-file',
        action='store',
        help='File to save timeline outputs. Output format determined by file extension. Supported extensions include: [csv, pickle, jsonl]',
        default='timeline-output.jsonl',
    )


def populate_timeline_entry(
    row: pd.Series, 
    timeline_entry_templates: Dict[str, Dict[str, str]]
    ) -> str:
    """Attempts to populate a timeline entry template with
    the relevant fields from a row in the database.
    """

    table_templates = timeline_entry_templates.get(row._table_name, {})
    template_text = table_templates.get(row._source_timestamp)
    if template_text:
        try:
            return template_text.format(**row.to_dict())
        except Exception as exc:
            logger.error(f"There was a problem parsing the message: {str(exc)}")
            return f"Error parsing template {row._table_name}.{row._source_timestamp}: Object ID - {row._object_id}" 
    else:
        return f"No template found for {row._table_name}.{row._source_timestamp}: Object ID - {row._object_id}"



def to_dataframe(
    session: sqlalchemy.orm.session.Session, 
    table: sqlalchemy.ext.declarative.api.DeclarativeMeta
    ) -> pd.DataFrame:
    """Reads sqlite table and converts to pd.DataFrame.
    This also converts the string values in datetime columns
    into their equivalent Python `datetime` representation.
    """

    rows = session.query(table).all()
    if not rows:
        return pd.DataFrame()

    df = pd.json_normalize([{
        **row._asdict(), 
        '_object_id': getattr(row, "objectId", None) or getattr(row, "id", None) or "Identifier Not Found",
        }
        for row in rows
    ]).assign(_table_name=table.name)

    for column in table.columns:
        # Attempts to coerce sqlite datetime columns
        # into a python Datetime object.
        if type(column.type) == sqlalchemy.sql.sqltypes.DATETIME:
            if column.name in df.columns:
                df[column.name] = df[column.name].apply(pd.to_datetime, errors="coerce")
            
    return df


def copy_dataframe_by_col(df: pd.DataFrame, col: str) -> pd.DataFrame:
    """Returns a pd.DataFrame with new columns for a given datetime field"""
    df = df.copy()
    df['_timestamp'] = df[col]
    df['_source_timestamp'] = col
    return df[df[col].notnull()]


def main(args: Optional[argparse.Namespace] = None):
    if args is None:
        parser = create_args_parser()
        args = parser.parse_args()

    db_url = database.parse_db_argument(args.database)
    engine = database.init(dburl=db_url)
    db_metadata = sqlalchemy.MetaData(bind=engine, schema='main')
    db_metadata.reflect()
    session = database.get_session(engine)

    templates_fp = Path(args.template_file)
    if not templates_fp.exists():
        print(f"Timeline entry template file {templates_fp} not found, defaulting to built-in templates")
        templates_fp = Path(__file__).with_suffix(".yaml")

    print(f"Loading timeline entry templates from {templates_fp}")
    timeline_entry_templates = yaml.safe_load(
        templates_fp.read_text(encoding="utf-8", errors="replace")
    )

    dataframes = []
    for table in db_metadata.sorted_tables:
        df = to_dataframe(session, table)
        for col in df.select_dtypes(include=[np.datetime64]).columns:
            dataframes.append(
                copy_dataframe_by_col(df, col))

    timeline = (
        pd.concat(dataframes, ignore_index=True)
        .assign(_message=lambda x: x.apply(populate_timeline_entry, args=(timeline_entry_templates,), axis=1))
        # Hacky way get these columns sorted first
        .set_index(['_source_timestamp', '_table_name', '_message', '_object_id'])
        .sort_index(axis=1) # The remaining columns are then sorted alphabetically
        .reset_index()
        .set_index('_timestamp') # Set the index datetime
        .sort_index() # Sort by timestamp
    )

    if args.output_file.endswith('.jsonl'):
        timeline.to_json(args.output_file, orient='records', lines=True, default_handler=str)
    elif args.output_file.endswith('.pickle'):
        timeline.to_pickle(args.output_file)
    elif args.output_file.endswith('.csv'):
        timeline.to_csv(args.output_file)
    else:
        raise ValueError(f"Unable to determine output format \
            for `--output-file` argument {args.output_file}. \
            Filename must end with one of: [jsonl, pickle, csv]"
        )


if __name__ == '__main__':
    main()