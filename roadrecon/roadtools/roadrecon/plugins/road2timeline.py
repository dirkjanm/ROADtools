"""
ROAD2Timeline Plugin
Contributed by Ryan Marcotte Cobb (Secureworks)

Copyright 2022 - MIT License

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
import sqlalchemy

import roadtools.roadlib.metadef.database as database

from pathlib import Path
from typing import Dict, Optional

# Currently, there is no good way to specify
# plugin-specific imports. Therefore, we need
# to manually check that the necessary modules
# are present in the environment.

try:
    import yaml
    import pandas as pd
    import numpy as np
    HAS_RTT_MODULES = True
except (ModuleNotFoundError, ImportError) as exc:
    HAS_RTT_MODULES = False


DESCRIPTION = "Timeline analysis of Azure AD objects"


def create_args_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
    )
    parser.add_argument(
        "-d",
        "--database",
        action="store",
        help="Database file. Can be the local database name for SQLite, or an SQLAlchemy "
        "compatible URL such as postgresql+psycopg2://dirkjan@/roadtools",
        default="roadrecon.db",
    )
    return parser


def add_args(parser: argparse.ArgumentParser):
    """Plugin-specific arguments"""
    parser.add_argument(
        "-t",
        "--template-file",
        action="store",
        help="File containing string templates to translate Azure AD objects into a timeline \
            entry. Defaults to `road2timeline.yaml` in the current working directory.",
        default="road2timeline.yaml",
    )
    parser.add_argument(
        "-f",
        "--output-file",
        action="store",
        help="File to save timeline outputs. Output format determined by file extension. Supported extensions include: [csv, pickle, jsonl, parquet]",
        default="timeline-output.jsonl",
    )

if HAS_RTT_MODULES:
    def populate_timeline_entry(
        row: pd.Series, timeline_entry_templates: Dict[str, Dict[str, str]]
    ) -> str:
        """Attempts to populate a timeline entry template with
        the relevant fields from a row in the database.

        Parameters
        ----------
        row : pd.Series
            A row from a DataFrame, passed by `.apply(..., axis=1)`
        timeline_entry_templates : Dict[str, Dict[str, str]]
            Dictionary of template strings organized by table and
            timestamp column name.

        Returns
        -------
        str
            Templated timeline event message
        """

        table_templates = timeline_entry_templates.get(row._table_name, {})
        template_text = table_templates.get(row._timestamp_column)
        if template_text:
            try:
                return template_text.format(**row.to_dict())
            except Exception as exc:
                print(f"There was a problem parsing the message: {str(exc)}")
                return f"Error parsing template {row._table_name}.{row._timestamp_column}: Object ID - {row._object_id}"
        else:
            return f"No template found for {row._table_name}.{row._timestamp_column}: Object ID - {row._object_id}"


    def to_dataframe(
        session: sqlalchemy.orm.session.Session,
        table: sqlalchemy.orm.DeclarativeMeta,
    ) -> pd.DataFrame:
        """Reads sqlite table and converts to pd.DataFrame.
        This also converts the string values in datetime columns
        into their equivalent Python `datetime` representation.

        Parameters
        ----------
        session : sqlalchemy.orm.session.Session
            SQLAlchemy session with the ROADtools database
        table : sqlalchemy.ext.declarative.api.DeclarativeMeta
            An object representing the SQL table in the ROADtools
            database

        Returns
        -------
        pd.DataFrame
            All data from the table converted to Python data
            types
        """
        rows = session.query(table).all()
        if not rows:
            return pd.DataFrame()

        df = pd.json_normalize(
            [
                {
                    **row._asdict(),
                    "_object_id": getattr(row, "objectId", None)
                    or getattr(row, "id", None)
                    or "Identifier Not Found",
                }
                for row in rows
            ]
        ).assign(_table_name=table.name)

        for column in table.columns:
            # Attempts to coerce sqlite datetime columns
            # into a python Datetime object.
            if type(column.type) == sqlalchemy.sql.sqltypes.DATETIME:
                if column.name in df.columns:
                    df[column.name] = df[column.name].apply(pd.to_datetime, errors="coerce")

        return df


    def copy_dataframe_by_col(df: pd.DataFrame, col: str) -> pd.DataFrame:
        """Returns a copy of a `pd.DataFrame` with additional columns
        for a given datetime field.

        Parameters
        ----------
        df : pd.DataFrame
            Source DataFrame
        col : str
            Timestamp column of interest

        Returns
        -------
        pd.DataFrame
            Copy of the source DataFrame, but with additional
            columns detailing the column of interest and dropping
            all rows where that timestamp column is not null
        """
        df = df.copy()
        df["_timestamp"] = df[col]
        df["_timestamp_column"] = col
        return df[df[col].notnull()]


def main(args: Optional[argparse.Namespace] = None) -> Path:

    if args is None:
        parser = create_args_parser()
        args = parser.parse_args()

    # Connect to the database
    db_url = database.parse_db_argument(args.database)
    engine = database.init(dburl=db_url)
    session = database.get_session(engine)

    # Do some reflection to grab the tables
    # and their respective column types
    db_metadata = sqlalchemy.MetaData(bind=engine, schema="main")
    db_metadata.reflect()

    if not HAS_RTT_MODULES:
        print('Error importing required modules for road2timeline. Make sure pyyaml, numpy and pandas are installed.')
        return

    # Find the templates file which is used
    # to populate timeline entries from the
    # source rows.
    templates_fp = Path(args.template_file)
    if not templates_fp.exists():
        print(
            f"Timeline entry template file {templates_fp} not found, defaulting to built-in templates"
        )
        templates_fp = Path(__file__).with_suffix(".yaml")

    print(f"Loading timeline entry templates from {templates_fp}")
    timeline_entry_templates = yaml.safe_load(
        templates_fp.read_text(encoding="utf-8", errors="replace")
    )

    # For each table, convert its rows into
    # a pandas DataFrame, then create n copies
    # of the DataFrame for each datetime column
    # in the DataFrame with additional metadata.
    dataframes = []
    for table in db_metadata.sorted_tables:
        df = to_dataframe(session, table)
        for col in df.select_dtypes(include=[np.datetime64]).columns:
            dataframes.append(copy_dataframe_by_col(df, col))

    # Transform the rows of the DataFrame into
    # a human-readable string that will be used
    # as the entry in the timeline `_message` field.
    # Then sort the timeline.
    timeline = (
        pd.concat(dataframes, ignore_index=True)
        .assign(
            _message=lambda x: x.apply(
                populate_timeline_entry, args=(timeline_entry_templates,), axis=1
            )
        )
        # TODO: Decide if a better column naming scheme is required.
        # See the actual [`log2timeline` docs](https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html)
        # for column names that would be compatible with their data model.
        #
        # Hacky way get these columns sorted first
        .set_index(["_timestamp_column", "_table_name", "_message", "_object_id"])
        # The remaining columns are then sorted alphabetically
        .sort_index(axis=1)
        .reset_index()
        # Set the index datetime
        .set_index("_timestamp")
        # Sort by timestamp
        .sort_index()
        # .reset_index()
    )

    # Infer the output format based on the
    # file extension of the `--output-file`
    # argument.
    output_file = Path(args.output_file)

    if output_file.suffix == ".jsonl":
        timeline.to_json(output_file, orient="records", lines=True, default_handler=str)
    elif output_file.suffix == ".pickle":
        timeline.to_pickle(str(output_file))
    elif output_file.suffix == ".csv":
        timeline.to_csv(output_file)
    elif output_file.suffix == ".parquet":
        timeline.to_parquet(output_file)
    else:
        raise ValueError(
            f"Unable to determine output format \
            for `--output-file` argument {args.output_file}. \
            Filename must end with one of: [jsonl, pickle, csv, parquet]"
        )

    print(f"Timeline saved to file {output_file.resolve()}")

    return output_file


if __name__ == "__main__":
    main()
