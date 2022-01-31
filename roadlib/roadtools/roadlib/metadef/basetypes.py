import sqlalchemy.types # import Integer, String, JSON, Binary
from sqlalchemy import Table, Column, MetaData, ForeignKey

class Edm(object):
    class String(object):
        DBTYPE = sqlalchemy.types.Text

    class Boolean(object):
        DBTYPE = sqlalchemy.types.Boolean

    class Stream(object):
        DBTYPE = sqlalchemy.types.LargeBinary

    class Int32(object):
        DBTYPE = sqlalchemy.types.Integer

    class Int16(object):
        DBTYPE = sqlalchemy.types.Integer

    class Single(object):
        DBTYPE = sqlalchemy.types.Integer

    class Double(object):
        DBTYPE = sqlalchemy.types.Float

    class Decimal(object):
        DBTYPE = sqlalchemy.types.Float

    class Int64(object):
        DBTYPE = sqlalchemy.types.Integer

    class Guid(object):
        DBTYPE = sqlalchemy.types.Text

    class Duration(object):
        DBTYPE = sqlalchemy.types.Text

    class DateTime(object):
        DBTYPE = sqlalchemy.types.DateTime

    class Date(object):
        DBTYPE = sqlalchemy.types.Date

    class TimeOfDay(object):
        DBTYPE = sqlalchemy.types.Time

    class DateTimeOffset(object):
        DBTYPE = sqlalchemy.types.DateTime

    class Binary(object):
        DBTYPE = sqlalchemy.types.LargeBinary

    class Byte(object):
        DBTYPE = sqlalchemy.types.LargeBinary

class Collection(object):
    DBTYPE = sqlalchemy.types.JSON

class ComplexType(object):
    DBTYPE = sqlalchemy.types.JSON
