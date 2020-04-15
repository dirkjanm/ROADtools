import sqlalchemy.types # import Integer, String, JSON, Binary
from sqlalchemy import Table, Column, MetaData, ForeignKey

class Edm(object):
    class String(object):
        DBTYPE = sqlalchemy.types.Text

    class Boolean(object):
        DBTYPE = sqlalchemy.types.Boolean

    class Stream(object):
        DBTYPE = sqlalchemy.types.Binary

    class Int32(object):
        DBTYPE = sqlalchemy.types.Integer

    class Int64(object):
        DBTYPE = sqlalchemy.types.Integer

    class Guid(object):
        DBTYPE = sqlalchemy.types.Text

    class DateTime(object):
        DBTYPE = sqlalchemy.types.DateTime

    class Binary(object):
        DBTYPE = sqlalchemy.types.Binary

class Collection(object):
    DBTYPE = sqlalchemy.types.JSON

class ComplexType(object):
    DBTYPE = sqlalchemy.types.JSON
