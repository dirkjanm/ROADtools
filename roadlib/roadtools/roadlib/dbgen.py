from roadtools.roadlib.metadef.entitytypes import *

header = '''import os
import json
import datetime
import sqlalchemy.types
from sqlalchemy import Column, Text, Boolean, BigInteger as Integer, Binary, create_engine, Table, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy.types import TypeDecorator, TEXT
Base = declarative_base()


class JSON(TypeDecorator):
    impl = TEXT
    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)

        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value

class DateTime(TypeDecorator):
    impl = sqlalchemy.types.DateTime
    def process_bind_param(self, value, dialect):
        if value is not None and isinstance(value, str):
            # Sometimes it ends on a Z, sometimes it doesn't
            if value[-1] == 'Z':
                if '.' in value:
                    value = datetime.datetime.strptime(value[:-2], '%Y-%m-%dT%H:%M:%S.%f')
                else:
                    value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
            elif '.' in value:
                if '+' in value:
                    value = datetime.datetime.strptime(value[:-7], '%Y-%m-%dT%H:%M:%S.%f')
                else:
                    value = datetime.datetime.strptime(value[:-1], '%Y-%m-%dT%H:%M:%S.%f')
            else:
                value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%S')

        return value

class SerializeMixin():
    def as_dict(self, delete_empty=False):
        """
            Converts the object to a dict
        """
        result = {}
        for c in self.__table__.columns:
            attr = getattr(self, c.name)
            if delete_empty:
                if attr:
                    result[c.name] = attr
            else:
                result[c.name] = attr
        return result


    def __repr__(self):
        return str(self.as_dict(True))
'''

dbdef = '''
class %s(Base, SerializeMixin):
    __tablename__ = "%ss"
%s
%s
'''

footer = '''
def parse_db_argument(dbarg):
    \'\'\'
    Parse DB string given as argument into full path required
    for SQLAlchemy
    \'\'\'
    if not ':/' in dbarg:
        if dbarg[0] != '/':
            return 'sqlite:///' + os.path.join(os.getcwd(), dbarg)
        else:
            return 'sqlite:///' + dbarg
    else:
        return dbarg

def init(create=False, dburl='sqlite:///roadrecon.db'):
    if 'postgresql' in dburl:
        engine = create_engine(dburl,
                               executemany_mode='values',
                               executemany_values_page_size=1001)
    else:
        engine = create_engine(dburl)

    if create:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
    return engine

def get_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()
'''

coldef = '    %s = Column(%s)'
pcoldef = '    %s = Column(%s, primary_key=True)'

def gen_db_class(classdef, rels, rev_rels):
    classname = classdef.__name__
    props = {}
    for base in classdef.__bases__:
        try:
            props.update(base.props)
        except AttributeError:
            # No base, so no props
            pass
    props.update(classdef.props)
    cols = []
    for pname, pclass in props.items():
        try:
            dbtype = pclass.DBTYPE.__name__
        except AttributeError:
            # Complex type
            dbtype = 'JSON'
        if dbtype == 'Binary':
            dbtype = 'Text'
        if pname == 'objectId' or (classname == 'Domain' and pname == 'name') or (classname == 'RoleAssignment' and pname == 'id') or (classname == 'ApplicationRef' and pname == 'appId'):
            cols.append(pcoldef % (pname, dbtype))
        else:
            cols.append(coldef % (pname, dbtype))
    outrels = []
    for rel in rels:
        reldata = relations[rel]
        if reldata[0] == reldata[1]:
            outrels.append(gen_link_fkey(rel, reldata[1], reldata[2], reldata[3], reldata[0], 'child'+reldata[0]))
        else:
            outrels.append(gen_link(rel, reldata[1], reldata[2], reldata[3]))

    for rel in rev_rels:
        reldata = relations[rel]
        if reldata[0] == reldata[1]:
            outrels.append(gen_link_fkey(rel, reldata[0], reldata[3], reldata[2], 'child'+reldata[0], reldata[0]))
        else:
            outrels.append(gen_link(rel, reldata[0], reldata[3], reldata[2]))
    return dbdef % (classname, classname, '\n'.join(cols), '\n'.join(outrels))

# Relationships defined here
relations = {
    # Relationship name: (LeftGroup, RightGroup, relation name, reverse relation name)
    'group_member_user': ('Group', 'User', 'memberUsers', 'memberOf'),
    'group_member_group': ('Group', 'Group', 'memberGroups', 'memberOf'),
    'group_member_contact': ('Group', 'Contact', 'memberContacts', 'memberOf'),
    'group_member_device': ('Group', 'Device', 'memberDevices', 'memberOf'),
    'group_member_serviceprincipal': ('Group', 'ServicePrincipal', 'memberServicePrincipals', 'memberOf'),
    'device_owner': ('Device', 'User', 'owner', 'ownedDevices'),
    'application_owner_user': ('Application', 'User', 'ownerUsers', 'ownedApplications'),
    'application_owner_serviceprincipal': ('Application', 'ServicePrincipal', 'ownerServicePrincipals', 'ownedApplications'),
    'serviceprincipal_owner_user': ('ServicePrincipal', 'User', 'ownerUsers', 'ownedServicePrincipals'),
    'serviceprincipal_owner_serviceprincipal': ('ServicePrincipal', 'ServicePrincipal', 'ownerServicePrincipals', 'ownedServicePrincipals'),
    'role_member_user': ('DirectoryRole', 'User', 'memberUsers', 'memberOfRole'),
    'role_member_serviceprincipal': ('DirectoryRole', 'ServicePrincipal', 'memberServicePrincipals', 'memberOfRole'),
}

link_tbl_tpl = '''
lnk_%s = Table('lnk_%s', Base.metadata,
    Column('%s', Text, ForeignKey('%ss.objectId')),
    Column('%s', Text, ForeignKey('%ss.objectId'))
)
'''

def gen_link_table(linkname, left_tbl, right_tbl):
    # For links between same properties, use different names
    if left_tbl == right_tbl:
        right_tbl_name = 'child' + right_tbl
    else:
        right_tbl_name = right_tbl
    return link_tbl_tpl % (linkname, linkname, left_tbl, left_tbl, right_tbl_name, right_tbl)

# Simple link template
link_tpl = '''    %s = relationship("%s",
        secondary=lnk_%s,
        back_populates="%s")
'''

def gen_link(link_name, ref_table, rel_name, rev_rel_name):
    return link_tpl % (rel_name, ref_table, link_name, rev_rel_name)

# Link template with explicit foreign key
# this voodoo is inspired by https://docs.sqlalchemy.org/en/13/orm/join_conditions.html#self-referential-many-to-many-relationship
link_tpl_fkey = '''    {0} = relationship("{1}",
        secondary=lnk_{2},
        primaryjoin=objectId==lnk_{2}.c.{3},
        secondaryjoin=objectId==lnk_{2}.c.{4},
        back_populates="{5}")
'''

def gen_link_fkey(link_name, ref_table, rel_name, rev_rel_name, ref_column, sec_ref_column):
    return link_tpl_fkey.format(rel_name, ref_table, link_name, ref_column, sec_ref_column, rev_rel_name)

# Tables to generate and relationships with other tables are defined here
tables = [
    # Table, relation, back_relation
    (User, [], ['group_member_user', 'application_owner_user', 'serviceprincipal_owner_user', 'role_member_user', 'device_owner']),
    (ServicePrincipal, ['serviceprincipal_owner_user', 'serviceprincipal_owner_serviceprincipal'], ['role_member_serviceprincipal', 'serviceprincipal_owner_serviceprincipal', 'application_owner_serviceprincipal', 'group_member_serviceprincipal']),
    (Group, ['group_member_group', 'group_member_user', 'group_member_contact', 'group_member_device', 'group_member_serviceprincipal'], ['group_member_group']),
    (Application, ['application_owner_user', 'application_owner_serviceprincipal'], []),
    (Device, ['device_owner'], ['group_member_device']),
    # (Domain, [], []),
    (DirectoryRole, ['role_member_user', 'role_member_serviceprincipal'], []),
    (TenantDetail, [], []),
    (ApplicationRef, [], []),
    (ExtensionProperty, [], []),
    (Contact, [], ['group_member_contact']),
    (OAuth2PermissionGrant, [], []),
    (Policy, [], []),
    (RoleDefinition, [], []),
    (RoleAssignment, [], []),
    (AppRoleAssignment, [], [])
]
with open('metadef/database.py', 'w') as outf:
    outf.write(header)
    for relname, reldata in relations.items():
        outf.write(gen_link_table(relname, reldata[0], reldata[1]))
    for table, links, revlinks in tables:
        outf.write(gen_db_class(table, links, revlinks))
    outf.write(footer)
