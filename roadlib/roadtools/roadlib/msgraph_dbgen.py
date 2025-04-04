from roadtools.roadlib.metadef.entitytypes_msgraph import *

header = '''import os
import json
import datetime
import sqlalchemy.types
from sqlalchemy import Column, Text, Boolean, BigInteger as Integer, create_engine, Table, ForeignKey
from sqlalchemy.orm import relationship, sessionmaker, foreign, declarative_base
from sqlalchemy.types import TypeDecorator, TEXT
Base = declarative_base()


class JSON(TypeDecorator):
    impl = TEXT
    cache_ok = True
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
                    try:
                        value = datetime.datetime.strptime(value[:-2], '%Y-%m-%dT%H:%M:%S.%f')
                    except ValueError:
                        value = datetime.datetime.strptime(value[:-2], '%Y-%m-%dT%H:%M:%S.')
                else:
                    value = datetime.datetime.strptime(value, '%Y-%m-%dT%H:%M:%SZ')
            elif '.' in value:
                if '+' in value:
                    value = datetime.datetime.strptime(value[:-7], '%Y-%m-%dT%H:%M:%S.%f')
                else:
                    try:
                        value = datetime.datetime.strptime(value[:-1], '%Y-%m-%dT%H:%M:%S.%f')
                    except ValueError:
                        value = datetime.datetime.strptime(value[:-1], '%Y-%m-%dT%H:%M:%S.')
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

# Custom joins for service principals since these are kinda weird
custom_splinks = '''
    oauth2PermissionGrants = relationship("OAuth2PermissionGrant",
        primaryjoin=id == foreign(OAuth2PermissionGrant.clientId))

    appRolesAssigned = relationship("AppRoleAssignment",
        primaryjoin=id == foreign(AppRoleAssignment.resourceId))

    appRolesAssignedTo = relationship("AppRoleAssignment",
        primaryjoin=id == foreign(AppRoleAssignment.principalId))
'''

coldef = '    %s = Column(%s)'
pcoldef = '    %s = Column(%s, primary_key=True)'
fcoldef = '    %s = Column(%s, ForeignKey("%s"))'

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
        if dbtype == 'LargeBinary':
            dbtype = 'Text'
        if pname == 'id' or (classname == 'Domain' and pname == 'name') or (classname in ['RoleAssignment', 'EligibleRoleAssignment', 'AuthorizationPolicy', 'DirectorySetting'] and pname == 'id') or (classname == 'ApplicationRef' and pname == 'appId'):
            cols.append(pcoldef % (pname, dbtype))
        elif pname == 'roleDefinitionId':
            cols.append(fcoldef % (pname, dbtype, 'RoleDefinitions.id'))
        else:
            cols.append(coldef % (pname, dbtype))
    outrels = []
    for rel in rels:
        reldata = relations[rel]
        if reldata[0] == reldata[1]:
            outrels.append(gen_link_fkey(rel, reldata[1], reldata[2], reldata[3], reldata[0], 'child'+reldata[0]))
        elif reldata[0] == 'RoleDefinition' or reldata[1] == 'RoleDefinition':
            outrels.append(gen_link_nolinktbl(reldata[1], reldata[2], reldata[3]))
        else:
            outrels.append(gen_link(rel, reldata[1], reldata[2], reldata[3]))

    for rel in rev_rels:
        reldata = relations[rel]
        if reldata[0] == reldata[1]:
            outrels.append(gen_link_fkey(rel, reldata[0], reldata[3], reldata[2], 'child'+reldata[0], reldata[0]))
        elif reldata[0] == 'RoleDefinition' or reldata[1] == 'RoleDefinition':
            outrels.append(gen_link_nolinktbl(reldata[0], reldata[3], reldata[2]))
        else:
            outrels.append(gen_link(rel, reldata[0], reldata[3], reldata[2]))

    if classname == 'ServicePrincipal':
        outrels.append(custom_splinks)
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
    'role_member_group': ('DirectoryRole', 'Group', 'memberGroups', 'memberOfRole'),
    'group_owner_user': ('Group', 'User', 'ownerUsers', 'ownedGroups'),
    'group_owner_serviceprincipal': ('Group', 'ServicePrincipal', 'ownerServicePrincipals', 'ownedGroups'),
    'au_member_user': ('AdministrativeUnit', 'User', 'memberUsers', 'memberOfAu'),
    'au_member_group': ('AdministrativeUnit', 'Group', 'memberGroups', 'memberOfAu'),
    'au_member_device': ('AdministrativeUnit', 'Device', 'memberDevices', 'memberOfAu'),
    'role_assignment_active': ('RoleDefinition', 'RoleAssignment', 'assignments', 'roleDefinition'),
    'role_assignment_eligible': ('RoleDefinition', 'EligibleRoleAssignment', 'eligibleAssignments', 'roleDefinition'),
}

link_tbl_tpl = '''
lnk_%s = Table('lnk_%s', Base.metadata,
    Column('%s', Text, ForeignKey('%ss.id')),
    Column('%s', Text, ForeignKey('%ss.id'))
)
'''

def gen_link_table(linkname, left_tbl, right_tbl):
    # For links between same properties, use different names
    if left_tbl == right_tbl:
        right_tbl_name = 'child' + right_tbl
    else:
        right_tbl_name = right_tbl
    return link_tbl_tpl % (linkname, linkname, left_tbl, left_tbl, right_tbl_name, right_tbl)

# Simple link template for many to many relationships with link table
link_tpl = '''    %s = relationship("%s",
        secondary=lnk_%s,
        back_populates="%s")
'''

def gen_link(link_name, ref_table, rel_name, rev_rel_name):
    return link_tpl % (rel_name, ref_table, link_name, rev_rel_name)

# Simple link template for one to many relationships
link_tpl_nolinktbl = '''    %s = relationship("%s",
        back_populates="%s")
'''

def gen_link_nolinktbl(ref_table, rel_name, rev_rel_name):
    return link_tpl_nolinktbl % (rel_name, ref_table, rev_rel_name)

# Link template with explicit foreign key
# this voodoo is inspired by https://docs.sqlalchemy.org/en/13/orm/join_conditions.html#self-referential-many-to-many-relationship
link_tpl_fkey = '''    {0} = relationship("{1}",
        secondary=lnk_{2},
        primaryjoin=id==lnk_{2}.c.{3},
        secondaryjoin=id==lnk_{2}.c.{4},
        back_populates="{5}")
'''

def gen_link_fkey(link_name, ref_table, rel_name, rev_rel_name, ref_column, sec_ref_column):
    return link_tpl_fkey.format(rel_name, ref_table, link_name, ref_column, sec_ref_column, rev_rel_name)

# Tables to generate and relationships with other tables are defined here
tables = [
    # Table, relation, back_relation
    # These come first since they are referenced from service principals
    (AppRoleAssignment, [], []),
    (OAuth2PermissionGrant, [], []),
    (User, [], ['group_member_user', 'application_owner_user', 'serviceprincipal_owner_user', 'role_member_user', 'device_owner', 'group_owner_user', 'au_member_user']),
    (ServicePrincipal, ['serviceprincipal_owner_user', 'serviceprincipal_owner_serviceprincipal'], ['role_member_serviceprincipal', 'serviceprincipal_owner_serviceprincipal', 'application_owner_serviceprincipal', 'group_member_serviceprincipal', 'group_owner_serviceprincipal']),
    (Group, ['group_member_group', 'group_member_user', 'group_member_contact', 'group_member_device', 'group_member_serviceprincipal', 'group_owner_user', 'group_owner_serviceprincipal'], ['group_member_group', 'role_member_group', 'au_member_group']),
    (Application, ['application_owner_user', 'application_owner_serviceprincipal'], []),
    (Device, ['device_owner'], ['group_member_device', 'au_member_device']),
    # (Domain, [], []),
    (DirectoryRole, ['role_member_user', 'role_member_serviceprincipal', 'role_member_group'], []),
    (TenantDetail, [], []),
    (ApplicationRef, [], []),
    (ExtensionProperty, [], []),
    (Contact, [], ['group_member_contact']),
    (Policy, [], []),
    (RoleDefinition, ['role_assignment_eligible', 'role_assignment_active'], []),
    (RoleAssignment, [], ['role_assignment_active']),
    (EligibleRoleAssignment, [], ['role_assignment_eligible']),
    (AuthorizationPolicy, [], []),
    (DirectorySetting, [], []),
    (AdministrativeUnit, ['au_member_group', 'au_member_user', 'au_member_device'], [])
]
with open('metadef/database.py', 'w') as outf:
    outf.write(header)
    for relname, reldata in relations.items():
        if relname == 'role_assignment_active' or relname == 'role_assignment_eligible':
            continue
        outf.write(gen_link_table(relname, reldata[0], reldata[1]))
    for table, links, revlinks in tables:
        outf.write(gen_db_class(table, links, revlinks))
    outf.write(footer)
