import sys
from flask import Flask, request, jsonify, abort, send_from_directory, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from marshmallow_sqlalchemy import ModelConverter
from marshmallow import fields
from roadtools.roadlib.metadef.database import User, Policy, JSON, Group, DirectoryRole, ServicePrincipal, AppRoleAssignment, TenantDetail, Application, Device, OAuth2PermissionGrant, AuthorizationPolicy, DirectorySetting, AdministrativeUnit, RoleDefinition
import os
import logging
import argparse
from sqlalchemy import func, and_, or_, select, desc, asc, cast
from sqlalchemy.event import listens_for
from sqlalchemy.pool import _ConnectionRecord
import mimetypes
import json
import zlib
import base64
from html import escape

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

logging.getLogger('werkzeug').setLevel(logging.DEBUG)

# This will get initialized later on
db = None
ma = Marshmallow(app)

mimetypes.add_type('application/javascript', '.js')

# Allow CORS requests from Angular if it's running in develop mode
CORS(app, origins=['http://127.0.0.1:4200', 'http://localhost:4200', 'http://localhost:5000'])

# Model definitions that include a custom JSON type, which doesn't get converted
class RTModelConverter(ModelConverter):
    SQLA_TYPE_MAPPING = dict(
        list(ModelConverter.SQLA_TYPE_MAPPING.items()) +
        [(JSON, fields.Raw)]
    )

# Our custom model schema which uses the model converter from above
class RTModelSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model_converter = RTModelConverter

# Schemas for objects
# For each object type there is an <objectname>Schema and <plural objectname>Schema
# the plural version is for lists of objects (doesn't include all fields)
# the regular version includes all possible fields based on the SQLAlchemy meta definition
class UsersSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'userPrincipalName', 'displayName', 'mail', 'lastDirSyncTime', 'accountEnabled', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'dirSyncEnabled', 'userType')

class PoliciesSchema(ma.Schema):
    class Meta:
        model = Policy
        fields = ('objectId', 'objectType', 'deletionTimestamp', 'displayName', 'keyCredentials', 'policyType', 'policyDetail', 'policyIdentifier', 'tenantDefaultPolicy')

class DevicesSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'accountEnabled', 'displayName', 'deviceManufacturer', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'deviceId', 'isManaged', 'isRooted', 'dirSyncEnabled')

class DirectoryRoleSchema(ma.Schema):
    class Meta:
        model = DirectoryRole
        fields = ('displayName', 'description', 'objectId', 'objectType')

class OAuth2PermissionGrantsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = OAuth2PermissionGrant

class AppRoleAssignmentsSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = AppRoleAssignment

class GroupsSchema(ma.Schema):
    class Meta:
        model = Group
        fields = ('displayName', 'description', 'createdDateTime', 'dirSyncEnabled', 'objectId', 'objectType', 'groupTypes', 'mail', 'isPublic', 'isAssignableToRole', 'membershipRule')

class AdministrativeUnitsSchema(ma.Schema):
    class Meta:
        model = AdministrativeUnit
        fields = ('displayName', 'description', 'createdDateTime', 'objectId', 'objectType', 'membershipType', 'membershipRule')

class SimpleServicePrincipalsSchema(ma.Schema):
    """
    Simple ServicePrincipalSchema to prevent looping relationships with serviceprincipals
    owning other serviceprincipals
    """
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'servicePrincipalType')

class ServicePrincipalsSchema(ma.Schema):
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'appDisplayName', 'appRoleAssignmentRequired', 'appId', 'appOwnerTenantId', 'publisherName', 'replyUrls', 'appRoles', 'microsoftFirstParty', 'isDirSyncEnabled', 'oauth2Permissions', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals', 'accountEnabled', 'servicePrincipalType')
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class ApplicationsSchema(ma.Schema):
    class Meta:
        model = Application
        fields = ('objectId', 'objectType', 'displayName', 'appId', 'appDisplayName', 'oauth2AllowIdTokenImplicitFlow', 'availableToOtherTenants', 'publisherDomain', 'replyUrls', 'appRoles', 'publicClient', 'oauth2AllowImplicitFlow', 'oauth2Permissions', 'homepage', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals')
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class DirectoryRolesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = DirectoryRole
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberGroups = fields.Nested(GroupsSchema, many=True)

class UserSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = User
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    ownedDevices = fields.Nested(DevicesSchema, many=True)
    ownedServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    ownedApplications = fields.Nested(ApplicationsSchema, many=True)
    ownedGroups = fields.Nested(GroupsSchema, many=True)

class PolicySchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Policy

class DeviceSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Device
    memberOf = fields.Nested(GroupsSchema, many=True)
    owner = fields.Nested(UsersSchema, many=True)

class GroupSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Group
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)
    memberServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class AdministrativeUnitSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AdministrativeUnit
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)

class ServicePrincipalSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = ServicePrincipal
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberOf = fields.Nested(GroupSchema, many=True)
    oauth2PermissionGrants = fields.Nested(OAuth2PermissionGrantsSchema, many=True)
    appRolesAssigned = fields.Nested(AppRoleAssignmentsSchema, many=True)
    appRolesAssignedTo = fields.Nested(AppRoleAssignmentsSchema, many=True)

class ApplicationSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Application
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)

class TenantDetailSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = TenantDetail

class DirectorySettingSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = DirectorySetting

class AuthorizationPolicySchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AuthorizationPolicy

# Instantiate all schemas
user_schema = UserSchema()
policy_schema = PolicySchema()
device_schema = DeviceSchema()
group_schema = GroupSchema()
application_schema = ApplicationSchema()
td_schema = TenantDetailSchema()
ds_schema = DirectorySettingSchema()
serviceprincipal_schema = ServicePrincipalSchema()
administrativeunit_schema = AdministrativeUnitSchema()
authorizationpolicy_schema = AuthorizationPolicySchema(many=True)
users_schema = UsersSchema(many=True)
policies_schema = PoliciesSchema(many=True)
devices_schema = DevicesSchema(many=True)
groups_schema = GroupsSchema(many=True)
applications_schema = ApplicationsSchema(many=True)
serviceprincipals_schema = ServicePrincipalsSchema(many=True)
directoryroles_schema = DirectoryRolesSchema(many=True)
administrativeunits_schema = AdministrativeUnitsSchema(many=True)


def _translate_locations(locs):
    policies = db.session.query(Policy).filter(Policy.policyType == 6).all()
    out = []
    # Not sure if there can be multiple
    for policy in policies:
        for pdetail in policy.policyDetail:
            detaildata = json.loads(pdetail)
            if 'KnownNetworkPolicies' in detaildata and detaildata['KnownNetworkPolicies']['NetworkId'] in locs:
                out.append(detaildata['KnownNetworkPolicies']['NetworkName'])
    # New format
    for loc in locs:
        policies = db.session.query(Policy).filter(Policy.policyType == 6, Policy.policyIdentifier == loc).all()
        for policy in policies:
            out.append(policy.displayName)
    return out

def parse_compressed_cidr(detail):
    if not 'CompressedCidrIpRanges' in detail:
            return ''
    compressed = detail['CompressedCidrIpRanges']
    b = base64.b64decode(compressed)
    cstr = zlib.decompress(b, -zlib.MAX_WBITS)
    decoded_cidrs = escape(cstr.decode()).split(",")
    return decoded_cidrs

def parse_associated_policies(location_object, is_trusted_location,condition_policy_list):
    found_pols = []

    for pol in condition_policy_list:
        if not pol.policyDetail:
            continue
        parsed = json.loads(pol.policyDetail[0])
        if not parsed.get('Conditions') or not parsed.get('Conditions').get('Locations'):
            continue

        cloc = parsed.get('Conditions').get('Locations')
        incl = cloc.get('Include') or []
        excl = cloc.get('Exclude') or []
        for i in incl:
            if location_object in i.get('Locations') or (is_trusted_location and "AllTrusted" in i.get('Locations')):
                found_pols.append(pol.displayName)

        for i in excl:
            if location_object in i.get('Locations') or (is_trusted_location and "AllTrusted" in i.get('Locations')):
                found_pols.append(pol.displayName)

    return found_pols

# Function to build a dynamic filter
def build_dynamic_filter(schema, search_string):
    search_string = f"%{search_string}%"  # SQL wildcard for partial match
    filters = []

    # Iterate through each field defined in the schema's Meta class
    for field in schema._declared_fields.keys():
        # Ensure the attribute exists in the User model
        if hasattr(User, field):
            filters.append(getattr(User, field).like(search_string))  # Build the filter for each field

    # Return an OR combination of all filters
    return or_(*filters)

def query_all_items(request,schema,model,fields):
    page = request.args.get('page', type=int)
    rows = request.args.get('rows', type=int)
    search = request.args.get('search', type=str)
    sortedField = request.args.get('sortedField', type=str)
    sortOrder = request.args.get('sortOrder', type=int)

    query = db.session.query(model)
    
    if search:
        # For now only search on the userPrincipalName and displayName fields, others will be added with advanced filtering
        #filter = build_dynamic_filter(user_schema, search)
        filters = []
        for field in fields:
            filters.append(getattr(model,field).like(f'%{search}%'))
        
        query = query.filter(or_(*filters))
    
    if sortedField:
        field = getattr(model, sortedField)
        if hasattr(field, 'type') and isinstance(field.type, JSON):
            # For JSON fields, use the length of the JSON array for sorting
            field = func.json_array_length(cast(field, db.Text))
        elif hasattr(field, 'property') and hasattr(field.property, 'direction'):
            # Handle relationship fields
            field = field.property.direction.mapper.class_.id
        if sortOrder == 1:
            query = query.order_by(field.desc())
        elif sortOrder == -1:
            query = query.order_by(field.asc())

    if page is None and rows is None:
        all_items = query.all()
        result = {
            'items': schema.dump(all_items),
            'total': None
        }
    else:
        all_items = query.paginate(page=page, per_page=rows)
        result = {
            'items': schema.dump(all_items),
            'total': all_items.total
        }
    return jsonify(result)

@app.route("/")
def get_index():
    return send_file('dist_gui/index.html')

@app.errorhandler(404)
def page_not_found(error):
    # Might be a valid angular page, serve that
    if not '.' in request.path:
        return send_file('dist_gui/index.html')
    return '404 - Page was not found', 404

@app.route("/<path:path>", methods=["GET"])
def get_gui(path):
    return send_from_directory('dist_gui', path)

@app.route("/api/users", methods=["GET"])
def get_users():
    return query_all_items(request, users_schema, User, ["userPrincipalName"])

@app.route("/api/users/<id>", methods=["GET"])
def user_detail(id):
    user = db.session.get(User,id)
    if not user:
        abort(404)
    return user_schema.jsonify(user)

@app.route("/api/policies", methods=["GET"])
def get_policies():
    policies = db.session.query(Policy).filter(or_(Policy.policyType == 18,Policy.policyType == 6)).order_by(Policy.displayName.asc()).all()
    results = policies_schema.dump(policies)

    for policy in results:
        if policy['policyType'] == 18:
            policy['policyDetail'] = json.loads(policy['policyDetail'][0])
            if 'Conditions' in policy['policyDetail']:
                conditions = policy['policyDetail']['Conditions']
                if 'Applications' in conditions:
                    applications = conditions['Applications']
                    for key in applications.keys():
                        resolved = []
                        for (index, object_type) in enumerate(applications[key]):
                            if 'Application' in applications[key][index]:
                                for app in applications[key][index]['Applications']:
                                    if app == "All":
                                        resolved.append({
                                            'displayName':'All',
                                            'objectId':'None'
                                        })
                                    # If its an appId (UUID)
                                    elif len(app) == 36:
                                        application = db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == app).first()
                                        if application is not None:
                                            resolved.append({
                                                'displayName': application.displayName,
                                                'objectId': app
                                            })
                                        else:
                                            resolved.append({
                                                'displayName': app,
                                                'objectId': app
                                            })
                                    # Already resolved, just pass
                                    else:
                                        resolved.append({
                                            'displayName':app,
                                            'objectId':'None'
                                        })
                            applications[key][index]['Applications'] = resolved
                if 'ServicePrincipals' in conditions:
                    serviceprincipals = conditions['ServicePrincipals']
                    for key in serviceprincipals.keys():
                        resolved = []
                        for (index, object_type) in enumerate(serviceprincipals[key]):
                            if 'ServicePrincipals' in serviceprincipals[key][index]:
                                for sp in serviceprincipals[key][index]['ServicePrincipals']:
                                    if sp == "All":
                                        resolved.append({
                                            'displayName':'All',
                                            'objectId':'None'
                                        })
                                    # If its an objectId (UUID)
                                    elif len(sp) == 36:
                                        serviceprincipal = db.session.query(ServicePrincipal).filter(ServicePrincipal.objectId == sp).first()
                                        if serviceprincipal is not None:
                                            resolved.append({
                                                'displayName': serviceprincipal.displayName,
                                                'objectId': sp
                                            })
                                        else:
                                            resolved.append({
                                                'displayName': sp,
                                                'objectId': sp
                                            })
                                    elif sp == "None":
                                        pass
                                    # Already resolved, just pass
                                    else:
                                        resolved.append({
                                            'displayName': sp,
                                            'objectId':'None'
                                        })
                            serviceprincipals[key][index]['ServicePrincipals'] = resolved
                if 'Users' in conditions:
                    users = conditions['Users']
                    for key in users.keys():
                        for (index, object_type) in enumerate(users[key]):
                            if 'Users' in object_type:
                                resolved = []
                                if 'Users' in users[key][index]:
                                    for usr in users[key][index]['Users']:
                                        if usr == 'None':
                                            users[key][index] = users[key][index].pop('Users')
                                            break
                                        if usr == "All":
                                            resolved.append({
                                                'displayName':'All',
                                                'objectId':'None'
                                            })
                                        # If its an appId (UUID)
                                        elif len(usr) == 36:
                                            user = db.session.query(User).filter(User.objectId == usr).first()
                                            if user is not None:
                                                resolved.append({
                                                    'displayName': user.displayName,
                                                    'objectId': usr
                                                })
                                            else:
                                                resolved.append({
                                                    'displayName': usr,
                                                    'objectId': usr
                                                })
                                        # Already resolved, just pass
                                        else:
                                            resolved.append({
                                                'displayName': usr,
                                                'objectId':'None'
                                            })
                                if len(resolved) > 0:
                                    users[key][index]['Users'] = resolved
                            if 'Groups' in object_type:
                                resolved = []
                                if 'Groups' in users[key][index]:
                                    for grp in users[key][index]['Groups']:
                                        if grp == "All":
                                            resolved.append({
                                                'displayName':'All',
                                                'objectId':'None'
                                            })
                                        # If its an appId (UUID)
                                        elif len(grp) == 36:
                                            group = db.session.query(Group).filter(Group.objectId == grp).first()
                                            if group is not None:
                                                resolved.append({
                                                    'displayName': group.displayName,
                                                    'objectId': grp
                                                })
                                            else:
                                                resolved.append({
                                                    'displayName': grp,
                                                    'objectId': grp
                                                })
                                        elif grp == "None":
                                            pass
                                        # Already resolved, just pass
                                        else:
                                            resolved.append({
                                                'displayName': grp,
                                                'objectId':'None'
                                            })
                                users[key][index]['Groups'] = resolved
                            if 'Roles' in object_type:
                                resolved = []
                                if 'Roles' in users[key][index]:
                                    for rle in users[key][index]['Roles']:
                                        if rle == "All":
                                            resolved.append({
                                                'displayName':'All',
                                                'objectId':'None'
                                            })
                                        # If its an appId (UUID)
                                        elif len(rle) == 36:
                                            role = db.session.query(RoleDefinition).filter(RoleDefinition.objectId == rle).first()
                                            if role is not None:
                                                resolved.append({
                                                    'displayName': role.displayName,
                                                    'objectId': rle
                                                })
                                            else:
                                                resolved.append({
                                                    'displayName': rle,
                                                    'objectId': rle
                                                })
                                        elif rle == "None":
                                            pass
                                        # Already resolved, just pass
                                        else:
                                            resolved.append({
                                                'displayName': rle,
                                                'objectId':'None'
                                            })
                                    users[key][index]['Roles'] = resolved
                    #Cleaning up data from DB
                    keys_to_remove = []
                    for key, value in users.items():
                        if isinstance(value, list) and all(isinstance(item, list) and item == ["None"] for item in value):
                            keys_to_remove.append(key)
                    for key in keys_to_remove:
                        del users[key]
                    if not users:
                        del conditions['Users']
                if 'Locations' in conditions:
                    locations = conditions['Locations']
                    for key in locations.keys():
                        for (index, object_type) in enumerate(locations[key]):
                            if "All" not in object_type['Locations']:
                                translated = _translate_locations(object_type['Locations'])
                            else:
                                translated = object_type['Locations']
                        conditions['Locations'][key] = translated
        elif policy['policyType'] == 6:
            policy['policyDetail'] = json.loads(policy['policyDetail'][0])

            detail = None
            oldpolicy = False

            if 'KnownNetworkPolicies' in policy['policyDetail']:
                    detail = policy['policyDetail']['KnownNetworkPolicies']
                    oldpolicy = True
            else:
                detail = policy['policyDetail']
            if not oldpolicy:
                policy['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
                policy['appliestounknowncountry'] = str(detail.get("ApplyToUnknownCountry")) if detail.get("ApplyToUnknownCountry") is not None else False
                policy['ipranges'] = ",".join(parse_compressed_cidr(detail))
                policy['categories'] = ",".join(detail.get("Categories")) if detail.get("Categories") is not None else ""
                policy['associated_policies'] = ",".join(parse_associated_policies(policy['policyIdentifier'],policy['trusted'],policies))
                policy['country_codes'] = ",".join(detail.get("CountryIsoCodes")) if detail.get("CountryIsoCodes") else None
            else:
                policy['name'] = detail.get("NetworkName")
                policy['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
                policy['appliestounknowncountry'] = str(detail.get("ApplyToUnknownCountry")) if detail.get("ApplyToUnknownCountry") is not None else False
                policy['ipranges'] = ",".join(detail.get('CidrIpRanges')) if detail.get("CidrIpRanges") else ""
                policy['categories'] = ", ".join(detail.get("Categories")) if detail.get("Categories") is not None else ""
                policy['associated_policies'] = ",".join(parse_associated_policies(detail.get('NetworkId'),policy['trusted'],policies))
                policy['country_codes'] =  ",".join(detail.get("CountryIsoCodes")) if detail.get("CountryIsoCodes") else None

    return jsonify(results)

@app.route("/api/devices", methods=["GET"])
def get_devices():
    return query_all_items(request, devices_schema, Device, ["displayName"])

@app.route("/api/devices/<id>", methods=["GET"])
def device_detail(id):
    device = db.session.get(Device, id)
    if not device:
        abort(404)
    return device_schema.jsonify(device)

@app.route("/api/users/<id>/groups", methods=["GET"])
def user_groups(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    result = groups_schema.dump(user.memberOf)
    return jsonify(result)

@app.route("/api/groups", methods=["GET"])
def get_groups():
    return query_all_items(request, groups_schema, Group, ["displayName"])

@app.route("/api/groups/<id>", methods=["GET"])
def group_detail(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    return group_schema.jsonify(group)

@app.route("/api/administrativeunits", methods=["GET"])
def get_administrativeunits():
    return query_all_items(request, administrativeunits_schema, AdministrativeUnit, ["displayName"])

@app.route("/api/administrativeunits/<id>", methods=["GET"])
def administrativeunit_detail(id):
    administrativeunit = db.session.get(AdministrativeUnit, id)
    if not administrativeunit:
        abort(404)
    return administrativeunit_schema.jsonify(administrativeunit)

@app.route("/api/serviceprincipals", methods=["GET"])
def get_sps():
    return query_all_items(request, serviceprincipals_schema, ServicePrincipal, ["displayName"])

@app.route("/api/serviceprincipals/<id>", methods=["GET"])
def sp_detail(id):
    sp = db.session.get(ServicePrincipal, id)
    if not sp:
        abort(404)
    result = serviceprincipal_schema.dump(sp)
    for (i,elem) in enumerate(sp.appRolesAssigned):
        resource_data = get_approle_by_resources_(sp.appRolesAssigned[i].resourceId)
        result['appRolesAssigned'][i]['desc'] = resource_data[0]['desc']
        result['appRolesAssigned'][i]['value'] = resource_data[0]['value']
    if len(sp.appRolesAssignedTo) > 0:
        principal_data = get_approles_by_principal_(sp.appRolesAssigned[0].resourceId)
        result['appRolesAssignedTo'] = principal_data
    return jsonify(result)

@app.route("/api/serviceprincipals-by-appid/<id>", methods=["GET"])
def sp_detail_by_appid(id):
    sp = db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == id).first()
    if not sp:
        abort(404)
    return serviceprincipal_schema.jsonify(sp)

@app.route("/api/applications", methods=["GET"])
def get_applications():
    return query_all_items(request, applications_schema, Application, ["displayName"])

@app.route("/api/mfa", methods=["GET"])
def get_mfa():
    # First get all users with per-user MFA
    # per_user = db.session.query(AppRoleAssignment).filter(AppRoleAssignment.resourceDisplayName == "MicrosoftAzureActiveAuthn" and AppRoleAssignment.principalType == "User").all()
    # enabledusers = []
    # for approle in per_user:
    #     enabledusers.append(approle.principalId)

    # Filter out mailbox-only users by default
    all_mfa = db.session.execute(select(User).where(
        or_(User.cloudMSExchRecipientDisplayType is None,
            and_(
                User.cloudMSExchRecipientDisplayType != 0,
                User.cloudMSExchRecipientDisplayType != 7,
                User.cloudMSExchRecipientDisplayType != 18
            )
        )
    ))
    out = []
    for user, in all_mfa: # pylint: disable=E1133
        mfa_methods = len(user.strongAuthenticationDetail['methods'])
        methods = [method['methodType'] for method in user.strongAuthenticationDetail['methods']]
        has_app = 'PhoneAppOTP' in methods or 'PhoneAppNotification' in methods
        has_phonenr = 'OneWaySms' in methods or 'TwoWayVoiceMobile' in methods
        has_fido = 'FIDO' in [key['usage'] for key in user.searchableDeviceKey]
        perusermfa = None
        if len(user.strongAuthenticationDetail['requirements']) > 0:
            perusermfa = user.strongAuthenticationDetail['requirements'][0]['state']
        out.append({
            'objectId': user.objectId,
            'displayName': user.displayName,
            'userPrincipalName': user.userPrincipalName,
            'mfamethods': mfa_methods,
            'accountEnabled': user.accountEnabled,
            'perusermfa': perusermfa,
            'has_app': has_app,
            'has_phonenr': has_phonenr,
            'has_fido': has_fido,
            'strongAuthenticationDetail': user.strongAuthenticationDetail
        })
    return jsonify(out)

@app.route("/api/applications/<id>", methods=["GET"])
def application_detail(id):
    application = db.session.get(Application, id)
    if not application:
        abort(404)
    return application_schema.jsonify(application)

def resolve_objectid(oid):
    res = db.session.get(User, oid)
    if res:
        return 'User', users_schema.dump([res])[0]
    res = db.session.get(ServicePrincipal, oid)
    if res:
        return 'ServicePrincipal', serviceprincipals_schema.dump([res])[0]
    res = db.session.get(Group, oid)
    if res:
        return 'Group', groups_schema.dump([res])[0]
    res = db.session.get(Device, oid)
    if res:
        return 'Device', devices_schema.dump([res])[0]
    res = db.session.get(Application, oid)
    if res:
        return 'Application', applications_schema.dump([res])[0]
    return 'Unknown', None

def translate_rolescopes(scopes):
    stypes = []
    sids = []
    snames = []
    for scope in scopes:
        parts = scope.split('/')
        if len(parts) > 2:
            # Includes type
            stype = parts[1]
            sid = parts[2]
            if stype == 'administrativeUnits':
                stype = 'AdministrativeUnit'
                res = db.session.get(AdministrativeUnit, sid)
                if res:
                    sname = f'AU: {res.displayName}'
                else:
                    sname = 'Unknown administrative unit'
            elif stype == 'applications':
                stype = 'Application'
                res = db.session.get(Application, sid)
                if res:
                    sname = f'Application: {res.displayName}'
                else:
                    sname = 'Unknown application'
            elif stype == 'servicePrincipals':
                stype = 'ServicePrincipal'
                res = db.session.get(ServicePrincipal, sid)
                if res:
                    sname = f'ServicePrincipal: {res.displayName}'
                else:
                    sname = 'Unknown serviceprincipal'
            else:
                sname = f'Unsupported scope type: {scope}'
        elif len(parts) > 1 and len(parts[1]) > 0:
            sid = parts[1]
            res = db.session.get(ServicePrincipal, sid)
            if res:
                stype = 'ServicePrincipal'
                sname = f'ServicePrincipal: {res.displayName}'
            else:
                res = db.session.get(Application, sid)
                if res:
                    stype = 'Application'
                    sname = f'Application: {res.displayName}'
                else:
                    stype = 'Unknown'
                    sname = f'Unknown scope type: {scope}'
        else:
            # Scope is entire directory
            stype = 'Directory'
            sname = 'Directory'
            sid = None
        stypes.append(stype)
        snames.append(sname)
        sids.append(sid)
    return stypes, snames, sids


def process_approle(approles, ar):
    rsp = db.session.get(ServicePrincipal, ar.resourceId)
    if ar.principalType == 'ServicePrincipal':
        sp = db.session.get(ServicePrincipal, ar.principalId)
    elif ar.principalType == 'User':
        sp = db.session.get(User, ar.principalId)
    elif ar.principalType == 'Group':
        sp = db.session.get(Group, ar.principalId)
    if ar.id == '00000000-0000-0000-0000-000000000000':
        if sp is not None and ar is not None:
            approles.append({'objectId':sp.objectId,
                            'principalType':ar.principalType,
                            'principalDisplayName':sp.displayName,
                            'resourceDisplayName':ar.resourceDisplayName,
                            'value':'Default',
                            'desc':'Default Role',
                            'spid':ar.resourceId,
                            })
    else:
        for approle in rsp.appRoles:
            if approle['id'] == ar.id:
                if sp is not None and ar is not None:
                    approles.append({'objectId':sp.objectId,
                                    'principalType':ar.principalType,
                                    'principalDisplayName':sp.displayName,
                                    'resourceDisplayName':ar.resourceDisplayName,
                                    'value':approle['value'],
                                    'desc':approle['displayName'],
                                    'spid':ar.resourceId,
                                    })

@app.route("/api/approles", methods=["GET"])
def get_approles():
    page = request.args.get('page', type=int)
    rows = request.args.get('rows', type=int)
    search = request.args.get('search', type=str)
    sortedField = request.args.get('sortedField', type=str)
    sortOrder = request.args.get('sortOrder', type=int)

    approles = []
    query = db.session.query(AppRoleAssignment)

    if search:
        # For now only search on the userPrincipalName and displayName fields, others will be added with advanced filtering
        #filter = build_dynamic_filter(user_schema, search)
        filters = []
        filters.append(AppRoleAssignment.principalDisplayName.like(f'%{search}%'))
        
        query = query.filter(or_(*filters))
    
    if sortedField:
        if sortOrder == 1:
            query = query.order_by(getattr(AppRoleAssignment,sortedField).desc())
        elif sortOrder == -1:
            query = query.order_by(getattr(AppRoleAssignment,sortedField).asc())

    if page is None and rows is None:
        result = query.all()
    else:
        result = query.paginate(page=page, per_page=rows)
    
    for ar in result:
        process_approle(approles, ar)
    
    result = {'items':approles,'total':result.total}

    return jsonify(result)

def get_approle_by_resources_(spid):
    approles = []
    for ar in db.session.query(AppRoleAssignment).filter(AppRoleAssignment.resourceId == spid):
        process_approle(approles, ar)
    return approles

@app.route("/api/approles_by_resource/<spid>", methods=["GET"])
def get_approles_by_resource(spid):
    return jsonify(get_approle_by_resources_(spid))

def get_approles_by_principal_(pid):
    approles = []
    for ar in db.session.query(AppRoleAssignment).filter(AppRoleAssignment.principalId == pid):
        process_approle(approles, ar)
    return approles

@app.route("/api/approles_by_principal/<pid>", methods=["GET"])
def get_approles_by_principal(pid):
    jsonify(get_approles_by_principal_(pid))

@app.route("/api/oauth2permissions", methods=["GET"])
def get_oauth2permissions():
    page = request.args.get('page', type=int)
    rows = request.args.get('rows', type=int)
    search = request.args.get('search', type=str)
    sortedField = request.args.get('sortedField', type=str)
    sortOrder = request.args.get('sortOrder', type=int)

    query = db.session.query(OAuth2PermissionGrant)

    if search:
        # For now only search on the userPrincipalName and displayName fields, others will be added with advanced filtering
        #filter = build_dynamic_filter(user_schema, search)
        filters = []
        filters.append(ServicePrincipal.displayName.like(f'%{search}%'))
        
        query = query.filter(or_(*filters))

    if sortedField:
        if sortOrder == 1:
            query = query.order_by(getattr(OAuth2PermissionGrant,sortedField).desc())
        elif sortOrder == -1:
            query = query.order_by(getattr(OAuth2PermissionGrant,sortedField).asc())

    if page is None and rows is None:
        result = query.all()
        result.total = len(result)
    else:
        result = query.paginate(page=page, per_page=rows)

    oauth2permissions = []
    for permgrant in result:
        grant = {}
        rsp = db.session.get(ServicePrincipal, permgrant.clientId)
        if permgrant.consentType == 'Principal':
            grant['consentType'] = 'user'
            user = db.session.get(User, permgrant.principalId)
            grant['userid'] = user.objectId
            grant['userdisplayname'] = user.displayName
        else:
            grant['consentType'] = 'all'
            grant['userid'] = None
            grant['userdisplayname'] = None
        targetapp = db.session.get(ServicePrincipal, permgrant.resourceId)
        grant['targetapplication'] = targetapp.displayName
        grant['targetspobjectid'] = targetapp.objectId
        grant['sourceapplication'] = rsp.displayName
        grant['sourcespobjectid'] = rsp.objectId
        grant['expiry'] = permgrant.expiryTime.strftime("%Y-%m-%dT%H:%M:%S")
        grant['scope'] = permgrant.scope
        oauth2permissions.append(grant)

    return jsonify({'items':oauth2permissions,'total':result.total})

@app.route("/api/roledefinitions", methods=["GET"])
def get_allroles():
    allroles = []
    for role in db.session.query(RoleDefinition).all():
        roleobj = {
            'objectId': role.objectId,
            'displayName': role.displayName,
            'description': role.description,
            'isBuiltIn': role.isBuiltIn,
            'templateId': role.templateId,
            'assignments': []
        }
        for assignment in role.assignments:
            stypes, snames, sids = translate_rolescopes(assignment.resourceScopes)
            aobj = {
                'type': 'assignment',
                'scope': assignment.resourceScopes,
                'scopeTypes': stypes,
                'scopeNames': snames,
                'scopeIds': sids
            }
            principalType, principal = resolve_objectid(assignment.principalId)
            aobj['principal'] = principal

            roleobj['assignments'].append(aobj)
            if principalType == 'Group':
                group = db.session.get(Group, assignment.principalId)
                for member in group.memberUsers:
                    mp = users_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member: {mp['displayName']}"
                    roleobj['assignments'].append({
                        'type': 'assignment',
                        'scope': assignment.resourceScopes,
                        'scopeTypes': stypes,
                        'scopeNames': snames,
                        'scopeIds': sids,
                        'principal': mp
                    })

        for assignment in role.eligibleAssignments:
            stypes, snames, sids = translate_rolescopes(assignment.resourceScopes)
            aobj = {
                'type': 'eligible',
                'scope': assignment.resourceScopes,
                'scopeTypes': stypes,
                'scopeNames': snames,
                'scopeIds': sids
            }
            principalType, principal = resolve_objectid(assignment.principalId)
            aobj['principal'] = principal
            roleobj['assignments'].append(aobj)
            if principalType == 'Group':
                group = db.session.get(Group, assignment.principalId)
                for member in group.memberUsers:
                    mp = users_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member: {mp['displayName']}"
                    roleobj['assignments'].append({
                        'type': 'eligible',
                        'scope': assignment.resourceScopes,
                        'scopeTypes': stypes,
                        'scopeNames': snames,
                        'scopeIds': sids,
                        'principal': mp
                    })
        allroles.append(roleobj)
    return jsonify(allroles)

@app.route("/api/directoryroles", methods=["GET"])
def get_dirroles():
    drs = db.session.query(DirectoryRole).all()
    return directoryroles_schema.jsonify(drs)

@app.route("/api/tenantdetails", methods=["GET"])
def get_tenantdetails():
    drs = db.session.query(TenantDetail).first()
    return td_schema.jsonify(drs)

@app.route("/api/directorysettings", methods=["GET"])
def get_directorysettings():
    drs = db.session.query(DirectorySetting).first()
    return ds_schema.jsonify(drs)

@app.route("/api/authorizationpolicies", methods=["GET"])
def get_authpolicies():
    drs = db.session.query(AuthorizationPolicy).all()
    return authorizationpolicy_schema.jsonify(drs)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    # pylint: disable=not-callable
    stats = {
        'countUsers': db.session.query(func.count(User.objectId)).scalar(),
        'countGroups': db.session.query(func.count(Group.objectId)).scalar(),
        'countServicePrincipals': db.session.query(func.count(ServicePrincipal.objectId)).scalar(),
        'countApplications': db.session.query(func.count(Application.objectId)).scalar(),
        'countDevices': db.session.query(func.count(Device.objectId)).scalar(),
        'countAdministrativeUnits': db.session.query(func.count(AdministrativeUnit.objectId)).scalar(),
    }
    return jsonify(stats)

def create_app_test():
    '''
    Create app for unit tests
    '''
    global db
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'roadrecon.db')
    if not db:
        db = SQLAlchemy(app)
    return app

def main(args=None):
    global db
    if not args:
        parser = argparse.ArgumentParser(add_help=True, description='ROADrecon GUI', formatter_class=argparse.RawDescriptionHelpFormatter)
        parser.add_argument('-d',
                            '--database',
                            action='store',
                            help='Database file. Can be the local database name for SQLite, or an SQLAlchemy compatible URL such as postgresql+psycopg2://dirkjan@/roadtools',
                            default='roadrecon.db')
        parser.add_argument('--debug',
                            action='store_true',
                            help='Enable flask debug')
        parser.add_argument('--profile',
                            action='store_true',
                            help='Enable flask profiler')
        parser.add_argument('--port',
                            type=int,
                            action='store',
                            help='HTTP Server port (default=5000)',
                            default=5000)
        args = parser.parse_args()
    
    if not ':/' in args.database:
        if args.database[0] != '/':
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), args.database)
        else:
            app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + args.database
    else:
        app.config['SQLALCHEMY_DATABASE_URI'] = args.database
    db = SQLAlchemy(app)
    if args.profile:
        from werkzeug.middleware.profiler import ProfilerMiddleware
        app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[5])
    app.run(debug=args.debug, host='0.0.0.0', port=args.port)

if __name__ == '__main__':
    main()
