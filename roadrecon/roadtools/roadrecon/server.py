from flask import Flask, request, jsonify, abort, send_from_directory, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from marshmallow_sqlalchemy import ModelConverter
from marshmallow import fields
from roadtools.roadlib.metadef.database import User, JSON, Group, DirectoryRole, \
ServicePrincipal, AppRoleAssignment, TenantDetail, Application, Device, \
OAuth2PermissionGrant, AuthorizationPolicy, DirectorySetting, AdministrativeUnit, \
RoleDefinition, Policy, lnk_policy_user_include_allusers, PIMgovernanceResource, \
PIMgovernanceRoleAssignment, PIMgovernanceRoleDefinition, PIMgovernanceRoleSetting, \
PIMgovernanceRoleSettingV2, IGaccessPackageAssignmentPolicy, IGaccessPackage, \
IGaccessPackageResourceRoleScope, IGaccessPackageResourceRole, IGaccessPackageResourceScope, \
AZroleDefinition, AZroleAssignment, AZsubscription, AZroleEligibilityScheduleInstance, \
FederatedIdentityCredential, AgentIdentityMetadata
from roadtools.roadrecon.nhi_analyzer import analyze_nhi_posture, evaluate_fic_risk, federated_credentials_collected
from sqlalchemy.exc import SQLAlchemyError
import os
import base64
import zlib
import argparse
import json
from sqlalchemy import func, and_, or_, select, desc, asc, cast, collate, inspect as sa_inspect
import mimetypes
import threading

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

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
        fields = ('objectId', 'objectType', 'userPrincipalName', 'displayName', 'mail', 'lastDirSyncTime', 'accountEnabled', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'strongAuthenticationDetail', 'userType', 'searchableDeviceKey')

class DevicesSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'accountEnabled', 'displayName', 'deviceManufacturer', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'deviceId', 'isManaged', 'isRooted', 'dirSyncEnabled')

class DirectoryRoleSchema(ma.Schema):
    class Meta:
        model = DirectoryRole
        fields = ('displayName', 'description')

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

class PIMgovernanceRoleSettingSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleSetting

class PIMgovernanceRoleSettingV2Schema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleSettingV2

class PIMgovernanceRoleDefinitionsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleDefinition

    roleSettings = fields.Nested(PIMgovernanceRoleSettingSchema, many=True)
    roleSettingsv2 = fields.Nested(PIMgovernanceRoleSettingV2Schema, many=True)

class PIMgovernanceResourcesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceResource

class PIMgovernanceRoleAssignmentsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleAssignment

    roleDefinition = fields.Nested(PIMgovernanceRoleDefinitionsSchema)
    resource = fields.Nested(PIMgovernanceResourcesSchema)

# include members
class PIMgovernanceRoleAssignmentsWithMembersSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceRoleAssignment

    subjectUser = fields.Nested(UsersSchema, many=True)
    subjectGroup = fields.Nested(GroupsSchema, many=True)
    subjectServicePrincipal = fields.Nested(ServicePrincipalsSchema, many=True)

class PIMgovernanceRoleDefinitionSchema(RTModelSchema):
    class Meta:
        model = PIMgovernanceRoleDefinition

class PIMgovernanceRoleDefinitionWithAssignmentsSchema(RTModelSchema):
    class Meta:
        model = PIMgovernanceRoleDefinition
    roleAssignments = fields.Nested(PIMgovernanceRoleAssignmentsWithMembersSchema, many=True)
    roleSettings = fields.Nested(PIMgovernanceRoleSettingSchema, many=True)
    roleSettingsv2 = fields.Nested(PIMgovernanceRoleSettingV2Schema, many=True)

# for individual resources, with more detail
class PIMgovernanceResourceSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = PIMgovernanceResource
    roleDefinitions = fields.Nested(PIMgovernanceRoleDefinitionWithAssignmentsSchema, many=True)


class IGaccessPackageResourceRolesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageResourceRole

class IGaccessPackageResourceScopesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageResourceScope

class IGaccessPackageResourceRoleScopesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageResourceRoleScope
    role = fields.Nested(IGaccessPackageResourceRolesSchema, many=True)
    scope = fields.Nested(IGaccessPackageResourceScopesSchema, many=True)

class IGaccessPackagesSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackage

    resourceRoleScopes = fields.Nested(IGaccessPackageResourceRoleScopesSchema, many=True)

class IGaccessPackageAssignmentPolicysSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = IGaccessPackageAssignmentPolicy
    accessPackage = fields.Nested(IGaccessPackagesSchema)

class AZroleDefinitionSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AZroleDefinition

class AZroleAssignmentsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AZroleAssignment
    role = fields.Nested(AZroleDefinitionSchema)

class AZeligibleRoleAssignmentsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AZroleEligibilityScheduleInstance
    role = fields.Nested(AZroleDefinitionSchema)

class UserSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = User
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    ownedDevices = fields.Nested(DevicesSchema, many=True)
    ownedServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    ownedApplications = fields.Nested(ApplicationsSchema, many=True)
    ownedGroups = fields.Nested(GroupsSchema, many=True)
    pimRoleAssignments = fields.Nested(PIMgovernanceRoleAssignmentsSchema, many=True)

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
    pimRoleAssignments = fields.Nested(PIMgovernanceRoleAssignmentsSchema, many=True)

class AdministrativeUnitSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AdministrativeUnit
    memberGroups = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberDevices = fields.Nested(DevicesSchema, many=True)

class FederatedIdentityCredentialsSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = FederatedIdentityCredential

class AgentIdentityMetadataSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = AgentIdentityMetadata

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
    agentMetadata = fields.Method("get_agent_metadata")

    def get_agent_metadata(self, obj):
        try:
            inspector = sa_inspect(db.session.get_bind())
            if "AgentIdentityMetadatas" not in inspector.get_table_names():
                return None
            meta = obj.agentMetadata
            return AgentIdentityMetadataSchema().dump(meta) if meta else None
        except SQLAlchemyError as exc:
            db.session.rollback()
            app.logger.warning("agentMetadata unavailable for %s: %s", getattr(obj, "objectId", "?"), exc)
            return None

class ApplicationSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Application
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    federatedIdentityCredentials = fields.Method("get_federated_credentials")

    def get_federated_credentials(self, obj):
        try:
            inspector = sa_inspect(db.session.get_bind())
            if "FederatedIdentityCredentials" not in inspector.get_table_names():
                return []
            rows = obj.federatedIdentityCredentials or []
            if rows and not federated_credentials_collected(db.session):
                return []  # rows from a failed/skipped/uncollected source are never reported
            return FederatedIdentityCredentialsSchema(many=True).dump(rows)
        except SQLAlchemyError as exc:
            db.session.rollback()
            app.logger.warning("federatedIdentityCredentials unavailable for %s: %s", getattr(obj, "objectId", "?"), exc)
            return []

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
device_schema = DeviceSchema()
group_schema = GroupSchema()
group_schema_simple = GroupsSchema()
application_schema = ApplicationSchema()
td_schema = TenantDetailSchema()
ds_schema = DirectorySettingSchema()
serviceprincipal_schema = ServicePrincipalSchema()
administrativeunit_schema = AdministrativeUnitSchema()
authorizationpolicy_schema = AuthorizationPolicySchema(many=True)
users_schema = UsersSchema(many=True)
devices_schema = DevicesSchema(many=True)
groups_schema = GroupsSchema(many=True)
applications_schema = ApplicationsSchema(many=True)
serviceprincipals_schema = ServicePrincipalsSchema(many=True)
directoryroles_schema = DirectoryRolesSchema(many=True)
administrativeunits_schema = AdministrativeUnitsSchema(many=True)
pimgovernanceroleassignments_schema = PIMgovernanceRoleAssignmentsSchema(many=True)
igaccesspackagepolicys_schema = IGaccessPackageAssignmentPolicysSchema(many=True)
azroleassignments_schema = AZroleAssignmentsSchema(many=True)
azeligibleroleassignments_schema = AZeligibleRoleAssignmentsSchema(many=True)
pimresource_schema = PIMgovernanceResourceSchema()

@app.route("/")
def get_index():
    return send_file('dist_gui/index.html')

@app.errorhandler(404)
def page_not_found(error):
    # Might be a valid angular page, serve that
    if not '.' in request.path and not request.path.startswith('/api/'):
        return send_file('dist_gui/index.html')
    return '404 - Page was not found', 404

@app.route("/<path:path>", methods=["GET"])
def get_gui(path):
    return send_from_directory('dist_gui', path)

@app.route("/api/users", methods=["GET"])
def get_users():
    all_users = db.session.query(User).all()
    result = users_schema.dump(all_users)
    return jsonify(result)

@app.route("/api/paged/users", methods=["GET"])
def get_paged_users():
    return query_all_items(request, users_schema, User, ["userPrincipalName", "displayName", "objectId"])

@app.route("/api/users/<id>", methods=["GET"])
def user_detail(id):
    user = db.session.get(User,id)
    if not user:
        abort(404)
    return user_schema.jsonify(user)

@app.route("/api/devices", methods=["GET"])
def get_devices():
    all_devices = db.session.query(Device).all()
    result = devices_schema.dump(all_devices)
    return jsonify(result)

@app.route("/api/paged/devices", methods=["GET"])
def get_paged_devices():
    return query_all_items(request, devices_schema, Device, ["displayName", "objectId", "deviceId"])

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

@app.route("/api/users/<id>/pimassignments", methods=["GET"])
def user_pimassignments(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    assignments = []
    for group in user.memberOf:
        assignments += group.pimRoleAssignments
    result = pimgovernanceroleassignments_schema.dump(assignments)
    return jsonify(result)

@app.route("/api/users/<id>/accesspackages", methods=["GET"])
def user_accesspackages(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    packages = [] + user.accessPackagePolicies
    for group in user.memberOf:
        packages += group.accessPackagePolicies
    if user.userType != 'Guest':
        alluserpackages = db.session.query(IGaccessPackageAssignmentPolicy).where(IGaccessPackageAssignmentPolicy.allowedTargetScope.in_(['allDirectoryUsers','allMemberUsers'])).all()
    else:
        alluserpackages = db.session.query(IGaccessPackageAssignmentPolicy).where(IGaccessPackageAssignmentPolicy.allowedTargetScope.in_(['allDirectoryUsers','allExternalUsers'])).all()
    packages += alluserpackages
    result = igaccesspackagepolicys_schema.dump(packages)
    return jsonify(result)

def add_ra_recursive(group, roles, processedgroups):
    roles += group.azRoleAssignments
    if group.objectId not in processedgroups:
        processedgroups.add(group.objectId)
        for sgroup in group.memberOf:
            add_ra_recursive(sgroup, roles, processedgroups)

@app.route("/api/users/<id>/azroleassignments", methods=["GET"])
def user_azroleassignments(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)
    roles = [] + user.azRoleAssignments
    processedgroups = set()
    for group in user.memberOf:
        add_ra_recursive(group, roles, processedgroups)

    result = azroleassignments_schema.dump(roles)
    return jsonify(result)

def get_application(aid):
    if isinstance(aid, list):
        return db.session.query(ServicePrincipal).filter(ServicePrincipal.appId.in_(aid)).all()
    else:
        return db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == aid).first()

def parse_appcrit(crit):
    ot = []
    for ctype, clist in crit.items():
        if ctype == 'Acrs':
            ot.append({
                'objectType':'SPECIAL',
                'objectId': None,
                'displayName': 'Action: ' +  ', '.join([action for action in clist])
            })
        elif ctype == 'NetworkAccess':
            # clist should be a dict, for example {"TrafficProfiles":"Internet"}
            ot.append({
                'objectType':'SPECIAL',
                'objectId': None,
                'displayName': 'Network access: ' + ', '.join([f"{action}: {target}" for action, target in clist.items()])
            })
        else:
            if 'All' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'All resources'
                })
                break
            if 'None' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'No resources (policy never applies)'
                })
                break
            if 'Office365' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'All Office 365 applications'
                })
            if 'MicrosoftAdminPortals' in clist:
                ot.append({
                    'objectType':'SPECIAL',
                    'objectId': None,
                    'displayName': 'All Microsoft admin portals'
                })
            objects = get_application(clist)
            if objects is not None:
                if len(objects) > 0:
                    if ctype == 'Applications':
                        for app in objects:
                            ot.append({
                                'objectType':'ServicePrincipal',
                                'objectId': app.objectId,
                                'displayName': app.displayName
                            })
    return ot

def parse_scope(cond):
    if not 'Applications' in cond:
        return
    ucond = cond['Applications']
    out = {'include':[],'exclude':[]}
    for icrit in ucond['Include']:
        out['include'] += parse_appcrit(icrit)
    if 'Exclude' in ucond:
        for icrit in ucond['Exclude']:
            out['exclude'] += parse_appcrit(icrit)
    return out

def process_user_policies(alluser_policies, user):
    policies = []
    for policy in user.policiesIncluded:
        detail = json.loads(policy.policyDetail[0])
        if detail['State'] != 'Enabled' or policy in user.policiesExcluded:
            continue
        else:
            policies.append({
                'objectId': policy.objectId,
                'policyDetail': detail,
                'displayName': policy.displayName,
                'policyScope': parse_scope(detail['Conditions'])
            })
    for policy in alluser_policies:
        detail = json.loads(policy.policyDetail[0])
        if detail['State'] != 'Enabled' or policy in user.policiesExcluded:
            continue
        else:
            policies.append({
                'objectId': policy.objectId,
                'policyDetail': detail,
                'displayName': policy.displayName,
                'policyScope': parse_scope(detail['Conditions'])
            })
    return policies

@app.route("/api/users/<id>/policies", methods=["GET"])
def user_policies(id):
    user = db.session.get(User, id)
    if not user:
        abort(404)

    aup_ids = [record[0] for record in db.session.query(lnk_policy_user_include_allusers).all()]

    alluser_policies = db.session.query(Policy).filter(Policy.objectId.in_(aup_ids)).all()
    return jsonify(process_user_policies(alluser_policies, user))

def parse_compressed_cidr(detail):
    if not 'CompressedCidrIpRanges' in detail:
        return ''
    compressed = detail['CompressedCidrIpRanges']
    b = base64.b64decode(compressed)
    cstr = zlib.decompress(b, -zlib.MAX_WBITS)
    decoded_cidrs = cstr.decode().split(",")
    return decoded_cidrs

@app.route("/api/policies/locations", methods=["GET"])
def policies_locations():
    locs = {}
    for policy in db.session.query(Policy).filter(Policy.policyType == 6).order_by(Policy.displayName):
        loc = {}
        loc['displayName'] = policy.displayName
        detail = None
        oldpolicy = False

        for pdetail in policy.policyDetail:
            detaildata = json.loads(pdetail)
            if 'KnownNetworkPolicies' in detaildata:
                detail = detaildata['KnownNetworkPolicies']
                oldpolicy = True

        if not oldpolicy:
            # New format
            detail = json.loads(policy.policyDetail[0])
            if not detail:
                continue

            loc['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
            loc['appliesToUnknownCountry'] = str(detail.get("ApplyToUnknownCountry")) if detail.get("ApplyToUnknownCountry") is not None else False
            loc['ipRanges'] = parse_compressed_cidr(detail)
            loc['categories'] = detail.get("Categories") if detail.get("Categories") is not None else ""
            loc['countryCodes'] =  detail.get("CountryIsoCodes") if detail.get("CountryIsoCodes") else None
            locs[policy.policyIdentifier] = loc
        else:
            # Old format
            if not detail:
                continue
            loc['displayName'] = detail.get("NetworkName")
            loc['trusted'] = ("trusted" in detail.get("Categories","") if detail.get("Categories") else False)
            loc['appliesToUnknownCountry'] = str(detail.get("ApplyToUnknownCountry")) if detail.get("ApplyToUnknownCountry") is not None else False
            loc['ipRanges'] = detail.get('CidrIpRanges') if detail.get("CidrIpRanges") else ""
            loc['categories'] = detail.get("Categories") if detail.get("Categories") is not None else ""
            loc['countryCodes'] =  detail.get("CountryIsoCodes") if detail.get("CountryIsoCodes") else None
            locs[detail.get("NetworkId")] = loc
    return jsonify(locs)

@app.route("/api/groups", methods=["GET"])
def get_groups():
    all_groups = db.session.query(Group).all()
    result = groups_schema.dump(all_groups)
    return jsonify(result)

@app.route("/api/paged/groups", methods=["GET"])
def get_paged_groups():
    return query_all_items(request, groups_schema, Group, ["displayName", "objectId"])

@app.route("/api/groups/<id>", methods=["GET"])
def group_detail(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    return group_schema.jsonify(group)

@app.route("/api/groups/<id>/pimresource", methods=["GET"])
def group_pimresource(id):
    group = db.session.get(Group, id)
    if not group or not group.pimResource:
        abort(404)
    return pimresource_schema.jsonify(group.pimResource[0])

@app.route("/api/groups/<id>/azroleassignments", methods=["GET"])
def group_azroleassignments(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    roles = []
    processedgroups = set()
    add_ra_recursive(group, roles, processedgroups)

    result = azroleassignments_schema.dump(roles)
    return jsonify(result)

@app.route("/api/groupresolve/<id>", methods=["GET"])
def group_detail_simple(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    return group_schema_simple.jsonify(group)

@app.route("/api/administrativeunits", methods=["GET"])
def get_administrativeunits():
    all_administrativeunits = db.session.query(AdministrativeUnit).all()
    result = administrativeunits_schema.dump(all_administrativeunits)
    return jsonify(result)

@app.route("/api/administrativeunits/<id>", methods=["GET"])
def administrativeunit_detail(id):
    administrativeunit = db.session.get(AdministrativeUnit, id)
    if not administrativeunit:
        abort(404)
    return administrativeunit_schema.jsonify(administrativeunit)

@app.route("/api/serviceprincipals", methods=["GET"])
def get_sps():
    all_sps = db.session.query(ServicePrincipal).all()
    return serviceprincipals_schema.jsonify(all_sps)

@app.route("/api/serviceprincipals/<id>", methods=["GET"])
def sp_detail(id):
    sp = db.session.get(ServicePrincipal, id)
    if not sp:
        abort(404)
    return serviceprincipal_schema.jsonify(sp)

@app.route("/api/serviceprincipals/<id>/azroleassignments", methods=["GET"])
def serviceprincipals_azroleassignments(id):
    serviceprincipals = db.session.get(ServicePrincipal, id)
    if not serviceprincipals:
        abort(404)
    roles = [] + serviceprincipals.azRoleAssignments
    processedgroups = set()
    for group in serviceprincipals.memberOf:
        add_ra_recursive(group, roles, processedgroups)

    result = azroleassignments_schema.dump(roles)
    return jsonify(result)

@app.route("/api/serviceprincipals-by-appid/<id>", methods=["GET"])
def sp_detail_by_appid(id):
    sp = db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == id).first()
    if not sp:
        abort(404)
    return serviceprincipal_schema.jsonify(sp)

@app.route("/api/applications-by-appid/<id>", methods=["GET"])
def app_detail_by_appid(id):
    sp = db.session.query(Application).filter(Application.appId == id).first()
    if not sp:
        abort(404)
    return application_schema.jsonify(sp)

@app.route("/api/applications", methods=["GET"])
def get_applications():
    all_applications = db.session.query(Application).all()
    result = applications_schema.dump(all_applications)
    return jsonify(result)

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
            'strongAuthenticationDetail': user.strongAuthenticationDetail,
            'searchableDeviceKey': user.searchableDeviceKey
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
    if ar.principalType == 'User':
        sp = db.session.get(User, ar.principalId)
    if ar.principalType == 'Group':
        sp = db.session.get(Group, ar.principalId)
    if ar.id == '00000000-0000-0000-0000-000000000000':
        approles.append({'objid':sp.objectId,
                         'ptype':ar.principalType,
                         'pname':sp.displayName,
                         'app':ar.resourceDisplayName,
                         'value':'Default',
                         'desc':'Default Role',
                         'spid':ar.resourceId,
                        })
    else:
        for approle in rsp.appRoles:
            if approle['id'] == ar.id:
                approles.append({'objid':sp.objectId,
                                 'ptype':ar.principalType,
                                 'pname':sp.displayName,
                                 'app':ar.resourceDisplayName,
                                 'value':approle['value'],
                                 'desc':approle['displayName'],
                                 'spid':ar.resourceId,
                                })

@app.route("/api/approles", methods=["GET"])
def get_approles():
    approles = []
    for ar in db.session.query(AppRoleAssignment).all():
        process_approle(approles, ar)
    return jsonify(approles)

@app.route("/api/approles_by_resource/<spid>", methods=["GET"])
def get_approles_by_resource(spid):
    approles = []
    for ar in db.session.query(AppRoleAssignment).filter(AppRoleAssignment.resourceId == spid):
        process_approle(approles, ar)
    return jsonify(approles)

@app.route("/api/approles_by_principal/<pid>", methods=["GET"])
def get_approles_by_principal(pid):
    approles = []
    for ar in db.session.query(AppRoleAssignment).filter(AppRoleAssignment.principalId == pid):
        process_approle(approles, ar)
    return jsonify(approles)

@app.route("/api/oauth2permissions", methods=["GET"])
def get_oauth2permissions():
    oauth2permissions = []
    for permgrant in db.session.query(OAuth2PermissionGrant).all():
        grant = {}
        rsp = db.session.get(ServicePrincipal, permgrant.clientId)
        if permgrant.consentType == 'Principal':
            grant['type'] = 'user'
            user = db.session.get(User, permgrant.principalId)
            grant['userid'] = user.objectId
            grant['userdisplayname'] = user.displayName
        else:
            grant['type'] = 'all'
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
    return jsonify(oauth2permissions)

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
                for member in group.memberServicePrincipals:
                    mp = serviceprincipals_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member SP: {mp['displayName']}"
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
                # SPs with eligible assignments probably don't make sense but who knows
                for member in group.memberServicePrincipals:
                    mp = serviceprincipals_schema.dump([member])[0]
                    mp['displayName'] = f"{principal['displayName']} member SP: {mp['displayName']}"
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


# NHI analysis is expensive (loads every SP/app/role), so it is computed once per DB state and shared
# by all /api/nhi/* routes. Keyed by DB file path; invalidated by a cheap file fingerprint.
_nhi_report_cache = {}
_nhi_cache_lock = threading.Lock()


def _nhi_db_fingerprint():
    """(path, fingerprint) for the SQLite file behind db.session, or (None, None) if not derivable."""
    try:
        path = db.session.get_bind().url.database
    except Exception:
        return None, None
    if not path or path == ":memory:" or not os.path.isfile(path):
        return None, None
    parts = []
    for candidate in (path, path + "-wal"):
        try:
            st = os.stat(candidate)
        except OSError:
            parts.append(None)
            continue
        parts.append((st.st_mtime_ns, st.st_size))
    try:
        with open(path, "rb") as fh:
            header = fh.read(100)  # bytes 24-27: SQLite file change counter
        parts.append(header[24:28])
    except OSError:
        parts.append(None)
    return path, tuple(parts)


def get_nhi_report():
    path, fingerprint = _nhi_db_fingerprint()
    if path is None:
        return analyze_nhi_posture(db.session)
    with _nhi_cache_lock:
        cached = _nhi_report_cache.get(path)
        if cached and cached[0] == fingerprint:
            return cached[1]
        report = analyze_nhi_posture(db.session)
        _nhi_report_cache[path] = (fingerprint, report)
        return report


@app.route("/api/nhi/summary", methods=["GET"])
def get_nhi_summary():
    return jsonify(get_nhi_report()["summary"])


@app.route("/api/nhi/agents", methods=["GET"])
def get_nhi_agents():
    return jsonify(get_nhi_report()["agents"])


@app.route("/api/nhi/workloads", methods=["GET"])
def get_nhi_workloads():
    return jsonify(get_nhi_report()["workloads"])


@app.route("/api/nhi/federatedcredentials", methods=["GET"])
def get_nhi_federated_credentials():
    return jsonify(get_nhi_report()["federatedCredentials"])


@app.route("/api/nhi/findings", methods=["GET"])
def get_nhi_findings():
    return jsonify(get_nhi_report()["findings"])


@app.route("/api/applications/<string:id>/federatedcredentials", methods=["GET"])
def get_application_federated_credentials(id):
    application = db.session.get(Application, id)
    if not application:
        abort(404)
    inspector = sa_inspect(db.session.get_bind())
    if "FederatedIdentityCredentials" not in inspector.get_table_names():
        return jsonify([])
    # Same hiding as the analyzer: rows from a source that was not fully collected (e.g. partial rows
    # after a failed gather) are never reported. Response stays an array; the collection state itself
    # is exposed via /api/nhi/summary (federatedCredentialsCollected / ...CollectionStatus).
    if not federated_credentials_collected(db.session):
        return jsonify([])
    fics = db.session.query(FederatedIdentityCredential).filter(
        or_(
            FederatedIdentityCredential.applicationObjectId == application.objectId,
            and_(
                FederatedIdentityCredential.appId.isnot(None),
                FederatedIdentityCredential.appId == application.appId,
            ),
        )
    ).all()
    evaluated = [evaluate_fic_risk(f, application.displayName or "") for f in fics]
    evaluated.sort(key=lambda x: (-x["severityWeight"], x["name"] or ""))
    return jsonify(evaluated)


@app.route("/api/serviceprincipals/<string:id>/nhi", methods=["GET"])
def get_serviceprincipal_nhi(id):
    sp = db.session.get(ServicePrincipal, id)
    if not sp:
        abort(404)
    report = get_nhi_report()
    agent_item = next((a for a in report["agents"] if a["objectId"] == id), None)
    workload_item = next((w for w in report["workloads"] if w["objectId"] == id), None)
    sp_findings = [
        f for f in report["findings"]
        if f["principalObjectId"] == id or (sp.appId and f.get("appId") == sp.appId)
    ]
    sp_fics = [
        fc for fc in report["federatedCredentials"]
        if sp.appId and fc.get("appId") == sp.appId
    ]
    return jsonify({
        "objectId": sp.objectId,
        "appId": sp.appId,
        "displayName": sp.displayName,
        "isAgent": agent_item is not None,
        "agent": agent_item,
        "workload": workload_item,
        "federatedCredentials": sp_fics,
        "findings": sp_findings,
        "collectionStatus": report["summary"]["collectionStatus"],
        "agentMetadataCollected": report["summary"]["agentMetadataCollected"],
        "agentMetadataCollectionDetail": report["summary"]["agentMetadataCollectionDetail"],
    })

# Wrapper that supports paging based on the work of Kevin Tellier (@flashlam)
def query_all_items(request, schema, model, searchfields):
    page = request.args.get('page', type=int)
    rows = request.args.get('limit', type=int)
    search = request.args.get('search', type=str)
    sort_column = request.args.get('sortColumn', type=str)
    sort_order = request.args.get('sortDirection', type=str)

    query = db.session.query(model)

    if search and search != 'undefined':
        # For now only search on the userPrincipalName and displayName fields, others will be added with advanced filtering
        #filter = build_dynamic_filter(user_schema, search)
        filters = []
        for field in searchfields:
            filters.append(getattr(model,field).like(f'%{search}%'))

        query = query.filter(or_(*filters))

    if sort_column and sort_column != 'undefined':
        field = getattr(model, sort_column)
        if hasattr(field, 'type') and isinstance(field.type, JSON):
            # For JSON fields, use the length of the JSON array for sorting
            field = func.json_array_length(cast(field, db.Text))
        elif hasattr(field, 'property') and hasattr(field.property, 'direction'):
            # Handle relationship fields
            field = field.property.direction.mapper.class_.id
        if sort_order and sort_order.lower() == 'desc':
            query = query.order_by(collate(field, "NOCASE").desc())
        else:
            query = query.order_by(collate(field, "NOCASE").asc())

    if page is None and rows is None:
        all_items = query.all()
    else:
        all_items = query.paginate(page=page, per_page=rows)
    result = {
        'items': schema.dump(all_items),
        'count': all_items.total
    }
    return jsonify(result)

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
        parser.add_argument('--host',
                            type=str,
                            action='store',
                            help='Host IP to bind to (default=127.0.0.1)',
                            default='127.0.0.1')
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
    app.run(host=args.host, port=args.port, debug=args.debug)

if __name__ == '__main__':
    main()
