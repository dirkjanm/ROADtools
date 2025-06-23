from flask import Flask, request, jsonify, abort, send_from_directory, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from marshmallow_sqlalchemy import ModelConverter
from marshmallow import fields
from roadtools.roadlib.metadef.database import User, JSON, Group, DirectoryRole, ServicePrincipal, AppRoleAssignment, TenantDetail, Application, Device, OAuth2PermissionGrant, AuthorizationPolicy, DirectorySetting, AdministrativeUnit, RoleDefinition
import os
import argparse
from sqlalchemy import func, and_, or_, select
import mimetypes

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

class UserSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = User
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    ownedDevices = fields.Nested(DevicesSchema, many=True)
    ownedServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    ownedApplications = fields.Nested(ApplicationsSchema, many=True)
    ownedGroups = fields.Nested(GroupsSchema, many=True)

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
device_schema = DeviceSchema()
group_schema = GroupSchema()
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
    all_users = db.session.query(User).all()
    result = users_schema.dump(all_users)
    return jsonify(result)


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
    all_groups = db.session.query(Group).all()
    result = groups_schema.dump(all_groups)
    return jsonify(result)

@app.route("/api/groups/<id>", methods=["GET"])
def group_detail(id):
    group = db.session.get(Group, id)
    if not group:
        abort(404)
    return group_schema.jsonify(group)

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

@app.route("/api/serviceprincipals-by-appid/<id>", methods=["GET"])
def sp_detail_by_appid(id):
    sp = db.session.query(ServicePrincipal).filter(ServicePrincipal.appId == id).first()
    if not sp:
        abort(404)
    return serviceprincipal_schema.jsonify(sp)

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