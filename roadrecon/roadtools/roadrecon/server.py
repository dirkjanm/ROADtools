from flask import Flask, request, jsonify, abort, send_from_directory, redirect, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from marshmallow_sqlalchemy import ModelConverter
from marshmallow import fields
from roadtools.roadlib.metadef.database import User, JSON, Group, DirectoryRole, ServicePrincipal, AppRoleAssignment, TenantDetail, Application, Device, OAuth2PermissionGrant
import os
import argparse
from sqlalchemy import func

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# This will get initialized later on
db = None
ma = Marshmallow(app)

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
        fields = ('objectId', 'objectType', 'userPrincipalName', 'displayName', 'mail', 'lastDirSyncTime', 'accountEnabled', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'strongAuthenticationDetail')

class DevicesSchema(ma.Schema):
    class Meta:
        model = User
        fields = ('objectId', 'objectType', 'accountEnabled', 'displayName', 'deviceManufacturer', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'deviceId', 'isManaged', 'isRooted', 'dirSyncEnabled')

class DirectoryRoleSchema(ma.Schema):
    class Meta:
        model = DirectoryRole
        fields = ('displayName', 'description')

class GroupsSchema(ma.Schema):
    class Meta:
        model = Group
        fields = ('displayName', 'description', 'createdDateTime', 'dirSyncEnabled', 'objectId', 'mail')

class SimpleServicePrincipalsSchema(ma.Schema):
    """
    Simple ServicePrincipalSchema to prevent looping relationships with serviceprincipals
    owning other serviceprincipals
    """
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName')

class ServicePrincipalsSchema(ma.Schema):
    class Meta:
        model = ServicePrincipal
        fields = ('objectId', 'objectType', 'displayName', 'appDisplayName', 'appId', 'appOwnerTenantId', 'publisherName', 'replyUrls', 'appRoles', 'microsoftFirstParty', 'isDirSyncEnabled', 'oauth2Permissions', 'passwordCredentials', 'keyCredentials', 'ownerUsers', 'ownerServicePrincipals', 'accountEnabled', 'servicePrincipalType')
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

class UserSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = User
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    ownedDevices = fields.Nested(DevicesSchema, many=True)
    ownedServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    ownedApplications = fields.Nested(ApplicationsSchema, many=True)

class DeviceSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Device
    memberOf = fields.Nested(GroupsSchema, many=True)
    owner = fields.Nested(UsersSchema, many=True)

class GroupSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Group
    memberOf = fields.Nested(GroupsSchema, many=True)
    memberUsers = fields.Nested(UsersSchema, many=True)
    memberServicePrincipals = fields.Nested(SimpleServicePrincipalsSchema, many=True)

class ServicePrincipalSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = ServicePrincipal
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)
    memberOfRole = fields.Nested(DirectoryRoleSchema, many=True)
    memberOf = fields.Nested(GroupSchema, many=True)


class ApplicationSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = Application
    ownerUsers = fields.Nested(UsersSchema, many=True)
    ownerServicePrincipals = fields.Nested(ServicePrincipalsSchema, many=True)

class TenantDetailSchema(RTModelSchema):
    class Meta(RTModelSchema.Meta):
        model = TenantDetail

# Instantiate all schemas
user_schema = UserSchema()
device_schema = DeviceSchema()
group_schema = GroupSchema()
application_schema = ApplicationSchema()
td_schema = TenantDetailSchema()
serviceprincipal_schema = ServicePrincipalSchema()
users_schema = UsersSchema(many=True)
devices_schema = DevicesSchema(many=True)
groups_schema = GroupsSchema(many=True)
applications_schema = ApplicationsSchema(many=True)
serviceprincipals_schema = ServicePrincipalsSchema(many=True)
directoryroles_schema = DirectoryRolesSchema(many=True)

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
    user = db.session.query(User).get(id)
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
    device = db.session.query(Device).get(id)
    if not device:
        abort(404)
    return device_schema.jsonify(device)

@app.route("/api/users/<id>/groups", methods=["GET"])
def user_groups(id):
    user = db.session.query(User).get(id)
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
    group = db.session.query(Group).get(id)
    if not group:
        abort(404)
    return group_schema.jsonify(group)
import json
@app.route("/api/serviceprincipals", methods=["GET"])
def get_sps():
    all_sps = db.session.query(ServicePrincipal).all()
    result = serviceprincipals_schema.dump(all_sps)
    for obj in result:
        try:
            json.dumps(obj)
        except TypeError:
            import pprint
            pprint.pprint(obj)
    return serviceprincipals_schema.jsonify(all_sps)

@app.route("/api/serviceprincipals/<id>", methods=["GET"])
def sp_detail(id):
    sp = db.session.query(ServicePrincipal).get(id)
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
    all_mfa = db.session.query(User).all()
    out = []
    for user in all_mfa:
        mfa_methods = len(user.strongAuthenticationDetail['methods'])
        methods = [method['methodType'] for method in user.strongAuthenticationDetail['methods']]
        has_app = 'PhoneAppOTP' in methods or 'PhoneAppNotification' in methods
        has_phonenr = 'OneWaySms' in methods or 'TwoWayVoiceMobile' in methods
        has_fido = 'FIDO' in [key['usage'] for key in user.searchableDeviceKey]
        out.append({
            'objectId': user.objectId,
            'displayName': user.displayName,
            'mfamethods': mfa_methods,
            'accountEnabled': user.accountEnabled,
            'has_app': has_app,
            'has_phonenr': has_phonenr,
            'has_fido': has_fido,
            'strongAuthenticationDetail': user.strongAuthenticationDetail
        })
    return jsonify(out)

@app.route("/api/applications/<id>", methods=["GET"])
def application_detail(id):
    application = db.session.query(Application).get(id)
    if not application:
        abort(404)
    return application_schema.jsonify(application)

@app.route("/api/approles", methods=["GET"])
def get_approles():
    approles = []
    for ar in db.session.query(AppRoleAssignment).all():
        rsp = db.session.query(ServicePrincipal).get(ar.resourceId)
        if ar.principalType == 'ServicePrincipal':
            sp = db.session.query(ServicePrincipal).get(ar.principalId)
        if ar.principalType == 'User':
            sp = db.session.query(User).get(ar.principalId)
        if ar.principalType == 'Group':
            sp = db.session.query(Group).get(ar.principalId)
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
    return jsonify(approles)

@app.route("/api/oauth2permissions", methods=["GET"])
def get_oauth2permissions():
    oauth2permissions = []
    for permgrant in db.session.query(OAuth2PermissionGrant).all():
        grant = {}
        rsp = db.session.query(ServicePrincipal).get(permgrant.clientId)
        if permgrant.consentType == 'Principal':
            grant['type'] = 'user'
            user = db.session.query(User).get(permgrant.principalId)
            grant['userid'] = user.objectId
            grant['userdisplayname'] = user.displayName
        else:
            grant['type'] = 'all'
            grant['userid'] = None
            grant['userdisplayname'] = None
        targetapp = db.session.query(ServicePrincipal).get(permgrant.resourceId)
        grant['targetapplication'] = targetapp.displayName
        grant['targetspobjectid'] = targetapp.objectId
        grant['sourceapplication'] = rsp.displayName
        grant['sourcespobjectid'] = rsp.objectId
        grant['expiry'] = permgrant.expiryTime
        grant['scope'] = permgrant.scope
        oauth2permissions.append(grant)
    return jsonify(oauth2permissions)

@app.route("/api/directoryroles", methods=["GET"])
def get_dirroles():
    approles = []
    drs = db.session.query(DirectoryRole).all()
    return directoryroles_schema.jsonify(drs)

@app.route("/api/tenantdetails", methods=["GET"])
def get_tenantdetails():
    approles = []
    drs = db.session.query(TenantDetail).first()
    return td_schema.jsonify(drs)

@app.route("/api/stats", methods=["GET"])
def get_stats():
    stats = {
        'countUsers': db.session.query(func.count(User.objectId)).scalar(),
        'countGroups': db.session.query(func.count(Group.objectId)).scalar(),
        'countServicePrincipals': db.session.query(func.count(ServicePrincipal.objectId)).scalar(),
        'countApplications': db.session.query(func.count(Application.objectId)).scalar(),
        'countDevices': db.session.query(func.count(Device.objectId)).scalar()
    }
    return jsonify(stats)

def create_app_test():
    '''
    Create app for unit tests
    '''
    global db
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(os.getcwd(), 'roadrecon.db')
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
    app.run(debug=args.debug)

if __name__ == '__main__':
    main()
