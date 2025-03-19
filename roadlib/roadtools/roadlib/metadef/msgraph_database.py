import os
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

lnk_au_member_device = Table('lnk_au_member_device', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.id')),
    Column('Device', Text, ForeignKey('Devices.id'))
)

lnk_au_member_group = Table('lnk_au_member_group', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.id')),
    Column('Group', Text, ForeignKey('Groups.id'))
)

lnk_au_member_user = Table('lnk_au_member_user', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_application_owner_serviceprincipal = Table('lnk_application_owner_serviceprincipal', Base.metadata,
    Column('Application', Text, ForeignKey('Applications.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_application_owner_user = Table('lnk_application_owner_user', Base.metadata,
    Column('Application', Text, ForeignKey('Applications.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_device_owner = Table('lnk_device_owner', Base.metadata,
    Column('Device', Text, ForeignKey('Devices.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_group_member_contact = Table('lnk_group_member_contact', Base.metadata,
    Column('Contact', Text, ForeignKey('Contacts.id')),
    Column('Group', Text, ForeignKey('Groups.id'))
)

lnk_group_member_device = Table('lnk_group_member_device', Base.metadata,
    Column('Device', Text, ForeignKey('Devices.id')),
    Column('Group', Text, ForeignKey('Groups.id'))
)

lnk_group_member_group = Table('lnk_group_member_group', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('childGroup', Text, ForeignKey('Groups.id'))
)

lnk_group_member_serviceprincipal = Table('lnk_group_member_serviceprincipal', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_group_member_user = Table('lnk_group_member_user', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_group_owner_serviceprincipal = Table('lnk_group_owner_serviceprincipal', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_group_owner_user = Table('lnk_group_owner_user', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_role_member_group = Table('lnk_role_member_group', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.id')),
    Column('Group', Text, ForeignKey('Groups.id'))
)

lnk_role_member_serviceprincipal = Table('lnk_role_member_serviceprincipal', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_role_member_user = Table('lnk_role_member_user', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_serviceprincipal_owner_serviceprincipal = Table('lnk_serviceprincipal_owner_serviceprincipal', Base.metadata,
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id')),
    Column('childServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_serviceprincipal_owner_user = Table('lnk_serviceprincipal_owner_user', Base.metadata,
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

class AdministrativeUnit(Base, SerializeMixin):
    __tablename__ = "AdministrativeUnits"
    deletionTimestamp = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    id = Column(Text, primary_key=True)
    isMemberManagementRestricted = Column(Boolean)
    membershipRule = Column(Text)
    membershipRuleProcessingState = Column(Text)
    membershipType = Column(Text)
    visibility = Column(Text)

    memberDevices = relationship("Device", secondary=lnk_au_member_device, back_populates="memberOfAu")
    memberGroups = relationship("Group", secondary=lnk_au_member_group, back_populates="memberOfAu")
    memberUsers = relationship("User", secondary=lnk_au_member_user, back_populates="memberOfAu")

class Application(Base, SerializeMixin):
    __tablename__ = "Applications"
    addIns = Column(JSON)
    api = Column(JSON)
    appId = Column(Text)
    appRoles = Column(JSON)
    applicationTemplateId = Column(Text)
    certification = Column(JSON)
    createdDateTime = Column(DateTime)
    defaultRedirectUri = Column(Text)
    deletedDateTime = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    groupMembershipClaims = Column(Text)
    id = Column(Text, primary_key=True)
    identifierUris = Column(JSON)
    info = Column(JSON)
    isDeviceOnlyAuthSupported = Column(Boolean)
    isFallbackPublicClient = Column(Boolean)
    keyCredentials = Column(JSON)
    nativeAuthenticationApisEnabled = Column(Boolean)
    notes = Column(Text)
    optionalClaims = Column(JSON)
    parentalControlSettings = Column(JSON)
    passwordCredentials = Column(JSON)
    publicClient = Column(JSON)
    publisherDomain = Column(Text)
    requestSignatureVerification = Column(Boolean)
    requiredResourceAccess = Column(JSON)
    samlMetadataUrl = Column(Text)
    serviceManagementReference = Column(Text)
    servicePrincipalLockConfiguration = Column(JSON)
    signInAudience = Column(Text)
    spa = Column(JSON)
    tags = Column(JSON)
    tokenEncryptionKeyId = Column(Text)
    uniqueName = Column(Text)
    verifiedPublisher = Column(JSON)
    web = Column(JSON)

    ownerServicePrincipals = relationship("ServicePrincipal", secondary=lnk_application_owner_serviceprincipal, back_populates="ownedApplications")
    ownerUsers = relationship("User", secondary=lnk_application_owner_user, back_populates="ownedApplications")

class ApplicationRef(Base, SerializeMixin):
    __tablename__ = "ApplicationRefs"
    appCategory = Column(Text)
    appContextId = Column(Text)
    appData = Column(Text)
    appId = Column(Text, primary_key=True)
    appRoles = Column(JSON)
    availableToOtherTenants = Column(Boolean)
    certification = Column(JSON)
    displayName = Column(Text)
    errorUrl = Column(Text)
    homepage = Column(Text)
    identifierUris = Column(JSON)
    knownClientApplications = Column(JSON)
    logoutUrl = Column(Text)
    logoUrl = Column(Text)
    mainLogo = Column(Text)
    oauth2Permissions = Column(JSON)
    publisherDomain = Column(Text)
    publisherName = Column(Text)
    publicClient = Column(Boolean)
    replyUrls = Column(JSON)
    requiredResourceAccess = Column(JSON)
    samlMetadataUrl = Column(Text)
    supportsConvergence = Column(Boolean)
    verifiedPublisher = Column(JSON)

class AppRoleAssignment(Base, SerializeMixin):
    __tablename__ = "AppRoleAssignments"
    appRoleId = Column(Text)
    creationTimestamp = Column(DateTime)
    deletionTimestamp = Column(DateTime)
    id = Column(Text, primary_key=True)
    principalDisplayName = Column(Text)
    principalId = Column(Text)
    principalType = Column(Text)
    resourceDisplayName = Column(Text)
    resourceId = Column(Text)

class AppRoleAssignmentto(Base, SerializeMixin):
    __tablename__ = "AppRoleAssignmentsto"
    appRoleId = Column(Text)
    createdDateTime = Column(DateTime)
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    principalDisplayName = Column(Text)
    principalId = Column(Text)
    principalType = Column(Text)
    resourceDisplayName = Column(Text)
    resourceId = Column(Text)

class AuthorizationPolicy(Base, SerializeMixin):
    __tablename__ = "AuthorizationPolicys"
    allowEmailVerifiedUsersToJoinOrganization = Column(Boolean)
    allowInvitesFrom = Column(Text)
    allowUserConsentForRiskyApps = Column(Boolean)
    allowedToSignUpEmailBasedSubscriptions = Column(Boolean)
    allowedToUseSSPR = Column(Boolean)
    blockMsolPowerShell = Column(Boolean)
    defaultUserRolePermissions = Column(JSON)
    description = Column(Text)
    displayName = Column(Text)
    guestUserRoleId = Column(Text)
    id = Column(Text, primary_key=True)

class Contact(Base, SerializeMixin):
    __tablename__ = "Contacts"
    assistantName = Column(Text)
    birthday = Column(DateTime)
    businessAddress = Column(Text)
    businessHomePage = Column(Text)
    businessPhones = Column(JSON)
    categories = Column(JSON)
    changeKey = Column(Text)
    children = Column(JSON)
    companyName = Column(Text)
    createdDateTime = Column(DateTime)
    department = Column(Text)
    displayName = Column(Text)
    emailAddresses = Column(Text)
    fileAs = Column(Text)
    generation = Column(Text)
    givenName = Column(Text)
    homeAddress = Column(Text)
    homePhones = Column(JSON)
    id = Column(Text, primary_key=True)
    imAddresses = Column(JSON)
    initials = Column(Text)
    jobTitle = Column(Text)
    lastModifiedDateTime = Column(DateTime)
    manager = Column(Text)
    middleName = Column(Text)
    mobilePhone = Column(Text)
    nickName = Column(Text)
    officeLocation = Column(Text)
    otherAddress = Column(Text)
    parentFolderId = Column(Text)
    personalNotes = Column(Text)
    photo = Column(Text)
    profession = Column(Text)
    spouseName = Column(Text)
    surname = Column(Text)
    title = Column(Text)
    yomiCompanyName = Column(Text)
    yomiGivenName = Column(Text)
    yomiSurname = Column(Text)

    memberOf = relationship("Group", secondary=lnk_group_member_contact, back_populates="memberContacts")

class Device(Base, SerializeMixin):
    __tablename__ = "Devices"
    accountEnabled = Column(Boolean)
    alternativeSecurityIds = Column(JSON)
    approximateLastSignInDateTime = Column(DateTime)
    complianceExpirationDateTime = Column(DateTime)
    createdDateTime = Column(DateTime)
    deletedDateTime = Column(DateTime)
    deviceCategory = Column(Text)
    deviceId = Column(Text)
    deviceMetadata = Column(Text)
    deviceOwnership = Column(Text)
    deviceVersion = Column(Integer)
    displayName = Column(Text)
    domainName = Column(Text)
    enrollmentProfileName = Column(Text)
    enrollmentType = Column(Text)
    extensionAttributes = Column(JSON)
    externalSourceName = Column(Text)
    id = Column(Text, primary_key=True)
    isCompliant = Column(Boolean)
    isManaged = Column(Boolean)
    isRooted = Column(Boolean)
    keyCredentials = Column(JSON)
    managementType = Column(Text)
    manufacturer = Column(Text)
    model = Column(Text)
    onPremisesLastSyncDateTime = Column(DateTime)
    onPremisesSyncEnabled = Column(Boolean)
    operatingSystem = Column(Text)
    operatingSystemVersion = Column(Text)
    physicalIds = Column(JSON)
    profileType = Column(Text)
    registrationDateTime = Column(DateTime)
    # reserved1 = Column(Text)
    sourceType = Column(Text)
    systemLabels = Column(JSON)
    trustType = Column(Text)

    memberOf = relationship("Group", secondary=lnk_group_member_device, back_populates="memberDevices")
    memberOfAu = relationship("AdministrativeUnit", secondary=lnk_au_member_device, back_populates="memberDevices")
    owner = relationship("User", secondary=lnk_device_owner, back_populates="ownedDevices")

class DirectoryRole(Base, SerializeMixin):
    __tablename__ = "DirectoryRoles"
    deletedDateTime = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    id = Column(Text, primary_key=True)
    roleDisabled = Column(Boolean)
    roleTemplateId = Column(Text)

    memberGroups = relationship("Group", secondary=lnk_role_member_group, back_populates="memberOfRole")
    memberServicePrincipals = relationship("ServicePrincipal", secondary=lnk_role_member_serviceprincipal, back_populates="memberOfRole")
    memberUsers = relationship("User", secondary=lnk_role_member_user, back_populates="memberOfRole")

class DirectorySetting(Base, SerializeMixin):
    __tablename__ = "DirectorySettings"
    displayName = Column(Text)
    id = Column(Text, primary_key=True)
    templateId = Column(Text)
    values = Column(JSON)

class EligibleRoleAssignment(Base, SerializeMixin):
    __tablename__ = "EligibleRoleAssignments"
    id = Column(Text, primary_key=True)
    principalId = Column(Text)
    resourceScopes = Column(JSON)
    roleDefinitionId = Column(Text, ForeignKey("RoleDefinitions.id"))
    directoryScopeId = Column(Text)
    appScopeId = Column(Text)
    createdUsing = Column(Text)
    createdDateTime = Column(DateTime)
    modifiedDateTime = Column(DateTime)
    status = Column(Text)
    memberType = Column(Text)
    scheduleInfo = Column(JSON)

    roleDefinition = relationship("RoleDefinition", back_populates="eligibleAssignments")

class ExtensionProperty(Base, SerializeMixin):
    __tablename__ = "ExtensionPropertys"
    appDisplayName = Column(Text)
    dataType = Column(Text)
    deletionTimestamp = Column(DateTime)
    id = Column(Text, primary_key=True)
    isSyncedFromOnPremises = Column(Boolean)
    name = Column(Text)
    objectType = Column(Text)
    targetObjects = Column(JSON)

class Group(Base, SerializeMixin):
    __tablename__ = "Groups"
    classification = Column(Text)
    createdDateTime = Column(DateTime)
    creationOptions = Column(JSON)
    deletedDateTime = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    expirationDateTime = Column(DateTime)
    groupTypes = Column(JSON)
    id = Column(Text, primary_key=True)
    isAssignableToRole = Column(Boolean)
    isMembershipRuleLocked = Column(Boolean)
    isPublic = Column(Boolean)
    mail = Column(Text)
    mailEnabled = Column(Boolean)
    mailNickname = Column(Text)
    onPremisesDomainName = Column(Text)
    onPremisesLastSyncDateTime = Column(DateTime)
    onPremisesNetBiosName = Column(Text)
    onPremisesProvisioningErrors = Column(JSON)
    onPremisesSamAccountName = Column(Text)
    onPremisesSecurityIdentifier = Column(Text)
    onPremisesSyncEnabled = Column(Boolean)
    preferredDataLocation = Column(Text)
    preferredLanguage = Column(Text)
    proxyAddresses = Column(JSON)
    renewedDateTime = Column(DateTime)
    resourceBehaviorOptions = Column(JSON)
    resourceProvisioningOptions = Column(JSON)
    securityEnabled = Column(Boolean)
    securityIdentifier = Column(Text)
    serviceProvisioningErrors = Column(JSON)
    theme = Column(Text)
    visibility = Column(Text)

    memberContacts = relationship("Contact", secondary=lnk_group_member_contact, back_populates="memberOf")
    memberDevices = relationship("Device", secondary=lnk_group_member_device, back_populates="memberOf")
    memberGroups = relationship("Group", secondary=lnk_group_member_group, primaryjoin=id==lnk_group_member_group.c.Group, secondaryjoin=id==lnk_group_member_group.c.childGroup, back_populates="memberOf")
    memberOf = relationship("Group", secondary=lnk_group_member_group, primaryjoin=id==lnk_group_member_group.c.childGroup, secondaryjoin=id==lnk_group_member_group.c.Group, back_populates="memberGroups")
    memberOfAu = relationship("AdministrativeUnit", secondary=lnk_au_member_group, back_populates="memberGroups")
    memberOfRole = relationship("DirectoryRole", secondary=lnk_role_member_group, back_populates="memberGroups")
    memberServicePrincipals = relationship("ServicePrincipal", secondary=lnk_group_member_serviceprincipal, back_populates="memberOf")
    memberUsers = relationship("User", secondary=lnk_group_member_user, back_populates="memberOf")
    ownerServicePrincipals = relationship("ServicePrincipal", secondary=lnk_group_owner_serviceprincipal, back_populates="ownedGroups")
    ownerUsers = relationship("User", secondary=lnk_group_owner_user, back_populates="ownedGroups")

class OAuth2PermissionGrant(Base, SerializeMixin):
    __tablename__ = "OAuth2PermissionGrants"
    clientId = Column(Text)
    consentType = Column(Text)
    id = Column(Text, primary_key=True)
    principalId = Column(Text)
    resourceId = Column(Text)
    scope = Column(Text)

class Policy(Base, SerializeMixin):
    __tablename__ = "Policys"
    conditions = Column(JSON)
    createdDateTime = Column(DateTime)
    displayName = Column(Text)
    grantControls = Column(JSON)
    id = Column(Text, primary_key=True)
    modifiedDateTime = Column(DateTime)
    sessionControls = Column(JSON)
    state = Column(Text)

class RoleAssignment(Base, SerializeMixin):
    __tablename__ = "RoleAssignments"
    id = Column(Text,primary_key=True)
    principalId = Column(Text)
    directoryScopeId = Column(JSON)
    roleDefinitionId = Column(Text, ForeignKey("RoleDefinitions.id"))

    roleDefinition = relationship("RoleDefinition", back_populates="assignments")

class RoleDefinition(Base, SerializeMixin):
    __tablename__ = "RoleDefinitions"
    description = Column(Text)
    displayName = Column(Text)
    id = Column(Text, primary_key=True)
    isBuiltIn = Column(Boolean)
    isEnabled = Column(Boolean)
    resourceScopes = Column(JSON)
    rolePermissions = Column(JSON)
    templateId = Column(Text)
    version = Column(Text)

    eligibleAssignments = relationship("EligibleRoleAssignment",
        back_populates="roleDefinition")

    assignments = relationship("RoleAssignment",
        back_populates="roleDefinition")
# class RoleDefinition(Base, SerializeMixin):
#     __tablename__ = "RoleDefinitions"
#     description = Column(Text)
#     displayName = Column(Text)
#     id = Column(Text, primary_key=True)
#     isBuiltIn = Column(Boolean)
#     roleAssignments = Column(JSON)
#     templateId = Column(Text)

    # eligibleAssignments = relationship("EligibleRoleAssignment",
    #     back_populates="roleDefinition")

    # assignments = relationship("RoleAssignment",
    #     back_populates="roleDefinition")

class ServicePrincipal(Base, SerializeMixin):
    __tablename__ = "ServicePrincipals"
    accountEnabled = Column(Boolean)
    addIns = Column(JSON)
    alternativeNames = Column(JSON)
    appDisplayName = Column(Text)
    appId = Column(Text)
    appOwnerOrganizationId = Column(Text)
    appRoleAssignmentRequired = Column(Boolean)
    appRoles = Column(JSON)
    createdDateTime = Column(DateTime)
    deletedDateTime = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    homepage = Column(Text)
    id = Column(Text, primary_key=True)
    info = Column(JSON)
    keyCredentials = Column(JSON)
    loginUrl = Column(Text)
    logoutUrl = Column(Text)
    notes = Column(Text)
    notificationEmailAddresses = Column(JSON)
    oauth2PermissionScopes = Column(JSON)
    passwordCredentials = Column(JSON)
    preferredSingleSignOnMode = Column(Text)
    preferredTokenSigningKeyThumbprint = Column(Text)
    replyUrls = Column(JSON)
    samlSingleSignOnSettings = Column(JSON)
    servicePrincipalNames = Column(JSON)
    servicePrincipalType = Column(Text)
    signInAudience = Column(Text)
    tags = Column(JSON)
    tokenEncryptionKeyId = Column(Text)
    useCustomTokenSigningKey = Column(Boolean)
    verifiedPublisher = Column(JSON)
    resourceSpecificApplicationPermissions = Column(JSON)

    appRolesAssigned = relationship("AppRoleAssignment", primaryjoin=id == foreign(AppRoleAssignment.resourceId))
    appRolesAssignedTo = relationship("AppRoleAssignment", primaryjoin=id == foreign(AppRoleAssignment.principalId))
    memberOf = relationship("Group", secondary=lnk_group_member_serviceprincipal, back_populates="memberServicePrincipals")
    memberOfRole = relationship("DirectoryRole", secondary=lnk_role_member_serviceprincipal, back_populates="memberServicePrincipals")
    oauth2PermissionGrants = relationship("OAuth2PermissionGrant", primaryjoin=id == foreign(OAuth2PermissionGrant.clientId))
    ownedApplications = relationship("Application", secondary=lnk_application_owner_serviceprincipal, back_populates="ownerServicePrincipals")
    ownedGroups = relationship("Group", secondary=lnk_group_owner_serviceprincipal, back_populates="ownerServicePrincipals")
    ownedServicePrincipals = relationship("ServicePrincipal", secondary=lnk_serviceprincipal_owner_serviceprincipal, primaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.ServicePrincipal, secondaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.childServicePrincipal, back_populates="ownerServicePrincipals")
    ownerServicePrincipals = relationship("ServicePrincipal", secondary=lnk_serviceprincipal_owner_serviceprincipal, primaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.childServicePrincipal, secondaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.ServicePrincipal, back_populates="ownedServicePrincipals")
    ownerUsers = relationship("User", secondary=lnk_serviceprincipal_owner_user, back_populates="ownedServicePrincipals")

class TenantDetail(Base, SerializeMixin):
    __tablename__ = "TenantDetails"
    assignedPlans = Column(JSON)
    businessPhones = Column(JSON)
    city = Column(Text)
    country = Column(Text)
    countryLetterCode = Column(Text)
    createdDateTime = Column(DateTime)
    defaultUsageLocation = Column(Text)
    deletedDateTime = Column(DateTime)
    directorySizeQuota = Column(JSON)
    displayName = Column(Text)
    id = Column(Text, primary_key=True)
    isMultipleDataLocationsForServicesEnabled = Column(Boolean)
    marketingNotificationEmails = Column(JSON)
    onPremisesLastSyncDateTime = Column(DateTime)
    onPremisesSyncEnabled = Column(Boolean)
    onPremisesSyncStatus = Column(JSON)
    partnerTenantType = Column(JSON)
    postalCode = Column(Text)
    preferredLanguage = Column(Text)
    privacyProfile = Column(JSON)
    provisionedPlans = Column(JSON)
    securityComplianceNotificationMails = Column(JSON)
    securityComplianceNotificationPhones = Column(JSON)
    state = Column(Text)
    street = Column(Text)
    technicalNotificationMails = Column(JSON)
    tenantType = Column(Text)
    verifiedDomains = Column(JSON)

class User(Base, SerializeMixin):
    __tablename__ = "Users"
    businessPhones = Column(JSON)
    displayName = Column(Text)
    givenName = Column(Text)
    id = Column(Text, primary_key=True)
    jobTitle = Column(Text)
    mail = Column(Text)
    mobilePhone = Column(Text)
    officeLocation = Column(Text)
    onPremisesSyncEnabled = Column(Boolean)
    preferredLanguage = Column(Text)
    surname = Column(Text)
    userPrincipalName = Column(Text)

    memberOf = relationship("Group", secondary=lnk_group_member_user, back_populates="memberUsers")
    memberOfAu = relationship("AdministrativeUnit", secondary=lnk_au_member_user, back_populates="memberUsers")
    memberOfRole = relationship("DirectoryRole", secondary=lnk_role_member_user, back_populates="memberUsers")
    ownedApplications = relationship("Application", secondary=lnk_application_owner_user, back_populates="ownerUsers")
    ownedDevices = relationship("Device", secondary=lnk_device_owner, back_populates="owner")
    ownedGroups = relationship("Group", secondary=lnk_group_owner_user, back_populates="ownerUsers")
    ownedServicePrincipals = relationship("ServicePrincipal", secondary=lnk_serviceprincipal_owner_user, back_populates="ownerUsers")

def parse_db_argument(dbarg):
    if not ':/' in dbarg:
        if dbarg[0] != '/':
            return 'sqlite:///' + os.path.join(os.getcwd(), dbarg)
        else:
            return 'sqlite:///' + dbarg
    else:
        return dbarg

def init(create=False, dburl='sqlite:///roadrecon.db'):
    if 'postgresql' in dburl:
        engine = create_engine(dburl, executemany_mode='values', executemany_values_page_size=1001)
    else:
        engine = create_engine(dburl)
    if create:
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
    return engine

def get_session(engine):
    Session = sessionmaker(bind=engine)
    return Session()
