import os
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

lnk_group_member_user = Table('lnk_group_member_user', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_group_member_group = Table('lnk_group_member_group', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('childGroup', Text, ForeignKey('Groups.objectId'))
)

lnk_group_member_contact = Table('lnk_group_member_contact', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('Contact', Text, ForeignKey('Contacts.objectId'))
)

lnk_group_member_device = Table('lnk_group_member_device', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('Device', Text, ForeignKey('Devices.objectId'))
)

lnk_group_member_serviceprincipal = Table('lnk_group_member_serviceprincipal', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_device_owner = Table('lnk_device_owner', Base.metadata,
    Column('Device', Text, ForeignKey('Devices.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_application_owner_user = Table('lnk_application_owner_user', Base.metadata,
    Column('Application', Text, ForeignKey('Applications.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_application_owner_serviceprincipal = Table('lnk_application_owner_serviceprincipal', Base.metadata,
    Column('Application', Text, ForeignKey('Applications.objectId')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_serviceprincipal_owner_user = Table('lnk_serviceprincipal_owner_user', Base.metadata,
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_serviceprincipal_owner_serviceprincipal = Table('lnk_serviceprincipal_owner_serviceprincipal', Base.metadata,
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId')),
    Column('childServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_role_member_user = Table('lnk_role_member_user', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_role_member_serviceprincipal = Table('lnk_role_member_serviceprincipal', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.objectId')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

class User(Base, SerializeMixin):
    __tablename__ = "Users"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    acceptedAs = Column(Text)
    acceptedOn = Column(DateTime)
    accountEnabled = Column(Boolean)
    ageGroup = Column(Text)
    alternativeSecurityIds = Column(JSON)
    signInNames = Column(JSON)
    signInNamesInfo = Column(JSON)
    appMetadata = Column(JSON)
    assignedLicenses = Column(JSON)
    assignedPlans = Column(JSON)
    city = Column(Text)
    cloudAudioConferencingProviderInfo = Column(Text)
    cloudMSExchRecipientDisplayType = Column(Integer)
    cloudMSRtcIsSipEnabled = Column(Boolean)
    cloudMSRtcOwnerUrn = Column(Text)
    cloudMSRtcPolicyAssignments = Column(JSON)
    cloudMSRtcPool = Column(Text)
    cloudMSRtcServiceAttributes = Column(JSON)
    cloudRtcUserPolicies = Column(Text)
    cloudSecurityIdentifier = Column(Text)
    cloudSipLine = Column(Text)
    cloudSipProxyAddress = Column(Text)
    companyName = Column(Text)
    consentProvidedForMinor = Column(Text)
    country = Column(Text)
    createdDateTime = Column(DateTime)
    creationType = Column(Text)
    department = Column(Text)
    dirSyncEnabled = Column(Boolean)
    displayName = Column(Text)
    employeeId = Column(Text)
    extensionAttribute1 = Column(Text)
    extensionAttribute2 = Column(Text)
    extensionAttribute3 = Column(Text)
    extensionAttribute4 = Column(Text)
    extensionAttribute5 = Column(Text)
    extensionAttribute6 = Column(Text)
    extensionAttribute7 = Column(Text)
    extensionAttribute8 = Column(Text)
    extensionAttribute9 = Column(Text)
    extensionAttribute10 = Column(Text)
    extensionAttribute11 = Column(Text)
    extensionAttribute12 = Column(Text)
    extensionAttribute13 = Column(Text)
    extensionAttribute14 = Column(Text)
    extensionAttribute15 = Column(Text)
    facsimileTelephoneNumber = Column(Text)
    givenName = Column(Text)
    hasOnPremisesShadow = Column(Boolean)
    immutableId = Column(Text)
    invitedAsMail = Column(Text)
    invitedOn = Column(DateTime)
    inviteReplyUrl = Column(JSON)
    inviteResources = Column(JSON)
    inviteTicket = Column(JSON)
    isCompromised = Column(Boolean)
    isResourceAccount = Column(Boolean)
    jobTitle = Column(Text)
    jrnlProxyAddress = Column(Text)
    lastDirSyncTime = Column(DateTime)
    lastPasswordChangeDateTime = Column(DateTime)
    legalAgeGroupClassification = Column(Text)
    mail = Column(Text)
    mailNickname = Column(Text)
    mobile = Column(Text)
    msExchRecipientTypeDetails = Column(Integer)
    msExchRemoteRecipientType = Column(Integer)
    msExchMailboxGuid = Column(Text)
    netId = Column(Text)
    onPremisesDistinguishedName = Column(Text)
    onPremisesPasswordChangeTimestamp = Column(DateTime)
    onPremisesSecurityIdentifier = Column(Text)
    onPremisesUserPrincipalName = Column(Text)
    otherMails = Column(JSON)
    passwordPolicies = Column(Text)
    passwordProfile = Column(JSON)
    physicalDeliveryOfficeName = Column(Text)
    postalCode = Column(Text)
    preferredDataLocation = Column(Text)
    preferredLanguage = Column(Text)
    primarySMTPAddress = Column(Text)
    provisionedPlans = Column(JSON)
    provisioningErrors = Column(JSON)
    proxyAddresses = Column(JSON)
    refreshTokensValidFromDateTime = Column(DateTime)
    releaseTrack = Column(Text)
    searchableDeviceKey = Column(JSON)
    selfServePasswordResetData = Column(JSON)
    shadowAlias = Column(Text)
    shadowDisplayName = Column(Text)
    shadowLegacyExchangeDN = Column(Text)
    shadowMail = Column(Text)
    shadowMobile = Column(Text)
    shadowOtherMobile = Column(JSON)
    shadowProxyAddresses = Column(JSON)
    shadowTargetAddress = Column(Text)
    shadowUserPrincipalName = Column(Text)
    showInAddressList = Column(Boolean)
    sipProxyAddress = Column(Text)
    smtpAddresses = Column(JSON)
    state = Column(Text)
    streetAddress = Column(Text)
    surname = Column(Text)
    telephoneNumber = Column(Text)
    thumbnailPhoto = Column(Text)
    usageLocation = Column(Text)
    userPrincipalName = Column(Text)
    userState = Column(Text)
    userStateChangedOn = Column(DateTime)
    userType = Column(Text)
    strongAuthenticationDetail = Column(JSON)
    windowsInformationProtectionKey = Column(JSON)
    memberOf = relationship("Group",
        secondary=lnk_group_member_user,
        back_populates="memberUsers")

    ownedApplications = relationship("Application",
        secondary=lnk_application_owner_user,
        back_populates="ownerUsers")

    ownedServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_serviceprincipal_owner_user,
        back_populates="ownerUsers")

    memberOfRole = relationship("DirectoryRole",
        secondary=lnk_role_member_user,
        back_populates="memberUsers")

    ownedDevices = relationship("Device",
        secondary=lnk_device_owner,
        back_populates="owner")


class ServicePrincipal(Base, SerializeMixin):
    __tablename__ = "ServicePrincipals"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    accountEnabled = Column(Boolean)
    addIns = Column(JSON)
    alternativeNames = Column(JSON)
    appBranding = Column(JSON)
    appCategory = Column(Text)
    appData = Column(Text)
    appDisplayName = Column(Text)
    appId = Column(Text)
    applicationTemplateId = Column(Text)
    appMetadata = Column(JSON)
    appOwnerTenantId = Column(Text)
    appRoleAssignmentRequired = Column(Boolean)
    appRoles = Column(JSON)
    authenticationPolicy = Column(JSON)
    displayName = Column(Text)
    errorUrl = Column(Text)
    homepage = Column(Text)
    informationalUrls = Column(JSON)
    keyCredentials = Column(JSON)
    logoutUrl = Column(Text)
    managedIdentityResourceId = Column(Text)
    microsoftFirstParty = Column(Boolean)
    notificationEmailAddresses = Column(JSON)
    oauth2Permissions = Column(JSON)
    passwordCredentials = Column(JSON)
    preferredSingleSignOnMode = Column(Text)
    preferredTokenSigningKeyEndDateTime = Column(DateTime)
    preferredTokenSigningKeyThumbprint = Column(Text)
    publisherName = Column(Text)
    replyUrls = Column(JSON)
    samlMetadataUrl = Column(Text)
    samlSingleSignOnSettings = Column(JSON)
    servicePrincipalNames = Column(JSON)
    tags = Column(JSON)
    tokenEncryptionKeyId = Column(Text)
    servicePrincipalType = Column(Text)
    useCustomTokenSigningKey = Column(Boolean)
    verifiedPublisher = Column(JSON)
    ownerUsers = relationship("User",
        secondary=lnk_serviceprincipal_owner_user,
        back_populates="ownedServicePrincipals")

    ownerServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_serviceprincipal_owner_serviceprincipal,
        primaryjoin=objectId==lnk_serviceprincipal_owner_serviceprincipal.c.ServicePrincipal,
        secondaryjoin=objectId==lnk_serviceprincipal_owner_serviceprincipal.c.childServicePrincipal,
        back_populates="ownedServicePrincipals")

    memberOfRole = relationship("DirectoryRole",
        secondary=lnk_role_member_serviceprincipal,
        back_populates="memberServicePrincipals")

    ownedServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_serviceprincipal_owner_serviceprincipal,
        primaryjoin=objectId==lnk_serviceprincipal_owner_serviceprincipal.c.childServicePrincipal,
        secondaryjoin=objectId==lnk_serviceprincipal_owner_serviceprincipal.c.ServicePrincipal,
        back_populates="ownerServicePrincipals")

    ownedApplications = relationship("Application",
        secondary=lnk_application_owner_serviceprincipal,
        back_populates="ownerServicePrincipals")

    memberOf = relationship("Group",
        secondary=lnk_group_member_serviceprincipal,
        back_populates="memberServicePrincipals")


class Group(Base, SerializeMixin):
    __tablename__ = "Groups"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    appMetadata = Column(JSON)
    classification = Column(Text)
    cloudSecurityIdentifier = Column(Text)
    createdDateTime = Column(DateTime)
    createdByAppId = Column(Text)
    description = Column(Text)
    dirSyncEnabled = Column(Boolean)
    displayName = Column(Text)
    exchangeResources = Column(JSON)
    expirationDateTime = Column(DateTime)
    externalGroupIds = Column(JSON)
    externalGroupProviderId = Column(Text)
    externalGroupState = Column(Text)
    creationOptions = Column(JSON)
    groupTypes = Column(JSON)
    isAssignableToRole = Column(Boolean)
    isMembershipRuleLocked = Column(Boolean)
    isPublic = Column(Boolean)
    lastDirSyncTime = Column(DateTime)
    licenseAssignment = Column(JSON)
    mail = Column(Text)
    mailNickname = Column(Text)
    mailEnabled = Column(Boolean)
    membershipRule = Column(Text)
    membershipRuleProcessingState = Column(Text)
    membershipTypes = Column(JSON)
    onPremisesSecurityIdentifier = Column(Text)
    preferredDataLocation = Column(Text)
    preferredLanguage = Column(Text)
    primarySMTPAddress = Column(Text)
    provisioningErrors = Column(JSON)
    proxyAddresses = Column(JSON)
    renewedDateTime = Column(DateTime)
    securityEnabled = Column(Boolean)
    sharepointResources = Column(JSON)
    targetAddress = Column(Text)
    theme = Column(Text)
    visibility = Column(Text)
    wellKnownObject = Column(Text)
    memberGroups = relationship("Group",
        secondary=lnk_group_member_group,
        primaryjoin=objectId==lnk_group_member_group.c.Group,
        secondaryjoin=objectId==lnk_group_member_group.c.childGroup,
        back_populates="memberOf")

    memberUsers = relationship("User",
        secondary=lnk_group_member_user,
        back_populates="memberOf")

    memberContacts = relationship("Contact",
        secondary=lnk_group_member_contact,
        back_populates="memberOf")

    memberDevices = relationship("Device",
        secondary=lnk_group_member_device,
        back_populates="memberOf")

    memberServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_group_member_serviceprincipal,
        back_populates="memberOf")

    memberOf = relationship("Group",
        secondary=lnk_group_member_group,
        primaryjoin=objectId==lnk_group_member_group.c.childGroup,
        secondaryjoin=objectId==lnk_group_member_group.c.Group,
        back_populates="memberGroups")


class Application(Base, SerializeMixin):
    __tablename__ = "Applications"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    addIns = Column(JSON)
    allowActAsForAllClients = Column(Boolean)
    allowPassthroughUsers = Column(Boolean)
    appBranding = Column(JSON)
    appCategory = Column(Text)
    appData = Column(Text)
    appId = Column(Text)
    applicationTemplateId = Column(Text)
    appMetadata = Column(JSON)
    appRoles = Column(JSON)
    availableToOtherTenants = Column(Boolean)
    displayName = Column(Text)
    encryptedMsiApplicationSecret = Column(Text)
    errorUrl = Column(Text)
    groupMembershipClaims = Column(Text)
    homepage = Column(Text)
    identifierUris = Column(JSON)
    informationalUrls = Column(JSON)
    isDeviceOnlyAuthSupported = Column(Boolean)
    keyCredentials = Column(JSON)
    knownClientApplications = Column(JSON)
    logo = Column(Text)
    logoUrl = Column(Text)
    logoutUrl = Column(Text)
    mainLogo = Column(Text)
    oauth2AllowIdTokenImplicitFlow = Column(Boolean)
    oauth2AllowImplicitFlow = Column(Boolean)
    oauth2AllowUrlPathMatching = Column(Boolean)
    oauth2Permissions = Column(JSON)
    oauth2RequirePostResponse = Column(Boolean)
    optionalClaims = Column(JSON)
    parentalControlSettings = Column(JSON)
    passwordCredentials = Column(JSON)
    publicClient = Column(Boolean)
    publisherDomain = Column(Text)
    recordConsentConditions = Column(Text)
    replyUrls = Column(JSON)
    requiredResourceAccess = Column(JSON)
    samlMetadataUrl = Column(Text)
    supportsConvergence = Column(Boolean)
    tokenEncryptionKeyId = Column(Text)
    trustedCertificateSubjects = Column(JSON)
    verifiedPublisher = Column(JSON)
    ownerUsers = relationship("User",
        secondary=lnk_application_owner_user,
        back_populates="ownedApplications")

    ownerServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_application_owner_serviceprincipal,
        back_populates="ownedApplications")


class Device(Base, SerializeMixin):
    __tablename__ = "Devices"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    accountEnabled = Column(Boolean)
    alternativeSecurityIds = Column(JSON)
    approximateLastLogonTimestamp = Column(DateTime)
    bitLockerKey = Column(JSON)
    capabilities = Column(JSON)
    complianceExpiryTime = Column(DateTime)
    compliantApplications = Column(JSON)
    compliantAppsManagementAppId = Column(Text)
    deviceCategory = Column(Text)
    deviceId = Column(Text)
    deviceKey = Column(JSON)
    deviceManufacturer = Column(Text)
    deviceManagementAppId = Column(Text)
    deviceMetadata = Column(Text)
    deviceModel = Column(Text)
    deviceObjectVersion = Column(Integer)
    deviceOSType = Column(Text)
    deviceOSVersion = Column(Text)
    deviceOwnership = Column(Text)
    devicePhysicalIds = Column(JSON)
    deviceSystemMetadata = Column(JSON)
    deviceTrustType = Column(Text)
    dirSyncEnabled = Column(Boolean)
    displayName = Column(Text)
    domainName = Column(Text)
    enrollmentProfileName = Column(Text)
    enrollmentType = Column(Text)
    exchangeActiveSyncId = Column(JSON)
    isCompliant = Column(Boolean)
    isManaged = Column(Boolean)
    isRooted = Column(Boolean)
    keyCredentials = Column(JSON)
    lastDirSyncTime = Column(DateTime)
    localCredentials = Column(Text)
    managementType = Column(Text)
    onPremisesSecurityIdentifier = Column(Text)
    organizationalUnit = Column(Text)
    profileType = Column(Text)
    reserved1 = Column(Text)
    systemLabels = Column(JSON)
    owner = relationship("User",
        secondary=lnk_device_owner,
        back_populates="ownedDevices")

    memberOf = relationship("Group",
        secondary=lnk_group_member_device,
        back_populates="memberDevices")


class DirectoryRole(Base, SerializeMixin):
    __tablename__ = "DirectoryRoles"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    cloudSecurityIdentifier = Column(Text)
    description = Column(Text)
    displayName = Column(Text)
    isSystem = Column(Boolean)
    roleDisabled = Column(Boolean)
    roleTemplateId = Column(Text)
    memberUsers = relationship("User",
        secondary=lnk_role_member_user,
        back_populates="memberOfRole")

    memberServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_role_member_serviceprincipal,
        back_populates="memberOfRole")


class TenantDetail(Base, SerializeMixin):
    __tablename__ = "TenantDetails"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    assignedPlans = Column(JSON)
    authorizedServiceInstance = Column(JSON)
    city = Column(Text)
    cloudRtcUserPolicies = Column(Text)
    companyLastDirSyncTime = Column(DateTime)
    companyTags = Column(JSON)
    compassEnabled = Column(Boolean)
    country = Column(Text)
    countryLetterCode = Column(Text)
    dirSyncEnabled = Column(Boolean)
    displayName = Column(Text)
    isMultipleDataLocationsForServicesEnabled = Column(Boolean)
    marketingNotificationEmails = Column(JSON)
    postalCode = Column(Text)
    preferredLanguage = Column(Text)
    privacyProfile = Column(JSON)
    provisionedPlans = Column(JSON)
    provisioningErrors = Column(JSON)
    releaseTrack = Column(Text)
    replicationScope = Column(Text)
    securityComplianceNotificationMails = Column(JSON)
    securityComplianceNotificationPhones = Column(JSON)
    selfServePasswordResetPolicy = Column(JSON)
    state = Column(Text)
    street = Column(Text)
    technicalNotificationMails = Column(JSON)
    telephoneNumber = Column(Text)
    tenantType = Column(Text)
    verifiedDomains = Column(JSON)
    windowsCredentialsEncryptionCertificate = Column(Text)


class ApplicationRef(Base, SerializeMixin):
    __tablename__ = "ApplicationRefs"
    appCategory = Column(Text)
    appContextId = Column(Text)
    appData = Column(Text)
    appId = Column(Text, primary_key=True)
    appRoles = Column(JSON)
    availableToOtherTenants = Column(Boolean)
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


class ExtensionProperty(Base, SerializeMixin):
    __tablename__ = "ExtensionPropertys"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    appDisplayName = Column(Text)
    name = Column(Text)
    dataType = Column(Text)
    isSyncedFromOnPremises = Column(Boolean)
    targetObjects = Column(JSON)


class Contact(Base, SerializeMixin):
    __tablename__ = "Contacts"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    city = Column(Text)
    cloudAudioConferencingProviderInfo = Column(Text)
    cloudMSRtcIsSipEnabled = Column(Boolean)
    cloudMSRtcOwnerUrn = Column(Text)
    cloudMSRtcPolicyAssignments = Column(JSON)
    cloudMSRtcPool = Column(Text)
    cloudMSRtcServiceAttributes = Column(JSON)
    cloudRtcUserPolicies = Column(Text)
    cloudSipLine = Column(Text)
    companyName = Column(Text)
    country = Column(Text)
    department = Column(Text)
    dirSyncEnabled = Column(Boolean)
    displayName = Column(Text)
    facsimileTelephoneNumber = Column(Text)
    givenName = Column(Text)
    jobTitle = Column(Text)
    lastDirSyncTime = Column(DateTime)
    mail = Column(Text)
    mailNickname = Column(Text)
    mobile = Column(Text)
    physicalDeliveryOfficeName = Column(Text)
    postalCode = Column(Text)
    provisioningErrors = Column(JSON)
    proxyAddresses = Column(JSON)
    sipProxyAddress = Column(Text)
    state = Column(Text)
    streetAddress = Column(Text)
    surname = Column(Text)
    telephoneNumber = Column(Text)
    thumbnailPhoto = Column(Text)
    memberOf = relationship("Group",
        secondary=lnk_group_member_contact,
        back_populates="memberContacts")


class OAuth2PermissionGrant(Base, SerializeMixin):
    __tablename__ = "OAuth2PermissionGrants"
    clientId = Column(Text)
    consentType = Column(Text)
    expiryTime = Column(DateTime)
    objectId = Column(Text, primary_key=True)
    principalId = Column(Text)
    resourceId = Column(Text)
    scope = Column(Text)
    startTime = Column(DateTime)


class Policy(Base, SerializeMixin):
    __tablename__ = "Policys"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    displayName = Column(Text)
    keyCredentials = Column(JSON)
    policyType = Column(Integer)
    policyDetail = Column(JSON)
    policyIdentifier = Column(Text)
    tenantDefaultPolicy = Column(Integer)


class RoleDefinition(Base, SerializeMixin):
    __tablename__ = "RoleDefinitions"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    isBuiltIn = Column(Boolean)
    isEnabled = Column(Boolean)
    resourceScopes = Column(JSON)
    rolePermissions = Column(JSON)
    templateId = Column(Text)
    version = Column(Text)


class RoleAssignment(Base, SerializeMixin):
    __tablename__ = "RoleAssignments"
    id = Column(Text, primary_key=True)
    principalId = Column(Text)
    resourceScopes = Column(JSON)
    roleDefinitionId = Column(Text)


class AppRoleAssignment(Base, SerializeMixin):
    __tablename__ = "AppRoleAssignments"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    creationTimestamp = Column(DateTime)
    id = Column(Text)
    principalDisplayName = Column(Text)
    principalId = Column(Text)
    principalType = Column(Text)
    resourceDisplayName = Column(Text)
    resourceId = Column(Text)


def parse_db_argument(dbarg):
    '''
    Parse DB string given as argument into full path required
    for SQLAlchemy
    '''
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
