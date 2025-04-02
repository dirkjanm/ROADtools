import os
import json
import datetime
import sqlalchemy.types
from sqlalchemy import Column, Text, Boolean, BigInteger as Integer, create_engine, Table, ForeignKey, Date, Time
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

lnk_group_member_user = Table('lnk_group_member_user', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_group_member_group = Table('lnk_group_member_group', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('childGroup', Text, ForeignKey('Groups.id'))
)

lnk_group_member_contact = Table('lnk_group_member_contact', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('Contact', Text, ForeignKey('Contacts.id'))
)

lnk_group_member_device = Table('lnk_group_member_device', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('Device', Text, ForeignKey('Devices.id'))
)

lnk_group_member_serviceprincipal = Table('lnk_group_member_serviceprincipal', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_device_owner = Table('lnk_device_owner', Base.metadata,
    Column('Device', Text, ForeignKey('Devices.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_application_owner_user = Table('lnk_application_owner_user', Base.metadata,
    Column('Application', Text, ForeignKey('Applications.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_application_owner_serviceprincipal = Table('lnk_application_owner_serviceprincipal', Base.metadata,
    Column('Application', Text, ForeignKey('Applications.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_serviceprincipal_owner_user = Table('lnk_serviceprincipal_owner_user', Base.metadata,
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_serviceprincipal_owner_serviceprincipal = Table('lnk_serviceprincipal_owner_serviceprincipal', Base.metadata,
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id')),
    Column('childServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_role_member_user = Table('lnk_role_member_user', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_role_member_serviceprincipal = Table('lnk_role_member_serviceprincipal', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_role_member_group = Table('lnk_role_member_group', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.id')),
    Column('Group', Text, ForeignKey('Groups.id'))
)

lnk_group_owner_user = Table('lnk_group_owner_user', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_group_owner_serviceprincipal = Table('lnk_group_owner_serviceprincipal', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.id'))
)

lnk_au_member_user = Table('lnk_au_member_user', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.id')),
    Column('User', Text, ForeignKey('Users.id'))
)

lnk_au_member_group = Table('lnk_au_member_group', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.id')),
    Column('Group', Text, ForeignKey('Groups.id'))
)

lnk_au_member_device = Table('lnk_au_member_device', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.id')),
    Column('Device', Text, ForeignKey('Devices.id'))
)

class AppRoleAssignment(Base, SerializeMixin):
    __tablename__ = "AppRoleAssignments"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    appRoleId = Column(Text)
    creationTimestamp = Column(DateTime)
    principalDisplayName = Column(Text)
    principalId = Column(Text)
    principalType = Column(Text)
    resourceDisplayName = Column(Text)
    resourceId = Column(Text)


class OAuth2PermissionGrant(Base, SerializeMixin):
    __tablename__ = "OAuth2PermissionGrants"
    id = Column(Text, primary_key=True)
    clientId = Column(Text)
    consentType = Column(Text)
    expiryTime = Column(DateTime)
    principalId = Column(Text)
    resourceId = Column(Text)
    scope = Column(Text)
    startTime = Column(DateTime)


class User(Base, SerializeMixin):
    __tablename__ = "Users"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    signInActivity = Column(JSON)
    cloudLicensing = Column(JSON)
    accountEnabled = Column(Boolean)
    ageGroup = Column(Text)
    assignedLicenses = Column(JSON)
    assignedPlans = Column(JSON)
    authorizationInfo = Column(JSON)
    businessPhones = Column(JSON)
    city = Column(Text)
    cloudRealtimeCommunicationInfo = Column(JSON)
    companyName = Column(Text)
    consentProvidedForMinor = Column(Text)
    country = Column(Text)
    createdDateTime = Column(DateTime)
    creationType = Column(Text)
    customSecurityAttributes = Column(JSON)
    department = Column(Text)
    deviceKeys = Column(JSON)
    displayName = Column(Text)
    employeeHireDate = Column(DateTime)
    employeeId = Column(Text)
    employeeLeaveDateTime = Column(DateTime)
    employeeOrgData = Column(JSON)
    employeeType = Column(Text)
    externalUserState = Column(Text)
    externalUserStateChangeDateTime = Column(Text)
    faxNumber = Column(Text)
    givenName = Column(Text)
    identities = Column(JSON)
    imAddresses = Column(JSON)
    infoCatalogs = Column(JSON)
    isLicenseReconciliationNeeded = Column(Boolean)
    isManagementRestricted = Column(Boolean)
    isResourceAccount = Column(Boolean)
    jobTitle = Column(Text)
    lastPasswordChangeDateTime = Column(DateTime)
    legalAgeGroupClassification = Column(Text)
    licenseAssignmentStates = Column(JSON)
    mail = Column(Text)
    mailNickname = Column(Text)
    mobilePhone = Column(Text)
    officeLocation = Column(Text)
    onPremisesDistinguishedName = Column(Text)
    onPremisesDomainName = Column(Text)
    onPremisesExtensionAttributes = Column(JSON)
    onPremisesImmutableId = Column(Text)
    onPremisesLastSyncDateTime = Column(DateTime)
    onPremisesProvisioningErrors = Column(JSON)
    onPremisesSamAccountName = Column(Text)
    onPremisesSecurityIdentifier = Column(Text)
    onPremisesSipInfo = Column(JSON)
    onPremisesSyncEnabled = Column(Boolean)
    onPremisesUserPrincipalName = Column(Text)
    otherMails = Column(JSON)
    passwordPolicies = Column(Text)
    passwordProfile = Column(JSON)
    postalCode = Column(Text)
    preferredDataLocation = Column(Text)
    preferredLanguage = Column(Text)
    provisionedPlans = Column(JSON)
    proxyAddresses = Column(JSON)
    refreshTokensValidFromDateTime = Column(DateTime)
    securityIdentifier = Column(Text)
    serviceProvisioningErrors = Column(JSON)
    showInAddressList = Column(Boolean)
    signInSessionsValidFromDateTime = Column(DateTime)
    state = Column(Text)
    streetAddress = Column(Text)
    surname = Column(Text)
    usageLocation = Column(Text)
    userPrincipalName = Column(Text)
    userType = Column(Text)
    mailboxSettings = Column(JSON)
    deviceEnrollmentLimit = Column(Integer)
    print = Column(JSON)
    aboutMe = Column(Text)
    birthday = Column(DateTime)
    hireDate = Column(DateTime)
    interests = Column(JSON)
    mySite = Column(Text)
    pastProjects = Column(JSON)
    preferredName = Column(Text)
    responsibilities = Column(JSON)
    schools = Column(JSON)
    skills = Column(JSON)
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

    ownedGroups = relationship("Group",
        secondary=lnk_group_owner_user,
        back_populates="ownerUsers")

    memberOfAU = relationship("AdministrativeUnit",
        secondary=lnk_au_member_user,
        back_populates="memberUsers")


class ServicePrincipal(Base, SerializeMixin):
    __tablename__ = "ServicePrincipals"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    passwordSingleSignOnSettings = Column(JSON)
    accountEnabled = Column(Boolean)
    addIns = Column(JSON)
    alternativeNames = Column(JSON)
    appDescription = Column(Text)
    appDisplayName = Column(Text)
    appId = Column(Text)
    applicationTemplateId = Column(Text)
    appOwnerOrganizationId = Column(Text)
    appRoleAssignmentRequired = Column(Boolean)
    appRoles = Column(JSON)
    customSecurityAttributes = Column(JSON)
    description = Column(Text)
    disabledByMicrosoftStatus = Column(Text)
    displayName = Column(Text)
    errorUrl = Column(Text)
    homepage = Column(Text)
    info = Column(JSON)
    keyCredentials = Column(JSON)
    loginUrl = Column(Text)
    logoutUrl = Column(Text)
    notes = Column(Text)
    notificationEmailAddresses = Column(JSON)
    passwordCredentials = Column(JSON)
    preferredSingleSignOnMode = Column(Text)
    preferredTokenSigningKeyEndDateTime = Column(DateTime)
    preferredTokenSigningKeyThumbprint = Column(Text)
    publishedPermissionScopes = Column(JSON)
    publisherName = Column(Text)
    replyUrls = Column(JSON)
    samlMetadataUrl = Column(Text)
    samlSingleSignOnSettings = Column(JSON)
    servicePrincipalNames = Column(JSON)
    servicePrincipalType = Column(Text)
    signInAudience = Column(Text)
    tags = Column(JSON)
    tokenEncryptionKeyId = Column(Text)
    verifiedPublisher = Column(JSON)
    ownerUsers = relationship("User",
        secondary=lnk_serviceprincipal_owner_user,
        back_populates="ownedServicePrincipals")

    ownerServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_serviceprincipal_owner_serviceprincipal,
        primaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.ServicePrincipal,
        secondaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.childServicePrincipal,
        back_populates="ownedServicePrincipals")

    memberOfRole = relationship("DirectoryRole",
        secondary=lnk_role_member_serviceprincipal,
        back_populates="memberServicePrincipals")

    ownedServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_serviceprincipal_owner_serviceprincipal,
        primaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.childServicePrincipal,
        secondaryjoin=id==lnk_serviceprincipal_owner_serviceprincipal.c.ServicePrincipal,
        back_populates="ownerServicePrincipals")

    ownedApplications = relationship("Application",
        secondary=lnk_application_owner_serviceprincipal,
        back_populates="ownerServicePrincipals")

    memberOf = relationship("Group",
        secondary=lnk_group_member_serviceprincipal,
        back_populates="memberServicePrincipals")

    ownedGroups = relationship("Group",
        secondary=lnk_group_owner_serviceprincipal,
        back_populates="ownerServicePrincipals")


    oauth2PermissionGrants = relationship("OAuth2PermissionGrant",
        primaryjoin=id == foreign(OAuth2PermissionGrant.clientId))

    appRolesAssigned = relationship("AppRoleAssignment",
        primaryjoin=id == foreign(AppRoleAssignment.principalId))


class Group(Base, SerializeMixin):
    __tablename__ = "Groups"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    cloudLicensing = Column(JSON)
    assignedLabels = Column(JSON)
    assignedLicenses = Column(JSON)
    classification = Column(Text)
    createdByAppId = Column(Text)
    createdDateTime = Column(DateTime)
    description = Column(Text)
    displayName = Column(Text)
    expirationDateTime = Column(DateTime)
    groupTypes = Column(JSON)
    hasMembersWithLicenseErrors = Column(Boolean)
    infoCatalogs = Column(JSON)
    isAssignableToRole = Column(Boolean)
    isManagementRestricted = Column(Boolean)
    licenseProcessingState = Column(JSON)
    mail = Column(Text)
    mailEnabled = Column(Boolean)
    mailNickname = Column(Text)
    membershipRule = Column(Text)
    membershipRuleProcessingState = Column(Text)
    onPremisesDomainName = Column(Text)
    onPremisesLastSyncDateTime = Column(DateTime)
    onPremisesNetBiosName = Column(Text)
    onPremisesProvisioningErrors = Column(JSON)
    onPremisesSamAccountName = Column(Text)
    onPremisesSecurityIdentifier = Column(Text)
    onPremisesSyncEnabled = Column(Boolean)
    organizationId = Column(Text)
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
    uniqueName = Column(Text)
    visibility = Column(Text)
    writebackConfiguration = Column(JSON)
    accessType = Column(JSON)
    allowExternalSenders = Column(Boolean)
    autoSubscribeNewMembers = Column(Boolean)
    hideFromAddressLists = Column(Boolean)
    hideFromOutlookClients = Column(Boolean)
    isFavorite = Column(Boolean)
    isSubscribedByMail = Column(Boolean)
    unseenConversationsCount = Column(Integer)
    unseenCount = Column(Integer)
    unseenMessagesCount = Column(Integer)
    membershipRuleProcessingStatus = Column(JSON)
    isArchived = Column(Boolean)
    memberGroups = relationship("Group",
        secondary=lnk_group_member_group,
        primaryjoin=id==lnk_group_member_group.c.Group,
        secondaryjoin=id==lnk_group_member_group.c.childGroup,
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

    ownerUsers = relationship("User",
        secondary=lnk_group_owner_user,
        back_populates="ownedGroups")

    ownerServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_group_owner_serviceprincipal,
        back_populates="ownedGroups")

    memberOf = relationship("Group",
        secondary=lnk_group_member_group,
        primaryjoin=id==lnk_group_member_group.c.childGroup,
        secondaryjoin=id==lnk_group_member_group.c.Group,
        back_populates="memberGroups")

    memberOfRole = relationship("DirectoryRole",
        secondary=lnk_role_member_group,
        back_populates="memberGroups")

    memberOfAU = relationship("AdministrativeUnit",
        secondary=lnk_au_member_group,
        back_populates="memberGroups")


class Application(Base, SerializeMixin):
    __tablename__ = "Applications"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    api = Column(JSON)
    appId = Column(Text)
    appRoles = Column(JSON)
    authenticationBehaviors = Column(JSON)
    certification = Column(JSON)
    createdDateTime = Column(DateTime)
    defaultRedirectUri = Column(Text)
    description = Column(Text)
    disabledByMicrosoftStatus = Column(Text)
    displayName = Column(Text)
    groupMembershipClaims = Column(Text)
    identifierUris = Column(JSON)
    info = Column(JSON)
    isDeviceOnlyAuthSupported = Column(Boolean)
    isFallbackPublicClient = Column(Boolean)
    keyCredentials = Column(JSON)
    logo = Column(Text)
    nativeAuthenticationApisEnabled = Column(JSON)
    notes = Column(Text)
    optionalClaims = Column(JSON)
    parentalControlSettings = Column(JSON)
    passwordCredentials = Column(JSON)
    publicClient = Column(JSON)
    publisherDomain = Column(Text)
    requestSignatureVerification = Column(JSON)
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
    windows = Column(JSON)
    onPremisesPublishing = Column(JSON)
    ownerUsers = relationship("User",
        secondary=lnk_application_owner_user,
        back_populates="ownedApplications")

    ownerServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_application_owner_serviceprincipal,
        back_populates="ownedApplications")


class Device(Base, SerializeMixin):
    __tablename__ = "Devices"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    accountEnabled = Column(Boolean)
    alternativeNames = Column(JSON)
    alternativeSecurityIds = Column(JSON)
    approximateLastSignInDateTime = Column(DateTime)
    complianceExpirationDateTime = Column(DateTime)
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
    hostnames = Column(JSON)
    isCompliant = Column(Boolean)
    isManaged = Column(Boolean)
    isManagementRestricted = Column(Boolean)
    isRooted = Column(Boolean)
    managementType = Column(Text)
    manufacturer = Column(Text)
    mdmAppId = Column(Text)
    model = Column(Text)
    onPremisesLastSyncDateTime = Column(DateTime)
    onPremisesSecurityIdentifier = Column(Text)
    onPremisesSyncEnabled = Column(Boolean)
    operatingSystem = Column(Text)
    operatingSystemVersion = Column(Text)
    physicalIds = Column(JSON)
    profileType = Column(Text)
    registrationDateTime = Column(DateTime)
    systemLabels = Column(JSON)
    trustType = Column(Text)
    kind = Column(Text)
    name = Column(Text)
    platform = Column(Text)
    status = Column(Text)
    owner = relationship("User",
        secondary=lnk_device_owner,
        back_populates="ownedDevices")

    memberOf = relationship("Group",
        secondary=lnk_group_member_device,
        back_populates="memberDevices")

    memberOfAU = relationship("AdministrativeUnit",
        secondary=lnk_au_member_device,
        back_populates="memberDevices")


class DirectoryRole(Base, SerializeMixin):
    __tablename__ = "DirectoryRoles"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    description = Column(Text)
    displayName = Column(Text)
    roleTemplateId = Column(Text)
    memberUsers = relationship("User",
        secondary=lnk_role_member_user,
        back_populates="memberOfRole")

    memberServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_role_member_serviceprincipal,
        back_populates="memberOfRole")

    memberGroups = relationship("Group",
        secondary=lnk_role_member_group,
        back_populates="memberOfRole")


class ExtensionProperty(Base, SerializeMixin):
    __tablename__ = "ExtensionPropertys"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    appDisplayName = Column(Text)
    dataType = Column(Text)
    isMultiValued = Column(Boolean)
    isSyncedFromOnPremises = Column(Boolean)
    name = Column(Text)
    targetObjects = Column(JSON)


class Contact(Base, SerializeMixin):
    __tablename__ = "Contacts"
    categories = Column(JSON)
    changeKey = Column(Text)
    createdDateTime = Column(DateTime)
    lastModifiedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    assistantName = Column(Text)
    birthday = Column(DateTime)
    children = Column(JSON)
    companyName = Column(Text)
    department = Column(Text)
    displayName = Column(Text)
    emailAddresses = Column(JSON)
    fileAs = Column(Text)
    flag = Column(JSON)
    gender = Column(Text)
    generation = Column(Text)
    givenName = Column(Text)
    imAddresses = Column(JSON)
    initials = Column(Text)
    isFavorite = Column(Boolean)
    jobTitle = Column(Text)
    manager = Column(Text)
    middleName = Column(Text)
    nickName = Column(Text)
    officeLocation = Column(Text)
    parentFolderId = Column(Text)
    personalNotes = Column(Text)
    phones = Column(JSON)
    postalAddresses = Column(JSON)
    profession = Column(Text)
    spouseName = Column(Text)
    surname = Column(Text)
    title = Column(Text)
    websites = Column(JSON)
    weddingAnniversary = Column(Date)
    yomiCompanyName = Column(Text)
    yomiGivenName = Column(Text)
    yomiSurname = Column(Text)
    memberOf = relationship("Group",
        secondary=lnk_group_member_contact,
        back_populates="memberContacts")


class RoleDefinition(Base, SerializeMixin):
    __tablename__ = "RoleDefinitions"
    id = Column(Text, primary_key=True)
    description = Column(Text)
    displayName = Column(Text)
    isBuiltIn = Column(Boolean)
    isBuiltInRoleDefinition = Column(Boolean)
    permissions = Column(JSON)
    rolePermissions = Column(JSON)
    roleScopeTagIds = Column(JSON)


class RoleAssignment(Base, SerializeMixin):
    __tablename__ = "RoleAssignments"
    id = Column(Text, primary_key=True)
    description = Column(Text)
    displayName = Column(Text)
    resourceScopes = Column(JSON)
    scopeMembers = Column(JSON)
    scopeType = Column(JSON)


class AuthorizationPolicy(Base, SerializeMixin):
    __tablename__ = "AuthorizationPolicys"
    description = Column(Text)
    displayName = Column(Text)
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    allowedToSignUpEmailBasedSubscriptions = Column(Boolean)
    allowedToUseSSPR = Column(Boolean)
    allowEmailVerifiedUsersToJoinOrganization = Column(Boolean)
    allowInvitesFrom = Column(JSON)
    allowUserConsentForRiskyApps = Column(Boolean)
    blockMsolPowerShell = Column(Boolean)
    defaultUserRolePermissions = Column(JSON)
    enabledPreviewFeatures = Column(JSON)
    guestUserRoleId = Column(Text)
    permissionGrantPolicyIdsAssignedToDefaultUserRole = Column(JSON)


class UnifiedRoleDefinition(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleDefinitions"
    id = Column(Text, primary_key=True)
    allowedPrincipalTypes = Column(JSON)
    description = Column(Text)
    displayName = Column(Text)
    isBuiltIn = Column(Boolean)
    isEnabled = Column(Boolean)
    isPrivileged = Column(Boolean)
    resourceScopes = Column(JSON)
    rolePermissions = Column(JSON)
    templateId = Column(Text)
    version = Column(Text)


class UnifiedRoleEligibilityScheduleRequest(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleEligibilityScheduleRequests"
    approvalId = Column(Text)
    completedDateTime = Column(DateTime)
    createdBy = Column(JSON)
    createdDateTime = Column(DateTime)
    customData = Column(Text)
    status = Column(Text)
    id = Column(Text, primary_key=True)
    action = Column(Text)
    appScopeId = Column(Text)
    directoryScopeId = Column(Text)
    isValidationOnly = Column(Boolean)
    justification = Column(Text)
    principalId = Column(Text)
    roleDefinitionId = Column(Text, ForeignKey("UnifiedRoleDefinitions.id"))
    scheduleInfo = Column(JSON)
    targetScheduleId = Column(Text)
    ticketInfo = Column(JSON)

    roleDefinition = relationship("UnifiedRoleDefinition")


class UnifiedRoleEligibilitySchedule(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleEligibilitySchedules"
    appScopeId = Column(Text)
    createdDateTime = Column(DateTime)
    createdUsing = Column(Text)
    directoryScopeId = Column(Text)
    modifiedDateTime = Column(DateTime)
    principalId = Column(Text)
    roleDefinitionId = Column(Text, ForeignKey("UnifiedRoleDefinitions.id"))
    status = Column(Text)
    id = Column(Text, primary_key=True)
    memberType = Column(Text)
    scheduleInfo = Column(JSON)

    roleDefinition = relationship("UnifiedRoleDefinition")


class UnifiedRoleEligibilityScheduleInstance(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleEligibilityScheduleInstances"
    appScopeId = Column(Text)
    directoryScopeId = Column(Text)
    principalId = Column(Text)
    roleDefinitionId = Column(Text, ForeignKey("UnifiedRoleDefinitions.id"))
    id = Column(Text, primary_key=True)
    endDateTime = Column(DateTime)
    memberType = Column(Text)
    roleEligibilityScheduleId = Column(Text)
    startDateTime = Column(DateTime)

    roleDefinition = relationship("UnifiedRoleDefinition")


class UnifiedRoleAssignmentSchedule(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleAssignmentSchedules"
    appScopeId = Column(Text)
    createdDateTime = Column(DateTime)
    createdUsing = Column(Text)
    directoryScopeId = Column(Text)
    modifiedDateTime = Column(DateTime)
    principalId = Column(Text)
    roleDefinitionId = Column(Text, ForeignKey("UnifiedRoleDefinitions.id"))
    status = Column(Text)
    id = Column(Text, primary_key=True)
    assignmentType = Column(Text)
    memberType = Column(Text)
    scheduleInfo = Column(JSON)

    roleDefinition = relationship("UnifiedRoleDefinition")


class UnifiedRoleAssignmentScheduleRequest(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleAssignmentScheduleRequests"
    approvalId = Column(Text)
    completedDateTime = Column(DateTime)
    createdBy = Column(JSON)
    createdDateTime = Column(DateTime)
    customData = Column(Text)
    status = Column(Text)
    id = Column(Text, primary_key=True)
    action = Column(Text)
    appScopeId = Column(Text)
    directoryScopeId = Column(Text)
    isValidationOnly = Column(Boolean)
    justification = Column(Text)
    principalId = Column(Text)
    roleDefinitionId = Column(Text, ForeignKey("UnifiedRoleDefinitions.id"))
    scheduleInfo = Column(JSON)
    targetScheduleId = Column(Text)
    ticketInfo = Column(JSON)

    roleDefinition = relationship("UnifiedRoleDefinition")


class UnifiedRoleAssignmentScheduleInstance(Base, SerializeMixin):
    __tablename__ = "UnifiedRoleAssignmentScheduleInstances"
    appScopeId = Column(Text)
    directoryScopeId = Column(Text)
    principalId = Column(Text)
    roleDefinitionId = Column(Text, ForeignKey("UnifiedRoleDefinitions.id"))
    id = Column(Text, primary_key=True)
    assignmentType = Column(Text)
    endDateTime = Column(DateTime)
    memberType = Column(Text)
    roleAssignmentOriginId = Column(Text)
    roleAssignmentScheduleId = Column(Text)
    startDateTime = Column(DateTime)

    roleDefinition = relationship("UnifiedRoleDefinition")


class AdministrativeUnit(Base, SerializeMixin):
    __tablename__ = "AdministrativeUnits"
    deletedDateTime = Column(DateTime)
    id = Column(Text, primary_key=True)
    description = Column(Text)
    displayName = Column(Text)
    isMemberManagementRestricted = Column(Boolean)
    membershipRule = Column(Text)
    membershipRuleProcessingState = Column(Text)
    membershipType = Column(Text)
    visibility = Column(Text)
    memberUsers = relationship("User",
        secondary=lnk_au_member_user,
        back_populates="memberOfAU")

    memberDevices = relationship("Device",
        secondary=lnk_au_member_device,
        back_populates="memberOfAU")

    memberGroups = relationship("Group",
        secondary=lnk_au_member_group,
        back_populates="memberOfAU")


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
