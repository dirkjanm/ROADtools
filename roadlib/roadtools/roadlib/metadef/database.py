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
                if '+' in value[-7:] or '-' in value[-7:]:
                    value = datetime.datetime.strptime(value[:-7], '%Y-%m-%dT%H:%M:%S.%f')
                else:
                    try:
                        value = datetime.datetime.strptime(value[:-1], '%Y-%m-%dT%H:%M:%S.%f')
                    except ValueError:
                        value = datetime.datetime.strptime(value[:-1], '%Y-%m-%dT%H:%M:%S.')
            elif '+' in value[-7:] or '-' in value[-7:]:
                value = datetime.datetime.strptime(value[:-6], '%Y-%m-%dT%H:%M:%S')
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

lnk_role_member_group = Table('lnk_role_member_group', Base.metadata,
    Column('DirectoryRole', Text, ForeignKey('DirectoryRoles.objectId')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_group_owner_user = Table('lnk_group_owner_user', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_group_owner_serviceprincipal = Table('lnk_group_owner_serviceprincipal', Base.metadata,
    Column('Group', Text, ForeignKey('Groups.objectId')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_au_member_user = Table('lnk_au_member_user', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_au_member_group = Table('lnk_au_member_group', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.objectId')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_au_member_device = Table('lnk_au_member_device', Base.metadata,
    Column('AdministrativeUnit', Text, ForeignKey('AdministrativeUnits.objectId')),
    Column('Device', Text, ForeignKey('Devices.objectId'))
)

lnk_policy_user_include = Table('lnk_policy_user_include', Base.metadata,
    Column('Policy', Text, ForeignKey('Policys.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_policy_user_exclude = Table('lnk_policy_user_exclude', Base.metadata,
    Column('Policy', Text, ForeignKey('Policys.objectId')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_pim_resource = Table('lnk_pim_resource', Base.metadata,
    Column('PIMprivilegedAccess', Text, ForeignKey('PIMprivilegedAccesss.id')),
    Column('PIMgovernanceResource', Text, ForeignKey('PIMgovernanceResources.id'))
)

lnk_pim_resource_rolealerts = Table('lnk_pim_resource_rolealerts', Base.metadata,
    Column('PIMgovernanceResource', Text, ForeignKey('PIMgovernanceResources.id')),
    Column('PIMgovernanceAlert', Text, ForeignKey('PIMgovernanceAlerts.id'))
)

lnk_pim_resource_aadgroup = Table('lnk_pim_resource_aadgroup', Base.metadata,
    Column('PIMgovernanceResource', Text, ForeignKey('PIMgovernanceResources.id')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_pim_roleassignment_subjectuser = Table('lnk_pim_roleassignment_subjectuser', Base.metadata,
    Column('PIMgovernanceRoleAssignment', Text, ForeignKey('PIMgovernanceRoleAssignments.id')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_pim_roleassignment_subjectgroup = Table('lnk_pim_roleassignment_subjectgroup', Base.metadata,
    Column('PIMgovernanceRoleAssignment', Text, ForeignKey('PIMgovernanceRoleAssignments.id')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_pim_roleassignment_subjectserviceprincipal = Table('lnk_pim_roleassignment_subjectserviceprincipal', Base.metadata,
    Column('PIMgovernanceRoleAssignment', Text, ForeignKey('PIMgovernanceRoleAssignments.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_pim_roleassignmentrequest_subjectuser = Table('lnk_pim_roleassignmentrequest_subjectuser', Base.metadata,
    Column('PIMgovernanceRoleAssignmentRequest', Text, ForeignKey('PIMgovernanceRoleAssignmentRequests.id')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_pim_roleassignmentrequest_subjectgroup = Table('lnk_pim_roleassignmentrequest_subjectgroup', Base.metadata,
    Column('PIMgovernanceRoleAssignmentRequest', Text, ForeignKey('PIMgovernanceRoleAssignmentRequests.id')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_pim_roleassignmentrequest_subjectserviceprincipal = Table('lnk_pim_roleassignmentrequest_subjectserviceprincipal', Base.metadata,
    Column('PIMgovernanceRoleAssignmentRequest', Text, ForeignKey('PIMgovernanceRoleAssignmentRequests.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_ig_cg_resource = Table('lnk_ig_cg_resource', Base.metadata,
    Column('IGaccessPackageCatalog', Text, ForeignKey('IGaccessPackageCatalogs.id')),
    Column('IGaccessPackageResource', Text, ForeignKey('IGaccessPackageResources.id'))
)

lnk_ig_ap = Table('lnk_ig_ap', Base.metadata,
    Column('IGaccessPackageCatalog', Text, ForeignKey('IGaccessPackageCatalogs.id')),
    Column('IGaccessPackage', Text, ForeignKey('IGaccessPackages.id'))
)

lnk_ig_ap_resource_request = Table('lnk_ig_ap_resource_request', Base.metadata,
    Column('IGaccessPackageResource', Text, ForeignKey('IGaccessPackageResources.id')),
    Column('IGaccessPackageResourceRequest', Text, ForeignKey('IGaccessPackageResourceRequests.id'))
)

lnk_ig_ap_rrs_role = Table('lnk_ig_ap_rrs_role', Base.metadata,
    Column('IGaccessPackageResourceRoleScope', Text, ForeignKey('IGaccessPackageResourceRoleScopes.id')),
    Column('IGaccessPackageResourceRole', Text, ForeignKey('IGaccessPackageResourceRoles.id'))
)

lnk_ig_ap_rrs_scope = Table('lnk_ig_ap_rrs_scope', Base.metadata,
    Column('IGaccessPackageResourceRoleScope', Text, ForeignKey('IGaccessPackageResourceRoleScopes.id')),
    Column('IGaccessPackageResourceScope', Text, ForeignKey('IGaccessPackageResourceScopes.id'))
)

lnk_ig_ap_rr = Table('lnk_ig_ap_rr', Base.metadata,
    Column('IGaccessPackageResource', Text, ForeignKey('IGaccessPackageResources.id')),
    Column('IGaccessPackageResourceRole', Text, ForeignKey('IGaccessPackageResourceRoles.id'))
)

lnk_ig_ap_rr_scope = Table('lnk_ig_ap_rr_scope', Base.metadata,
    Column('IGaccessPackage', Text, ForeignKey('IGaccessPackages.id')),
    Column('IGaccessPackageResourceRoleScope', Text, ForeignKey('IGaccessPackageResourceRoleScopes.id'))
)

lnk_ig_ap_assignment_target = Table('lnk_ig_ap_assignment_target', Base.metadata,
    Column('IGaccessPackageAssignment', Text, ForeignKey('IGaccessPackageAssignments.id')),
    Column('IGaccessPackageSubject', Text, ForeignKey('IGaccessPackageSubjects.id'))
)

lnk_ig_ap_assignment_request = Table('lnk_ig_ap_assignment_request', Base.metadata,
    Column('IGaccessPackage', Text, ForeignKey('IGaccessPackages.id')),
    Column('IGaccessPackageAssignmentRequest', Text, ForeignKey('IGaccessPackageAssignmentRequests.id'))
)

lnk_ig_ap_assignment_request_target = Table('lnk_ig_ap_assignment_request_target', Base.metadata,
    Column('IGaccessPackageAssignmentRequest', Text, ForeignKey('IGaccessPackageAssignmentRequests.id')),
    Column('IGaccessPackageSubject', Text, ForeignKey('IGaccessPackageSubjects.id'))
)

lnk_ig_ap_assignment_request_requestor = Table('lnk_ig_ap_assignment_request_requestor', Base.metadata,
    Column('IGaccessPackageAssignmentRequest', Text, ForeignKey('IGaccessPackageAssignmentRequests.id')),
    Column('IGaccessPackageSubject', Text, ForeignKey('IGaccessPackageSubjects.id'))
)

lnk_ig_ap_assignment_policy_inscope_user = Table('lnk_ig_ap_assignment_policy_inscope_user', Base.metadata,
    Column('IGaccessPackageAssignmentPolicy', Text, ForeignKey('IGaccessPackageAssignmentPolicys.id')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_ig_ap_assignment_policy_inscope_group = Table('lnk_ig_ap_assignment_policy_inscope_group', Base.metadata,
    Column('IGaccessPackageAssignmentPolicy', Text, ForeignKey('IGaccessPackageAssignmentPolicys.id')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_ig_ap_assignment_policy_inscope_serviceprincipal = Table('lnk_ig_ap_assignment_policy_inscope_serviceprincipal', Base.metadata,
    Column('IGaccessPackageAssignmentPolicy', Text, ForeignKey('IGaccessPackageAssignmentPolicys.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_ig_ap_assignment_resource_role = Table('lnk_ig_ap_assignment_resource_role', Base.metadata,
    Column('IGaccessPackageAssignment', Text, ForeignKey('IGaccessPackageAssignments.id')),
    Column('IGaccessPackageAssignmentResourceRole', Text, ForeignKey('IGaccessPackageAssignmentResourceRoles.id'))
)

lnk_az_roleassignment_user = Table('lnk_az_roleassignment_user', Base.metadata,
    Column('AZroleAssignment', Text, ForeignKey('AZroleAssignments.id')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_az_roleassignment_group = Table('lnk_az_roleassignment_group', Base.metadata,
    Column('AZroleAssignment', Text, ForeignKey('AZroleAssignments.id')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_az_roleassignment_serviceprincipal = Table('lnk_az_roleassignment_serviceprincipal', Base.metadata,
    Column('AZroleAssignment', Text, ForeignKey('AZroleAssignments.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_az_roleassignment_eligible_user = Table('lnk_az_roleassignment_eligible_user', Base.metadata,
    Column('AZroleEligibilityScheduleInstance', Text, ForeignKey('AZroleEligibilityScheduleInstances.id')),
    Column('User', Text, ForeignKey('Users.objectId'))
)

lnk_az_roleassignment_eligible_group = Table('lnk_az_roleassignment_eligible_group', Base.metadata,
    Column('AZroleEligibilityScheduleInstance', Text, ForeignKey('AZroleEligibilityScheduleInstances.id')),
    Column('Group', Text, ForeignKey('Groups.objectId'))
)

lnk_az_roleassignment_eligible_serviceprincipal = Table('lnk_az_roleassignment_eligible_serviceprincipal', Base.metadata,
    Column('AZroleEligibilityScheduleInstance', Text, ForeignKey('AZroleEligibilityScheduleInstances.id')),
    Column('ServicePrincipal', Text, ForeignKey('ServicePrincipals.objectId'))
)

lnk_policy_user_include_allusers = Table('lnk_policy_user_include_allusers', Base.metadata,
    Column('Policy', Text, ForeignKey('Policys.objectId'))
)

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
    employeeHireDate = Column(DateTime)
    employeeOrgData = Column(JSON)
    employeeType = Column(Text)
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
    infoCatalogs = Column(JSON)
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
    onPremisesObjectIdentifier = Column(Text)
    onPremisesPasswordChangeTimestamp = Column(DateTime)
    onPremisesSecurityIdentifier = Column(Text)
    onPremisesUserPrincipalName = Column(Text)
    otherMails = Column(JSON)
    originTenantInfo = Column(JSON)
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

    ownedGroups = relationship("Group",
        secondary=lnk_group_owner_user,
        back_populates="ownerUsers")

    memberOfAu = relationship("AdministrativeUnit",
        secondary=lnk_au_member_user,
        back_populates="memberUsers")

    policiesIncluded = relationship("Policy",
        secondary=lnk_policy_user_include,
        back_populates="includedUsers")

    policiesExcluded = relationship("Policy",
        secondary=lnk_policy_user_exclude,
        back_populates="excludedUsers")

    pimRoleAssignments = relationship("PIMgovernanceRoleAssignment",
        secondary=lnk_pim_roleassignment_subjectuser,
        back_populates="subjectUser")

    pimRoleAssignmentRequests = relationship("PIMgovernanceRoleAssignmentRequest",
        secondary=lnk_pim_roleassignmentrequest_subjectuser,
        back_populates="subjectUser")

    accessPackagePolicies = relationship("IGaccessPackageAssignmentPolicy",
        secondary=lnk_ig_ap_assignment_policy_inscope_user,
        back_populates="scopeUsers")

    azRoleAssignments = relationship("AZroleAssignment",
        secondary=lnk_az_roleassignment_user,
        back_populates="user")

    azEligibleRoleAssignments = relationship("AZroleEligibilityScheduleInstance",
        secondary=lnk_az_roleassignment_eligible_user,
        back_populates="user")


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
    disabledByMicrosoftStatus = Column(Text)
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

    ownedGroups = relationship("Group",
        secondary=lnk_group_owner_serviceprincipal,
        back_populates="ownerServicePrincipals")

    pimRoleAssignments = relationship("PIMgovernanceRoleAssignment",
        secondary=lnk_pim_roleassignment_subjectserviceprincipal,
        back_populates="subjectServicePrincipal")

    pimRoleAssignmentRequests = relationship("PIMgovernanceRoleAssignmentRequest",
        secondary=lnk_pim_roleassignmentrequest_subjectserviceprincipal,
        back_populates="subjectServicePrincipal")

    accessPackagePolicies = relationship("IGaccessPackageAssignmentPolicy",
        secondary=lnk_ig_ap_assignment_policy_inscope_serviceprincipal,
        back_populates="scopeServicePrincipals")

    azRoleAssignments = relationship("AZroleAssignment",
        secondary=lnk_az_roleassignment_serviceprincipal,
        back_populates="serviceprincipal")

    azEligibleRoleAssignments = relationship("AZroleEligibilityScheduleInstance",
        secondary=lnk_az_roleassignment_eligible_serviceprincipal,
        back_populates="serviceprincipal")


    oauth2PermissionGrants = relationship("OAuth2PermissionGrant",
        primaryjoin=objectId == foreign(OAuth2PermissionGrant.clientId))

    appRolesAssigned = relationship("AppRoleAssignment",
        primaryjoin=objectId == foreign(AppRoleAssignment.resourceId))

    appRolesAssignedTo = relationship("AppRoleAssignment",
        primaryjoin=objectId == foreign(AppRoleAssignment.principalId))

    agentMetadata = relationship("AgentIdentityMetadata",
        back_populates="servicePrincipal",
        uselist=False)


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
    infoCatalogs = Column(JSON)
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
    resourceBehaviorOptions = Column(JSON)
    resourceProvisioningOptions = Column(JSON)
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

    ownerUsers = relationship("User",
        secondary=lnk_group_owner_user,
        back_populates="ownedGroups")

    ownerServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_group_owner_serviceprincipal,
        back_populates="ownedGroups")

    memberOf = relationship("Group",
        secondary=lnk_group_member_group,
        primaryjoin=objectId==lnk_group_member_group.c.childGroup,
        secondaryjoin=objectId==lnk_group_member_group.c.Group,
        back_populates="memberGroups")

    memberOfRole = relationship("DirectoryRole",
        secondary=lnk_role_member_group,
        back_populates="memberGroups")

    memberOfAu = relationship("AdministrativeUnit",
        secondary=lnk_au_member_group,
        back_populates="memberGroups")

    pimRoleAssignments = relationship("PIMgovernanceRoleAssignment",
        secondary=lnk_pim_roleassignment_subjectgroup,
        back_populates="subjectGroup")

    pimRoleAssignmentRequests = relationship("PIMgovernanceRoleAssignmentRequest",
        secondary=lnk_pim_roleassignmentrequest_subjectgroup,
        back_populates="subjectGroup")

    accessPackagePolicies = relationship("IGaccessPackageAssignmentPolicy",
        secondary=lnk_ig_ap_assignment_policy_inscope_group,
        back_populates="scopeGroups")

    azRoleAssignments = relationship("AZroleAssignment",
        secondary=lnk_az_roleassignment_group,
        back_populates="group")

    azEligibleRoleAssignments = relationship("AZroleEligibilityScheduleInstance",
        secondary=lnk_az_roleassignment_eligible_group,
        back_populates="group")

    pimResource = relationship("PIMgovernanceResource",
        secondary=lnk_pim_resource_aadgroup,
        back_populates="group")


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
    certification = Column(JSON)
    disabledByMicrosoftStatus = Column(Text)
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

    federatedIdentityCredentials = relationship("FederatedIdentityCredential",
        back_populates="application")


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
    externalSourceName = Column(Text)
    hostnames = Column(JSON)
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
    sourceType = Column(Text)
    systemLabels = Column(JSON)
    owner = relationship("User",
        secondary=lnk_device_owner,
        back_populates="ownedDevices")

    memberOf = relationship("Group",
        secondary=lnk_group_member_device,
        back_populates="memberDevices")

    memberOfAu = relationship("AdministrativeUnit",
        secondary=lnk_au_member_device,
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

    memberGroups = relationship("Group",
        secondary=lnk_role_member_group,
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
    createdDateTime = Column(DateTime)
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
    onPremisesObjectIdentifier = Column(Text)
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
    includedUsers = relationship("User",
        secondary=lnk_policy_user_include,
        back_populates="policiesIncluded")

    excludedUsers = relationship("User",
        secondary=lnk_policy_user_exclude,
        back_populates="policiesExcluded")


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
    eligibleAssignments = relationship("EligibleRoleAssignment",
        back_populates="roleDefinition")

    assignments = relationship("RoleAssignment",
        back_populates="roleDefinition")


class RoleAssignment(Base, SerializeMixin):
    __tablename__ = "RoleAssignments"
    id = Column(Text, primary_key=True)
    principalId = Column(Text)
    resourceScopes = Column(JSON)
    roleDefinitionId = Column(Text, ForeignKey("RoleDefinitions.objectId"))
    roleDefinition = relationship("RoleDefinition",
        back_populates="assignments")


class EligibleRoleAssignment(Base, SerializeMixin):
    __tablename__ = "EligibleRoleAssignments"
    id = Column(Text, primary_key=True)
    principalId = Column(Text)
    resourceScopes = Column(JSON)
    roleDefinitionId = Column(Text, ForeignKey("RoleDefinitions.objectId"))
    roleDefinition = relationship("RoleDefinition",
        back_populates="eligibleAssignments")


class AuthorizationPolicy(Base, SerializeMixin):
    __tablename__ = "AuthorizationPolicys"
    id = Column(Text, primary_key=True)
    allowInvitesFrom = Column(Text)
    allowedToSignUpEmailBasedSubscriptions = Column(Boolean)
    allowedToUseSSPR = Column(Boolean)
    allowEmailVerifiedUsersToJoinOrganization = Column(Boolean)
    blockMsolPowerShell = Column(Boolean)
    defaultUserRolePermissions = Column(JSON)
    displayName = Column(Text)
    description = Column(Text)
    enabledPreviewFeatures = Column(JSON)
    guestUserRoleId = Column(Text)
    permissionGrantPolicyIdsAssignedToDefaultUserRole = Column(JSON)


class DirectorySetting(Base, SerializeMixin):
    __tablename__ = "DirectorySettings"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    templateId = Column(Text)
    values = Column(JSON)


class AdministrativeUnit(Base, SerializeMixin):
    __tablename__ = "AdministrativeUnits"
    objectType = Column(Text)
    objectId = Column(Text, primary_key=True)
    deletionTimestamp = Column(DateTime)
    displayName = Column(Text)
    description = Column(Text)
    isMemberManagementRestricted = Column(Boolean)
    membershipRule = Column(Text)
    membershipRuleProcessingState = Column(Text)
    membershipType = Column(Text)
    visibility = Column(Text)
    memberGroups = relationship("Group",
        secondary=lnk_au_member_group,
        back_populates="memberOfAu")

    memberUsers = relationship("User",
        secondary=lnk_au_member_user,
        back_populates="memberOfAu")

    memberDevices = relationship("Device",
        secondary=lnk_au_member_device,
        back_populates="memberOfAu")


class PIMprivilegedAccess(Base, SerializeMixin):
    __tablename__ = "PIMprivilegedAccesss"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    resources = relationship("PIMgovernanceResource",
        secondary=lnk_pim_resource,
        back_populates="parent")


class PIMgovernanceResource(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceResources"
    id = Column(Text, primary_key=True)
    externalId = Column(Text)
    type = Column(Text)
    displayName = Column(Text)
    status = Column(Text)
    onboardDateTime = Column(DateTime)
    registeredDateTime = Column(DateTime)
    managedAt = Column(Text)
    registeredRoot = Column(Text)
    originTenantId = Column(Text)
    roleDefinitions = relationship("PIMgovernanceRoleDefinition",
        back_populates="resource")

    roleAssignments = relationship("PIMgovernanceRoleAssignment",
        back_populates="resource")

    roleAssignmentrequests = relationship("PIMgovernanceRoleAssignmentRequest",
        back_populates="resource")

    alerts = relationship("PIMgovernanceAlert",
        secondary=lnk_pim_resource_rolealerts,
        back_populates="resource")

    roleSettings = relationship("PIMgovernanceRoleSetting",
        back_populates="resource")

    roleSettingsv2 = relationship("PIMgovernanceRoleSettingV2",
        back_populates="resource")

    group = relationship("Group",
        secondary=lnk_pim_resource_aadgroup,
        back_populates="pimResource")

    parent = relationship("PIMprivilegedAccess",
        secondary=lnk_pim_resource,
        back_populates="resources")


class PIMgovernanceRoleDefinition(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceRoleDefinitions"
    id = Column(Text, primary_key=True)
    resourceId = Column(Text, ForeignKey("PIMgovernanceResources.id"))
    externalId = Column(Text)
    templateId = Column(Text)
    displayName = Column(Text)
    type = Column(Text)
    roleAssignments = relationship("PIMgovernanceRoleAssignment",
        back_populates="roleDefinition")

    roleSettings = relationship("PIMgovernanceRoleSetting",
        back_populates="roleDefinition")

    roleSettingsv2 = relationship("PIMgovernanceRoleSettingV2",
        back_populates="roleDefinition")

    resource = relationship("PIMgovernanceResource",
        back_populates="roleDefinitions")


class PIMgovernanceRoleAssignment(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceRoleAssignments"
    id = Column(Text, primary_key=True)
    resourceId = Column(Text, ForeignKey("PIMgovernanceResources.id"))
    roleDefinitionId = Column(Text, ForeignKey("PIMgovernanceRoleDefinitions.id"))
    subjectId = Column(Text)
    scopedResourceId = Column(Text)
    linkedEligibleRoleAssignmentId = Column(Text)
    externalId = Column(Text)
    isPermanent = Column(Boolean)
    startDateTime = Column(DateTime)
    endDateTime = Column(DateTime)
    memberType = Column(Text)
    assignmentState = Column(Text)
    status = Column(Text)
    condition = Column(Text)
    conditionVersion = Column(Text)
    conditionDescription = Column(Text)
    subjectUser = relationship("User",
        secondary=lnk_pim_roleassignment_subjectuser,
        back_populates="pimRoleAssignments")

    subjectGroup = relationship("Group",
        secondary=lnk_pim_roleassignment_subjectgroup,
        back_populates="pimRoleAssignments")

    subjectServicePrincipal = relationship("ServicePrincipal",
        secondary=lnk_pim_roleassignment_subjectserviceprincipal,
        back_populates="pimRoleAssignments")

    resource = relationship("PIMgovernanceResource",
        back_populates="roleAssignments")

    roleDefinition = relationship("PIMgovernanceRoleDefinition",
        back_populates="roleAssignments")


class PIMgovernanceRoleAssignmentRequest(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceRoleAssignmentRequests"
    id = Column(Text, primary_key=True)
    resourceId = Column(Text, ForeignKey("PIMgovernanceResources.id"))
    roleDefinitionId = Column(Text, ForeignKey("PIMgovernanceRoleDefinitions.id"))
    subjectId = Column(Text)
    scopedResourceId = Column(Text)
    linkedEligibleRoleAssignmentId = Column(Text)
    type = Column(Text)
    assignmentState = Column(Text)
    requestedDateTime = Column(DateTime)
    roleAssignmentStartDateTime = Column(DateTime)
    roleAssignmentEndDateTime = Column(DateTime)
    reason = Column(Text)
    status = Column(JSON)
    schedule = Column(JSON)
    PIMmetadata = Column(JSON)
    ticketNumber = Column(Text)
    ticketSystem = Column(Text)
    condition = Column(Text)
    conditionVersion = Column(Text)
    conditionDescription = Column(Text)
    subjectUser = relationship("User",
        secondary=lnk_pim_roleassignmentrequest_subjectuser,
        back_populates="pimRoleAssignmentRequests")

    subjectGroup = relationship("Group",
        secondary=lnk_pim_roleassignmentrequest_subjectgroup,
        back_populates="pimRoleAssignmentRequests")

    subjectServicePrincipal = relationship("ServicePrincipal",
        secondary=lnk_pim_roleassignmentrequest_subjectserviceprincipal,
        back_populates="pimRoleAssignmentRequests")

    resource = relationship("PIMgovernanceResource",
        back_populates="roleAssignmentrequests")


class PIMgovernanceRoleSetting(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceRoleSettings"
    id = Column(Text, primary_key=True)
    resourceId = Column(Text, ForeignKey("PIMgovernanceResources.id"))
    roleDefinitionId = Column(Text, ForeignKey("PIMgovernanceRoleDefinitions.id"))
    isDefault = Column(Boolean)
    lastUpdatedDateTime = Column(DateTime)
    lastUpdatedBy = Column(Text)
    adminEligibleSettings = Column(JSON)
    adminMemberSettings = Column(JSON)
    userEligibleSettings = Column(JSON)
    userMemberSettings = Column(JSON)
    resource = relationship("PIMgovernanceResource",
        back_populates="roleSettings")

    roleDefinition = relationship("PIMgovernanceRoleDefinition",
        back_populates="roleSettings")


class PIMgovernanceRoleSettingV2(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceRoleSettingV2s"
    id = Column(Text, primary_key=True)
    resourceId = Column(Text, ForeignKey("PIMgovernanceResources.id"))
    roleDefinitionId = Column(Text, ForeignKey("PIMgovernanceRoleDefinitions.id"))
    isDefault = Column(Boolean)
    lastUpdatedDateTime = Column(DateTime)
    lastUpdatedBy = Column(Text)
    lifeCycleManagement = Column(JSON)
    resource = relationship("PIMgovernanceResource",
        back_populates="roleSettingsv2")

    roleDefinition = relationship("PIMgovernanceRoleDefinition",
        back_populates="roleSettingsv2")


class PIMgovernanceAlert(Base, SerializeMixin):
    __tablename__ = "PIMgovernanceAlerts"
    id = Column(Text, primary_key=True)
    resourceId = Column(Text, ForeignKey("PIMgovernanceResources.id"))
    alertName = Column(Text)
    alertDescription = Column(Text)
    numberOfAffectedItems = Column(Integer)
    additionalData = Column(JSON)
    lastModifiedDateTime = Column(DateTime)
    lastScannedDateTime = Column(DateTime)
    severityLevel = Column(Text)
    alertType = Column(Text)
    securityImpact = Column(Text)
    mitigationSteps = Column(Text)
    howToPrevent = Column(Text)
    isDisabled = Column(Boolean)
    isActive = Column(Boolean)
    isResolvable = Column(Boolean)
    isConfigurable = Column(Boolean)
    status = Column(Text)
    settings = Column(JSON)
    resource = relationship("PIMgovernanceResource",
        secondary=lnk_pim_resource_rolealerts,
        back_populates="alerts")


class IGaccessPackageCatalog(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageCatalogs"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    uniqueName = Column(Text)
    description = Column(Text)
    catalogType = Column(Text)
    catalogStatus = Column(Text)
    state = Column(Text)
    isExternallyVisible = Column(Boolean)
    createdBy = Column(Text)
    createdByString = Column(Text)
    createdDateTime = Column(DateTime)
    modifiedBy = Column(Text)
    lastModifiedByString = Column(Text)
    modifiedDateTime = Column(DateTime)
    lastModifiedDateTime = Column(DateTime)
    serviceManagementReference = Column(JSON)
    privilegeLevel = Column(Text)
    resources = relationship("IGaccessPackageResource",
        secondary=lnk_ig_cg_resource,
        back_populates="catalog")

    accessPackages = relationship("IGaccessPackage",
        secondary=lnk_ig_ap,
        back_populates="catalog")


class IGaccessPackageResource(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageResources"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    description = Column(Text)
    url = Column(Text)
    resourceType = Column(Text)
    originId = Column(Text)
    originSystem = Column(Text)
    isPendingOnboarding = Column(Boolean)
    addedBy = Column(Text)
    addedOn = Column(DateTime)
    attributes = Column(JSON)
    createdBy = Column(Text)
    createdByString = Column(Text)
    createdDateTime = Column(DateTime)
    resourceRequests = relationship("IGaccessPackageResourceRequest",
        secondary=lnk_ig_ap_resource_request,
        back_populates="resource")

    resourceRoles = relationship("IGaccessPackageResourceRole",
        secondary=lnk_ig_ap_rr,
        back_populates="resource")

    catalog = relationship("IGaccessPackageCatalog",
        secondary=lnk_ig_cg_resource,
        back_populates="resources")


class IGaccessPackageResourceRequest(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageResourceRequests"
    id = Column(Text, primary_key=True)
    requestType = Column(Text)
    requestState = Column(Text)
    state = Column(Text)
    requestStatus = Column(Text)
    createdBy = Column(Text)
    createdByString = Column(Text)
    createdDateTime = Column(DateTime)
    catalogId = Column(Text)
    executeImmediately = Column(Boolean)
    justification = Column(Text)
    expirationDateTime = Column(DateTime)
    history = Column(JSON)
    answers = Column(JSON)
    parameters = Column(JSON)
    resource = relationship("IGaccessPackageResource",
        secondary=lnk_ig_ap_resource_request,
        back_populates="resourceRequests")


class IGaccessPackage(Base, SerializeMixin):
    __tablename__ = "IGaccessPackages"
    id = Column(Text, primary_key=True)
    catalogId = Column(Text)
    displayName = Column(Text)
    uniqueName = Column(Text)
    description = Column(Text)
    isHidden = Column(Boolean)
    isRoleScopesVisible = Column(Boolean)
    createdBy = Column(Text)
    createdByString = Column(Text)
    createdDateTime = Column(DateTime)
    modifiedBy = Column(Text)
    lastModifiedByString = Column(Text)
    modifiedDateTime = Column(DateTime)
    lastModifiedDateTime = Column(DateTime)
    lastCriticalModificationDateTime = Column(DateTime)
    lastSuccessfulChangeEvaluationDateTime = Column(DateTime)
    assignmentPolicies = relationship("IGaccessPackageAssignmentPolicy",
        back_populates="accessPackage")

    assignments = relationship("IGaccessPackageAssignment",
        back_populates="accessPackage")

    assignmentRequests = relationship("IGaccessPackageAssignmentRequest",
        secondary=lnk_ig_ap_assignment_request,
        back_populates="accessPackage")

    resourceRoleScopes = relationship("IGaccessPackageResourceRoleScope",
        secondary=lnk_ig_ap_rr_scope,
        back_populates="accessPackage")

    catalog = relationship("IGaccessPackageCatalog",
        secondary=lnk_ig_ap,
        back_populates="accessPackages")


class IGaccessPackageResourceRoleScope(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageResourceRoleScopes"
    id = Column(Text, primary_key=True)
    createdBy = Column(Text)
    createdByString = Column(Text)
    createdDateTime = Column(DateTime)
    modifiedBy = Column(Text)
    modifiedDateTime = Column(DateTime)
    role = relationship("IGaccessPackageResourceRole",
        secondary=lnk_ig_ap_rrs_role,
        back_populates="resourceRoleScopes")

    scope = relationship("IGaccessPackageResourceScope",
        secondary=lnk_ig_ap_rrs_scope,
        back_populates="resourceRoleScopes")

    accessPackage = relationship("IGaccessPackage",
        secondary=lnk_ig_ap_rr_scope,
        back_populates="resourceRoleScopes")


class IGaccessPackageResourceScope(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageResourceScopes"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    description = Column(Text)
    originId = Column(Text)
    originSystem = Column(Text)
    roleOriginId = Column(Text)
    isRootScope = Column(Boolean)
    url = Column(Text)
    resourceRoleScopes = relationship("IGaccessPackageResourceRoleScope",
        secondary=lnk_ig_ap_rrs_scope,
        back_populates="scope")


class IGaccessPackageResourceRole(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageResourceRoles"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    description = Column(Text)
    roleType = Column(Text)
    originSystem = Column(Text)
    originId = Column(Text)
    resourceRoleScopes = relationship("IGaccessPackageResourceRoleScope",
        secondary=lnk_ig_ap_rrs_role,
        back_populates="role")

    resource = relationship("IGaccessPackageResource",
        secondary=lnk_ig_ap_rr,
        back_populates="resourceRoles")


class IGaccessPackageAssignmentPolicy(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageAssignmentPolicys"
    id = Column(Text, primary_key=True)
    displayName = Column(Text)
    description = Column(Text)
    allowedTargetScope = Column(Text)
    specificAllowedTargets = Column(JSON)
    expiration = Column(JSON)
    countOfUsersIncludedInPolicy = Column(Integer)
    activeAssignmentCount = Column(Integer)
    createdDateTime = Column(DateTime)
    createdByString = Column(Text)
    accessPackageAssignmentRequestorSettings = Column(JSON)
    automaticRequestSettings = Column(JSON)
    lastModifiedByString = Column(Text)
    approvalSettings = Column(JSON)
    lastModifiedDateTime = Column(DateTime)
    reviewSettings = Column(JSON)
    questions = Column(JSON)
    notificationSettings = Column(JSON)
    accessPackageNotificationSettings = Column(JSON)
    verifiableCredentialSettings = Column(JSON)
    createdBy = Column(Text)
    modifiedBy = Column(Text)
    isDenyPolicy = Column(Boolean)
    canExtend = Column(Boolean)
    durationInDays = Column(Integer)
    expirationDateTime = Column(DateTime)
    isCustomAssignmentScheduleAllowed = Column(Boolean)
    policyAssignmentType = Column(Text)
    requestorSettings = Column(JSON)
    accessReviewSettings = Column(JSON)
    assignmentReviewSettings = Column(JSON)
    requestApprovalSettings = Column(JSON)
    accessPackageId = Column(Text, ForeignKey("IGaccessPackages.id"))
    modifiedDateTime = Column(DateTime)
    scopeUsers = relationship("User",
        secondary=lnk_ig_ap_assignment_policy_inscope_user,
        back_populates="accessPackagePolicies")

    scopeGroups = relationship("Group",
        secondary=lnk_ig_ap_assignment_policy_inscope_group,
        back_populates="accessPackagePolicies")

    scopeServicePrincipals = relationship("ServicePrincipal",
        secondary=lnk_ig_ap_assignment_policy_inscope_serviceprincipal,
        back_populates="accessPackagePolicies")

    accessPackage = relationship("IGaccessPackage",
        back_populates="assignmentPolicies")


class IGaccessPackageAssignment(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageAssignments"
    id = Column(Text, primary_key=True)
    catalogId = Column(Text)
    accessPackageId = Column(Text, ForeignKey("IGaccessPackages.id"))
    assignmentPolicyId = Column(Text, ForeignKey("IGaccessPackageAssignmentPolicys.id"))
    targetId = Column(Text)
    schedule = Column(JSON)
    assignmentStatus = Column(Text)
    assignmentState = Column(Text)
    state = Column(Text)
    status = Column(Text)
    isExtended = Column(Boolean)
    expiredDateTime = Column(DateTime)
    createdDateTime = Column(DateTime)
    modifiedDateTime = Column(DateTime)
    history = Column(JSON)
    customExtensionHandlerInstances = Column(JSON)
    customExtensionCalloutInstances = Column(JSON)
    assignmentResourceRoles = relationship("IGaccessPackageAssignmentResourceRole",
        secondary=lnk_ig_ap_assignment_resource_role,
        back_populates="assignment")

    subject = relationship("IGaccessPackageSubject",
        secondary=lnk_ig_ap_assignment_target,
        back_populates="assignments")

    accessPackage = relationship("IGaccessPackage",
        back_populates="assignments")


class IGaccessPackageAssignmentRequest(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageAssignmentRequests"
    id = Column(Text, primary_key=True)
    requestType = Column(Text)
    schedule = Column(JSON)
    answers = Column(JSON)
    requestState = Column(Text)
    state = Column(Text)
    requestStatus = Column(Text)
    status = Column(Text)
    createdDateTime = Column(DateTime)
    modifiedDateTime = Column(DateTime)
    completedDate = Column(DateTime)
    justification = Column(Text)
    isValidationOnly = Column(Boolean)
    history = Column(JSON)
    parameters = Column(JSON)
    customProperties = Column(JSON)
    referenceId = Column(Text)
    verifiedCredentialsData = Column(JSON)
    customExtensionHandlerInstances = Column(JSON)
    customExtensionCalloutInstances = Column(JSON)
    subject = relationship("IGaccessPackageSubject",
        secondary=lnk_ig_ap_assignment_request_target,
        back_populates="assignmentRequestsAsTarget")

    requestor = relationship("IGaccessPackageSubject",
        secondary=lnk_ig_ap_assignment_request_requestor,
        back_populates="assignmentRequests")

    accessPackage = relationship("IGaccessPackage",
        secondary=lnk_ig_ap_assignment_request,
        back_populates="assignmentRequests")


class IGaccessPackageAssignmentResourceRole(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageAssignmentResourceRoles"
    id = Column(Text, primary_key=True)
    originId = Column(Text)
    originSystem = Column(Text)
    status = Column(Text)
    assignment = relationship("IGaccessPackageAssignment",
        secondary=lnk_ig_ap_assignment_resource_role,
        back_populates="assignmentResourceRoles")


class IGaccessPackageSubject(Base, SerializeMixin):
    __tablename__ = "IGaccessPackageSubjects"
    connectedOrganizationId = Column(Text)
    id = Column(Text, primary_key=True)
    objectId = Column(Text, primary_key=True)
    altSecId = Column(Text)
    displayName = Column(Text)
    principalName = Column(Text)
    email = Column(Text)
    onPremisesSecurityIdentifier = Column(Text)
    type = Column(Text)
    subjectType = Column(Text)
    subjectLifecycle = Column(Text)
    cleanupScheduledDateTime = Column(DateTime)
    createdDateTime = Column(DateTime)
    assignmentRequestsAsTarget = relationship("IGaccessPackageAssignmentRequest",
        secondary=lnk_ig_ap_assignment_request_target,
        back_populates="subject")

    assignmentRequests = relationship("IGaccessPackageAssignmentRequest",
        secondary=lnk_ig_ap_assignment_request_requestor,
        back_populates="requestor")

    assignments = relationship("IGaccessPackageAssignment",
        secondary=lnk_ig_ap_assignment_target,
        back_populates="subject")


class AZroleDefinition(Base, SerializeMixin):
    __tablename__ = 'AZroleDefinitions'

    id = Column(Text, primary_key=True)
    name = Column(Text)
    type = Column(Text)
    role_name = Column(Text)
    description = Column(Text)
    role_type = Column(Text)
    created_on = Column(DateTime)
    permissions = Column(JSON)

    roleAssignments = relationship("AZroleAssignment",
        back_populates="role")

    eligibleRoleAssignments = relationship("AZroleEligibilityScheduleInstance",
        back_populates="role")

class AZroleAssignment(Base, SerializeMixin):
    __tablename__ = 'AZroleAssignments'

    id = Column(Text, primary_key=True)
    name = Column(Text)
    type = Column(Text)
    scope = Column(Text)
    role_definition_id = Column(Text, ForeignKey("AZroleDefinitions.id"))
    principal_id = Column(Text)
    principal_type = Column(Text)
    description = Column(Text)
    condition = Column(Text)
    condition_version = Column(Text)
    created_on = Column(DateTime)
    delegated_managed_identity_resource_id = Column(Text)

    group = relationship("Group",
        secondary=lnk_az_roleassignment_group,
        back_populates="azRoleAssignments")

    user = relationship("User",
        secondary=lnk_az_roleassignment_user,
        back_populates="azRoleAssignments")

    serviceprincipal = relationship("ServicePrincipal",
        secondary=lnk_az_roleassignment_serviceprincipal,
        back_populates="azRoleAssignments")

    role = relationship("AZroleDefinition",
        back_populates="roleAssignments")

class AZsubscription(Base, SerializeMixin):
    __tablename__ = 'AZsubscriptions'

    id = Column(Text, primary_key=True)
    subscription_id = Column(Text)
    display_name = Column(Text)
    state = Column(Text)
    subscription_policies = Column(JSON)
    authorization_source = Column(Text)

class AZmanagementGroup(Base, SerializeMixin):
    __tablename__ = 'AZmanagementGroups'

    id = Column(Text, primary_key=True)
    name = Column(Text)
    type = Column(Text)
    display_name = Column(Text)
    tenant_id = Column(Text)
    details = Column(JSON)

class AZroleEligibilityScheduleInstance(Base, SerializeMixin):
    __tablename__ = 'AZroleEligibilityScheduleInstances'

    id = Column(Text, primary_key=True)
    name = Column(Text)
    type = Column(Text)
    role_definition_id = Column(Text, ForeignKey("AZroleDefinitions.id"))
    principal_id = Column(Text)
    principal_type = Column(Text)
    scope = Column(Text)
    role_eligibility_schedule_id = Column(Text)
    status = Column(Text)
    start_date_time = Column(DateTime)
    end_date_time = Column(DateTime)
    member_type = Column(Text)
    condition = Column(Text)
    condition_version = Column(Text)
    created_on = Column(DateTime)
    expanded_properties = Column(JSON)

    group = relationship("Group",
        secondary=lnk_az_roleassignment_eligible_group,
        back_populates="azEligibleRoleAssignments")

    user = relationship("User",
        secondary=lnk_az_roleassignment_eligible_user,
        back_populates="azEligibleRoleAssignments")

    serviceprincipal = relationship("ServicePrincipal",
        secondary=lnk_az_roleassignment_eligible_serviceprincipal,
        back_populates="azEligibleRoleAssignments")

    role = relationship("AZroleDefinition",
        back_populates="eligibleRoleAssignments")

class AZresource(Base, SerializeMixin):
    __tablename__ = 'AZresources'

    id = Column(Text, primary_key=True)
    name = Column(Text)
    type = Column(Text)
    type_display_name = Column(Text)
    resource_group = Column(Text)
    location_display_name = Column(Text)
    subscription_display_name = Column(Text)
    kind = Column(Text)
    location = Column(Text)
    subscription_id = Column(Text, ForeignKey("AZsubscriptions.id"))
    tags = Column(JSON)
    extended_location = Column(JSON)


class FederatedIdentityCredential(Base, SerializeMixin):
    __tablename__ = "FederatedIdentityCredentials"
    id = Column(Text, primary_key=True)
    applicationObjectId = Column(Text, ForeignKey("Applications.objectId"), index=True)
    appId = Column(Text)
    name = Column(Text)
    issuer = Column(Text)
    subject = Column(Text)
    description = Column(Text)
    audiences = Column(JSON)
    claimsMatchingExpression = Column(JSON)
    application = relationship("Application",
        back_populates="federatedIdentityCredentials")


class AgentIdentityMetadata(Base, SerializeMixin):
    __tablename__ = "AgentIdentityMetadatas"
    objectId = Column(Text, ForeignKey("ServicePrincipals.objectId"), primary_key=True)
    appId = Column(Text)
    agentCategory = Column(Text)
    executionMode = Column(Text)
    blueprintId = Column(Text)
    sponsorUserIds = Column(JSON)
    m365Scopes = Column(JSON)
    mcpTools = Column(JSON)
    collectionSource = Column(Text)
    rawMetadata = Column(JSON)
    servicePrincipal = relationship("ServicePrincipal",
        back_populates="agentMetadata",
        uselist=False)


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
