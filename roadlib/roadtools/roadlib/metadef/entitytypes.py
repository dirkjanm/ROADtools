from roadtools.roadlib.metadef.basetypes import Edm, Collection
from roadtools.roadlib.metadef.complextypes import *

class DirectoryObject(object):
    props = {
        'objectType': Edm.String,
        'objectId': Edm.String,
        'deletionTimestamp': Edm.DateTime,
    }
    rels = [
        'createdOnBehalfOf',
        'createdObjects',
        'manager',
        'directReports',
        'members',
        'transitiveMembers',
        'memberOf',
        'transitiveMemberOf',
        'owners',
        'ownedObjects',
    ]


class ExtensionProperty(DirectoryObject):
    props = {
        'appDisplayName': Edm.String,
        'name': Edm.String,
        'dataType': Edm.String,
        'isSyncedFromOnPremises': Edm.Boolean,
        'targetObjects': Collection,
    }
    rels = [

    ]


class ServiceEndpoint(DirectoryObject):
    props = {
        'capability': Edm.String,
        'serviceId': Edm.String,
        'serviceName': Edm.String,
        'serviceEndpointUri': Edm.String,
        'serviceResourceId': Edm.String,
    }
    rels = [

    ]


class AdministrativeUnit(DirectoryObject):
    props = {
        'displayName': Edm.String,
        'description': Edm.String,
        'membershipRule': Edm.String,
        'membershipType': Edm.String,
        'visibility': Edm.String,
    }
    rels = [
        'scopedAdministrators',
    ]


class Application(DirectoryObject):
    props = {
        'addIns': Collection,
        'allowActAsForAllClients': Edm.Boolean,
        'allowPassthroughUsers': Edm.Boolean,
        'appBranding': AppBranding,
        'appCategory': Edm.String,
        'appData': Edm.String,
        'appId': Edm.String,
        'applicationTemplateId': Edm.String,
        'appMetadata': AppMetadata,
        'appRoles': Collection,
        'availableToOtherTenants': Edm.Boolean,
        'displayName': Edm.String,
        'encryptedMsiApplicationSecret': Edm.Binary,
        'errorUrl': Edm.String,
        'groupMembershipClaims': Edm.String,
        'homepage': Edm.String,
        'identifierUris': Collection,
        'informationalUrls': InformationalUrl,
        'isDeviceOnlyAuthSupported': Edm.Boolean,
        'keyCredentials': Collection,
        'knownClientApplications': Collection,
        'logo': Edm.Stream,
        'logoUrl': Edm.String,
        'logoutUrl': Edm.String,
        'mainLogo': Edm.Stream,
        'oauth2AllowIdTokenImplicitFlow': Edm.Boolean,
        'oauth2AllowImplicitFlow': Edm.Boolean,
        'oauth2AllowUrlPathMatching': Edm.Boolean,
        'oauth2Permissions': Collection,
        'oauth2RequirePostResponse': Edm.Boolean,
        'optionalClaims': OptionalClaims,
        'parentalControlSettings': ParentalControlSettings,
        'passwordCredentials': Collection,
        'publicClient': Edm.Boolean,
        'publisherDomain': Edm.String,
        'recordConsentConditions': Edm.String,
        'replyUrls': Collection,
        'requiredResourceAccess': Collection,
        'samlMetadataUrl': Edm.String,
        'supportsConvergence': Edm.Boolean,
        'tokenEncryptionKeyId': Edm.Guid,
        'trustedCertificateSubjects': Collection,
        'verifiedPublisher': VerifiedPublisher,
    }
    rels = [
        'defaultPolicy',
        'extensionProperties',
        'serviceEndpoints',
    ]


class ApplicationRef(object):
    props = {
        'appCategory': Edm.String,
        'appContextId': Edm.Guid,
        'appData': Edm.String,
        'appId': Edm.String,
        'appRoles': Collection,
        'availableToOtherTenants': Edm.Boolean,
        'displayName': Edm.String,
        'errorUrl': Edm.String,
        'homepage': Edm.String,
        'identifierUris': Collection,
        'knownClientApplications': Collection,
        'logoutUrl': Edm.String,
        'logoUrl': Edm.String,
        'mainLogo': Edm.Stream,
        'oauth2Permissions': Collection,
        'publisherDomain': Edm.String,
        'publisherName': Edm.String,
        'publicClient': Edm.Boolean,
        'replyUrls': Collection,
        'requiredResourceAccess': Collection,
        'samlMetadataUrl': Edm.String,
        'supportsConvergence': Edm.Boolean,
    }
    rels = [

    ]


class AppRoleAssignment(DirectoryObject):
    props = {
        'creationTimestamp': Edm.DateTime,
        'id': Edm.Guid,
        'principalDisplayName': Edm.String,
        'principalId': Edm.Guid,
        'principalType': Edm.String,
        'resourceDisplayName': Edm.String,
        'resourceId': Edm.Guid,
    }
    rels = [

    ]


class AuthorizationPolicy(object):
    props = {
        'id': Edm.String,
        'displayName': Edm.String,
        'description': Edm.String,
        'enabledPreviewFeatures': Collection,
        'guestUserRoleId': Edm.Guid,
        'permissionGrantPolicyIdsAssignedToDefaultUserRole': Collection,
    }
    rels = [

    ]


class Contact(DirectoryObject):
    props = {
        'city': Edm.String,
        'cloudAudioConferencingProviderInfo': Edm.String,
        'cloudMSRtcIsSipEnabled': Edm.Boolean,
        'cloudMSRtcOwnerUrn': Edm.String,
        'cloudMSRtcPolicyAssignments': Collection,
        'cloudMSRtcPool': Edm.String,
        'cloudMSRtcServiceAttributes': CloudMSRtcServiceAttributes,
        'cloudRtcUserPolicies': Edm.String,
        'cloudSipLine': Edm.String,
        'companyName': Edm.String,
        'country': Edm.String,
        'department': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'displayName': Edm.String,
        'facsimileTelephoneNumber': Edm.String,
        'givenName': Edm.String,
        'jobTitle': Edm.String,
        'lastDirSyncTime': Edm.DateTime,
        'mail': Edm.String,
        'mailNickname': Edm.String,
        'mobile': Edm.String,
        'physicalDeliveryOfficeName': Edm.String,
        'postalCode': Edm.String,
        'provisioningErrors': Collection,
        'proxyAddresses': Collection,
        'sipProxyAddress': Edm.String,
        'state': Edm.String,
        'streetAddress': Edm.String,
        'surname': Edm.String,
        'telephoneNumber': Edm.String,
        'thumbnailPhoto': Edm.Stream,
    }
    rels = [

    ]


class Contract(DirectoryObject):
    props = {
        'contractType': Edm.String,
        'customerContextId': Edm.Guid,
        'defaultDomainName': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class Device(DirectoryObject):
    props = {
        'accountEnabled': Edm.Boolean,
        'alternativeSecurityIds': Collection,
        'approximateLastLogonTimestamp': Edm.DateTime,
        'bitLockerKey': Collection,
        'capabilities': Collection,
        'complianceExpiryTime': Edm.DateTime,
        'compliantApplications': Collection,
        'compliantAppsManagementAppId': Edm.String,
        'deviceCategory': Edm.String,
        'deviceId': Edm.Guid,
        'deviceKey': Collection,
        'deviceManufacturer': Edm.String,
        'deviceManagementAppId': Edm.String,
        'deviceMetadata': Edm.String,
        'deviceModel': Edm.String,
        'deviceObjectVersion': Edm.Int32,
        'deviceOSType': Edm.String,
        'deviceOSVersion': Edm.String,
        'deviceOwnership': Edm.String,
        'devicePhysicalIds': Collection,
        'deviceSystemMetadata': Collection,
        'deviceTrustType': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'displayName': Edm.String,
        'domainName': Edm.String,
        'enrollmentProfileName': Edm.String,
        'enrollmentType': Edm.String,
        'exchangeActiveSyncId': Collection,
        'isCompliant': Edm.Boolean,
        'isManaged': Edm.Boolean,
        'isRooted': Edm.Boolean,
        'keyCredentials': Collection,
        'lastDirSyncTime': Edm.DateTime,
        'localCredentials': Edm.String,
        'managementType': Edm.String,
        'onPremisesSecurityIdentifier': Edm.String,
        'organizationalUnit': Edm.String,
        'profileType': Edm.String,
        'reserved1': Edm.String,
        'systemLabels': Collection,
    }
    rels = [
        'registeredOwners',
        'registeredUsers',
        'resourceAccount',
    ]


class DeviceConfiguration(DirectoryObject):
    props = {
        'publicIssuerCertificates': Collection,
        'cloudPublicIssuerCertificates': Collection,
        'registrationQuota': Edm.Int32,
        'maximumRegistrationInactivityPeriod': Edm.Int32,
    }
    rels = [

    ]


class DirectoryLinkChange(DirectoryObject):
    props = {
        'associationType': Edm.String,
        'sourceObjectId': Edm.String,
        'sourceObjectType': Edm.String,
        'sourceObjectUri': Edm.String,
        'targetObjectId': Edm.String,
        'targetObjectType': Edm.String,
        'targetObjectUri': Edm.String,
    }
    rels = [

    ]


class DirectoryObjectReference(DirectoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'externalContextId': Edm.Guid,
    }
    rels = [

    ]


class DirectoryRole(DirectoryObject):
    props = {
        'cloudSecurityIdentifier': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'isSystem': Edm.Boolean,
        'roleDisabled': Edm.Boolean,
        'roleTemplateId': Edm.String,
    }
    rels = [
        'eligibleMembers',
        'scopedAdministrators',
    ]


class DirectoryRoleTemplate(DirectoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class DirectorySetting(object):
    props = {
        'id': Edm.String,
        'displayName': Edm.String,
        'templateId': Edm.String,
        'values': Collection,
    }
    rels = [

    ]


class DirectorySettingTemplate(DirectoryObject):
    props = {
        'displayName': Edm.String,
        'description': Edm.String,
        'values': Collection,
    }
    rels = [

    ]


class EligibleRoleAssignment(object):
    props = {
        'id': Edm.String,
        'principalId': Edm.String,
        'resourceScopes': Collection,
        'roleDefinitionId': Edm.String,
    }
    rels = [

    ]


class EnabledFeature(object):
    props = {
        'featureId': Edm.String,
        'featureName': Edm.String,
    }
    rels = [

    ]


class ExternalDomainFederation(object):
    props = {
        'externalDomainName': Edm.String,
        'federationSettings': DomainFederationSettings,
    }
    rels = [

    ]


class Group(DirectoryObject):
    props = {
        'appMetadata': AppMetadata,
        'classification': Edm.String,
        'cloudSecurityIdentifier': Edm.String,
        'createdDateTime': Edm.DateTime,
        'createdByAppId': Edm.String,
        'description': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'displayName': Edm.String,
        'exchangeResources': Collection,
        'expirationDateTime': Edm.DateTime,
        'externalGroupIds': Collection,
        'externalGroupProviderId': Edm.String,
        'externalGroupState': Edm.String,
        'creationOptions': Collection,
        'groupTypes': Collection,
        'isAssignableToRole': Edm.Boolean,
        'isMembershipRuleLocked': Edm.Boolean,
        'isPublic': Edm.Boolean,
        'lastDirSyncTime': Edm.DateTime,
        'licenseAssignment': Collection,
        'mail': Edm.String,
        'mailNickname': Edm.String,
        'mailEnabled': Edm.Boolean,
        'membershipRule': Edm.String,
        'membershipRuleProcessingState': Edm.String,
        'membershipTypes': Collection,
        'onPremisesSecurityIdentifier': Edm.String,
        'preferredDataLocation': Edm.String,
        'preferredLanguage': Edm.String,
        'primarySMTPAddress': Edm.String,
        'provisioningErrors': Collection,
        'proxyAddresses': Collection,
        'renewedDateTime': Edm.DateTime,
        'securityEnabled': Edm.Boolean,
        'sharepointResources': Collection,
        'targetAddress': Edm.String,
        'theme': Edm.String,
        'visibility': Edm.String,
        'wellKnownObject': Edm.String,
    }
    rels = [
        'allowAccessTo',
        'appRoleAssignments',
        'eligibleMemberOf',
        'hasAccessTo',
        'pendingMembers',
        'securedExternalData',
        'settings',
        'endpoints',
    ]


class LicenseDetail(object):
    props = {
        'objectId': Edm.String,
        'servicePlans': Collection,
        'skuId': Edm.Guid,
        'skuPartNumber': Edm.String,
    }
    rels = [

    ]


class LoginTenantBranding(object):
    props = {
        'backgroundColor': Edm.String,
        'bannerLogo': Edm.Stream,
        'bannerLogoUrl': Edm.String,
        'boilerPlateText': Edm.String,
        'illustration': Edm.Stream,
        'illustrationUrl': Edm.String,
        'keepMeSignedInDisabled': Edm.Boolean,
        'locale': Edm.String,
        'metadataUrl': Edm.String,
        'postSignoutUrl': Edm.String,
        'postSignoutUrlText': Edm.String,
        'signInTextHeading': Edm.String,
        'squareLogoDark': Edm.Stream,
        'squareLogoDarkUrl': Edm.String,
        'tileLogo': Edm.Stream,
        'tileLogoUrl': Edm.String,
        'userIdLabel': Edm.String,
    }
    rels = [

    ]


class OAuth2PermissionGrant(object):
    props = {
        'clientId': Edm.String,
        'consentType': Edm.String,
        'expiryTime': Edm.DateTime,
        'objectId': Edm.String,
        'principalId': Edm.String,
        'resourceId': Edm.String,
        'scope': Edm.String,
        'startTime': Edm.DateTime,
    }
    rels = [

    ]


class PermissionGrantPolicy(object):
    props = {
        'id': Edm.String,
        'displayName': Edm.String,
        'description': Edm.String,
        'includes': Collection,
        'excludes': Collection,
    }
    rels = [

    ]


class Policy(DirectoryObject):
    props = {
        'displayName': Edm.String,
        'keyCredentials': Collection,
        'policyType': Edm.Int32,
        'policyDetail': Collection,
        'policyIdentifier': Edm.String,
        'tenantDefaultPolicy': Edm.Int32,
    }
    rels = [
        'policyAppliedTo',
    ]


class RoleAssignment(object):
    props = {
        'id': Edm.String,
        'principalId': Edm.String,
        'resourceScopes': Collection,
        'roleDefinitionId': Edm.String,
    }
    rels = [
        'principal',
        'roleDefinition',
    ]


class RoleDefinition(DirectoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isBuiltIn': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'resourceScopes': Collection,
        'rolePermissions': Collection,
        'templateId': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'inheritsPermissionsFrom',
    ]


class ScopedRoleMembership(object):
    props = {
        'id': Edm.String,
        'roleObjectId': Edm.Guid,
        'administrativeUnitObjectId': Edm.Guid,
        'roleMemberInfo': IdentityInfo,
    }
    rels = [

    ]


class SecuredExternalData(object):
    props = {
        'partnerId': Edm.String,
        'shardId': Edm.Int32,
        'version': Edm.Int32,
        'encryptionAlgorithm': Edm.String,
        'encryptedData': Edm.Binary,
    }
    rels = [

    ]


class DpapiData(object):
    props = {
        'objectId': Edm.String,
        'keyData': Edm.Binary,
    }
    rels = [

    ]


class SecuredEncryptedData(object):
    props = {
        'objectId': Edm.String,
        'shardId': Edm.Int32,
        'version': Edm.Int32,
        'encryptionAlgorithm': Edm.String,
        'encryptedData': Edm.Binary,
    }
    rels = [

    ]


class ServiceInfo(DirectoryObject):
    props = {
        'serviceInstance': Edm.String,
        'version': Edm.Int32,
        'serviceElements': Collection,
    }
    rels = [

    ]


class ServicePrincipal(DirectoryObject):
    props = {
        'accountEnabled': Edm.Boolean,
        'addIns': Collection,
        'alternativeNames': Collection,
        'appBranding': AppBranding,
        'appCategory': Edm.String,
        'appData': Edm.String,
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'applicationTemplateId': Edm.String,
        'appMetadata': AppMetadata,
        'appOwnerTenantId': Edm.Guid,
        'appRoleAssignmentRequired': Edm.Boolean,
        'appRoles': Collection,
        'authenticationPolicy': ServicePrincipalAuthenticationPolicy,
        'displayName': Edm.String,
        'errorUrl': Edm.String,
        'homepage': Edm.String,
        'informationalUrls': InformationalUrl,
        'keyCredentials': Collection,
        'logoutUrl': Edm.String,
        'managedIdentityResourceId': Edm.String,
        'microsoftFirstParty': Edm.Boolean,
        'notificationEmailAddresses': Collection,
        'oauth2Permissions': Collection,
        'passwordCredentials': Collection,
        'preferredSingleSignOnMode': Edm.String,
        'preferredTokenSigningKeyEndDateTime': Edm.DateTime,
        'preferredTokenSigningKeyThumbprint': Edm.String,
        'publisherName': Edm.String,
        'replyUrls': Collection,
        'samlMetadataUrl': Edm.String,
        'samlSingleSignOnSettings': SamlSingleSignOnSettings,
        'servicePrincipalNames': Collection,
        'tags': Collection,
        'tokenEncryptionKeyId': Edm.Guid,
        'servicePrincipalType': Edm.String,
        'useCustomTokenSigningKey': Edm.Boolean,
        'verifiedPublisher': VerifiedPublisher,
    }
    rels = [
        'appRoleAssignedTo',
        'appRoleAssignments',
        'defaultAdministrativeUnitScope',
        'defaultPolicy',
        'extensionProperties',
        'oauth2PermissionGrants',
        'securedExternalData',
        'serviceEndpoints',
    ]


class StubDirectoryObject(DirectoryObject):
    props = {
        'displayName': Edm.String,
        'mail': Edm.String,
        'thumbnailPhoto': Edm.Stream,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class SubscribedSku(object):
    props = {
        'capabilityStatus': Edm.String,
        'consumedUnits': Edm.Int32,
        'objectId': Edm.String,
        'prepaidUnits': LicenseUnitsDetail,
        'servicePlans': Collection,
        'skuId': Edm.Guid,
        'skuPartNumber': Edm.String,
        'appliesTo': Edm.String,
    }
    rels = [

    ]


class Takeover(object):
    props = {
        'type': Edm.String,
        'sourceContextId': Edm.String,
        'targetContextId': Edm.String,
    }
    rels = [

    ]


class TenantDetail(DirectoryObject):
    props = {
        'assignedPlans': Collection,
        'authorizedServiceInstance': Collection,
        'city': Edm.String,
        'cloudRtcUserPolicies': Edm.String,
        'companyLastDirSyncTime': Edm.DateTime,
        'companyTags': Collection,
        'compassEnabled': Edm.Boolean,
        'country': Edm.String,
        'countryLetterCode': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'displayName': Edm.String,
        'isMultipleDataLocationsForServicesEnabled': Edm.Boolean,
        'marketingNotificationEmails': Collection,
        'postalCode': Edm.String,
        'preferredLanguage': Edm.String,
        'privacyProfile': PrivacyProfile,
        'provisionedPlans': Collection,
        'provisioningErrors': Collection,
        'releaseTrack': Edm.String,
        'replicationScope': Edm.String,
        'securityComplianceNotificationMails': Collection,
        'securityComplianceNotificationPhones': Collection,
        'selfServePasswordResetPolicy': SelfServePasswordResetPolicy,
        'state': Edm.String,
        'street': Edm.String,
        'technicalNotificationMails': Collection,
        'telephoneNumber': Edm.String,
        'tenantType': Edm.String,
        'verifiedDomains': Collection,
        'windowsCredentialsEncryptionCertificate': Edm.Binary,
    }
    rels = [
        'serviceInfo',
        'trustedCAsForPasswordlessAuth',
    ]


class TrustedCAsForPasswordlessAuth(object):
    props = {
        'id': Edm.String,
        'certificateAuthorities': Collection,
    }
    rels = [

    ]


class User(DirectoryObject):
    props = {
        'acceptedAs': Edm.String,
        'acceptedOn': Edm.DateTime,
        'accountEnabled': Edm.Boolean,
        'ageGroup': Edm.String,
        'alternativeSecurityIds': Collection,
        'signInNames': Collection,
        'signInNamesInfo': Collection,
        'appMetadata': AppMetadata,
        'assignedLicenses': Collection,
        'assignedPlans': Collection,
        'city': Edm.String,
        'cloudAudioConferencingProviderInfo': Edm.String,
        'cloudMSExchRecipientDisplayType': Edm.Int32,
        'cloudMSRtcIsSipEnabled': Edm.Boolean,
        'cloudMSRtcOwnerUrn': Edm.String,
        'cloudMSRtcPolicyAssignments': Collection,
        'cloudMSRtcPool': Edm.String,
        'cloudMSRtcServiceAttributes': CloudMSRtcServiceAttributes,
        'cloudRtcUserPolicies': Edm.String,
        'cloudSecurityIdentifier': Edm.String,
        'cloudSipLine': Edm.String,
        'cloudSipProxyAddress': Edm.String,
        'companyName': Edm.String,
        'consentProvidedForMinor': Edm.String,
        'country': Edm.String,
        'createdDateTime': Edm.DateTime,
        'creationType': Edm.String,
        'department': Edm.String,
        'dirSyncEnabled': Edm.Boolean,
        'displayName': Edm.String,
        'employeeId': Edm.String,
        'extensionAttribute1': Edm.String,
        'extensionAttribute2': Edm.String,
        'extensionAttribute3': Edm.String,
        'extensionAttribute4': Edm.String,
        'extensionAttribute5': Edm.String,
        'extensionAttribute6': Edm.String,
        'extensionAttribute7': Edm.String,
        'extensionAttribute8': Edm.String,
        'extensionAttribute9': Edm.String,
        'extensionAttribute10': Edm.String,
        'extensionAttribute11': Edm.String,
        'extensionAttribute12': Edm.String,
        'extensionAttribute13': Edm.String,
        'extensionAttribute14': Edm.String,
        'extensionAttribute15': Edm.String,
        'facsimileTelephoneNumber': Edm.String,
        'givenName': Edm.String,
        'hasOnPremisesShadow': Edm.Boolean,
        'immutableId': Edm.String,
        'invitedAsMail': Edm.String,
        'invitedOn': Edm.DateTime,
        'inviteReplyUrl': Collection,
        'inviteResources': Collection,
        'inviteTicket': Collection,
        'isCompromised': Edm.Boolean,
        'isResourceAccount': Edm.Boolean,
        'jobTitle': Edm.String,
        'jrnlProxyAddress': Edm.String,
        'lastDirSyncTime': Edm.DateTime,
        'lastPasswordChangeDateTime': Edm.DateTime,
        'legalAgeGroupClassification': Edm.String,
        'mail': Edm.String,
        'mailNickname': Edm.String,
        'mobile': Edm.String,
        'msExchRecipientTypeDetails': Edm.Int64,
        'msExchRemoteRecipientType': Edm.Int64,
        'msExchMailboxGuid': Edm.Guid,
        'netId': Edm.String,
        'onPremisesDistinguishedName': Edm.String,
        'onPremisesPasswordChangeTimestamp': Edm.DateTime,
        'onPremisesSecurityIdentifier': Edm.String,
        'onPremisesUserPrincipalName': Edm.String,
        'otherMails': Collection,
        'passwordPolicies': Edm.String,
        'passwordProfile': PasswordProfile,
        'physicalDeliveryOfficeName': Edm.String,
        'postalCode': Edm.String,
        'preferredDataLocation': Edm.String,
        'preferredLanguage': Edm.String,
        'primarySMTPAddress': Edm.String,
        'provisionedPlans': Collection,
        'provisioningErrors': Collection,
        'proxyAddresses': Collection,
        'refreshTokensValidFromDateTime': Edm.DateTime,
        'releaseTrack': Edm.String,
        'searchableDeviceKey': Collection,
        'selfServePasswordResetData': SelfServePasswordResetData,
        'shadowAlias': Edm.String,
        'shadowDisplayName': Edm.String,
        'shadowLegacyExchangeDN': Edm.String,
        'shadowMail': Edm.String,
        'shadowMobile': Edm.String,
        'shadowOtherMobile': Collection,
        'shadowProxyAddresses': Collection,
        'shadowTargetAddress': Edm.String,
        'shadowUserPrincipalName': Edm.String,
        'showInAddressList': Edm.Boolean,
        'sipProxyAddress': Edm.String,
        'smtpAddresses': Collection,
        'state': Edm.String,
        'streetAddress': Edm.String,
        'surname': Edm.String,
        'telephoneNumber': Edm.String,
        'thumbnailPhoto': Edm.Stream,
        'usageLocation': Edm.String,
        'userPrincipalName': Edm.String,
        'userState': Edm.String,
        'userStateChangedOn': Edm.DateTime,
        'userType': Edm.String,
        'strongAuthenticationDetail': StrongAuthenticationDetail,
        'windowsInformationProtectionKey': Collection,
    }
    rels = [
        'assistant',
        'acceptMessagesOnlyFrom',
        'acceptMessagesOnlyFromGroup',
        'appRoleAssignments',
        'bypassModerationFrom',
        'bypassModerationFromGroup',
        'cloudMSExchDelegates',
        'cloudMSExchTeamMailboxOwners',
        'cloudPublicDelegates',
        'deviceForResourceAccount',
        'eligibleMemberOf',
        'forwardingAddress',
        'invitedBy',
        'invitedUsers',
        'licenseDetails',
        'moderatedBy',
        'oauth2PermissionGrants',
        'ownedDevices',
        'pendingMemberOf',
        'registeredDevices',
        'rejectMessagesFrom',
        'rejectMessagesFromGroup',
        'securedExternalData',
        'dpapiEncryptionKeys',
        'securedDpapiEncryptionKeys',
        'serviceInfo',
        'scopedAdministratorOf',
    ]

