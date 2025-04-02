from roadtools.roadlib.metadef.basetypes import Edm, Collection
from roadtools.roadlib.metadef.complextypes_msgraph import *


class entity(object):
    props = {
        'id': Edm.String,
    }
    rels = [

    ]

class DirectoryObject(object):
    props = {
        'deletionTimestamp': Edm.DateTime,
        'id': Edm.String,
        'objectType': Edm.String,
    }
    rels = [
        'createdOnBehalfOf',
        'createdObjects',
        'directReports',
        'manager',
        'members',
        'memberOf',
        'ownedObjects',
        'owners',
        'transitiveMemberOf',
        'transitiveMembers',
    ]

class AdministrativeUnit(DirectoryObject):
    props = {
        'deletionTimestamp': Edm.DateTime,
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
        'isMemberManagementRestricted': Edm.Boolean,
        'membershipRule': Edm.String,
        'membershipRuleProcessingState': Edm.String,
        'membershipType': Edm.String,
        'visibility': Edm.String,
    }
    rels = [
        'members',
        'scopedRoleMembers',
        'extensions',
    ]

class Application(DirectoryObject):
    props = {
        'addIns': Collection,
        'api': apiApplication,
        'appId': Edm.String,
        'appRoles': Collection,
        'applicationTemplateId': Edm.String,
        'certification': Certification,
        'createdDateTime': Edm.DateTime,
        'defaultRedirectUri': Edm.String,
        'deletedDateTime': Edm.DateTime,
        'description': Edm.String,
        'displayName': Edm.String,
        'groupMembershipClaims': Edm.String,
        'id': Edm.String,
        'identifierUris': Collection,
        'info': InformationalUrl,
        'isDeviceOnlyAuthSupported': Edm.Boolean,
        'isFallbackPublicClient': Edm.Boolean,
        'keyCredentials': Collection,
        'nativeAuthenticationApisEnabled': Edm.Boolean,
        'notes': Edm.String,
        'optionalClaims': OptionalClaims,
        'parentalControlSettings': parentalControlSettings,
        'passwordCredentials': Collection,
        'publicClient': publicClientApplication,
        'publisherDomain': Edm.String,
        'requestSignatureVerification': Edm.Boolean,
        'requiredResourceAccess': Collection,
        'samlMetadataUrl': Edm.String,
        'serviceManagementReference': Edm.String,
        'servicePrincipalLockConfiguration': servicePrincipalLockConfiguration,
        'signInAudience': Edm.String,
        'spa': spaApplication,
        'tags': Collection,
        'tokenEncryptionKeyId': Edm.String,
        'uniqueName': Edm.String,
        'verifiedPublisher': VerifiedPublisher,
        'web': webApplication,
    }
    rels = [
        'appManagementPolicies',
        'createdOnBehalfOf',
        'extensionProperties',
        'federatedIdentityCredentials',
        'owners',
        'synchronization',
    ]

class ApplicationRef(object):
    props = {
        'appCategory': Edm.String,
        'appContextId': Edm.Guid,
        'appData': Edm.String,
        'appId': Edm.String,
        'appRoles': Collection,
        'availableToOtherTenants': Edm.Boolean,
        'certification': Certification,
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
        'verifiedPublisher': VerifiedPublisher,
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
        'deletionTimestamp': Edm.DateTime,
        'appRoleId': Edm.Stream,
    }
    rels = [

    ]

class AppRoleAssignmentto(DirectoryObject):
    props = {
        'createdDateTime': Edm.DateTime,
        'id': Edm.Guid,
        'principalDisplayName': Edm.String,
        'principalId': Edm.Guid,
        'principalType': Edm.String,
        'resourceDisplayName': Edm.String,
        'resourceId': Edm.Guid,
        'deletedDateTime': Edm.DateTime,
        'appRoleId': Edm.Stream,
    }
    rels = [

    ]

class AuthorizationPolicy(object):
    props = {
        'allowEmailVerifiedUsersToJoinOrganization': Edm.Boolean,
        'allowInvitesFrom': Edm.String,
        'allowUserConsentForRiskyApps': Edm.Boolean,
        'allowedToSignUpEmailBasedSubscriptions': Edm.Boolean,
        'allowedToUseSSPR': Edm.Boolean,
        'blockMsolPowerShell': Edm.Boolean,
        'defaultUserRolePermissions': DefaultUserRolePermissions,
        'description': Edm.String,
        'displayName': Edm.String,
        'guestUserRoleId': Edm.Guid,
        'id': Edm.String,
        # 'enabledPreviewFeatures': Collection,
        # 'permissionGrantPolicyIdsAssignedToDefaultUserRole': Collection,
    }
    rels = [

    ]

class CertificateBasedDeviceAuthConfiguration(DirectoryObject):
    props = {
        'certificateAuthorities': Collection,
        'displayName': Edm.String,
        'tlsClientAuthParameter': Edm.String,
    }
    rels = [

    ]

class CustomSecurityAttributeDefinition(object):
    props = {
        'advancedOptions': Collection,
        'attributeSet': Edm.String,
        'description': Edm.String,
        'id': Edm.String,
        'isCollection': Edm.Boolean,
        'isSearchable': Edm.Boolean,
        'name': Edm.String,
        'status': Edm.String,
        'type': Edm.String,
        'usePreDefinedValuesOnly': Edm.Boolean,
    }
    rels = [
        'allowedValues',
    ]

class ConditionalAccessPolicy(DirectoryObject):
    props = {
        'definition': Collection,
        'displayName': Edm.String,
        'isOrganizationDefault': Edm.Boolean,
        'policyIdentifier': Edm.String,
    }
    rels = [
        'appliesTo',
    ]

class outlookItem(entity):
    props = {
        'categories': Collection,
        'changeKey': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]

class Contact(outlookItem):
    props = {
        "assistantName": Edm.String,
        "birthday": Edm.DateTimeOffset,
        "businessAddress": Edm.String,
        "businessHomePage": Edm.String,
        "businessPhones": Collection,
        "categories": Collection,
        "changeKey": Edm.String,
        "children": Collection,
        "companyName": Edm.String,
        "createdDateTime": Edm.DateTime,
        "department": Edm.String,
        "displayName": Edm.String,
        "emailAddresses": Edm.String,
        "fileAs": Edm.String,
        "generation": Edm.String,
        "givenName": Edm.String,
        "homeAddress": Edm.String,
        "homePhones": Collection,
        "id": Edm.String,
        "imAddresses": Collection,
        "initials": Edm.String,
        "jobTitle": Edm.String,
        "lastModifiedDateTime": Edm.DateTime,
        "manager": Edm.String,
        "middleName": Edm.String,
        "mobilePhone": Edm.String,
        "nickName": Edm.String,
        "officeLocation": Edm.String,
        "otherAddress": Edm.String,
        "parentFolderId": Edm.String,
        "personalNotes": Edm.String,
        "photo": Edm.String,
        "profession": Edm.String,
        "spouseName": Edm.String,
        "surname": Edm.String,
        "title": Edm.String,
        "yomiCompanyName": Edm.String,
        "yomiGivenName": Edm.String,
        "yomiSurname": Edm.String
        }
    rels = [
        'extensions',
        'multiValueExtendedProperties',
        'photo',
        'singleValueExtendedProperties',
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
        'approximateLastSignInDateTime': Edm.DateTime,
        'complianceExpirationDateTime': Edm.DateTime,
        'createdDateTime': Edm.DateTime,
        'deletedDateTime': Edm.DateTime,
        'deviceCategory': Edm.String,
        'deviceId': Edm.String,
        'deviceMetadata': Edm.String,
        'deviceOwnership': Edm.String,
        'deviceVersion': Edm.Int32,
        'displayName': Edm.String,
        'domainName': Edm.String,
        'enrollmentProfileName': Edm.String,
        'enrollmentType': Edm.String,
        'externalSourceName': Edm.String,
        'extensionAttributes': onPremisesExtensionAttributes,
        'id': Edm.String,
        'isCompliant': Edm.Boolean,
        'isManaged': Edm.Boolean,
        'isRooted': Edm.Boolean,
        'keyCredentials': Collection,
        'managementType': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'mdmAppId': Edm.String,
        'onPremisesLastSyncDateTime': Edm.DateTime,
        'onPremisesSyncEnabled': Edm.Boolean,
        'operatingSystem': Edm.String,
        'operatingSystemVersion': Edm.String,
        'organizationalUnit': Edm.String,
        'physicalIds': Collection,
        'profileType': Edm.String,
        'registrationDateTime': Edm.DateTime,
        # 'reserved1': Edm.String,
        'sourceType': Edm.String,
        'systemLabels': Collection,
        'trustType': Edm.String,
    }
    rels = [
        'extensions',
        'memberOf',
        'registeredOwners',
        'registeredUsers',
        'transitiveMemberOf',
    ]

class DeviceConfiguration(DirectoryObject):
    props = {
        'cloudPublicIssuerCertificates': Collection,
        'maximumRegistrationInactivityPeriod': Edm.Int32,
        'publicIssuerCertificates': Collection,
        'registrationQuota': Edm.Int32,
    }
    rels = [

    ]

class DeviceTemplate(DirectoryObject):
    props = {
        'certificateBasedDeviceAuthConfigurationId': Edm.Guid,
        'certificateBasedDeviceAuthConfigurationTenantId': Edm.Guid,
        'deviceAuthority': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'operatingSystem': Edm.String,
    }
    rels = [
        'deviceInstances',
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
        'deletedDateTime': Edm.DateTime,
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
        'roleDisabled': Edm.Boolean,
        'roleTemplateId': Edm.String,
    }
    rels = [
        'members',
        'scopedMembers',
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
        'displayName': Edm.String,
        'id': Edm.String,
        'templateId': Edm.String,
        'values': Collection,
    }
    rels = [

    ]

class DirectorySettingTemplate(DirectoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
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
        'directoryScopeId': Edm.String,
        'appScopeId': Edm.String,
        'createdUsing': Edm.String,
        'createdDateTime': Edm.DateTime,
        'modifiedDateTime': Edm.DateTime,
        'status': Edm.String,
        'memberType': Edm.String,
        'scheduleInfo': Collection,
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
        'classification': Edm.String,
        'createdDateTime': Edm.DateTime,
        'creationOptions': Collection,
        'deletedDateTime': Edm.DateTime,
        'description': Edm.String,
        'displayName': Edm.String,
        'expirationDateTime': Edm.DateTime,
        'groupTypes': Collection,
        'id': Edm.String,
        'isAssignableToRole': Edm.Boolean,
        'isMembershipRuleLocked': Edm.Boolean,
        'isPublic': Edm.Boolean,
        'mail': Edm.String,
        'mailEnabled': Edm.Boolean,
        'mailNickname': Edm.String,
        'membershipRule': Edm.String,
        'membershipRuleProcessingState': Edm.String,
        'onPremisesDomainName': Edm.String,
        'onPremisesLastSyncDateTime': Edm.DateTime,
        'onPremisesNetBiosName': Edm.String,
        'onPremisesProvisioningErrors': Collection,
        'onPremisesSamAccountName': Edm.String,
        'onPremisesSecurityIdentifier': Edm.String,
        'onPremisesSyncEnabled': Edm.Boolean,
        'preferredDataLocation': Edm.String,
        'preferredLanguage': Edm.String,
        'proxyAddresses': Collection,
        'renewedDateTime': Edm.DateTime,
        'resourceBehaviorOptions': Collection,
        'resourceProvisioningOptions': Collection,
        'securityEnabled': Edm.Boolean,
        'securityIdentifier': Edm.String,
        'serviceProvisioningErrors': Collection,
        'theme': Edm.String,
        'visibility': Edm.String,
    }
    rels = [
        'appRoleAssignments',
        'calendar',
        'calendarView',
        'conversations',
        'createdOnBehalfOf',
        'drive',
        'drives',
        'events',
        'extensions',
        'groupLifecyclePolicies',
        'memberOf',
        'members',
        'membersWithLicenseErrors',
        'onenote',
        'owners',
        'photo',
        'photos',
        'planner',
        'rejectedSenders',
        'settings',
        'sites',
        'team',
        'threads',
        'transitiveMemberOf',
        'transitiveMembers',
    ]

class LicenseDetail(object):
    props = {
        'id': Edm.String,
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


class NamedLocationsPolicy(DirectoryObject):
    props = {
        'appliesTo': Collection,
        'definition': Collection,
        'displayName': Edm.String,
        'isOrganizationDefault': Edm.Boolean,
        'policyIdentifier': Edm.String,
    }
    rels = [

    ]

class OAuth2PermissionGrant(object):
    props = {
        'clientId': Edm.String,
        'consentType': Edm.String,
        # 'expiryTime': Edm.DateTime,
        'id': Edm.String,
        'principalId': Edm.String,
        'resourceId': Edm.String,
        'scope': Edm.String,
        # 'startTime': Edm.DateTime,
    }
    rels = [

    ]

class PermissionGrantPolicy(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
    }
    rels = [
        'excludes',
        'includes',
    ]

class Policy(DirectoryObject):
    props = {
        'conditions': Collection,
        'createdDateTime': Edm.DateTime,
        'displayName': Edm.String,
        'grantControls': Collection,
        'id': Edm.String,
        'modifiedDateTime': Edm.DateTime,
        'sessionControls': Collection,
        'state': Edm.String,
    }
    rels = [
    ]

class RoleAssignment(object):
    props = {
        'id': Edm.String,
        'principalId': Edm.String,
        'directoryScopeId': Collection,
        'roleDefinitionId': Edm.String,
    }
    rels = [
        'directoryScope',
        'principal',
        'roleDefinition',
    ]

# https://learn.microsoft.com/en-us/graph/api/resources/unifiedroledefinition?view=graph-rest-1.0
class RoleDefinition(DirectoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
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

# https://learn.microsoft.com/en-us/graph/api/resources/intune-rbac-roledefinition?view=graph-rest-1.0#relationships
# class RoleDefinition(DirectoryObject):
#     props = {
#         'description': Edm.String,
#         'displayName': Edm.String,
#         'id': Edm.String,
#         'isBuiltIn': Edm.Boolean,
#         'roleAssignments': Collection,
#         'templateId': Edm.String,
#     }
#     rels = [
#         'inheritsPermissionsFrom',
#     ]

class ScopedRoleMembership(object):
    props = {
        'administrativeUnitObjectId': Edm.Guid,
        'id': Edm.String,
        'roleMemberInfo': IdentityInfo,
        'roleObjectId': Edm.Guid,
    }
    rels = [

    ]

class SecuredExternalData(object):
    props = {
        'encryptedData': Edm.Binary,
        'encryptionAlgorithm': Edm.String,
        'partnerId': Edm.String,
        'shardId': Edm.Int32,
        'version': Edm.Int32,
    }
    rels = [

    ]

class DpapiData(object):
    props = {
        'id': Edm.String,
        'keyData': Edm.Binary,
    }
    rels = [

    ]

class SecuredEncryptedData(object):
    props = {
        'encryptedData': Edm.Binary,
        'encryptionAlgorithm': Edm.String,
        'id': Edm.String,
        'shardId': Edm.Int32,
        'version': Edm.Int32,
    }
    rels = [

    ]

class ServiceInfo(DirectoryObject):
    props = {
        'serviceElements': Collection,
        'serviceInstance': Edm.String,
        'version': Edm.Int32,
    }
    rels = [

    ]

class ServicePrincipal(DirectoryObject):
    props = {
        'accountEnabled': Edm.Boolean,
        'addIns': Collection,
        'alternativeNames': Collection,
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'appOwnerOrganizationId': Edm.Guid,
        'appRoleAssignmentRequired': Edm.Boolean,
        'appRoles': Collection,
        'createdDateTime': Edm.DateTime,
        'deletedDateTime': Edm.DateTime,
        'disabledByMicrosoftStatus': Edm.String,
        'displayName': Edm.String,
        'homepage': Edm.String,
        'id': Edm.String,
        'info': informationalUrl,
        'keyCredentials': Collection,
        'loginUrl': Edm.String,
        'logoutUrl': Edm.String,
        'notes': Edm.String,
        'notificationEmailAddresses': Collection,
        'oauth2Permissions': OAuth2Permission,
        'passwordCredentials': Collection,
        'preferredSingleSignOnMode': Edm.String,
        'preferredTokenSigningKeyThumbprint': Edm.String,
        'replyUrls': Collection,
        'samlSingleSignOnSettings': SamlSingleSignOnSettings,
        'servicePrincipalNames': Collection,
        'servicePrincipalType': Edm.String,
        'signInAudience': Edm.String,
        'tags': Collection,
        'tokenEncryptionKeyId': Edm.Guid,
        'useCustomTokenSigningKey': Edm.Boolean,
        'verifiedPublisher': VerifiedPublisher,
        'resourceSpecificApplicationPermissions': Collection,
    }
    rels = [
        'appRoleAssignedTo',
        'appRoleAssignments',
        'claimsMappingPolicies',
        'createdObjects',
        'federatedIdentityCredentials',
        'homeRealmDiscoveryPolicies',
        'memberOf',
        'oauth2PermissionGrants',
        'ownedObjects',
        'owners',
        'remoteDesktopSecurityConfiguration',
        'synchronization',
        'tokenIssuancePolicies',
        'tokenLifetimePolicies',
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
        'accountId': Edm.Guid,
        'accountName': Edm.String,
        'appliesTo': Edm.String,
        'capabilityStatus': Edm.String,
        'consumedUnits': Edm.Int32,
        'id': Edm.String,
        'overageUnits': LicenseUnitsDetail,
        'prepaidUnits': LicenseUnitsDetail,
        'selfServiceSignupUnits': LicenseUnitsDetail,
        'servicePlans': Collection,
        'skuId': Edm.Guid,
        'skuPartNumber': Edm.String,
        'subscriptionIds': Collection,
        'trialUnits': LicenseUnitsDetail,
    }
    rels = [

    ]

class Takeover(object):
    props = {
        'sourceContextId': Edm.String,
        'targetContextId': Edm.String,
        'type': Edm.String,
    }
    rels = [

    ]

class TenantDetail(DirectoryObject):
    props = {
        'assignedPlans': Collection,
        'city': Edm.String,
        'country': Edm.String,
        'countryLetterCode': Edm.String,
        'createdDateTime': Edm.DateTime,
        'defaultUsageLocation': Edm.String,
        'deletedDateTime': Edm.DateTime,
        'directorySizeQuota': directorySizeQuota,
        'displayName': Edm.String,
        'id': Edm.String,
        'isMultipleDataLocationsForServicesEnabled': Edm.Boolean,
        'marketingNotificationEmails': Collection,
        'onPremisesLastSyncDateTime': Edm.DateTime,
        'onPremisesSyncEnabled': Edm.Boolean,
        'onPremisesSyncStatus': Collection,
        'partnerTenantType': partnerTenantType,
        'postalCode': Edm.String,
        'preferredLanguage': Edm.String,
        'privacyProfile': PrivacyProfile,
        'provisionedPlans': Collection,
        'securityComplianceNotificationMails': Collection,
        'securityComplianceNotificationPhones': Collection,
        'state': Edm.String,
        'street': Edm.String,
        'technicalNotificationMails': Collection,
        'telephoneNumber': Edm.String,
        'tenantType': Edm.String,
        'verifiedDomains': Collection,
        'businessPhones': Collection,
    }
    rels = [
        'branding',
        'certificateBasedAuthConfiguration',
        'extensions',
    ]

class TrustedCAsForPasswordlessAuth(object):
    props = {
        'certificateAuthorities': Collection,
        'id': Edm.String,
    }
    rels = [

    ]

class User(DirectoryObject):
    props = {
        'businessPhones': Collection,
        'displayName': Edm.String,
        'givenName': Edm.String,
        'id': Edm.String,
        'jobTitle': Edm.String,
        'mail': Edm.String,
        'mobilePhone': Edm.String,
        'officeLocation': Edm.String,
        'preferredLanguage': Edm.String,
        'surname': Edm.String,
        'userPrincipalName': Edm.String,
        'isAdmin': Edm.Boolean,
        'isMfaCapable': Edm.Boolean,
        'isMfaRegistered': Edm.Boolean,
        'isPasswordlessCapable': Edm.Boolean,
        'isSsprCapable': Edm.Boolean,
        'isSsprEnabled': Edm.Boolean,
        'isSsprRegistered' : Edm.Boolean,
        'isSystemPreferredAuthenticationMethodEnabled': Edm.Boolean,
        'lastUpdatedDate': Edm.DateTime,
        'methodsRegistered': Collection,
        'systemPreferredAuthenticationMethods' : Collection,
        'userPreferredMethodForSecondaryAuthentication': Edm.String,
        'userType': Edm.String,
    }
    rels = [
        'agreementAcceptances',
        'appRoleAssignments',
        'authentication',
        'calendar',
        'calendarGroups',
        'calendars ',
        'calendarView',
        'contactFolders',
        'contacts',
        'createdObjects',
        'directReports ',
        'drive ',
        'drives',
        'events',
        'extensions',
        'inferenceClassification ',
        'insights',
        'licenseDetails',
        'mailFolders ',
        'manager ',
        'memberOf',
        'messages',
        'onenote ',
        'onlineMeetings',
        'outlook ',
        'ownedDevices',
        'ownedObjects',
        'people',
        'permissionGrants',
        'photo ',
        'photos',
        'planner ',
        'registeredDevices ',
        'solutions ',
        'sponsors',
        'teamwork',
        'todo',
        'transitiveMemberOf',
    ]

class User_MFA(object):
    props = {
        'id': Edm.String,
        'isAdmin': Edm.Boolean,
        'isMfaCapable': Edm.Boolean,
        'isMfaRegistered': Edm.Boolean,
        'isPasswordlessCapable': Edm.Boolean,
        'isSsprCapable': Edm.Boolean,
        'isSsprEnabled': Edm.Boolean,
        'isSsprRegistered' : Edm.Boolean,
        'isSystemPreferredAuthenticationMethodEnabled': Edm.Boolean,
        'lastUpdatedDate': Edm.DateTime,
        'methodsRegistered': Collection,
        'systemPreferredAuthenticationMethods' : Collection,
        'userDisplayName': Edm.String,
        'userPreferredMethodForSecondaryAuthentication': Edm.String,
        'userPrincipalName': Edm.String,
        'userType': Edm.String,
    }

class PermissionGrantConditionSet(object):
    props = {
        'certifiedClientApplicationsOnly': Edm.Boolean,
        'clientApplicationIds': Collection,
        'clientApplicationPublisherIds': Collection,
        'clientApplicationTenantIds': Collection,
        'clientApplicationsFromVerifiedPublisherOnly': Edm.Boolean,
        'id': Edm.String,
        'permissionClassification': Edm.String,
        'permissionType': Edm.String,
        'permissions': Collection,
        'resourceApplication': Edm.String,
    }
    rels = [

    ]

class AllowedValue(object):
    props = {
        'id': Edm.String,
        'isActive': Edm.Boolean,
    }
    rels = [

    ]
