from roadtools.roadlib.metadef.basetypes import Edm, Collection

class AccessPass(object):
    props = {
        'creationTime': Edm.DateTime,
        'startTime': Edm.DateTime,
        'endTime': Edm.DateTime,
        'passId': Edm.Guid,
        'accessPassCode': Edm.String,
    }


class AlternativeSecurityId(object):
    props = {
        'type': Edm.Int32,
        'identityProvider': Edm.String,
        'key': Edm.Binary,
    }


class AppAddress(object):
    props = {
        'address': Edm.String,
        'addressType': Edm.String,
    }


class AppBranding(object):
    props = {
        'fontColor': Edm.String,
        'logoBackgroundColor': Edm.String,
    }


class AppMetadataEntry(object):
    props = {
        'key': Edm.String,
        'value': Edm.Binary,
    }


class AppRole(object):
    props = {
        'allowedMemberTypes': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'isEnabled': Edm.Boolean,
        'lang': Edm.String,
        'origin': Edm.String,
        'value': Edm.String,
    }


class AssignedLabel(object):
    props = {
        'labelId': Edm.String,
        'displayName': Edm.String,
    }


class AssignedLicense(object):
    props = {
        'disabledPlans': Collection,
        'skuId': Edm.Guid,
    }


class AssignedPlan(object):
    props = {
        'assignedTimestamp': Edm.DateTime,
        'capabilityStatus': Edm.String,
        'service': Edm.String,
        'servicePlanId': Edm.Guid,
    }


class BitLockerKey(object):
    props = {
        'creationTime': Edm.DateTime,
        'customKeyInformation': Edm.Binary,
        'keyIdentifier': Edm.Guid,
        'keyMaterial': Edm.Binary,
    }


class CertificateAuthorityInformation(object):
    props = {
        'authorityType': Edm.String,
        'crlDistributionPoint': Edm.String,
        'deltaCrlDistributionPoint': Edm.String,
        'trustedCertificate': Edm.Binary,
        'trustedIssuer': Edm.String,
        'trustedIssuerSki': Edm.String,
    }


class CloudMSRtcServiceAttributes(object):
    props = {
        'applicationOptions': Edm.Int32,
        'deploymentLocator': Edm.String,
        'hideFromAddressLists': Edm.Boolean,
        'optionFlags': Edm.Int32,
    }


class CompliantApplication(object):
    props = {
        'mamEnrollmentId': Edm.Guid,
        'expirationTime': Edm.DateTime,
    }


class CredentialList(object):
    props = {
        'passwords': Collection,
        'userName': Edm.String,
    }


class DeviceKey(object):
    props = {
        'creationTime': Edm.DateTime,
        'customKeyInformation': Edm.Binary,
        'keyIdentifier': Edm.Guid,
        'keyMaterial': Edm.Binary,
        'usage': Edm.String,
    }


class SecuredEncryptionKey(object):
    props = {
        'partnerId': Edm.String,
        'shardId': Edm.Int32,
        'version': Edm.Int32,
        'publicKey': Edm.Binary,
    }


class GuestTenantDetail(object):
    props = {
        'tenantId': Edm.String,
        'country': Edm.String,
        'countryCode': Edm.String,
        'defaultDomain': Edm.String,
        'displayName': Edm.String,
        'domains': Collection,
        'isHomeTenant': Edm.Boolean,
        'tenantType': Edm.String,
        'tenantBrandingLogoUrl': Edm.String,
    }


class IdentityInfo(object):
    props = {
        'objectId': Edm.Guid,
        'displayName': Edm.String,
        'userPrincipalName': Edm.String,
    }


class KeyCredential(object):
    props = {
        'customKeyIdentifier': Edm.Binary,
        'endDate': Edm.DateTime,
        'keyId': Edm.Guid,
        'startDate': Edm.DateTime,
        'type': Edm.String,
        'usage': Edm.String,
        'value': Edm.Binary,
    }


class LicenseAssignment(object):
    props = {
        'accountId': Edm.Guid,
        'skuId': Edm.Guid,
    }


class KeyValue(object):
    props = {
        'key': Edm.String,
        'value': Edm.String,
    }


class InvitationTicket(object):
    props = {
        'type': Edm.String,
        'ticket': Edm.String,
    }


class LicenseUnitsDetail(object):
    props = {
        'enabled': Edm.Int32,
        'suspended': Edm.Int32,
        'warning': Edm.Int32,
    }


class PrivacyProfile(object):
    props = {
        'contactEmail': Edm.String,
        'statementUrl': Edm.String,
    }


class PermissionConditionSet(object):
    props = {
        'resourceApplication': Edm.String,
        'includeAllPermissions': Edm.Boolean,
        'includeSpecificPermissions': Collection,
    }


class ClientAppConditionSet(object):
    props = {
        'includeAllClientApplications': Edm.Boolean,
        'includeSpecificClientApplications': Collection,
    }


class SettingValue(object):
    props = {
        'name': Edm.String,
        'value': Edm.String,
    }


class SettingTemplateValue(object):
    props = {
        'name': Edm.String,
        'type': Edm.String,
        'defaultValue': Edm.String,
        'description': Edm.String,
    }


class SignInNamesInfo(object):
    props = {
        'type': Edm.String,
        'value': Edm.String,
    }


class OAuth2Permission(object):
    props = {
        'adminConsentDescription': Edm.String,
        'adminConsentDisplayName': Edm.String,
        'id': Edm.Guid,
        'isEnabled': Edm.Boolean,
        'lang': Edm.String,
        'origin': Edm.String,
        'type': Edm.String,
        'userConsentDescription': Edm.String,
        'userConsentDisplayName': Edm.String,
        'value': Edm.String,
    }


class PasswordCredential(object):
    props = {
        'customKeyIdentifier': Edm.Binary,
        'endDate': Edm.DateTime,
        'keyId': Edm.Guid,
        'startDate': Edm.DateTime,
        'value': Edm.String,
    }


class PasswordProfile(object):
    props = {
        'password': Edm.String,
        'forceChangePasswordNextLogin': Edm.Boolean,
        'enforceChangePasswordPolicy': Edm.Boolean,
    }


class ProvisionedPlan(object):
    props = {
        'capabilityStatus': Edm.String,
        'provisioningStatus': Edm.String,
        'service': Edm.String,
    }


class ProvisioningError(object):
    props = {
        'errorDetail': Edm.String,
        'resolved': Edm.Boolean,
        'service': Edm.String,
        'timestamp': Edm.DateTime,
    }


class ResourceAccess(object):
    props = {
        'id': Edm.Guid,
        'type': Edm.String,
    }


class ResourceAction(object):
    props = {
        'allowedResourceActions': Collection,
    }


class DynamicResourceAccess(object):
    props = {
        'appIdentifier': Edm.String,
        'scopes': Collection,
        'appRoles': Collection,
    }


class SearchableDeviceKey(object):
    props = {
        'usage': Edm.String,
        'keyIdentifier': Edm.String,
        'keyMaterial': Edm.Binary,
        'creationTime': Edm.DateTime,
        'deviceId': Edm.Guid,
        'customKeyInformation': Edm.Binary,
        'fidoAaGuid': Edm.String,
        'fidoAuthenticatorVersion': Edm.String,
        'fidoAttestationCertificates': Collection,
    }


class ServicePlanInfo(object):
    props = {
        'servicePlanId': Edm.Guid,
        'servicePlanName': Edm.String,
        'provisioningStatus': Edm.String,
        'appliesTo': Edm.String,
    }


class ServiceOriginatedResource(object):
    props = {
        'capability': Edm.String,
        'isLicenseReconciliationNeeded': Edm.Boolean,
        'serviceInstance': Edm.String,
        'servicePlanId': Edm.Guid,
    }


class SelfServePasswordResetData(object):
    props = {
        'alternateAuthenticationPhoneRegisteredTime': Edm.DateTime,
        'alternateEmailRegisteredTime': Edm.DateTime,
        'authenticationEmailRegisteredTime': Edm.DateTime,
        'authenticationPhoneRegisteredTime': Edm.DateTime,
        'deferralCount': Edm.Int32,
        'deferredTime': Edm.DateTime,
        'lastRegisteredTime': Edm.DateTime,
        'mobilePhoneRegisteredTime': Edm.DateTime,
        'reinforceAfterTime': Edm.DateTime,
        'securityAnswersRegisteredTime': Edm.DateTime,
    }


class SelfServePasswordResetPolicy(object):
    props = {
        'enforcedRegistrationEnablement': Edm.String,
        'enforcedRegistrationIntervalInDays': Edm.Int32,
    }


class ServicePrincipalAuthenticationPolicy(object):
    props = {
        'defaultPolicy': Edm.String,
        'allowedPolicies': Collection,
    }


class SigningCertificateUpdateStatus(object):
    props = {
        'result': Edm.Int32,
        'lastRunAt': Edm.DateTime,
    }


class SamlSingleSignOnSettings(object):
    props = {
        'relayState': Edm.String,
    }


class EncryptedSecretHash(object):
    props = {
        'encryptedHashValue': Edm.Binary,
        'version': Edm.Int32,
        'hashAlgorithm': Edm.String,
        'hashSalt': Edm.Binary,
        'iterationCount': Edm.Int32,
        'creationTime': Edm.DateTime,
    }


class StrongAuthenticationMethod(object):
    props = {
        'methodType': Edm.String,
        'isDefault': Edm.Boolean,
    }


class StrongAuthenticationRequirement(object):
    props = {
        'relyingParty': Edm.String,
        'state': Edm.String,
        'rememberDevicesNotIssuedBefore': Edm.DateTime,
    }


class StrongAuthenticationPhoneAppDetail(object):
    props = {
        'authenticationType': Edm.String,
        'deviceToken': Edm.String,
        'deviceName': Edm.String,
        'deviceTag': Edm.String,
        'oathSecretKey': Edm.String,
        'oathTokenTimeDrift': Edm.Int32,
        'phoneAppVersion': Edm.String,
        'notificationType': Edm.String,
    }


class StrongAuthenticationUserDetail(object):
    props = {
        'alternativePhoneNumber': Edm.String,
        'email': Edm.String,
        'phoneNumber': Edm.String,
    }


class VerifiedDomain(object):
    props = {
        'capabilities': Edm.String,
        'default': Edm.Boolean,
        'id': Edm.String,
        'initial': Edm.Boolean,
        'name': Edm.String,
        'type': Edm.String,
    }


class TrustedCertificateSubject(object):
    props = {
        'authorityId': Edm.Guid,
        'subjectName': Edm.String,
    }


class InformationalUrl(object):
    props = {
        'termsOfService': Edm.String,
        'support': Edm.String,
        'privacy': Edm.String,
        'marketing': Edm.String,
    }


class OptionalClaim(object):
    props = {
        'name': Edm.String,
        'source': Edm.String,
        'essential': Edm.Boolean,
        'additionalProperties': Collection,
    }


class ParentalControlSettings(object):
    props = {
        'countriesBlockedForMinors': Collection,
        'legalAgeGroupRule': Edm.String,
    }


class AuthorizationAction(object):
    props = {
        'id': Edm.String,
    }


class AuthorizationDecision(object):
    props = {
        'actionId': Edm.String,
        'accessDecision': Edm.String,
    }


class AuthorizationResource(object):
    props = {
        'scope': Edm.String,
    }


class AuthorizationSubject(object):
    props = {
        'appId': Edm.String,
        'authorizationFlow': Edm.String,
        'userId': Edm.String,
    }


class RoleAssignmentDetail(object):
    props = {
        'isDirect': Edm.Boolean,
        'principalType': Edm.String,
        'principalId': Edm.String,
        'principalDisplayName': Edm.String,
        'roleAssignmentId': Edm.String,
    }


class VerifiedPublisher(object):
    props = {
        'displayName': Edm.String,
        'verifiedPublisherId': Edm.String,
        'addedDateTime': Edm.DateTime,
    }


class AddIn(object):
    props = {
        'id': Edm.Guid,
        'type': Edm.String,
        'properties': Collection,
    }


class AppMetadata(object):
    props = {
        'version': Edm.Int32,
        'data': Collection,
    }


class RolePermission(object):
    props = {
        'resourceActions': ResourceAction,
        'condition': Edm.String,
    }


class DomainFederationSettings(object):
    props = {
        'activeLogOnUri': Edm.String,
        'defaultInteractiveAuthenticationMethod': Edm.String,
        'federationBrandName': Edm.String,
        'issuerUri': Edm.String,
        'isExternal': Edm.Boolean,
        'logOffUri': Edm.String,
        'metadataExchangeUri': Edm.String,
        'nextSigningCertificate': Edm.String,
        'openIdConnectDiscoveryEndpoint': Edm.String,
        'passiveLogOnUri': Edm.String,
        'passwordChangeUri': Edm.String,
        'passwordResetUri': Edm.String,
        'preferredAuthenticationProtocol': Edm.String,
        'promptLoginBehavior': Edm.String,
        'signingCertificate': Edm.String,
        'signingCertificateUpdateStatus': SigningCertificateUpdateStatus,
        'supportsMfa': Edm.Boolean,
    }


class PermissionGrantConditionSet(object):
    props = {
        'permissionClassification': Edm.String,
        'permissionType': Edm.String,
        'permissions': PermissionConditionSet,
        'clientApplications': ClientAppConditionSet,
    }


class RequiredResourceAccess(object):
    props = {
        'resourceAppId': Edm.String,
        'resourceAccess': Collection,
    }


class StrongAuthenticationDetail(object):
    props = {
        'encryptedPinHash': EncryptedSecretHash,
        'encryptedPinHashHistory': Edm.Binary,
        'methods': Collection,
        'requirements': Collection,
        'phoneAppDetails': Collection,
        'proofupTime': Edm.Int64,
        'verificationDetail': StrongAuthenticationUserDetail,
    }


class OptionalClaims(object):
    props = {
        'idToken': Collection,
        'accessToken': Collection,
        'saml2Token': Collection,
    }


class ResourceAuthorizationDecision(object):
    props = {
        'resourceScope': Edm.String,
        'authorizationDecisions': Collection,
    }

