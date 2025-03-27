from roadtools.roadlib.metadef.basetypes import Edm, Collection
import enum

identityGovernance_customTaskExtensionOperationStatus_data = {
    'completed': 0,
    'failed': 1,
    'unknownFutureValue': 2,
}
identityGovernance_customTaskExtensionOperationStatus = enum.Enum('identityGovernance_customTaskExtensionOperationStatus', identityGovernance_customTaskExtensionOperationStatus_data)


identityGovernance_lifecycleTaskCategory_data = {
    'joiner': 1,
    'leaver': 2,
    'unknownFutureValue': 4,
    'mover': 8,
}
identityGovernance_lifecycleTaskCategory = enum.Enum('identityGovernance_lifecycleTaskCategory', identityGovernance_lifecycleTaskCategory_data)


identityGovernance_lifecycleWorkflowCategory_data = {
    'joiner': 0,
    'leaver': 1,
    'unknownFutureValue': 2,
    'mover': 3,
}
identityGovernance_lifecycleWorkflowCategory = enum.Enum('identityGovernance_lifecycleWorkflowCategory', identityGovernance_lifecycleWorkflowCategory_data)


identityGovernance_lifecycleWorkflowProcessingStatus_data = {
    'queued': 0,
    'inProgress': 1,
    'completed': 2,
    'completedWithErrors': 3,
    'canceled': 4,
    'failed': 5,
    'unknownFutureValue': 6,
}
identityGovernance_lifecycleWorkflowProcessingStatus = enum.Enum('identityGovernance_lifecycleWorkflowProcessingStatus', identityGovernance_lifecycleWorkflowProcessingStatus_data)


identityGovernance_membershipChangeType_data = {
    'add': 1,
    'remove': 2,
    'unknownFutureValue': 3,
}
identityGovernance_membershipChangeType = enum.Enum('identityGovernance_membershipChangeType', identityGovernance_membershipChangeType_data)


identityGovernance_valueType_data = {
    'enum': 0,
    'string': 1,
    'int': 2,
    'bool': 3,
    'unknownFutureValue': 4,
}
identityGovernance_valueType = enum.Enum('identityGovernance_valueType', identityGovernance_valueType_data)


identityGovernance_workflowExecutionType_data = {
    'scheduled': 0,
    'onDemand': 1,
    'unknownFutureValue': 2,
}
identityGovernance_workflowExecutionType = enum.Enum('identityGovernance_workflowExecutionType', identityGovernance_workflowExecutionType_data)


identityGovernance_workflowTriggerTimeBasedAttribute_data = {
    'employeeHireDate': 0,
    'employeeLeaveDateTime': 1,
    'unknownFutureValue': 2,
    'createdDateTime': 3,
}
identityGovernance_workflowTriggerTimeBasedAttribute = enum.Enum('identityGovernance_workflowTriggerTimeBasedAttribute', identityGovernance_workflowTriggerTimeBasedAttribute_data)


applicationKeyOrigin_data = {
    'application': 0,
    'servicePrincipal': 1,
    'unknownFutureValue': 2,
}
applicationKeyOrigin = enum.Enum('applicationKeyOrigin', applicationKeyOrigin_data)


applicationKeyType_data = {
    'clientSecret': 0,
    'certificate': 1,
    'unknownFutureValue': 2,
}
applicationKeyType = enum.Enum('applicationKeyType', applicationKeyType_data)


applicationKeyUsage_data = {
    'sign': 0,
    'verify': 1,
    'unknownFutureValue': 2,
}
applicationKeyUsage = enum.Enum('applicationKeyUsage', applicationKeyUsage_data)


appliedConditionalAccessPolicyResult_data = {
    'success': 0,
    'failure': 1,
    'notApplied': 2,
    'notEnabled': 3,
    'unknown': 4,
    'unknownFutureValue': 5,
    'reportOnlySuccess': 6,
    'reportOnlyFailure': 7,
    'reportOnlyNotApplied': 8,
    'reportOnlyInterrupted': 9,
}
appliedConditionalAccessPolicyResult = enum.Enum('appliedConditionalAccessPolicyResult', appliedConditionalAccessPolicyResult_data)


authenticationAppAdminConfiguration_data = {
    'notApplicable': 0,
    'enabled': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
authenticationAppAdminConfiguration = enum.Enum('authenticationAppAdminConfiguration', authenticationAppAdminConfiguration_data)


authenticationAppEvaluation_data = {
    'success': 0,
    'failure': 1,
    'unknownFutureValue': 2,
}
authenticationAppEvaluation = enum.Enum('authenticationAppEvaluation', authenticationAppEvaluation_data)


authenticationAppPolicyStatus_data = {
    'unknown': 0,
    'appLockOutOfDate': 1,
    'appLockEnabled': 2,
    'appLockDisabled': 3,
    'appContextOutOfDate': 4,
    'appContextShown': 5,
    'appContextNotShown': 6,
    'locationContextOutOfDate': 7,
    'locationContextShown': 8,
    'locationContextNotShown': 9,
    'numberMatchOutOfDate': 10,
    'numberMatchCorrectNumberEntered': 11,
    'numberMatchIncorrectNumberEntered': 12,
    'numberMatchDeny': 13,
    'tamperResistantHardwareOutOfDate': 14,
    'tamperResistantHardwareUsed': 15,
    'tamperResistantHardwareNotUsed': 16,
    'unknownFutureValue': 17,
}
authenticationAppPolicyStatus = enum.Enum('authenticationAppPolicyStatus', authenticationAppPolicyStatus_data)


authenticationContextDetail_data = {
    'required': 0,
    'previouslySatisfied': 1,
    'notApplicable': 2,
    'unknownFutureValue': 3,
}
authenticationContextDetail = enum.Enum('authenticationContextDetail', authenticationContextDetail_data)


authenticationEventType_data = {
    'tokenIssuanceStart': 0,
    'pageRenderStart': 1,
    'unknownFutureValue': 2,
    'attributeCollectionStart': 3,
    'attributeCollectionSubmit': 4,
    'emailOtpSend': 5,
}
authenticationEventType = enum.Enum('authenticationEventType', authenticationEventType_data)


authenticationFailureReasonCode_data = {
    'incomplete': 0,
    'denied': 1,
    'systemFailure': 2,
    'badRequest': 3,
    'other': 4,
    'unknownFutureValue': 5,
    'userError': 6,
    'configError': 7,
}
authenticationFailureReasonCode = enum.Enum('authenticationFailureReasonCode', authenticationFailureReasonCode_data)


authenticationMethodFeature_data = {
    'ssprRegistered': 0,
    'ssprEnabled': 1,
    'ssprCapable': 2,
    'passwordlessCapable': 3,
    'mfaCapable': 4,
    'unknownFutureValue': 5,
}
authenticationMethodFeature = enum.Enum('authenticationMethodFeature', authenticationMethodFeature_data)


authenticationStrengthResult_data = {
    'notSet': 0,
    'skippedForProofUp': 1,
    'satisfied': 2,
    'singleChallengeRequired': 3,
    'multipleChallengesRequired': 4,
    'singleRegistrationRequired': 5,
    'multipleRegistrationsRequired': 6,
    'cannotSatisfyDueToCombinationConfiguration': 7,
    'cannotSatisfy': 8,
    'unknownFutureValue': 9,
}
authenticationStrengthResult = enum.Enum('authenticationStrengthResult', authenticationStrengthResult_data)


authMethodsType_data = {
    'email': 0,
    'mobileSMS': 1,
    'mobilePhone': 2,
    'officePhone': 3,
    'securityQuestion': 4,
    'appNotification': 5,
    'appNotificationCode': 6,
    'appNotificationAndCode': 7,
    'appPassword': 8,
    'fido': 9,
    'alternateMobilePhone': 10,
    'mobilePhoneAndSMS': 11,
    'unknownFutureValue': 12,
}
authMethodsType = enum.Enum('authMethodsType', authMethodsType_data)


clientCredentialType_data = {
    'none': 0,
    'clientSecret': 1,
    'clientAssertion': 2,
    'federatedIdentityCredential': 3,
    'managedIdentity': 4,
    'certificate': 5,
    'unknownFutureValue': 6,
}
clientCredentialType = enum.Enum('clientCredentialType', clientCredentialType_data)


conditionalAccessAudienceReason_data = {
    'none': 0,
    'resourcelessRequest': 1,
    'confidentialClientIdToken': 2,
    'confidentialClientNonIdToken': 4,
    'resourceMapping': 8,
    'resourceMappingDefault': 16,
    'scopeMapping': 32,
    'scopeMappingDefault': 64,
    'delegatedScope': 128,
    'firstPartyResourceDefault': 256,
    'thirdPartyResourceDefault': 512,
    'unknownFutureValue': 1024,
}
conditionalAccessAudienceReason = enum.Enum('conditionalAccessAudienceReason', conditionalAccessAudienceReason_data)


conditionalAccessConditions_data = {
    'none': 0,
    'application': 1,
    'users': 2,
    'devicePlatform': 4,
    'location': 8,
    'clientType': 16,
    'signInRisk': 32,
    'userRisk': 64,
    'time': 128,
    'deviceState': 256,
    'client': 512,
    'ipAddressSeenByAzureAD': 1024,
    'ipAddressSeenByResourceProvider': 2048,
    'unknownFutureValue': 4096,
    'servicePrincipals': 8192,
    'servicePrincipalRisk': 16384,
    'authenticationFlows': 32768,
    'insiderRisk': 65536,
}
conditionalAccessConditions = enum.Enum('conditionalAccessConditions', conditionalAccessConditions_data)


conditionalAccessRule_data = {
    'allApps': 0,
    'firstPartyApps': 1,
    'office365': 2,
    'appId': 3,
    'acr': 4,
    'appFilter': 5,
    'allUsers': 6,
    'guest': 7,
    'groupId': 8,
    'roleId': 9,
    'userId': 10,
    'allDevicePlatforms': 11,
    'devicePlatform': 12,
    'allLocations': 13,
    'insideCorpnet': 14,
    'allTrustedLocations': 15,
    'locationId': 16,
    'allDevices': 17,
    'deviceFilter': 18,
    'deviceState': 19,
    'unknownFutureValue': 20,
    'deviceFilterIncludeRuleNotMatched': 21,
    'allDeviceStates': 22,
    'anonymizedIPAddress': 23,
    'unfamiliarFeatures': 24,
    'nationStateIPAddress': 25,
    'realTimeThreatIntelligence': 26,
    'internalGuest': 27,
    'b2bCollaborationGuest': 28,
    'b2bCollaborationMember': 29,
    'b2bDirectConnectUser': 30,
    'otherExternalUser': 31,
    'serviceProvider': 32,
    'microsoftAdminPortals': 33,
    'deviceCodeFlow': 34,
    'authenticationTransfer': 35,
    'insiderRisk': 36,
}
conditionalAccessRule = enum.Enum('conditionalAccessRule', conditionalAccessRule_data)


conditionalAccessStatus_data = {
    'success': 0,
    'failure': 1,
    'notApplied': 2,
    'unknownFutureValue': 3,
}
conditionalAccessStatus = enum.Enum('conditionalAccessStatus', conditionalAccessStatus_data)


defaultMfaMethodType_data = {
    'none': 0,
    'mobilePhone': 1,
    'alternateMobilePhone': 2,
    'officePhone': 3,
    'microsoftAuthenticatorPush': 4,
    'softwareOneTimePasscode': 5,
    'unknownFutureValue': 6,
}
defaultMfaMethodType = enum.Enum('defaultMfaMethodType', defaultMfaMethodType_data)


expirationRequirement_data = {
    'rememberMultifactorAuthenticationOnTrustedDevices': 0,
    'tenantTokenLifetimePolicy': 1,
    'audienceTokenLifetimePolicy': 2,
    'signInFrequencyPeriodicReauthentication': 3,
    'ngcMfa': 4,
    'signInFrequencyEveryTime': 5,
    'unknownFutureValue': 6,
}
expirationRequirement = enum.Enum('expirationRequirement', expirationRequirement_data)


featureType_data = {
    'registration': 0,
    'reset': 1,
    'unknownFutureValue': 2,
}
featureType = enum.Enum('featureType', featureType_data)


groupType_data = {
    'unifiedGroups': 0,
    'azureAD': 1,
    'unknownFutureValue': 2,
}
groupType = enum.Enum('groupType', groupType_data)


includedUserRoles_data = {
    'all': 0,
    'privilegedAdmin': 1,
    'admin': 2,
    'user': 3,
    'unknownFutureValue': 4,
}
includedUserRoles = enum.Enum('includedUserRoles', includedUserRoles_data)


includedUserTypes_data = {
    'all': 0,
    'member': 1,
    'guest': 2,
    'unknownFutureValue': 3,
}
includedUserTypes = enum.Enum('includedUserTypes', includedUserTypes_data)


incomingTokenType_data = {
    'none': 0,
    'primaryRefreshToken': 1,
    'saml11': 2,
    'saml20': 4,
    'unknownFutureValue': 8,
    'remoteDesktopToken': 16,
    'refreshToken': 32,
}
incomingTokenType = enum.Enum('incomingTokenType', incomingTokenType_data)


initiatorType_data = {
    'user': 0,
    'application': 1,
    'system': 2,
    'unknownFutureValue': 3,
}
initiatorType = enum.Enum('initiatorType', initiatorType_data)


mfaFailureReasonCode_data = {
    'mfaIncomplete': 0,
    'mfaDenied': 1,
    'systemFailure': 2,
    'badRequest': 3,
    'other': 4,
    'unknownFutureValue': 5,
}
mfaFailureReasonCode = enum.Enum('mfaFailureReasonCode', mfaFailureReasonCode_data)


mfaType_data = {
    'eotp': 0,
    'oneWaySms': 1,
    'twoWaySms': 2,
    'twoWaySmsOtherMobile': 3,
    'phoneAppNotification': 4,
    'phoneAppOtp': 5,
    'twoWayVoiceMobile': 6,
    'twoWayVoiceOffice': 7,
    'twoWayVoiceOtherMobile': 8,
    'fido': 9,
    'certificate': 10,
    'other': 11,
    'unknownFutureValue': 12,
}
mfaType = enum.Enum('mfaType', mfaType_data)


migrationStatus_data = {
    'ready': 0,
    'needsReview': 1,
    'additionalStepsRequired': 2,
    'unknownFutureValue': 3,
}
migrationStatus = enum.Enum('migrationStatus', migrationStatus_data)


msiType_data = {
    'none': 0,
    'userAssigned': 1,
    'systemAssigned': 2,
    'unknownFutureValue': 3,
}
msiType = enum.Enum('msiType', msiType_data)


networkType_data = {
    'intranet': 0,
    'extranet': 1,
    'namedNetwork': 2,
    'trusted': 3,
    'trustedNamedLocation': 4,
    'unknownFutureValue': 5,
}
networkType = enum.Enum('networkType', networkType_data)


operationResult_data = {
    'success': 0,
    'failure': 1,
    'timeout': 2,
    'unknownFutureValue': 3,
}
operationResult = enum.Enum('operationResult', operationResult_data)


originalTransferMethods_data = {
    'none': 0,
    'deviceCodeFlow': 1,
    'authenticationTransfer': 2,
    'unknownFutureValue': 3,
}
originalTransferMethods = enum.Enum('originalTransferMethods', originalTransferMethods_data)


outlierContainerType_data = {
    'group': 0,
    'unknownFutureValue': 1,
}
outlierContainerType = enum.Enum('outlierContainerType', outlierContainerType_data)


outlierMemberType_data = {
    'user': 0,
    'unknownFutureValue': 1,
}
outlierMemberType = enum.Enum('outlierMemberType', outlierMemberType_data)


protocolType_data = {
    'none': 0,
    'oAuth2': 1,
    'ropc': 2,
    'wsFederation': 4,
    'saml20': 8,
    'deviceCode': 16,
    'unknownFutureValue': 32,
    'authenticationTransfer': 64,
    'nativeAuth': 128,
}
protocolType = enum.Enum('protocolType', protocolType_data)


provisioningAction_data = {
    'other': 0,
    'create': 1,
    'delete': 2,
    'disable': 3,
    'update': 4,
    'stagedDelete': 5,
    'unknownFutureValue': 6,
}
provisioningAction = enum.Enum('provisioningAction', provisioningAction_data)


provisioningResult_data = {
    'success': 0,
    'failure': 1,
    'skipped': 2,
    'warning': 3,
    'unknownFutureValue': 4,
}
provisioningResult = enum.Enum('provisioningResult', provisioningResult_data)


provisioningStatusErrorCategory_data = {
    'failure': 0,
    'nonServiceFailure': 1,
    'success': 2,
    'unknownFutureValue': 3,
}
provisioningStatusErrorCategory = enum.Enum('provisioningStatusErrorCategory', provisioningStatusErrorCategory_data)


provisioningStepType_data = {
    'import': 0,
    'scoping': 1,
    'matching': 2,
    'processing': 3,
    'referenceResolution': 4,
    'export': 5,
    'unknownFutureValue': 6,
}
provisioningStepType = enum.Enum('provisioningStepType', provisioningStepType_data)


recommendationCategory_data = {
    'identityBestPractice': 0,
    'identitySecureScore': 1,
    'unknownFutureValue': 2,
}
recommendationCategory = enum.Enum('recommendationCategory', recommendationCategory_data)


recommendationFeatureAreas_data = {
    'users': 0,
    'groups': 1,
    'devices': 2,
    'applications': 3,
    'accessReviews': 4,
    'conditionalAccess': 5,
    'governance': 6,
    'unknownFutureValue': 7,
}
recommendationFeatureAreas = enum.Enum('recommendationFeatureAreas', recommendationFeatureAreas_data)


recommendationPriority_data = {
    'low': 0,
    'medium': 1,
    'high': 2,
}
recommendationPriority = enum.Enum('recommendationPriority', recommendationPriority_data)


recommendationStatus_data = {
    'active': 0,
    'completedBySystem': 1,
    'completedByUser': 2,
    'dismissed': 3,
    'postponed': 4,
    'unknownFutureValue': 5,
}
recommendationStatus = enum.Enum('recommendationStatus', recommendationStatus_data)


recommendationType_data = {
    'adfsAppsMigration': 0,
    'enableDesktopSSO': 1,
    'enablePHS': 2,
    'enableProvisioning': 3,
    'switchFromPerUserMFA': 4,
    'tenantMFA': 5,
    'thirdPartyApps': 6,
    'turnOffPerUserMFA': 7,
    'useAuthenticatorApp': 8,
    'useMyApps': 9,
    'staleApps': 10,
    'staleAppCreds': 11,
    'applicationCredentialExpiry': 12,
    'servicePrincipalKeyExpiry': 13,
    'adminMFAV2': 14,
    'blockLegacyAuthentication': 15,
    'integratedApps': 16,
    'mfaRegistrationV2': 17,
    'pwagePolicyNew': 18,
    'passwordHashSync': 19,
    'oneAdmin': 20,
    'roleOverlap': 21,
    'selfServicePasswordReset': 22,
    'signinRiskPolicy': 23,
    'userRiskPolicy': 24,
    'verifyAppPublisher': 25,
    'privateLinkForAAD': 26,
    'appRoleAssignmentsGroups': 27,
    'appRoleAssignmentsUsers': 28,
    'managedIdentity': 29,
    'overprivilegedApps': 30,
    'unknownFutureValue': 31,
    'longLivedCredentials': 32,
    'aadConnectDeprecated': 33,
    'adalToMsalMigration': 34,
    'ownerlessApps': 35,
    'inactiveGuests': 36,
    'aadGraphDeprecationApplication': 37,
    'aadGraphDeprecationServicePrincipal': 38,
    'mfaServerDeprecation': 39,
}
recommendationType = enum.Enum('recommendationType', recommendationType_data)


registrationAuthMethod_data = {
    'email': 0,
    'mobilePhone': 1,
    'officePhone': 2,
    'securityQuestion': 3,
    'appNotification': 4,
    'appCode': 5,
    'alternateMobilePhone': 6,
    'fido': 7,
    'appPassword': 8,
    'unknownFutureValue': 9,
}
registrationAuthMethod = enum.Enum('registrationAuthMethod', registrationAuthMethod_data)


registrationStatusType_data = {
    'registered': 0,
    'enabled': 1,
    'capable': 2,
    'mfaRegistered': 3,
    'unknownFutureValue': 4,
}
registrationStatusType = enum.Enum('registrationStatusType', registrationStatusType_data)


releaseType_data = {
    'preview': 0,
    'generallyAvailable': 1,
    'unknownFutureValue': 2,
}
releaseType = enum.Enum('releaseType', releaseType_data)


requiredLicenses_data = {
    'notApplicable': 0,
    'microsoftEntraIdFree': 1,
    'microsoftEntraIdP1': 2,
    'microsoftEntraIdP2': 3,
    'microsoftEntraIdGovernance': 4,
    'microsoftEntraWorkloadId': 5,
    'unknownFutureValue': 6,
}
requiredLicenses = enum.Enum('requiredLicenses', requiredLicenses_data)


requirementProvider_data = {
    'user': 0,
    'request': 1,
    'servicePrincipal': 2,
    'v1ConditionalAccess': 3,
    'multiConditionalAccess': 4,
    'tenantSessionRiskPolicy': 5,
    'accountCompromisePolicies': 6,
    'v1ConditionalAccessDependency': 7,
    'v1ConditionalAccessPolicyIdRequested': 8,
    'mfaRegistrationRequiredByIdentityProtectionPolicy': 9,
    'baselineProtection': 10,
    'mfaRegistrationRequiredByBaselineProtection': 11,
    'mfaRegistrationRequiredByMultiConditionalAccess': 12,
    'enforcedForCspAdmins': 13,
    'securityDefaults': 14,
    'mfaRegistrationRequiredBySecurityDefaults': 15,
    'proofUpCodeRequest': 16,
    'crossTenantOutboundRule': 17,
    'gpsLocationCondition': 18,
    'riskBasedPolicy': 19,
    'unknownFutureValue': 20,
    'scopeBasedAuthRequirementPolicy': 21,
    'authenticationStrengths': 22,
}
requirementProvider = enum.Enum('requirementProvider', requirementProvider_data)


riskDetail_data = {
    'none': 0,
    'adminGeneratedTemporaryPassword': 1,
    'userPerformedSecuredPasswordChange': 2,
    'userPerformedSecuredPasswordReset': 3,
    'adminConfirmedSigninSafe': 4,
    'aiConfirmedSigninSafe': 5,
    'userPassedMFADrivenByRiskBasedPolicy': 6,
    'adminDismissedAllRiskForUser': 7,
    'adminConfirmedSigninCompromised': 8,
    'hidden': 9,
    'adminConfirmedUserCompromised': 10,
    'unknownFutureValue': 11,
    'adminConfirmedServicePrincipalCompromised': 12,
    'adminDismissedAllRiskForServicePrincipal': 13,
    'm365DAdminDismissedDetection': 14,
    'userChangedPasswordOnPremises': 15,
    'adminDismissedRiskForSignIn': 16,
    'adminConfirmedAccountSafe': 17,
}
riskDetail = enum.Enum('riskDetail', riskDetail_data)


riskLevel_data = {
    'low': 0,
    'medium': 1,
    'high': 2,
    'hidden': 3,
    'none': 4,
    'unknownFutureValue': 5,
}
riskLevel = enum.Enum('riskLevel', riskLevel_data)


riskState_data = {
    'none': 0,
    'confirmedSafe': 1,
    'remediated': 2,
    'dismissed': 3,
    'atRisk': 4,
    'confirmedCompromised': 5,
    'unknownFutureValue': 6,
}
riskState = enum.Enum('riskState', riskState_data)


signInAccessType_data = {
    'none': 0,
    'b2bCollaboration': 1,
    'b2bDirectConnect': 2,
    'microsoftSupport': 4,
    'serviceProvider': 8,
    'unknownFutureValue': 16,
    'passthrough': 32,
}
signInAccessType = enum.Enum('signInAccessType', signInAccessType_data)


signInIdentifierType_data = {
    'userPrincipalName': 0,
    'phoneNumber': 1,
    'proxyAddress': 2,
    'qrCode': 3,
    'onPremisesUserPrincipalName': 4,
    'unknownFutureValue': 5,
}
signInIdentifierType = enum.Enum('signInIdentifierType', signInIdentifierType_data)


signInUserType_data = {
    'member': 0,
    'guest': 1,
    'unknownFutureValue': 3,
}
signInUserType = enum.Enum('signInUserType', signInUserType_data)


signUpIdentifierType_data = {
    'emailAddress': 0,
    'unknownFutureValue': 1,
}
signUpIdentifierType = enum.Enum('signUpIdentifierType', signUpIdentifierType_data)


signUpStage_data = {
    'credentialCollection': 0,
    'credentialValidation': 1,
    'credentialFederation': 2,
    'consent': 3,
    'attributeCollectionAndValidation': 4,
    'userCreation': 5,
    'tenantConsent': 6,
    'unknownFutureValue': 7,
}
signUpStage = enum.Enum('signUpStage', signUpStage_data)


tokenIssuerType_data = {
    'AzureAD': 0,
    'ADFederationServices': 1,
    'UnknownFutureValue': 2,
    'AzureADBackupAuth': 3,
    'ADFederationServicesMFAAdapter': 4,
    'NPSExtension': 5,
}
tokenIssuerType = enum.Enum('tokenIssuerType', tokenIssuerType_data)


tokenProtectionStatus_data = {
    'none': 0,
    'bound': 1,
    'unbound': 2,
    'unknownFutureValue': 3,
}
tokenProtectionStatus = enum.Enum('tokenProtectionStatus', tokenProtectionStatus_data)


usageAuthMethod_data = {
    'email': 0,
    'mobileSMS': 1,
    'mobileCall': 2,
    'officePhone': 3,
    'securityQuestion': 4,
    'appNotification': 5,
    'appCode': 6,
    'alternateMobileCall': 7,
    'fido': 8,
    'appPassword': 9,
    'unknownFutureValue': 10,
}
usageAuthMethod = enum.Enum('usageAuthMethod', usageAuthMethod_data)


userDefaultAuthenticationMethod_data = {
    'push': 0,
    'oath': 1,
    'voiceMobile': 2,
    'voiceAlternateMobile': 3,
    'voiceOffice': 4,
    'sms': 5,
    'none': 6,
    'unknownFutureValue': 7,
}
userDefaultAuthenticationMethod = enum.Enum('userDefaultAuthenticationMethod', userDefaultAuthenticationMethod_data)


analyticsActivityType_data = {
    'Email': 0,
    'Meeting': 1,
    'Focus': 2,
    'Chat': 3,
    'Call': 4,
}
analyticsActivityType = enum.Enum('analyticsActivityType', analyticsActivityType_data)


uriUsageType_data = {
    'redirectUri': 0,
    'identifierUri': 1,
    'loginUrl': 2,
    'logoutUrl': 3,
    'unknownFutureValue': 4,
}
uriUsageType = enum.Enum('uriUsageType', uriUsageType_data)


approvalItemState_data = {
    'canceled': 0,
    'created': 1,
    'pending': 2,
    'completed': 3,
    'unknownFutureValue': 4,
}
approvalItemState = enum.Enum('approvalItemState', approvalItemState_data)


approvalItemType_data = {
    'basic': 0,
    'basicAwaitAll': 1,
    'custom': 2,
    'customAwaitAll': 3,
    'unknownFutureValue': 4,
}
approvalItemType = enum.Enum('approvalItemType', approvalItemType_data)


approvalOperationStatus_data = {
    'scheduled': 0,
    'inProgress': 1,
    'succeeded': 2,
    'failed': 3,
    'timeout': 4,
    'unknownFutureValue': 5,
}
approvalOperationStatus = enum.Enum('approvalOperationStatus', approvalOperationStatus_data)


approverRole_data = {
    'owner': 0,
    'approver': 1,
    'unknownFutureValue': 2,
}
approverRole = enum.Enum('approverRole', approverRole_data)


provisionState_data = {
    'notProvisioned': 0,
    'provisioningInProgress': 1,
    'provisioningFailed': 2,
    'provisioningCompleted': 3,
    'unknownFutureValue': 4,
}
provisionState = enum.Enum('provisionState', provisionState_data)


advancedConfigState_data = {
    'default': 0,
    'enabled': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
advancedConfigState = enum.Enum('advancedConfigState', advancedConfigState_data)


authenticationMethodModes_data = {
    'password': 1,
    'voice': 2,
    'hardwareOath': 4,
    'softwareOath': 8,
    'sms': 16,
    'fido2': 32,
    'windowsHelloForBusiness': 64,
    'microsoftAuthenticatorPush': 128,
    'deviceBasedPush': 256,
    'temporaryAccessPassOneTime': 512,
    'temporaryAccessPassMultiUse': 1024,
    'email': 2048,
    'x509CertificateSingleFactor': 4096,
    'x509CertificateMultiFactor': 8192,
    'federatedSingleFactor': 16384,
    'federatedMultiFactor': 32768,
    'unknownFutureValue': 65536,
}
authenticationMethodModes = enum.Enum('authenticationMethodModes', authenticationMethodModes_data)


authenticationMethodsPolicyMigrationState_data = {
    'preMigration': 0,
    'migrationInProgress': 1,
    'migrationComplete': 2,
    'unknownFutureValue': 3,
}
authenticationMethodsPolicyMigrationState = enum.Enum('authenticationMethodsPolicyMigrationState', authenticationMethodsPolicyMigrationState_data)


authenticationMethodState_data = {
    'enabled': 0,
    'disabled': 1,
}
authenticationMethodState = enum.Enum('authenticationMethodState', authenticationMethodState_data)


authenticationMethodTargetType_data = {
    'user': 0,
    'group': 1,
    'unknownFutureValue': 2,
}
authenticationMethodTargetType = enum.Enum('authenticationMethodTargetType', authenticationMethodTargetType_data)


authenticationStrengthPolicyType_data = {
    'builtIn': 0,
    'custom': 1,
    'unknownFutureValue': 2,
}
authenticationStrengthPolicyType = enum.Enum('authenticationStrengthPolicyType', authenticationStrengthPolicyType_data)


authenticationStrengthRequirements_data = {
    'none': 0,
    'mfa': 1,
    'unknownFutureValue': 2,
}
authenticationStrengthRequirements = enum.Enum('authenticationStrengthRequirements', authenticationStrengthRequirements_data)


baseAuthenticationMethod_data = {
    'password': 1,
    'voice': 2,
    'hardwareOath': 3,
    'softwareOath': 4,
    'sms': 5,
    'fido2': 6,
    'windowsHelloForBusiness': 7,
    'microsoftAuthenticator': 8,
    'temporaryAccessPass': 9,
    'email': 10,
    'x509Certificate': 11,
    'federation': 12,
    'unknownFutureValue': 13,
}
baseAuthenticationMethod = enum.Enum('baseAuthenticationMethod', baseAuthenticationMethod_data)


externalEmailOtpState_data = {
    'default': 0,
    'enabled': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
externalEmailOtpState = enum.Enum('externalEmailOtpState', externalEmailOtpState_data)


featureTargetType_data = {
    'group': 0,
    'administrativeUnit': 1,
    'role': 2,
    'unknownFutureValue': 3,
}
featureTargetType = enum.Enum('featureTargetType', featureTargetType_data)


fido2RestrictionEnforcementType_data = {
    'allow': 0,
    'block': 1,
    'unknownFutureValue': 2,
}
fido2RestrictionEnforcementType = enum.Enum('fido2RestrictionEnforcementType', fido2RestrictionEnforcementType_data)


microsoftAuthenticatorAuthenticationMode_data = {
    'deviceBasedPush': 0,
    'push': 1,
    'any': 2,
}
microsoftAuthenticatorAuthenticationMode = enum.Enum('microsoftAuthenticatorAuthenticationMode', microsoftAuthenticatorAuthenticationMode_data)


securityQuestionType_data = {
    'predefined': 0,
    'custom': 1,
}
securityQuestionType = enum.Enum('securityQuestionType', securityQuestionType_data)


x509CertificateAffinityLevel_data = {
    'low': 0,
    'high': 1,
    'unknownFutureValue': 2,
}
x509CertificateAffinityLevel = enum.Enum('x509CertificateAffinityLevel', x509CertificateAffinityLevel_data)


x509CertificateAuthenticationMode_data = {
    'x509CertificateSingleFactor': 0,
    'x509CertificateMultiFactor': 1,
    'unknownFutureValue': 2,
}
x509CertificateAuthenticationMode = enum.Enum('x509CertificateAuthenticationMode', x509CertificateAuthenticationMode_data)


x509CertificateIssuerHintsState_data = {
    'disabled': 0,
    'enabled': 1,
    'unknownFutureValue': 2,
}
x509CertificateIssuerHintsState = enum.Enum('x509CertificateIssuerHintsState', x509CertificateIssuerHintsState_data)


x509CertificateRuleType_data = {
    'issuerSubject': 0,
    'policyOID': 1,
    'unknownFutureValue': 2,
    'issuerSubjectAndPolicyOID': 3,
}
x509CertificateRuleType = enum.Enum('x509CertificateRuleType', x509CertificateRuleType_data)


entityType_data = {
    'event': 0,
    'message': 1,
    'driveItem': 2,
    'externalItem': 4,
    'site': 5,
    'list': 6,
    'listItem': 7,
    'drive': 8,
    'unknownFutureValue': 9,
    'acronym': 10,
    'bookmark': 11,
    'chatMessage': 12,
    'person': 13,
    'qna': 16,
}
entityType = enum.Enum('entityType', entityType_data)


phoneType_data = {
    'home': 0,
    'business': 1,
    'mobile': 2,
    'other': 3,
    'assistant': 4,
    'homeFax': 5,
    'businessFax': 6,
    'otherFax': 7,
    'pager': 8,
    'radio': 9,
}
phoneType = enum.Enum('phoneType', phoneType_data)


volumeType_data = {
    'operatingSystemVolume': 1,
    'fixedDataVolume': 2,
    'removableDataVolume': 3,
    'unknownFutureValue': 4,
}
volumeType = enum.Enum('volumeType', volumeType_data)


answerInputType_data = {
    'text': 0,
    'radioButton': 1,
    'unknownFutureValue': 2,
}
answerInputType = enum.Enum('answerInputType', answerInputType_data)


bookingInvoiceStatus_data = {
    'draft': 0,
    'reviewing': 1,
    'open': 2,
    'canceled': 3,
    'paid': 4,
    'corrective': 5,
}
bookingInvoiceStatus = enum.Enum('bookingInvoiceStatus', bookingInvoiceStatus_data)


bookingPageAccessControl_data = {
    'unrestricted': 0,
    'restrictedToOrganization': 1,
    'unknownFutureValue': 2,
}
bookingPageAccessControl = enum.Enum('bookingPageAccessControl', bookingPageAccessControl_data)


bookingPriceType_data = {
    'undefined': 0,
    'fixedPrice': 1,
    'startingAt': 2,
    'hourly': 3,
    'free': 4,
    'priceVaries': 5,
    'callUs': 6,
    'notSet': 7,
}
bookingPriceType = enum.Enum('bookingPriceType', bookingPriceType_data)


bookingReminderRecipients_data = {
    'allAttendees': 0,
    'staff': 1,
    'customer': 2,
}
bookingReminderRecipients = enum.Enum('bookingReminderRecipients', bookingReminderRecipients_data)


bookingsAvailabilityStatus_data = {
    'available': 0,
    'busy': 1,
    'slotsAvailable': 2,
    'outOfOffice': 3,
    'unknownFutureValue': 4,
}
bookingsAvailabilityStatus = enum.Enum('bookingsAvailabilityStatus', bookingsAvailabilityStatus_data)


bookingsServiceAvailabilityType_data = {
    'bookWhenStaffAreFree': 0,
    'notBookable': 1,
    'customWeeklyHours': 2,
    'unknownFutureValue': 3,
}
bookingsServiceAvailabilityType = enum.Enum('bookingsServiceAvailabilityType', bookingsServiceAvailabilityType_data)


bookingStaffMembershipStatus_data = {
    'active': 0,
    'pendingAcceptance': 1,
    'rejectedByStaff': 2,
    'unknownFutureValue': 3,
}
bookingStaffMembershipStatus = enum.Enum('bookingStaffMembershipStatus', bookingStaffMembershipStatus_data)


bookingStaffRole_data = {
    'guest': 0,
    'administrator': 1,
    'viewer': 2,
    'externalGuest': 3,
    'unknownFutureValue': 4,
    'scheduler': 5,
    'teamMember': 6,
}
bookingStaffRole = enum.Enum('bookingStaffRole', bookingStaffRole_data)


dayOfWeek_data = {
    'sunday': 0,
    'monday': 1,
    'tuesday': 2,
    'wednesday': 3,
    'thursday': 4,
    'friday': 5,
    'saturday': 6,
}
dayOfWeek = enum.Enum('dayOfWeek', dayOfWeek_data)


locationType_data = {
    'default': 0,
    'conferenceRoom': 1,
    'homeAddress': 2,
    'businessAddress': 3,
    'geoCoordinates': 4,
    'streetAddress': 5,
    'hotel': 6,
    'restaurant': 7,
    'localBusiness': 8,
    'postalAddress': 9,
}
locationType = enum.Enum('locationType', locationType_data)


locationUniqueIdType_data = {
    'unknown': 0,
    'locationStore': 1,
    'directory': 2,
    'private': 3,
    'bing': 4,
}
locationUniqueIdType = enum.Enum('locationUniqueIdType', locationUniqueIdType_data)


physicalAddressType_data = {
    'unknown': 0,
    'home': 1,
    'business': 2,
    'other': 3,
}
physicalAddressType = enum.Enum('physicalAddressType', physicalAddressType_data)


plannerRelationshipUserRoles_data = {
    'defaultRules': 0,
    'groupOwners': 1,
    'groupMembers': 2,
    'taskAssignees': 3,
    'applications': 4,
    'unknownFutureValue': 5,
}
plannerRelationshipUserRoles = enum.Enum('plannerRelationshipUserRoles', plannerRelationshipUserRoles_data)


plannerRuleKind_data = {
    'taskRule': 1,
    'bucketRule': 2,
    'planRule': 3,
    'unknownFutureValue': 4,
}
plannerRuleKind = enum.Enum('plannerRuleKind', plannerRuleKind_data)


plannerUserRoleKind_data = {
    'relationship': 1,
    'unknownFutureValue': 2,
}
plannerUserRoleKind = enum.Enum('plannerUserRoleKind', plannerUserRoleKind_data)


changeAnnouncementChangeType_data = {
    'breakingChange': 0,
    'deprecation': 1,
    'endOfSupport': 2,
    'featureChange': 3,
    'other': 4,
    'retirement': 5,
    'securityIncident': 6,
    'uxChange': 7,
    'unknownFutureValue': 8,
}
changeAnnouncementChangeType = enum.Enum('changeAnnouncementChangeType', changeAnnouncementChangeType_data)


changeItemState_data = {
    'available': 0,
    'comingSoon': 1,
    'unknownFutureValue': 2,
}
changeItemState = enum.Enum('changeItemState', changeItemState_data)


roadmapItemDeliveryStage_data = {
    'privatePreview': 0,
    'publicPreview': 1,
    'ga': 2,
    'unknownFutureValue': 3,
}
roadmapItemDeliveryStage = enum.Enum('roadmapItemDeliveryStage', roadmapItemDeliveryStage_data)


actionCapability_data = {
    'enabled': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
}
actionCapability = enum.Enum('actionCapability', actionCapability_data)


actionState_data = {
    'none': 0,
    'pending': 1,
    'canceled': 2,
    'active': 3,
    'done': 4,
    'failed': 5,
    'notSupported': 6,
}
actionState = enum.Enum('actionState', actionState_data)


allowedRolePrincipalTypes_data = {
    'user': 1,
    'servicePrincipal': 2,
    'group': 4,
    'unknownFutureValue': 8,
}
allowedRolePrincipalTypes = enum.Enum('allowedRolePrincipalTypes', allowedRolePrincipalTypes_data)


cloudPcAuditActivityOperationType_data = {
    'create': 0,
    'delete': 1,
    'patch': 2,
    'unknownFutureValue': 3,
}
cloudPcAuditActivityOperationType = enum.Enum('cloudPcAuditActivityOperationType', cloudPcAuditActivityOperationType_data)


cloudPcAuditActivityResult_data = {
    'success': 0,
    'clientError': 1,
    'failure': 2,
    'timeout': 3,
    'unknownFutureValue': 4,
}
cloudPcAuditActivityResult = enum.Enum('cloudPcAuditActivityResult', cloudPcAuditActivityResult_data)


cloudPcAuditActorType_data = {
    'itPro': 0,
    'application': 1,
    'partner': 2,
    'unknownFutureValue': 3,
}
cloudPcAuditActorType = enum.Enum('cloudPcAuditActorType', cloudPcAuditActorType_data)


cloudPcAuditCategory_data = {
    'cloudPC': 0,
    'unknownFutureValue': 1,
}
cloudPcAuditCategory = enum.Enum('cloudPcAuditCategory', cloudPcAuditCategory_data)


cloudPcBlobAccessTier_data = {
    'hot': 0,
    'cool': 1,
    'cold': 2,
    'archive': 3,
    'unknownFutureValue': 4,
}
cloudPcBlobAccessTier = enum.Enum('cloudPcBlobAccessTier', cloudPcBlobAccessTier_data)


cloudPcBulkActionStatus_data = {
    'pending': 0,
    'succeeded': 1,
    'failed': 2,
    'unknownFutureValue': 3,
}
cloudPcBulkActionStatus = enum.Enum('cloudPcBulkActionStatus', cloudPcBulkActionStatus_data)


cloudPCConnectionQualityReportType_data = {
    'remoteConnectionQualityReport': 0,
    'regionalConnectionQualityTrendReport': 1,
    'regionalConnectionQualityInsightsReport': 2,
    'unknownFutureValue': 3,
}
cloudPCConnectionQualityReportType = enum.Enum('cloudPCConnectionQualityReportType', cloudPCConnectionQualityReportType_data)


cloudPcConnectivityEventResult_data = {
    'unknown': 0,
    'success': 1,
    'failure': 2,
    'unknownFutureValue': 999,
}
cloudPcConnectivityEventResult = enum.Enum('cloudPcConnectivityEventResult', cloudPcConnectivityEventResult_data)


cloudPcConnectivityEventType_data = {
    'unknown': 0,
    'userConnection': 1,
    'userTroubleshooting': 2,
    'deviceHealthCheck': 3,
    'unknownFutureValue': 999,
}
cloudPcConnectivityEventType = enum.Enum('cloudPcConnectivityEventType', cloudPcConnectivityEventType_data)


cloudPcConnectivityStatus_data = {
    'unknown': 0,
    'available': 1,
    'availableWithWarning': 2,
    'unavailable': 3,
    'unknownFutureValue': 999,
}
cloudPcConnectivityStatus = enum.Enum('cloudPcConnectivityStatus', cloudPcConnectivityStatus_data)


cloudPcDeviceImageErrorCode_data = {
    'internalServerError': 0,
    'sourceImageNotFound': 1,
    'osVersionNotSupported': 2,
    'sourceImageInvalid': 3,
    'sourceImageNotGeneralized': 4,
    'unknownFutureValue': 5,
    'vmAlreadyAzureAdjoined': 6,
    'paidSourceImageNotSupport': 7,
    'sourceImageNotSupportCustomizeVMName': 8,
    'sourceImageSizeExceedsLimitation': 9,
}
cloudPcDeviceImageErrorCode = enum.Enum('cloudPcDeviceImageErrorCode', cloudPcDeviceImageErrorCode_data)


cloudPcDeviceImageOsStatus_data = {
    'supported': 0,
    'supportedWithWarning': 1,
    'unknown': 2,
    'unknownFutureValue': 3,
}
cloudPcDeviceImageOsStatus = enum.Enum('cloudPcDeviceImageOsStatus', cloudPcDeviceImageOsStatus_data)


cloudPcDeviceImageStatus_data = {
    'pending': 0,
    'ready': 1,
    'failed': 2,
    'unknownFutureValue': 3,
}
cloudPcDeviceImageStatus = enum.Enum('cloudPcDeviceImageStatus', cloudPcDeviceImageStatus_data)


cloudPcDeviceImageStatusDetails_data = {
    'internalServerError': 0,
    'sourceImageNotFound': 1,
    'osVersionNotSupported': 2,
    'sourceImageInvalid': 3,
    'sourceImageNotGeneralized': 4,
    'unknownFutureValue': 5,
    'vmAlreadyAzureAdjoined': 6,
    'paidSourceImageNotSupport': 7,
    'sourceImageNotSupportCustomizeVMName': 8,
    'sourceImageSizeExceedsLimitation': 9,
}
cloudPcDeviceImageStatusDetails = enum.Enum('cloudPcDeviceImageStatusDetails', cloudPcDeviceImageStatusDetails_data)


cloudPcDisasterRecoveryCapabilityType_data = {
    'none': 0,
    'failover': 1,
    'failback': 2,
    'unknownFutureValue': 3,
}
cloudPcDisasterRecoveryCapabilityType = enum.Enum('cloudPcDisasterRecoveryCapabilityType', cloudPcDisasterRecoveryCapabilityType_data)


cloudPcDisasterRecoveryLicenseType_data = {
    'none': 0,
    'standard': 1,
    'unknownFutureValue': 3,
}
cloudPcDisasterRecoveryLicenseType = enum.Enum('cloudPcDisasterRecoveryLicenseType', cloudPcDisasterRecoveryLicenseType_data)


cloudPcDisasterRecoveryReportName_data = {
    'crossRegionDisasterRecoveryReport': 0,
    'disasterRecoveryReport': 1,
    'unknownFutureValue': 2,
}
cloudPcDisasterRecoveryReportName = enum.Enum('cloudPcDisasterRecoveryReportName', cloudPcDisasterRecoveryReportName_data)


cloudPcDisasterRecoveryType_data = {
    'notConfigured': 0,
    'crossRegion': 1,
    'premium': 2,
    'unknownFutureValue': 3,
}
cloudPcDisasterRecoveryType = enum.Enum('cloudPcDisasterRecoveryType', cloudPcDisasterRecoveryType_data)


cloudPcDiskEncryptionState_data = {
    'notAvailable': 0,
    'notEncrypted': 1,
    'encryptedUsingPlatformManagedKey': 2,
    'encryptedUsingCustomerManagedKey': 3,
    'unknownFutureValue': 4,
}
cloudPcDiskEncryptionState = enum.Enum('cloudPcDiskEncryptionState', cloudPcDiskEncryptionState_data)


cloudPcDiskEncryptionType_data = {
    'platformManagedKey': 0,
    'customerManagedKey': 1,
    'unknownFutureValue': 2,
}
cloudPcDiskEncryptionType = enum.Enum('cloudPcDiskEncryptionType', cloudPcDiskEncryptionType_data)


cloudPcDomainJoinType_data = {
    'azureADJoin': 0,
    'hybridAzureADJoin': 1,
    'unknownFutureValue': 999,
}
cloudPcDomainJoinType = enum.Enum('cloudPcDomainJoinType', cloudPcDomainJoinType_data)


cloudPcExportJobStatus_data = {
    'notStarted': 0,
    'inProgress': 1,
    'completed': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
cloudPcExportJobStatus = enum.Enum('cloudPcExportJobStatus', cloudPcExportJobStatus_data)


cloudPcExternalPartnerStatus_data = {
    'notAvailable': 0,
    'available': 1,
    'healthy': 2,
    'unhealthy': 3,
    'unknownFutureValue': 999,
}
cloudPcExternalPartnerStatus = enum.Enum('cloudPcExternalPartnerStatus', cloudPcExternalPartnerStatus_data)


cloudPCFrontlineReportType_data = {
    'noLicenseAvailableConnectivityFailureReport': 0,
    'licenseUsageReport': 1,
    'licenseUsageRealTimeReport': 2,
    'licenseHourlyUsageReport': 3,
    'connectedUserRealtimeReport': 4,
    'unknownFutureValue': 5,
}
cloudPCFrontlineReportType = enum.Enum('cloudPCFrontlineReportType', cloudPCFrontlineReportType_data)


cloudPcGalleryImageStatus_data = {
    'supported': 0,
    'supportedWithWarning': 1,
    'notSupported': 2,
    'unknownFutureValue': 3,
}
cloudPcGalleryImageStatus = enum.Enum('cloudPcGalleryImageStatus', cloudPcGalleryImageStatus_data)


cloudPCInaccessibleReportName_data = {
    'inaccessibleCloudPcReports': 0,
    'inaccessibleCloudPcTrendReport': 1,
    'unknownFutureValue': 2,
}
cloudPCInaccessibleReportName = enum.Enum('cloudPCInaccessibleReportName', cloudPCInaccessibleReportName_data)


cloudPcManagementService_data = {
    'windows365': 1,
    'devBox': 2,
    'unknownFutureValue': 4,
    'rpaBox': 8,
}
cloudPcManagementService = enum.Enum('cloudPcManagementService', cloudPcManagementService_data)


cloudPcOnPremisesConnectionHealthCheckErrorType_data = {
    'dnsCheckFqdnNotFound': 100,
    'dnsCheckNameWithInvalidCharacter': 101,
    'dnsCheckUnknownError': 199,
    'adJoinCheckFqdnNotFound': 200,
    'adJoinCheckIncorrectCredentials': 201,
    'adJoinCheckOrganizationalUnitNotFound': 202,
    'adJoinCheckOrganizationalUnitIncorrectFormat': 203,
    'adJoinCheckComputerObjectAlreadyExists': 204,
    'adJoinCheckAccessDenied': 205,
    'adJoinCheckCredentialsExpired': 206,
    'adJoinCheckAccountLockedOrDisabled': 207,
    'adJoinCheckAccountQuotaExceeded': 208,
    'adJoinCheckServerNotOperational': 209,
    'adJoinCheckUnknownError': 299,
    'endpointConnectivityCheckCloudPcUrlNotAllowListed': 300,
    'endpointConnectivityCheckWVDUrlNotAllowListed': 301,
    'endpointConnectivityCheckIntuneUrlNotAllowListed': 302,
    'endpointConnectivityCheckAzureADUrlNotAllowListed': 303,
    'endpointConnectivityCheckLocaleUrlNotAllowListed': 304,
    'endpointConnectivityCheckVMAgentEndPointCommunicationError': 305,
    'endpointConnectivityCheckUnknownError': 399,
    'azureAdDeviceSyncCheckDeviceNotFound': 400,
    'azureAdDeviceSyncCheckLongSyncCircle': 401,
    'azureAdDeviceSyncCheckConnectDisabled': 402,
    'azureAdDeviceSyncCheckDurationExceeded': 403,
    'azureAdDeviceSyncCheckScpNotConfigured': 404,
    'azureAdDeviceSyncCheckTransientServiceError': 498,
    'azureAdDeviceSyncCheckUnknownError': 499,
    'resourceAvailabilityCheckNoSubnetIP': 500,
    'resourceAvailabilityCheckSubscriptionDisabled': 501,
    'resourceAvailabilityCheckAzurePolicyViolation': 502,
    'resourceAvailabilityCheckSubscriptionNotFound': 503,
    'resourceAvailabilityCheckSubscriptionTransferred': 504,
    'resourceAvailabilityCheckGeneralSubscriptionError': 505,
    'resourceAvailabilityCheckUnsupportedVNetRegion': 506,
    'resourceAvailabilityCheckResourceGroupInvalid': 507,
    'resourceAvailabilityCheckVNetInvalid': 508,
    'resourceAvailabilityCheckSubnetInvalid': 509,
    'resourceAvailabilityCheckResourceGroupBeingDeleted': 510,
    'resourceAvailabilityCheckVNetBeingMoved': 511,
    'resourceAvailabilityCheckSubnetDelegationFailed': 512,
    'resourceAvailabilityCheckSubnetWithExternalResources': 513,
    'resourceAvailabilityCheckResourceGroupLockedForReadonly': 514,
    'resourceAvailabilityCheckResourceGroupLockedForDelete': 515,
    'resourceAvailabilityCheckNoIntuneReaderRoleError': 516,
    'resourceAvailabilityCheckIntuneDefaultWindowsRestrictionViolation': 517,
    'resourceAvailabilityCheckIntuneCustomWindowsRestrictionViolation': 518,
    'resourceAvailabilityCheckDeploymentQuotaLimitReached': 519,
    'resourceAvailabilityCheckTransientServiceError': 598,
    'resourceAvailabilityCheckUnknownError': 599,
    'permissionCheckNoSubscriptionReaderRole': 600,
    'permissionCheckNoResourceGroupOwnerRole': 601,
    'permissionCheckNoVNetContributorRole': 602,
    'permissionCheckNoResourceGroupNetworkContributorRole': 603,
    'permissionCheckNoWindows365NetworkUserRole': 604,
    'permissionCheckNoWindows365NetworkInterfaceContributorRole': 605,
    'permissionCheckTransientServiceError': 698,
    'permissionCheckUnknownError': 699,
    'udpConnectivityCheckStunUrlNotAllowListed': 800,
    'udpConnectivityCheckTurnUrlNotAllowListed': 801,
    'udpConnectivityCheckUrlsNotAllowListed': 802,
    'udpConnectivityCheckUnknownError': 899,
    'internalServerErrorDeploymentCanceled': 900,
    'internalServerErrorAllocateResourceFailed': 901,
    'internalServerErrorVMDeploymentTimeout': 902,
    'internalServerErrorUnableToRunDscScript': 903,
    'ssoCheckKerberosConfigurationError': 904,
    'internalServerUnknownError': 999,
    'unknownFutureValue': 1000,
}
cloudPcOnPremisesConnectionHealthCheckErrorType = enum.Enum('cloudPcOnPremisesConnectionHealthCheckErrorType', cloudPcOnPremisesConnectionHealthCheckErrorType_data)


cloudPcOnPremisesConnectionStatus_data = {
    'pending': 0,
    'running': 10,
    'passed': 20,
    'failed': 30,
    'warning': 40,
    'informational': 50,
    'unknownFutureValue': 51,
}
cloudPcOnPremisesConnectionStatus = enum.Enum('cloudPcOnPremisesConnectionStatus', cloudPcOnPremisesConnectionStatus_data)


cloudPcOnPremisesConnectionType_data = {
    'hybridAzureADJoin': 0,
    'azureADJoin': 1,
    'unknownFutureValue': 999,
}
cloudPcOnPremisesConnectionType = enum.Enum('cloudPcOnPremisesConnectionType', cloudPcOnPremisesConnectionType_data)


cloudPcOperatingSystem_data = {
    'windows10': 0,
    'windows11': 1,
    'unknownFutureValue': 999,
}
cloudPcOperatingSystem = enum.Enum('cloudPcOperatingSystem', cloudPcOperatingSystem_data)


cloudPcPartnerAgentInstallStatus_data = {
    'installed': 0,
    'installFailed': 1,
    'installing': 2,
    'uninstalling': 3,
    'uninstallFailed': 4,
    'licensed': 5,
    'unknownFutureValue': 6,
}
cloudPcPartnerAgentInstallStatus = enum.Enum('cloudPcPartnerAgentInstallStatus', cloudPcPartnerAgentInstallStatus_data)


cloudPcPartnerAgentName_data = {
    'citrix': 0,
    'unknownFutureValue': 1,
    'vMware': 2,
    'hp': 3,
}
cloudPcPartnerAgentName = enum.Enum('cloudPcPartnerAgentName', cloudPcPartnerAgentName_data)


cloudPCPerformanceReportName_data = {
    'performanceTrendReport': 0,
    'unknownFutureValue': 1,
}
cloudPCPerformanceReportName = enum.Enum('cloudPCPerformanceReportName', cloudPCPerformanceReportName_data)


cloudPcPolicyApplyActionStatus_data = {
    'processing': 0,
    'succeeded': 1,
    'failed': 2,
    'unknownFutureValue': 3,
}
cloudPcPolicyApplyActionStatus = enum.Enum('cloudPcPolicyApplyActionStatus', cloudPcPolicyApplyActionStatus_data)


cloudPcPolicySettingType_data = {
    'region': 1,
    'singleSignOn': 2,
    'unknownFutureValue': 4,
}
cloudPcPolicySettingType = enum.Enum('cloudPcPolicySettingType', cloudPcPolicySettingType_data)


cloudPcPowerState_data = {
    'running': 0,
    'poweredOff': 1,
    'unknownFutureValue': 2,
}
cloudPcPowerState = enum.Enum('cloudPcPowerState', cloudPcPowerState_data)


cloudPcProductType_data = {
    'enterprise': 0,
    'frontline': 1,
    'devBox': 2,
    'powerAutomate': 3,
    'business': 4,
    'unknownFutureValue': 5,
}
cloudPcProductType = enum.Enum('cloudPcProductType', cloudPcProductType_data)


cloudPcProvisioningPolicyImageType_data = {
    'gallery': 0,
    'custom': 1,
    'unknownFutureValue': 2,
}
cloudPcProvisioningPolicyImageType = enum.Enum('cloudPcProvisioningPolicyImageType', cloudPcProvisioningPolicyImageType_data)


cloudPcProvisioningType_data = {
    'dedicated': 0,
    'shared': 1,
    'unknownFutureValue': 2,
    'sharedByUser': 3,
    'sharedByEntraGroup': 4,
}
cloudPcProvisioningType = enum.Enum('cloudPcProvisioningType', cloudPcProvisioningType_data)


cloudPcRegionGroup_data = {
    'default': 0,
    'australia': 1,
    'canada': 2,
    'usCentral': 3,
    'usEast': 4,
    'usWest': 5,
    'france': 6,
    'germany': 7,
    'europeUnion': 8,
    'unitedKingdom': 9,
    'japan': 10,
    'asia': 11,
    'india': 12,
    'southAmerica': 13,
    'euap': 17,
    'usGovernment': 18,
    'usGovernmentDOD': 19,
    'unknownFutureValue': 20,
    'norway': 21,
    'switzerland': 22,
    'southKorea': 23,
    'middleEast': 25,
    'mexico': 26,
}
cloudPcRegionGroup = enum.Enum('cloudPcRegionGroup', cloudPcRegionGroup_data)


cloudPcRemoteActionName_data = {
    'unknown': 0,
    'restart': 1,
    'rename': 2,
    'resize': 3,
    'restore': 4,
    'reprovision': 5,
    'changeUserAccountType': 6,
    'troubleshoot': 7,
    'placeUnderReview': 8,
    'unknownFutureValue': 9,
    'createSnapshot': 10,
    'powerOn': 11,
    'powerOff': 12,
    'moveRegion': 13,
}
cloudPcRemoteActionName = enum.Enum('cloudPcRemoteActionName', cloudPcRemoteActionName_data)


cloudPcReportName_data = {
    'remoteConnectionHistoricalReports': 0,
    'dailyAggregatedRemoteConnectionReports': 1,
    'totalAggregatedRemoteConnectionReports': 2,
    'unknownFutureValue': 5,
    'noLicenseAvailableConnectivityFailureReport': 6,
    'frontlineLicenseUsageReport': 7,
    'frontlineLicenseUsageRealTimeReport': 8,
    'remoteConnectionQualityReports': 9,
    'inaccessibleCloudPcReports': 10,
    'actionStatusReport': 11,
    'rawRemoteConnectionReports': 12,
    'cloudPcUsageCategoryReports': 13,
    'crossRegionDisasterRecoveryReport': 14,
    'performanceTrendReport': 15,
    'inaccessibleCloudPcTrendReport': 16,
    'regionalConnectionQualityTrendReport': 17,
    'regionalConnectionQualityInsightsReport': 18,
    'remoteConnectionQualityReport': 19,
    'frontlineLicenseHourlyUsageReport': 20,
    'frontlineRealtimeUserConnectionsReport': 21,
    'bulkActionStatusReport': 22,
    'troubleshootDetailsReport': 23,
    'troubleshootTrendCountReport': 24,
    'troubleshootRegionalReport': 25,
    'troubleshootIssueCountReport': 26,
}
cloudPcReportName = enum.Enum('cloudPcReportName', cloudPcReportName_data)


cloudPcResizeValidationCode_data = {
    'success': 0,
    'cloudPcNotFound': 1,
    'operationConflict': 2,
    'operationNotSupported': 3,
    'targetLicenseHasAssigned': 4,
    'internalServerError': 5,
    'unknownFutureValue': 6,
}
cloudPcResizeValidationCode = enum.Enum('cloudPcResizeValidationCode', cloudPcResizeValidationCode_data)


cloudPcRestorePointFrequencyType_data = {
    'default': 0,
    'fourHours': 1,
    'sixHours': 2,
    'twelveHours': 3,
    'sixteenHours': 4,
    'twentyFourHours': 5,
    'unknownFutureValue': 6,
}
cloudPcRestorePointFrequencyType = enum.Enum('cloudPcRestorePointFrequencyType', cloudPcRestorePointFrequencyType_data)


cloudPcServicePlanType_data = {
    'enterprise': 0,
    'business': 1,
    'unknownFutureValue': 999,
}
cloudPcServicePlanType = enum.Enum('cloudPcServicePlanType', cloudPcServicePlanType_data)


cloudPcSnapshotStatus_data = {
    'ready': 0,
    'unknownFutureValue': 999,
}
cloudPcSnapshotStatus = enum.Enum('cloudPcSnapshotStatus', cloudPcSnapshotStatus_data)


cloudPcSnapshotType_data = {
    'automatic': 0,
    'manual': 1,
    'unknownFutureValue': 2,
}
cloudPcSnapshotType = enum.Enum('cloudPcSnapshotType', cloudPcSnapshotType_data)


cloudPcStatus_data = {
    'notProvisioned': 0,
    'provisioning': 1,
    'provisioned': 2,
    'inGracePeriod': 3,
    'deprovisioning': 4,
    'failed': 5,
    'provisionedWithWarnings': 6,
    'resizing': 7,
    'restoring': 8,
    'pendingProvision': 9,
    'unknownFutureValue': 10,
    'movingRegion': 11,
    'resizePendingLicense': 12,
    'updatingSingleSignOn': 13,
    'modifyingSingleSignOn': 14,
    'preparing': 16,
}
cloudPcStatus = enum.Enum('cloudPcStatus', cloudPcStatus_data)


cloudPcStorageAccountAccessTier_data = {
    'hot': 0,
    'cool': 1,
    'premium': 2,
    'cold': 3,
    'unknownFutureValue': 4,
}
cloudPcStorageAccountAccessTier = enum.Enum('cloudPcStorageAccountAccessTier', cloudPcStorageAccountAccessTier_data)


cloudPcSupportedRegionStatus_data = {
    'available': 0,
    'restricted': 1,
    'unavailable': 2,
    'unknownFutureValue': 3,
}
cloudPcSupportedRegionStatus = enum.Enum('cloudPcSupportedRegionStatus', cloudPcSupportedRegionStatus_data)


cloudPCTroubleshootReportType_data = {
    'troubleshootDetailsReport': 0,
    'troubleshootTrendCountReport': 1,
    'troubleshootRegionalReport': 2,
    'unknownFutureValue': 3,
    'troubleshootIssueCountReport': 4,
}
cloudPCTroubleshootReportType = enum.Enum('cloudPCTroubleshootReportType', cloudPCTroubleshootReportType_data)


cloudPcUserAccessLevel_data = {
    'unrestricted': 0,
    'restricted': 1,
    'unknownFutureValue': 999,
}
cloudPcUserAccessLevel = enum.Enum('cloudPcUserAccessLevel', cloudPcUserAccessLevel_data)


cloudPcUserAccountType_data = {
    'standardUser': 0,
    'administrator': 1,
    'unknownFutureValue': 999,
}
cloudPcUserAccountType = enum.Enum('cloudPcUserAccountType', cloudPcUserAccountType_data)


frontlineCloudPcAccessState_data = {
    'unassigned': 0,
    'noLicensesAvailable': 1,
    'activationFailed': 2,
    'active': 3,
    'activating': 4,
    'standbyMode': 5,
    'unknownFutureValue': 6,
}
frontlineCloudPcAccessState = enum.Enum('frontlineCloudPcAccessState', frontlineCloudPcAccessState_data)


frontlineCloudPcAvailability_data = {
    'notApplicable': 0,
    'available': 1,
    'notAvailable': 2,
    'unknownFutureValue': 3,
}
frontlineCloudPcAvailability = enum.Enum('frontlineCloudPcAvailability', frontlineCloudPcAvailability_data)


microsoftManagedDesktopType_data = {
    'notManaged': 0,
    'premiumManaged': 1,
    'standardManaged': 2,
    'starterManaged': 3,
    'unknownFutureValue': 999,
}
microsoftManagedDesktopType = enum.Enum('microsoftManagedDesktopType', microsoftManagedDesktopType_data)


restoreTimeRange_data = {
    'before': 0,
    'after': 1,
    'beforeOrAfter': 2,
    'unknownFutureValue': 999,
}
restoreTimeRange = enum.Enum('restoreTimeRange', restoreTimeRange_data)


usageRightState_data = {
    'active': 0,
    'inactive': 1,
    'warning': 2,
    'suspended': 3,
    'unknownFutureValue': 4,
}
usageRightState = enum.Enum('usageRightState', usageRightState_data)


bodyType_data = {
    'text': 0,
    'html': 1,
}
bodyType = enum.Enum('bodyType', bodyType_data)


dataSubjectType_data = {
    'customer': 0,
    'currentEmployee': 1,
    'formerEmployee': 2,
    'prospectiveEmployee': 3,
    'student': 4,
    'teacher': 5,
    'faculty': 6,
    'other': 7,
    'unknownFutureValue': 8,
}
dataSubjectType = enum.Enum('dataSubjectType', dataSubjectType_data)


subjectRightsRequestStage_data = {
    'contentRetrieval': 0,
    'contentReview': 1,
    'generateReport': 2,
    'contentDeletion': 3,
    'caseResolved': 4,
    'contentEstimate': 5,
    'unknownFutureValue': 6,
    'approval': 7,
}
subjectRightsRequestStage = enum.Enum('subjectRightsRequestStage', subjectRightsRequestStage_data)


subjectRightsRequestStageStatus_data = {
    'notStarted': 0,
    'current': 1,
    'completed': 3,
    'failed': 4,
    'unknownFutureValue': 5,
}
subjectRightsRequestStageStatus = enum.Enum('subjectRightsRequestStageStatus', subjectRightsRequestStageStatus_data)


subjectRightsRequestStatus_data = {
    'active': 0,
    'closed': 1,
    'unknownFutureValue': 2,
}
subjectRightsRequestStatus = enum.Enum('subjectRightsRequestStatus', subjectRightsRequestStatus_data)


subjectRightsRequestType_data = {
    'export': 0,
    'delete': 1,
    'access': 2,
    'tagForAction': 3,
    'unknownFutureValue': 4,
}
subjectRightsRequestType = enum.Enum('subjectRightsRequestType', subjectRightsRequestType_data)


authenticationAttributeCollectionInputType_data = {
    'text': 1,
    'radioSingleSelect': 2,
    'checkboxMultiSelect': 3,
    'boolean': 4,
    'unknownFutureValue': 5,
}
authenticationAttributeCollectionInputType = enum.Enum('authenticationAttributeCollectionInputType', authenticationAttributeCollectionInputType_data)


identityProviderState_data = {
    'enabled': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
identityProviderState = enum.Enum('identityProviderState', identityProviderState_data)


identityUserFlowAttributeDataType_data = {
    'string': 1,
    'boolean': 2,
    'int64': 3,
    'stringCollection': 4,
    'dateTime': 5,
    'unknownFutureValue': 6,
}
identityUserFlowAttributeDataType = enum.Enum('identityUserFlowAttributeDataType', identityUserFlowAttributeDataType_data)


identityUserFlowAttributeInputType_data = {
    'textBox': 1,
    'dateTimeDropdown': 2,
    'radioSingleSelect': 3,
    'dropdownSingleSelect': 4,
    'emailBox': 5,
    'checkboxMultiSelect': 6,
}
identityUserFlowAttributeInputType = enum.Enum('identityUserFlowAttributeInputType', identityUserFlowAttributeInputType_data)


identityUserFlowAttributeType_data = {
    'builtIn': 1,
    'custom': 2,
    'required': 3,
    'unknownFutureValue': 4,
}
identityUserFlowAttributeType = enum.Enum('identityUserFlowAttributeType', identityUserFlowAttributeType_data)


oidcResponseType_data = {
    'code': 1,
    'id_token': 2,
    'token': 4,
    'unknownFutureValue': 8,
}
oidcResponseType = enum.Enum('oidcResponseType', oidcResponseType_data)


openIdConnectResponseMode_data = {
    'form_post': 1,
    'query': 2,
    'unknownFutureValue': 3,
}
openIdConnectResponseMode = enum.Enum('openIdConnectResponseMode', openIdConnectResponseMode_data)


openIdConnectResponseTypes_data = {
    'code': 1,
    'id_token': 2,
    'token': 4,
}
openIdConnectResponseTypes = enum.Enum('openIdConnectResponseTypes', openIdConnectResponseTypes_data)


trustFrameworkKeyStatus_data = {
    'enabled': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
}
trustFrameworkKeyStatus = enum.Enum('trustFrameworkKeyStatus', trustFrameworkKeyStatus_data)


userFlowType_data = {
    'signUp': 1,
    'signIn': 2,
    'signUpOrSignIn': 3,
    'passwordReset': 4,
    'profileUpdate': 5,
    'resourceOwner': 6,
    'unknownFutureValue': 7,
}
userFlowType = enum.Enum('userFlowType', userFlowType_data)


userType_data = {
    'member': 0,
    'guest': 1,
    'unknownFutureValue': 2,
}
userType = enum.Enum('userType', userType_data)


alignment_data = {
    'left': 0,
    'right': 1,
    'center': 2,
}
alignment = enum.Enum('alignment', alignment_data)


applicationMode_data = {
    'manual': 0,
    'automatic': 1,
    'recommended': 2,
}
applicationMode = enum.Enum('applicationMode', applicationMode_data)


classificationMethod_data = {
    'patternMatch': 0,
    'exactDataMatch': 1,
    'fingerprint': 2,
    'machineLearning': 3,
}
classificationMethod = enum.Enum('classificationMethod', classificationMethod_data)


component_data = {
    'Label': 0,
}
component = enum.Enum('component', component_data)


encryptWith_data = {
    'template': 0,
    'userDefinedRights': 1,
}
encryptWith = enum.Enum('encryptWith', encryptWith_data)


groupPrivacy_data = {
    'unspecified': 0,
    'public': 1,
    'private': 2,
    'unknownFutureValue': 3,
}
groupPrivacy = enum.Enum('groupPrivacy', groupPrivacy_data)


lobbyBypassScope_data = {
    'organizer': 0,
    'organization': 1,
    'organizationAndFederated': 2,
    'everyone': 3,
    'unknownFutureValue': 4,
    'invited': 5,
    'organizationExcludingGuests': 6,
}
lobbyBypassScope = enum.Enum('lobbyBypassScope', lobbyBypassScope_data)


meetingChatMode_data = {
    'enabled': 0,
    'disabled': 1,
    'limited': 2,
    'unknownFutureValue': 3,
}
meetingChatMode = enum.Enum('meetingChatMode', meetingChatMode_data)


mlClassificationMatchTolerance_data = {
    'exact': 1,
    'near': 2,
}
mlClassificationMatchTolerance = enum.Enum('mlClassificationMatchTolerance', mlClassificationMatchTolerance_data)


onlineMeetingForwarders_data = {
    'everyone': 0,
    'organizer': 1,
    'unknownFutureValue': 2,
}
onlineMeetingForwarders = enum.Enum('onlineMeetingForwarders', onlineMeetingForwarders_data)


onlineMeetingPresenters_data = {
    'everyone': 0,
    'organization': 1,
    'roleIsPresenter': 2,
    'organizer': 3,
    'unknownFutureValue': 4,
}
onlineMeetingPresenters = enum.Enum('onlineMeetingPresenters', onlineMeetingPresenters_data)


pageOrientation_data = {
    'horizontal': 0,
    'diagonal': 1,
}
pageOrientation = enum.Enum('pageOrientation', pageOrientation_data)


restrictionAction_data = {
    'warn': 0,
    'audit': 1,
    'block': 2,
}
restrictionAction = enum.Enum('restrictionAction', restrictionAction_data)


restrictionTrigger_data = {
    'copyPaste': 0,
    'copyToNetworkShare': 1,
    'copyToRemovableMedia': 2,
    'screenCapture': 3,
    'print': 4,
    'cloudEgress': 5,
    'unallowedApps': 6,
}
restrictionTrigger = enum.Enum('restrictionTrigger', restrictionTrigger_data)


ruleMode_data = {
    'audit': 1,
    'auditAndNotify': 2,
    'enforce': 3,
    'pendingDeletion': 4,
    'test': 5,
}
ruleMode = enum.Enum('ruleMode', ruleMode_data)


sensitiveTypeScope_data = {
    'fullDocument': 1,
    'partialDocument': 2,
}
sensitiveTypeScope = enum.Enum('sensitiveTypeScope', sensitiveTypeScope_data)


sensitiveTypeSource_data = {
    'outOfBox': 0,
    'tenant': 1,
}
sensitiveTypeSource = enum.Enum('sensitiveTypeSource', sensitiveTypeSource_data)


sensitivityLabelTarget_data = {
    'email': 1,
    'site': 2,
    'unifiedGroup': 4,
    'teamwork': 8,
    'unknownFutureValue': 16,
}
sensitivityLabelTarget = enum.Enum('sensitivityLabelTarget', sensitivityLabelTarget_data)


siteAccessType_data = {
    'block': 0,
    'full': 1,
    'limited': 2,
}
siteAccessType = enum.Enum('siteAccessType', siteAccessType_data)


multiFactorAuthConfiguration_data = {
    'notRequired': 0,
    'required': 1,
    'unknownFutureValue': 2,
}
multiFactorAuthConfiguration = enum.Enum('multiFactorAuthConfiguration', multiFactorAuthConfiguration_data)


allowInvitesFrom_data = {
    'none': 0,
    'adminsAndGuestInviters': 1,
    'adminsGuestInvitersAndAllMembers': 2,
    'everyone': 3,
    'unknownFutureValue': 4,
}
allowInvitesFrom = enum.Enum('allowInvitesFrom', allowInvitesFrom_data)


appCredentialRestrictionType_data = {
    'passwordAddition': 0,
    'passwordLifetime': 1,
    'symmetricKeyAddition': 2,
    'symmetricKeyLifetime': 3,
    'customPasswordAddition': 4,
    'unknownFutureValue': 99,
}
appCredentialRestrictionType = enum.Enum('appCredentialRestrictionType', appCredentialRestrictionType_data)


appKeyCredentialRestrictionType_data = {
    'asymmetricKeyLifetime': 0,
    'trustedCertificateAuthority': 1,
    'unknownFutureValue': 99,
}
appKeyCredentialRestrictionType = enum.Enum('appKeyCredentialRestrictionType', appKeyCredentialRestrictionType_data)


appManagementRestrictionState_data = {
    'enabled': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
appManagementRestrictionState = enum.Enum('appManagementRestrictionState', appManagementRestrictionState_data)


authenticationProtocol_data = {
    'wsFed': 0,
    'saml': 1,
    'unknownFutureValue': 2,
}
authenticationProtocol = enum.Enum('authenticationProtocol', authenticationProtocol_data)


b2bIdentityProvidersType_data = {
    'azureActiveDirectory': 1,
    'externalFederation': 2,
    'socialIdentityProviders': 3,
    'emailOneTimePasscode': 4,
    'microsoftAccount': 5,
    'defaultConfiguredIdp': 6,
    'unknownFutureValue': 7,
}
b2bIdentityProvidersType = enum.Enum('b2bIdentityProvidersType', b2bIdentityProvidersType_data)


certificateAuthorityType_data = {
    'root': 0,
    'intermediate': 1,
    'unknownFutureValue': 2,
}
certificateAuthorityType = enum.Enum('certificateAuthorityType', certificateAuthorityType_data)


claimConditionUserType_data = {
    'any': 0,
    'members': 1,
    'allGuests': 2,
    'aadGuests': 3,
    'externalGuests': 4,
    'unknownFutureValue': 5,
}
claimConditionUserType = enum.Enum('claimConditionUserType', claimConditionUserType_data)


crossTenantAccessPolicyTargetConfigurationAccessType_data = {
    'allowed': 1,
    'blocked': 2,
    'unknownFutureValue': 3,
}
crossTenantAccessPolicyTargetConfigurationAccessType = enum.Enum('crossTenantAccessPolicyTargetConfigurationAccessType', crossTenantAccessPolicyTargetConfigurationAccessType_data)


crossTenantAccessPolicyTargetType_data = {
    'user': 1,
    'group': 2,
    'application': 3,
    'unknownFutureValue': 4,
}
crossTenantAccessPolicyTargetType = enum.Enum('crossTenantAccessPolicyTargetType', crossTenantAccessPolicyTargetType_data)


customSecurityAttributeComparisonOperator_data = {
    'equals': 1,
    'unknownFutureValue': 2,
}
customSecurityAttributeComparisonOperator = enum.Enum('customSecurityAttributeComparisonOperator', customSecurityAttributeComparisonOperator_data)


federatedIdpMfaBehavior_data = {
    'acceptIfMfaDoneByFederatedIdp': 0,
    'enforceMfaByFederatedIdp': 1,
    'rejectMfaByFederatedIdp': 2,
    'unknownFutureValue': 3,
}
federatedIdpMfaBehavior = enum.Enum('federatedIdpMfaBehavior', federatedIdpMfaBehavior_data)


filterType_data = {
    'prefix': 0,
    'suffix': 1,
    'contains': 2,
    'unknownFutureValue': 3,
}
filterType = enum.Enum('filterType', filterType_data)


labelKind_data = {
    'all': 1,
    'enumerated': 2,
    'unknownFutureValue': 3,
}
labelKind = enum.Enum('labelKind', labelKind_data)


layoutTemplateType_data = {
    'default': 0,
    'verticalSplit': 1,
    'unknownFutureValue': 10,
}
layoutTemplateType = enum.Enum('layoutTemplateType', layoutTemplateType_data)


matchOn_data = {
    'displayName': 0,
    'samAccountName': 1,
    'unknownFutureValue': 2,
}
matchOn = enum.Enum('matchOn', matchOn_data)


multiTenantOrganizationMemberProcessingStatus_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
multiTenantOrganizationMemberProcessingStatus = enum.Enum('multiTenantOrganizationMemberProcessingStatus', multiTenantOrganizationMemberProcessingStatus_data)


multiTenantOrganizationMemberRole_data = {
    'owner': 0,
    'member': 1,
    'unknownFutureValue': 2,
}
multiTenantOrganizationMemberRole = enum.Enum('multiTenantOrganizationMemberRole', multiTenantOrganizationMemberRole_data)


multiTenantOrganizationMemberState_data = {
    'pending': 0,
    'active': 1,
    'removed': 2,
    'unknownFutureValue': 3,
}
multiTenantOrganizationMemberState = enum.Enum('multiTenantOrganizationMemberState', multiTenantOrganizationMemberState_data)


multiTenantOrganizationState_data = {
    'active': 0,
    'inactive': 1,
    'unknownFutureValue': 2,
}
multiTenantOrganizationState = enum.Enum('multiTenantOrganizationState', multiTenantOrganizationState_data)


nativeAuthenticationApisEnabled_data = {
    'none': 0,
    'all': 1,
    'unknownFutureValue': 2,
}
nativeAuthenticationApisEnabled = enum.Enum('nativeAuthenticationApisEnabled', nativeAuthenticationApisEnabled_data)


onPremisesDirectorySynchronizationDeletionPreventionType_data = {
    'disabled': 0,
    'enabledForCount': 1,
    'enabledForPercentage': 2,
    'unknownFutureValue': 3,
}
onPremisesDirectorySynchronizationDeletionPreventionType = enum.Enum('onPremisesDirectorySynchronizationDeletionPreventionType', onPremisesDirectorySynchronizationDeletionPreventionType_data)


partnerTenantType_data = {
    'microsoftSupport': 1,
    'syndicatePartner': 2,
    'breadthPartner': 3,
    'breadthPartnerDelegatedAdmin': 4,
    'resellerPartnerDelegatedAdmin': 5,
    'valueAddedResellerPartnerDelegatedAdmin': 6,
    'unknownFutureValue': 7,
}
partnerTenantType = enum.Enum('partnerTenantType', partnerTenantType_data)


permissionClassificationType_data = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'unknownFutureValue': 4,
}
permissionClassificationType = enum.Enum('permissionClassificationType', permissionClassificationType_data)


permissionKind_data = {
    'all': 1,
    'enumerated': 2,
    'allPermissionsOnResourceApp': 3,
    'unknownFutureValue': 4,
}
permissionKind = enum.Enum('permissionKind', permissionKind_data)


permissionType_data = {
    'application': 1,
    'delegated': 2,
    'delegatedUserConsentable': 3,
}
permissionType = enum.Enum('permissionType', permissionType_data)


perUserMfaState_data = {
    'disabled': 0,
    'enforced': 1,
    'enabled': 2,
    'unknownFutureValue': 3,
}
perUserMfaState = enum.Enum('perUserMfaState', perUserMfaState_data)


promptLoginBehavior_data = {
    'translateToFreshPasswordAuthentication': 0,
    'nativeSupport': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
promptLoginBehavior = enum.Enum('promptLoginBehavior', promptLoginBehavior_data)


resourceScopeType_data = {
    'group': 1,
    'chat': 2,
    'tenant': 3,
    'unknownFutureValue': 4,
    'team': 5,
}
resourceScopeType = enum.Enum('resourceScopeType', resourceScopeType_data)


rootDomains_data = {
    'none': 0,
    'all': 1,
    'allFederated': 2,
    'allManaged': 3,
    'enumerated': 4,
    'allManagedAndEnumeratedFederated': 5,
    'unknownFutureValue': 6,
}
rootDomains = enum.Enum('rootDomains', rootDomains_data)


samlAttributeNameFormat_data = {
    'unspecified': 0,
    'uri': 1,
    'basic': 2,
    'unknownFutureValue': 3,
}
samlAttributeNameFormat = enum.Enum('samlAttributeNameFormat', samlAttributeNameFormat_data)


samlNameIDFormat_data = {
    'default': 0,
    'unspecified': 1,
    'emailAddress': 2,
    'windowsDomainQualifiedName': 3,
    'persistent': 4,
    'unknownFutureValue': 5,
}
samlNameIDFormat = enum.Enum('samlNameIDFormat', samlNameIDFormat_data)


samlSLOBindingType_data = {
    'httpRedirect': 0,
    'httpPost': 1,
    'unknownFutureValue': 2,
}
samlSLOBindingType = enum.Enum('samlSLOBindingType', samlSLOBindingType_data)


templateApplicationLevel_data = {
    'none': 0,
    'newPartners': 1,
    'existingPartners': 2,
    'unknownFutureValue': 4,
}
templateApplicationLevel = enum.Enum('templateApplicationLevel', templateApplicationLevel_data)


tlsClientRegistrationMetadata_data = {
    'tls_client_auth_subject_dn': 0,
    'tls_client_auth_san_dns': 1,
    'tls_client_auth_san_uri': 2,
    'tls_client_auth_san_ip': 3,
    'tls_client_auth_san_email': 4,
    'unknownFutureValue': 5,
}
tlsClientRegistrationMetadata = enum.Enum('tlsClientRegistrationMetadata', tlsClientRegistrationMetadata_data)


tokenFormat_data = {
    'saml': 0,
    'jwt': 1,
    'unknownFutureValue': 2,
}
tokenFormat = enum.Enum('tokenFormat', tokenFormat_data)


transformationExtractType_data = {
    'prefix': 1,
    'suffix': 2,
    'unknownFutureValue': 3,
}
transformationExtractType = enum.Enum('transformationExtractType', transformationExtractType_data)


transformationTrimType_data = {
    'leading': 1,
    'trailing': 2,
    'leadingAndTrailing': 3,
    'unknownFutureValue': 4,
}
transformationTrimType = enum.Enum('transformationTrimType', transformationTrimType_data)


weakAlgorithms_data = {
    'rsaSha1': 1,
    'unknownFutureValue': 2,
}
weakAlgorithms = enum.Enum('weakAlgorithms', weakAlgorithms_data)


browserSharedCookieSourceEnvironment_data = {
    'microsoftEdge': 0,
    'internetExplorer11': 1,
    'both': 2,
    'unknownFutureValue': 3,
}
browserSharedCookieSourceEnvironment = enum.Enum('browserSharedCookieSourceEnvironment', browserSharedCookieSourceEnvironment_data)


browserSharedCookieStatus_data = {
    'published': 0,
    'pendingAdd': 1,
    'pendingEdit': 2,
    'pendingDelete': 3,
    'unknownFutureValue': 4,
}
browserSharedCookieStatus = enum.Enum('browserSharedCookieStatus', browserSharedCookieStatus_data)


browserSiteCompatibilityMode_data = {
    'default': 0,
    'internetExplorer8Enterprise': 1,
    'internetExplorer7Enterprise': 2,
    'internetExplorer11': 3,
    'internetExplorer10': 4,
    'internetExplorer9': 5,
    'internetExplorer8': 6,
    'internetExplorer7': 7,
    'internetExplorer5': 8,
    'unknownFutureValue': 9,
}
browserSiteCompatibilityMode = enum.Enum('browserSiteCompatibilityMode', browserSiteCompatibilityMode_data)


browserSiteListStatus_data = {
    'draft': 0,
    'published': 1,
    'pending': 2,
    'unknownFutureValue': 3,
}
browserSiteListStatus = enum.Enum('browserSiteListStatus', browserSiteListStatus_data)


browserSiteMergeType_data = {
    'noMerge': 0,
    'default': 1,
    'unknownFutureValue': 2,
}
browserSiteMergeType = enum.Enum('browserSiteMergeType', browserSiteMergeType_data)


browserSiteStatus_data = {
    'published': 0,
    'pendingAdd': 1,
    'pendingEdit': 2,
    'pendingDelete': 3,
    'unknownFutureValue': 4,
}
browserSiteStatus = enum.Enum('browserSiteStatus', browserSiteStatus_data)


browserSiteTargetEnvironment_data = {
    'internetExplorerMode': 0,
    'internetExplorer11': 1,
    'microsoftEdge': 2,
    'configurable': 3,
    'none': 4,
    'unknownFutureValue': 5,
}
browserSiteTargetEnvironment = enum.Enum('browserSiteTargetEnvironment', browserSiteTargetEnvironment_data)


responseEmotionType_data = {
    'none': 0,
    'confident': 1,
    'excited': 2,
    'happy': 3,
    'motivated': 4,
    'peaceful': 5,
    'ambitious': 6,
    'cheerful': 7,
    'comfortable': 8,
    'creative': 9,
    'determined': 10,
    'energized': 11,
    'focused': 12,
    'fulfilled': 13,
    'grateful': 14,
    'included': 15,
    'inspired': 16,
    'optimistic': 17,
    'proud': 18,
    'successful': 19,
    'valuable': 20,
    'annoyed': 21,
    'bored': 22,
    'calm': 23,
    'confused': 24,
    'glad': 25,
    'content': 26,
    'pensive': 27,
    'reserved': 28,
    'restless': 29,
    'shocked': 30,
    'tired': 31,
    'angry': 32,
    'depressed': 33,
    'exhausted': 34,
    'lonely': 35,
    'nervous': 36,
    'anxious': 37,
    'apathetic': 38,
    'concerned': 39,
    'disappointed': 40,
    'frightened': 41,
    'frustrated': 42,
    'hopeless': 43,
    'hurt': 44,
    'jealous': 45,
    'miserable': 46,
    'overwhelmed': 47,
    'skeptical': 48,
    'stressed': 49,
    'stuck': 50,
    'worthless': 51,
    'awed': 52,
    'ashamed': 53,
    'curious': 54,
    'sensitive': 55,
    'sad': 56,
    'unknownFutureValue': 57,
}
responseEmotionType = enum.Enum('responseEmotionType', responseEmotionType_data)


responseFeedbackType_data = {
    'none': 0,
    'notDetected': 1,
    'veryUnpleasant': 2,
    'unpleasant': 3,
    'neutral': 4,
    'pleasant': 5,
    'veryPleasant': 6,
    'unknownFutureValue': 7,
}
responseFeedbackType = enum.Enum('responseFeedbackType', responseFeedbackType_data)


educationAddedStudentAction_data = {
    'none': 0,
    'assignIfOpen': 1,
    'unknownFutureValue': 2,
}
educationAddedStudentAction = enum.Enum('educationAddedStudentAction', educationAddedStudentAction_data)


educationAddToCalendarOptions_data = {
    'none': 0,
    'studentsAndPublisher': 1,
    'studentsAndTeamOwners': 2,
    'unknownFutureValue': 3,
    'studentsOnly': 4,
}
educationAddToCalendarOptions = enum.Enum('educationAddToCalendarOptions', educationAddToCalendarOptions_data)


educationAssignmentStatus_data = {
    'draft': 0,
    'published': 1,
    'assigned': 2,
    'unknownFutureValue': 3,
    'inactive': 4,
}
educationAssignmentStatus = enum.Enum('educationAssignmentStatus', educationAssignmentStatus_data)


educationFeedbackResourceOutcomeStatus_data = {
    'notPublished': 0,
    'pendingPublish': 1,
    'published': 2,
    'failedPublish': 3,
    'unknownFutureValue': 4,
}
educationFeedbackResourceOutcomeStatus = enum.Enum('educationFeedbackResourceOutcomeStatus', educationFeedbackResourceOutcomeStatus_data)


educationModuleStatus_data = {
    'draft': 0,
    'published': 1,
    'unknownFutureValue': 2,
}
educationModuleStatus = enum.Enum('educationModuleStatus', educationModuleStatus_data)


educationSubmissionStatus_data = {
    'working': 0,
    'submitted': 1,
    'released': 2,
    'returned': 3,
    'unknownFutureValue': 4,
    'reassigned': 5,
    'excused': 6,
}
educationSubmissionStatus = enum.Enum('educationSubmissionStatus', educationSubmissionStatus_data)


contactRelationship_data = {
    'parent': 0,
    'relative': 1,
    'aide': 2,
    'doctor': 3,
    'guardian': 4,
    'child': 5,
    'other': 6,
    'unknownFutureValue': 7,
}
contactRelationship = enum.Enum('contactRelationship', contactRelationship_data)


educationExternalSource_data = {
    'sis': 0,
    'manual': 1,
    'unknownFutureValue': 2,
    'lms': 3,
}
educationExternalSource = enum.Enum('educationExternalSource', educationExternalSource_data)


educationGender_data = {
    'female': 0,
    'male': 1,
    'other': 2,
    'unknownFutureValue': 3,
}
educationGender = enum.Enum('educationGender', educationGender_data)


educationUserRole_data = {
    'student': 0,
    'teacher': 1,
    'none': 2,
    'unknownFutureValue': 3,
    'faculty': 4,
}
educationUserRole = enum.Enum('educationUserRole', educationUserRole_data)


artifactRestoreStatus_data = {
    'added': 0,
    'scheduling': 1,
    'scheduled': 2,
    'inProgress': 3,
    'succeeded': 4,
    'failed': 5,
    'unknownFutureValue': 6,
}
artifactRestoreStatus = enum.Enum('artifactRestoreStatus', artifactRestoreStatus_data)


backupServiceConsumer_data = {
    'unknown': 0,
    'firstparty': 1,
    'thirdparty': 2,
    'unknownFutureValue': 3,
}
backupServiceConsumer = enum.Enum('backupServiceConsumer', backupServiceConsumer_data)


backupServiceStatus_data = {
    'disabled': 0,
    'enabled': 1,
    'protectionChangeLocked': 2,
    'restoreLocked': 3,
    'unknownFutureValue': 4,
}
backupServiceStatus = enum.Enum('backupServiceStatus', backupServiceStatus_data)


destinationType_data = {
    'new': 0,
    'inPlace': 1,
    'unknownFutureValue': 2,
}
destinationType = enum.Enum('destinationType', destinationType_data)


disableReason_data = {
    'none': 0,
    'invalidBillingProfile': 1,
    'userRequested': 2,
    'unknownFutureValue': 3,
    'controllerServiceAppDeleted': 4,
}
disableReason = enum.Enum('disableReason', disableReason_data)


mailboxType_data = {
    'unknown': 0,
    'user': 1,
    'shared': 2,
    'unknownFutureValue': 3,
}
mailboxType = enum.Enum('mailboxType', mailboxType_data)


protectionPolicyStatus_data = {
    'inactive': 0,
    'activeWithErrors': 1,
    'updating': 2,
    'active': 3,
    'unknownFutureValue': 4,
}
protectionPolicyStatus = enum.Enum('protectionPolicyStatus', protectionPolicyStatus_data)


protectionRuleStatus_data = {
    'draft': 0,
    'active': 1,
    'completed': 2,
    'completedWithErrors': 3,
    'unknownFutureValue': 4,
    'updateRequested': 5,
    'deleteRequested': 6,
}
protectionRuleStatus = enum.Enum('protectionRuleStatus', protectionRuleStatus_data)


protectionSource_data = {
    'none': 0,
    'manual': 1,
    'dynamicRule': 2,
    'unknownFutureValue': 4,
}
protectionSource = enum.Enum('protectionSource', protectionSource_data)


protectionUnitsBulkJobStatus_data = {
    'unknown': 0,
    'active': 1,
    'completed': 2,
    'completedWithErrors': 3,
    'unknownFutureValue': 4,
}
protectionUnitsBulkJobStatus = enum.Enum('protectionUnitsBulkJobStatus', protectionUnitsBulkJobStatus_data)


protectionUnitStatus_data = {
    'protectRequested': 0,
    'protected': 1,
    'unprotectRequested': 2,
    'unprotected': 3,
    'removeRequested': 4,
    'unknownFutureValue': 5,
}
protectionUnitStatus = enum.Enum('protectionUnitStatus', protectionUnitStatus_data)


restorableArtifact_data = {
    'message': 0,
    'unknownFutureValue': 1,
}
restorableArtifact = enum.Enum('restorableArtifact', restorableArtifact_data)


restoreArtifactsBulkRequestStatus_data = {
    'unknown': 0,
    'active': 1,
    'completed': 2,
    'completedWithErrors': 3,
    'unknownFutureValue': 4,
}
restoreArtifactsBulkRequestStatus = enum.Enum('restoreArtifactsBulkRequestStatus', restoreArtifactsBulkRequestStatus_data)


restoreJobType_data = {
    'standard': 0,
    'bulk': 1,
    'unknownFutureValue': 2,
}
restoreJobType = enum.Enum('restoreJobType', restoreJobType_data)


restorePointPreference_data = {
    'latest': 0,
    'oldest': 1,
    'unknownFutureValue': 2,
}
restorePointPreference = enum.Enum('restorePointPreference', restorePointPreference_data)


restorePointTags_data = {
    'none': 0,
    'fastRestore': 1,
    'unknownFutureValue': 2,
}
restorePointTags = enum.Enum('restorePointTags', restorePointTags_data)


restoreSessionStatus_data = {
    'draft': 0,
    'activating': 1,
    'active': 2,
    'completedWithError': 3,
    'completed': 4,
    'unknownFutureValue': 5,
    'failed': 6,
}
restoreSessionStatus = enum.Enum('restoreSessionStatus', restoreSessionStatus_data)


serviceAppStatus_data = {
    'inactive': 0,
    'active': 1,
    'pendingActive': 2,
    'pendingInactive': 3,
    'unknownFutureValue': 4,
}
serviceAppStatus = enum.Enum('serviceAppStatus', serviceAppStatus_data)


workbookOperationStatus_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
}
workbookOperationStatus = enum.Enum('workbookOperationStatus', workbookOperationStatus_data)


activityDomain_data = {
    'unknown': 0,
    'work': 1,
    'personal': 2,
    'unrestricted': 3,
}
activityDomain = enum.Enum('activityDomain', activityDomain_data)


attendeeType_data = {
    'required': 0,
    'optional': 1,
    'resource': 2,
}
attendeeType = enum.Enum('attendeeType', attendeeType_data)


freeBusyStatus_data = {
    'unknown': -1,
    'free': 0,
    'tentative': 1,
    'busy': 2,
    'oof': 3,
    'workingElsewhere': 4,
}
freeBusyStatus = enum.Enum('freeBusyStatus', freeBusyStatus_data)


bookingType_data = {
    'unknown': 0,
    'standard': 1,
    'reserved': 2,
}
bookingType = enum.Enum('bookingType', bookingType_data)


workplaceSensorEventType_data = {
    'badgeIn': 0,
    'badgeOut': 1,
    'unknownFutureValue': 2,
}
workplaceSensorEventType = enum.Enum('workplaceSensorEventType', workplaceSensorEventType_data)


workplaceSensorType_data = {
    'occupancy': 0,
    'peopleCount': 1,
    'inferredOccupancy': 2,
    'heartbeat': 3,
    'badge': 4,
    'unknownFutureValue': 5,
}
workplaceSensorType = enum.Enum('workplaceSensorType', workplaceSensorType_data)


attachmentType_data = {
    'file': 0,
    'item': 1,
    'reference': 2,
}
attachmentType = enum.Enum('attachmentType', attachmentType_data)


automaticRepliesStatus_data = {
    'disabled': 0,
    'alwaysEnabled': 1,
    'scheduled': 2,
}
automaticRepliesStatus = enum.Enum('automaticRepliesStatus', automaticRepliesStatus_data)


calendarColor_data = {
    'auto': -1,
    'lightBlue': 0,
    'lightGreen': 1,
    'lightOrange': 2,
    'lightGray': 3,
    'lightYellow': 4,
    'lightTeal': 5,
    'lightPink': 6,
    'lightBrown': 7,
    'lightRed': 8,
    'maxColor': 9,
}
calendarColor = enum.Enum('calendarColor', calendarColor_data)


calendarRoleType_data = {
    'none': 0,
    'freeBusyRead': 1,
    'limitedRead': 2,
    'read': 3,
    'write': 4,
    'delegateWithoutPrivateEventAccess': 5,
    'delegateWithPrivateEventAccess': 6,
    'custom': 7,
}
calendarRoleType = enum.Enum('calendarRoleType', calendarRoleType_data)


calendarSharingAction_data = {
    'accept': 0,
    'acceptAndViewCalendar': 1,
    'viewCalendar': 2,
    'addThisCalendar': 3,
}
calendarSharingAction = enum.Enum('calendarSharingAction', calendarSharingAction_data)


calendarSharingActionImportance_data = {
    'primary': 0,
    'secondary': 1,
}
calendarSharingActionImportance = enum.Enum('calendarSharingActionImportance', calendarSharingActionImportance_data)


calendarSharingActionType_data = {
    'accept': 0,
}
calendarSharingActionType = enum.Enum('calendarSharingActionType', calendarSharingActionType_data)


categoryColor_data = {
    'none': -1,
    'preset0': 0,
    'preset1': 1,
    'preset2': 2,
    'preset3': 3,
    'preset4': 4,
    'preset5': 5,
    'preset6': 6,
    'preset7': 7,
    'preset8': 8,
    'preset9': 9,
    'preset10': 10,
    'preset11': 11,
    'preset12': 12,
    'preset13': 13,
    'preset14': 14,
    'preset15': 15,
    'preset16': 16,
    'preset17': 17,
    'preset18': 18,
    'preset19': 19,
    'preset20': 20,
    'preset21': 21,
    'preset22': 22,
    'preset23': 23,
    'preset24': 24,
}
categoryColor = enum.Enum('categoryColor', categoryColor_data)


delegateMeetingMessageDeliveryOptions_data = {
    'sendToDelegateAndInformationToPrincipal': 0,
    'sendToDelegateAndPrincipal': 1,
    'sendToDelegateOnly': 2,
}
delegateMeetingMessageDeliveryOptions = enum.Enum('delegateMeetingMessageDeliveryOptions', delegateMeetingMessageDeliveryOptions_data)


emailType_data = {
    'unknown': 0,
    'work': 1,
    'personal': 2,
    'main': 3,
    'other': 4,
}
emailType = enum.Enum('emailType', emailType_data)


eventType_data = {
    'singleInstance': 0,
    'occurrence': 1,
    'exception': 2,
    'seriesMaster': 3,
}
eventType = enum.Enum('eventType', eventType_data)


exchangeIdFormat_data = {
    'entryId': 0,
    'ewsId': 1,
    'immutableEntryId': 2,
    'restId': 3,
    'restImmutableEntryId': 4,
}
exchangeIdFormat = enum.Enum('exchangeIdFormat', exchangeIdFormat_data)


externalAudienceScope_data = {
    'none': 0,
    'contactsOnly': 1,
    'all': 2,
}
externalAudienceScope = enum.Enum('externalAudienceScope', externalAudienceScope_data)


followupFlagStatus_data = {
    'notFlagged': 0,
    'complete': 1,
    'flagged': 2,
}
followupFlagStatus = enum.Enum('followupFlagStatus', followupFlagStatus_data)


groupAccessType_data = {
    'none': 0,
    'private': 1,
    'secret': 2,
    'public': 3,
}
groupAccessType = enum.Enum('groupAccessType', groupAccessType_data)


importance_data = {
    'low': 0,
    'normal': 1,
    'high': 2,
}
importance = enum.Enum('importance', importance_data)


inferenceClassificationType_data = {
    'focused': 0,
    'other': 1,
}
inferenceClassificationType = enum.Enum('inferenceClassificationType', inferenceClassificationType_data)


mailboxRecipientType_data = {
    'unknown': 0,
    'user': 1,
    'linked': 2,
    'shared': 3,
    'room': 4,
    'equipment': 5,
    'others': 6,
}
mailboxRecipientType = enum.Enum('mailboxRecipientType', mailboxRecipientType_data)


mailFolderOperationStatus_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
mailFolderOperationStatus = enum.Enum('mailFolderOperationStatus', mailFolderOperationStatus_data)


mailTipsType_data = {
    'automaticReplies': 1,
    'mailboxFullStatus': 2,
    'customMailTip': 4,
    'externalMemberCount': 8,
    'totalMemberCount': 16,
    'maxMessageSize': 32,
    'deliveryRestriction': 64,
    'moderationStatus': 128,
    'recipientScope': 256,
    'recipientSuggestions': 512,
}
mailTipsType = enum.Enum('mailTipsType', mailTipsType_data)


meetingMessageType_data = {
    'none': 0,
    'meetingRequest': 1,
    'meetingCancelled': 2,
    'meetingAccepted': 3,
    'meetingTentativelyAccepted': 4,
    'meetingDeclined': 5,
}
meetingMessageType = enum.Enum('meetingMessageType', meetingMessageType_data)


meetingRequestType_data = {
    'none': 0,
    'newMeetingRequest': 1,
    'fullUpdate': 65536,
    'informationalUpdate': 131072,
    'silentUpdate': 262144,
    'outdated': 524288,
    'principalWantsCopy': 1048576,
}
meetingRequestType = enum.Enum('meetingRequestType', meetingRequestType_data)


messageActionFlag_data = {
    'any': 0,
    'call': 1,
    'doNotForward': 2,
    'followUp': 3,
    'fyi': 4,
    'forward': 5,
    'noResponseNecessary': 6,
    'read': 7,
    'reply': 8,
    'replyToAll': 9,
    'review': 10,
}
messageActionFlag = enum.Enum('messageActionFlag', messageActionFlag_data)


onlineMeetingProviderType_data = {
    'unknown': 0,
    'skypeForBusiness': 1,
    'skypeForConsumer': 2,
    'teamsForBusiness': 3,
}
onlineMeetingProviderType = enum.Enum('onlineMeetingProviderType', onlineMeetingProviderType_data)


recipientScopeType_data = {
    'none': 0,
    'internal': 1,
    'external': 2,
    'externalPartner': 4,
    'externalNonPartner': 8,
}
recipientScopeType = enum.Enum('recipientScopeType', recipientScopeType_data)


recurrencePatternType_data = {
    'daily': 0,
    'weekly': 1,
    'absoluteMonthly': 2,
    'relativeMonthly': 3,
    'absoluteYearly': 4,
    'relativeYearly': 5,
}
recurrencePatternType = enum.Enum('recurrencePatternType', recurrencePatternType_data)


recurrenceRangeType_data = {
    'endDate': 0,
    'noEnd': 1,
    'numbered': 2,
}
recurrenceRangeType = enum.Enum('recurrenceRangeType', recurrenceRangeType_data)


referenceAttachmentPermission_data = {
    'other': 0,
    'view': 1,
    'edit': 2,
    'anonymousView': 3,
    'anonymousEdit': 4,
    'organizationView': 5,
    'organizationEdit': 6,
}
referenceAttachmentPermission = enum.Enum('referenceAttachmentPermission', referenceAttachmentPermission_data)


referenceAttachmentProvider_data = {
    'other': 0,
    'oneDriveBusiness': 1,
    'oneDriveConsumer': 2,
    'dropbox': 3,
}
referenceAttachmentProvider = enum.Enum('referenceAttachmentProvider', referenceAttachmentProvider_data)


responseType_data = {
    'none': 0,
    'organizer': 1,
    'tentativelyAccepted': 2,
    'accepted': 3,
    'declined': 4,
    'notResponded': 5,
}
responseType = enum.Enum('responseType', responseType_data)


sensitivity_data = {
    'normal': 0,
    'personal': 1,
    'private': 2,
    'confidential': 3,
}
sensitivity = enum.Enum('sensitivity', sensitivity_data)


taskStatus_data = {
    'notStarted': 0,
    'inProgress': 1,
    'completed': 2,
    'waitingOnOthers': 3,
    'deferred': 4,
}
taskStatus = enum.Enum('taskStatus', taskStatus_data)


timeZoneStandard_data = {
    'windows': 0,
    'iana': 1,
}
timeZoneStandard = enum.Enum('timeZoneStandard', timeZoneStandard_data)


userPurpose_data = {
    'unknown': 0,
    'user': 1,
    'linked': 2,
    'shared': 3,
    'room': 4,
    'equipment': 5,
    'others': 6,
    'unknownFutureValue': 7,
}
userPurpose = enum.Enum('userPurpose', userPurpose_data)


websiteType_data = {
    'other': 0,
    'home': 1,
    'work': 2,
    'blog': 3,
    'profile': 4,
}
websiteType = enum.Enum('websiteType', websiteType_data)


weekIndex_data = {
    'first': 0,
    'second': 1,
    'third': 2,
    'fourth': 3,
    'last': 4,
}
weekIndex = enum.Enum('weekIndex', weekIndex_data)


fileStorageContainerOwnershipType_data = {
    'tenantOwned': 0,
    'userOwned': 1,
    'unknownFutureValue': 2,
}
fileStorageContainerOwnershipType = enum.Enum('fileStorageContainerOwnershipType', fileStorageContainerOwnershipType_data)


fileStorageContainerStatus_data = {
    'inactive': 0,
    'active': 1,
    'unknownFutureValue': 2,
}
fileStorageContainerStatus = enum.Enum('fileStorageContainerStatus', fileStorageContainerStatus_data)


imageTaggingChoice_data = {
    'disabled': 0,
    'basic': 1,
    'enhanced': 2,
    'unknownFutureValue': 3,
}
imageTaggingChoice = enum.Enum('imageTaggingChoice', imageTaggingChoice_data)


sharingCapabilities_data = {
    'disabled': 0,
    'externalUserSharingOnly': 1,
    'externalUserAndGuestSharing': 2,
    'existingExternalUserSharingOnly': 3,
    'unknownFutureValue': 4,
}
sharingCapabilities = enum.Enum('sharingCapabilities', sharingCapabilities_data)


sharingDomainRestrictionMode_data = {
    'none': 0,
    'allowList': 1,
    'blockList': 2,
    'unknownFutureValue': 3,
}
sharingDomainRestrictionMode = enum.Enum('sharingDomainRestrictionMode', sharingDomainRestrictionMode_data)


columnTypes_data = {
    'note': 0,
    'text': 1,
    'choice': 2,
    'multichoice': 3,
    'number': 4,
    'currency': 5,
    'dateTime': 6,
    'lookup': 7,
    'boolean': 8,
    'user': 9,
    'url': 10,
    'calculated': 11,
    'location': 12,
    'geolocation': 13,
    'term': 14,
    'multiterm': 15,
    'thumbnail': 16,
    'approvalStatus': 17,
    'unknownFutureValue': 18,
}
columnTypes = enum.Enum('columnTypes', columnTypes_data)


contentModelType_data = {
    'teachingMethod': 0,
    'layoutMethod': 1,
    'freeformSelectionMethod': 2,
    'prebuiltContractModel': 3,
    'prebuiltInvoiceModel': 4,
    'prebuiltReceiptModel': 5,
    'unknownFutureValue': 6,
}
contentModelType = enum.Enum('contentModelType', contentModelType_data)


documentProcessingJobStatus_data = {
    'inProgress': 0,
    'completed': 1,
    'failed': 2,
    'unknownFutureValue': 3,
}
documentProcessingJobStatus = enum.Enum('documentProcessingJobStatus', documentProcessingJobStatus_data)


documentProcessingJobType_data = {
    'file': 0,
    'folder': 1,
    'unknownFutureValue': 2,
}
documentProcessingJobType = enum.Enum('documentProcessingJobType', documentProcessingJobType_data)


driveItemSourceApplication_data = {
    'teams': 0,
    'yammer': 1,
    'sharePoint': 2,
    'oneDrive': 3,
    'stream': 4,
    'powerPoint': 5,
    'office': 6,
    'loki': 7,
    'loop': 8,
    'other': 9,
    'unknownFutureValue': 10,
}
driveItemSourceApplication = enum.Enum('driveItemSourceApplication', driveItemSourceApplication_data)


horizontalSectionLayoutType_data = {
    'none': 0,
    'oneColumn': 1,
    'twoColumns': 2,
    'threeColumns': 3,
    'oneThirdLeftColumn': 4,
    'oneThirdRightColumn': 5,
    'fullWidth': 6,
    'unknownFutureValue': 7,
}
horizontalSectionLayoutType = enum.Enum('horizontalSectionLayoutType', horizontalSectionLayoutType_data)


longRunningOperationStatus_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
longRunningOperationStatus = enum.Enum('longRunningOperationStatus', longRunningOperationStatus_data)


mediaSourceContentCategory_data = {
    'meeting': 0,
    'liveStream': 1,
    'presentation': 2,
    'screenRecording': 3,
    'story': 4,
    'profile': 5,
    'chat': 6,
    'note': 7,
    'comment': 8,
    'unknownFutureValue': 9,
}
mediaSourceContentCategory = enum.Enum('mediaSourceContentCategory', mediaSourceContentCategory_data)


pageLayoutType_data = {
    'microsoftReserved': 0,
    'article': 1,
    'home': 2,
    'unknownFutureValue': 3,
    'newsLink': 5,
    'videoNewsLink': 6,
}
pageLayoutType = enum.Enum('pageLayoutType', pageLayoutType_data)


pagePromotionType_data = {
    'microsoftReserved': 0,
    'page': 1,
    'newsPost': 2,
    'unknownFutureValue': 3,
}
pagePromotionType = enum.Enum('pagePromotionType', pagePromotionType_data)


sectionEmphasisType_data = {
    'none': 0,
    'neutral': 1,
    'soft': 2,
    'strong': 3,
    'unknownFutureValue': 4,
}
sectionEmphasisType = enum.Enum('sectionEmphasisType', sectionEmphasisType_data)


sensitivityLabelAssignmentMethod_data = {
    'standard': 0,
    'privileged': 1,
    'auto': 2,
    'unknownFutureValue': 3,
}
sensitivityLabelAssignmentMethod = enum.Enum('sensitivityLabelAssignmentMethod', sensitivityLabelAssignmentMethod_data)


sharingRole_data = {
    'none': 0,
    'view': 1,
    'edit': 2,
    'manageList': 3,
    'review': 4,
    'restrictedView': 5,
    'submitOnly': 6,
    'unknownFutureValue': 7,
}
sharingRole = enum.Enum('sharingRole', sharingRole_data)


sharingScope_data = {
    'anyone': 0,
    'organization': 1,
    'specificPeople': 2,
    'anonymous': 3,
    'users': 4,
    'unknownFutureValue': 5,
}
sharingScope = enum.Enum('sharingScope', sharingScope_data)


sharingVariant_data = {
    'none': 0,
    'requiresAuthentication': 1,
    'passwordProtected': 2,
    'addressBar': 4,
    'embed': 8,
    'unknownFutureValue': 16,
}
sharingVariant = enum.Enum('sharingVariant', sharingVariant_data)


siteArchiveStatus_data = {
    'recentlyArchived': 0,
    'fullyArchived': 1,
    'reactivating': 2,
    'unknownFutureValue': 3,
}
siteArchiveStatus = enum.Enum('siteArchiveStatus', siteArchiveStatus_data)


siteLockState_data = {
    'unlocked': 0,
    'lockedReadOnly': 1,
    'lockedNoAccess': 2,
    'lockedNoAdditions': 3,
    'unknownFutureValue': 4,
}
siteLockState = enum.Enum('siteLockState', siteLockState_data)


titleAreaLayoutType_data = {
    'imageAndTitle': 0,
    'plain': 1,
    'colorBlock': 2,
    'overlap': 3,
    'unknownFutureValue': 4,
}
titleAreaLayoutType = enum.Enum('titleAreaLayoutType', titleAreaLayoutType_data)


titleAreaTextAlignmentType_data = {
    'left': 0,
    'center': 1,
    'unknownFutureValue': 2,
}
titleAreaTextAlignmentType = enum.Enum('titleAreaTextAlignmentType', titleAreaTextAlignmentType_data)


remindBeforeTimeInMinutesType_data = {
    'mins15': 0,
    'unknownFutureValue': 100,
}
remindBeforeTimeInMinutesType = enum.Enum('remindBeforeTimeInMinutesType', remindBeforeTimeInMinutesType_data)


virtualAppointmentMessageType_data = {
    'confirmation': 0,
    'reschedule': 1,
    'cancellation': 2,
    'unknownFutureValue': 10,
}
virtualAppointmentMessageType = enum.Enum('virtualAppointmentMessageType', virtualAppointmentMessageType_data)


messageEventType_data = {
    'received': 1,
    'sent': 2,
    'delivered': 3,
    'failed': 4,
    'processingFailed': 5,
    'distributionGroupExpanded': 6,
    'submitted': 7,
    'delayed': 8,
    'redirected': 9,
    'resolved': 10,
    'dropped': 11,
    'recipientsAdded': 12,
    'malwareDetected': 13,
    'malwareDetectedInMessage': 14,
    'malwareDetectedInAttachment': 15,
    'ttZapped': 16,
    'ttDelivered': 17,
    'spamDetected': 18,
    'transportRuleTriggered': 19,
    'dlpRuleTriggered': 20,
    'journaled': 21,
    'unknownFutureValue': 22,
}
messageEventType = enum.Enum('messageEventType', messageEventType_data)


messageStatus_data = {
    'gettingStatus': 1,
    'pending': 2,
    'failed': 3,
    'delivered': 4,
    'expanded': 5,
    'quarantined': 6,
    'filteredAsSpam': 7,
    'unknownFutureValue': 8,
}
messageStatus = enum.Enum('messageStatus', messageStatus_data)


agentStatus_data = {
    'active': 0,
    'inactive': 1,
}
agentStatus = enum.Enum('agentStatus', agentStatus_data)


connectorGroupRegion_data = {
    'nam': 0,
    'eur': 1,
    'aus': 2,
    'asia': 3,
    'ind': 4,
    'unknownFutureValue': 5,
}
connectorGroupRegion = enum.Enum('connectorGroupRegion', connectorGroupRegion_data)


connectorGroupType_data = {
    'applicationProxy': 0,
}
connectorGroupType = enum.Enum('connectorGroupType', connectorGroupType_data)


connectorStatus_data = {
    'active': 0,
    'inactive': 1,
}
connectorStatus = enum.Enum('connectorStatus', connectorStatus_data)


externalAuthenticationType_data = {
    'passthru': 0,
    'aadPreAuthentication': 1,
}
externalAuthenticationType = enum.Enum('externalAuthenticationType', externalAuthenticationType_data)


kerberosSignOnMappingAttributeType_data = {
    'userPrincipalName': 0,
    'onPremisesUserPrincipalName': 1,
    'userPrincipalUsername': 2,
    'onPremisesUserPrincipalUsername': 3,
    'onPremisesSAMAccountName': 4,
}
kerberosSignOnMappingAttributeType = enum.Enum('kerberosSignOnMappingAttributeType', kerberosSignOnMappingAttributeType_data)


onPremisesPublishingType_data = {
    'applicationProxy': 0,
    'exchangeOnline': 1,
    'authentication': 2,
    'provisioning': 3,
    'intunePfx': 4,
    'oflineDomainJoin': 5,
    'unknownFutureValue': 6,
}
onPremisesPublishingType = enum.Enum('onPremisesPublishingType', onPremisesPublishingType_data)


privateNetworkDestinationType_data = {
    'ipAddress': 0,
    'ipRange': 1,
    'ipRangeCidr': 2,
    'fqdn': 3,
    'dnsSuffix': 4,
    'unknownFutureValue': 5,
}
privateNetworkDestinationType = enum.Enum('privateNetworkDestinationType', privateNetworkDestinationType_data)


privateNetworkProtocol_data = {
    'tcp': 1,
    'udp': 2,
    'unknownFutureValue': 4,
}
privateNetworkProtocol = enum.Enum('privateNetworkProtocol', privateNetworkProtocol_data)


singleSignOnMode_data = {
    'none': 0,
    'onPremisesKerberos': 1,
    'saml': 3,
    'pingHeaderBased': 4,
    'aadHeaderBased': 5,
    'oAuthToken': 6,
    'unknownFutureValue': 7,
}
singleSignOnMode = enum.Enum('singleSignOnMode', singleSignOnMode_data)


stagedFeatureName_data = {
    'passthroughAuthentication': 0,
    'seamlessSso': 1,
    'passwordHashSync': 2,
    'emailAsAlternateId': 3,
    'unknownFutureValue': 4,
    'certificateBasedAuthentication': 5,
}
stagedFeatureName = enum.Enum('stagedFeatureName', stagedFeatureName_data)


MembershipRuleProcessingStatusDetails_data = {
    'NotStarted': 0,
    'Running': 1,
    'Failed': 2,
    'Succeeded': 3,
    'UnsupportedFutureValue': 4,
}
MembershipRuleProcessingStatusDetails = enum.Enum('MembershipRuleProcessingStatusDetails', MembershipRuleProcessingStatusDetails_data)


attributeDefinitionMetadata_data = {
    'BaseAttributeName': 0,
    'ComplexObjectDefinition': 1,
    'IsContainer': 2,
    'IsCustomerDefined': 3,
    'IsDomainQualified': 4,
    'LinkPropertyNames': 5,
    'LinkTypeName': 6,
    'MaximumLength': 7,
    'ReferencedProperty': 8,
}
attributeDefinitionMetadata = enum.Enum('attributeDefinitionMetadata', attributeDefinitionMetadata_data)


attributeFlowBehavior_data = {
    'FlowWhenChanged': 0,
    'FlowAlways': 1,
}
attributeFlowBehavior = enum.Enum('attributeFlowBehavior', attributeFlowBehavior_data)


attributeFlowType_data = {
    'Always': 0,
    'ObjectAddOnly': 1,
    'MultiValueAddOnly': 2,
    'ValueAddOnly': 3,
    'AttributeAddOnly': 4,
}
attributeFlowType = enum.Enum('attributeFlowType', attributeFlowType_data)


attributeMappingSourceType_data = {
    'Attribute': 0,
    'Constant': 1,
    'Function': 2,
}
attributeMappingSourceType = enum.Enum('attributeMappingSourceType', attributeMappingSourceType_data)


attributeType_data = {
    'String': 0,
    'Integer': 1,
    'Reference': 2,
    'Binary': 3,
    'Boolean': 4,
    'DateTime': 5,
}
attributeType = enum.Enum('attributeType', attributeType_data)


directoryDefinitionDiscoverabilities_data = {
    'None': 0,
    'AttributeNames': 1,
    'AttributeDataTypes': 2,
    'AttributeReadOnly': 4,
    'ReferenceAttributes': 8,
    'UnknownFutureValue': 16,
}
directoryDefinitionDiscoverabilities = enum.Enum('directoryDefinitionDiscoverabilities', directoryDefinitionDiscoverabilities_data)


entryExportStatus_data = {
    'Noop': 0,
    'Success': 1,
    'RetryableError': 2,
    'PermanentError': 3,
    'Error': 4,
}
entryExportStatus = enum.Enum('entryExportStatus', entryExportStatus_data)


entrySyncOperation_data = {
    'None': 0,
    'Add': 1,
    'Delete': 2,
    'Update': 3,
}
entrySyncOperation = enum.Enum('entrySyncOperation', entrySyncOperation_data)


escrowBehavior_data = {
    'Default': 1,
    'IgnoreLookupReferenceResolutionFailure': 2,
}
escrowBehavior = enum.Enum('escrowBehavior', escrowBehavior_data)


mutability_data = {
    'ReadWrite': 0,
    'ReadOnly': 1,
    'Immutable': 2,
    'WriteOnly': 3,
}
mutability = enum.Enum('mutability', mutability_data)


objectDefinitionMetadata_data = {
    'PropertyNameAccountEnabled': 0,
    'PropertyNameSoftDeleted': 1,
    'IsSoftDeletionSupported': 2,
    'IsSynchronizeAllSupported': 3,
    'ConnectorDataStorageRequired': 4,
    'Extensions': 5,
    'BaseObjectName': 6,
}
objectDefinitionMetadata = enum.Enum('objectDefinitionMetadata', objectDefinitionMetadata_data)


objectFlowTypes_data = {
    'None': 0,
    'Add': 1,
    'Update': 2,
    'Delete': 4,
}
objectFlowTypes = enum.Enum('objectFlowTypes', objectFlowTypes_data)


objectMappingMetadata_data = {
    'EscrowBehavior': 0,
    'DisableMonitoringForChanges': 1,
    'OriginalJoiningProperty': 2,
    'Disposition': 3,
    'IsCustomerDefined': 4,
    'ExcludeFromReporting': 5,
    'Unsynchronized': 6,
}
objectMappingMetadata = enum.Enum('objectMappingMetadata', objectMappingMetadata_data)


quarantineReason_data = {
    'EncounteredBaseEscrowThreshold': 0,
    'EncounteredTotalEscrowThreshold': 1,
    'EncounteredEscrowProportionThreshold': 2,
    'EncounteredQuarantineException': 4,
    'Unknown': 8,
    'QuarantinedOnDemand': 16,
    'TooManyDeletes': 32,
    'IngestionInterrupted': 64,
}
quarantineReason = enum.Enum('quarantineReason', quarantineReason_data)


scopeOperatorMultiValuedComparisonType_data = {
    'All': 0,
    'Any': 1,
}
scopeOperatorMultiValuedComparisonType = enum.Enum('scopeOperatorMultiValuedComparisonType', scopeOperatorMultiValuedComparisonType_data)


scopeOperatorType_data = {
    'Binary': 0,
    'Unary': 1,
}
scopeOperatorType = enum.Enum('scopeOperatorType', scopeOperatorType_data)


synchronizationDisposition_data = {
    'Normal': 0,
    'Discard': 1,
    'Escrow': 2,
}
synchronizationDisposition = enum.Enum('synchronizationDisposition', synchronizationDisposition_data)


synchronizationJobRestartScope_data = {
    'None': 0,
    'ConnectorDataStore': 1,
    'Escrows': 2,
    'Watermark': 4,
    'QuarantineState': 8,
    'Full': 15,
    'ForceDeletes': 32,
}
synchronizationJobRestartScope = enum.Enum('synchronizationJobRestartScope', synchronizationJobRestartScope_data)


synchronizationMetadata_data = {
    'galleryApplicationIdentifier': 0,
    'galleryApplicationKey': 1,
    'isOAuthEnabled': 2,
    'IsSynchronizationAgentAssignmentRequired': 3,
    'isSynchronizationAgentRequired': 4,
    'isSynchronizationInPreview': 5,
    'oAuthSettings': 6,
    'synchronizationLearnMoreIbizaFwLink': 7,
    'configurationFields': 8,
}
synchronizationMetadata = enum.Enum('synchronizationMetadata', synchronizationMetadata_data)


synchronizationScheduleState_data = {
    'Active': 0,
    'Disabled': 1,
    'Paused': 2,
}
synchronizationScheduleState = enum.Enum('synchronizationScheduleState', synchronizationScheduleState_data)


synchronizationSecret_data = {
    'None': 0,
    'UserName': 1,
    'Password': 2,
    'SecretToken': 3,
    'AppKey': 4,
    'BaseAddress': 5,
    'ClientIdentifier': 6,
    'ClientSecret': 7,
    'SingleSignOnType': 11,
    'Sandbox': 12,
    'Url': 13,
    'Domain': 14,
    'ConsumerKey': 15,
    'ConsumerSecret': 16,
    'TokenKey': 17,
    'TokenExpiration': 18,
    'Oauth2AccessToken': 19,
    'Oauth2AccessTokenCreationTime': 20,
    'Oauth2RefreshToken': 21,
    'SyncAll': 22,
    'InstanceName': 24,
    'Oauth2ClientId': 27,
    'Oauth2ClientSecret': 28,
    'CompanyId': 29,
    'UpdateKeyOnSoftDelete': 30,
    'SynchronizationSchedule': 33,
    'SystemOfRecord': 34,
    'SandboxName': 35,
    'EnforceDomain': 36,
    'SyncNotificationSettings': 37,
    'SkipOutOfScopeDeletions': 40,
    'Oauth2AuthorizationCode': 62,
    'Oauth2RedirectUri': 63,
    'ApplicationTemplateIdentifier': 64,
    'Oauth2TokenExchangeUri': 65,
    'Oauth2AuthorizationUri': 66,
    'AuthenticationType': 67,
    'Server': 70,
    'PerformInboundEntitlementGrants': 100,
    'HardDeletesEnabled': 101,
    'SyncAgentCompatibilityKey': 102,
    'SyncAgentADContainer': 103,
    'ValidateDomain': 206,
    'TestReferences': 207,
    'ConnectionString': 250,
}
synchronizationSecret = enum.Enum('synchronizationSecret', synchronizationSecret_data)


synchronizationStatusCode_data = {
    'NotConfigured': 0,
    'NotRun': 1,
    'Active': 2,
    'Paused': 3,
    'Quarantine': 4,
}
synchronizationStatusCode = enum.Enum('synchronizationStatusCode', synchronizationStatusCode_data)


synchronizationTaskExecutionResult_data = {
    'Succeeded': 0,
    'Failed': 1,
    'EntryLevelErrors': 2,
}
synchronizationTaskExecutionResult = enum.Enum('synchronizationTaskExecutionResult', synchronizationTaskExecutionResult_data)


endpointType_data = {
    'default': 0,
    'voicemail': 1,
    'skypeForBusiness': 2,
    'skypeForBusinessVoipPhone': 3,
    'unknownFutureValue': 4,
}
endpointType = enum.Enum('endpointType', endpointType_data)


accessReviewHistoryDecisionFilter_data = {
    'approve': 0,
    'deny': 1,
    'notReviewed': 2,
    'dontKnow': 3,
    'notNotified': 4,
    'unknownFutureValue': 5,
}
accessReviewHistoryDecisionFilter = enum.Enum('accessReviewHistoryDecisionFilter', accessReviewHistoryDecisionFilter_data)


accessReviewHistoryStatus_data = {
    'done': 0,
    'inprogress': 1,
    'error': 2,
    'requested': 3,
    'unknownFutureValue': 4,
}
accessReviewHistoryStatus = enum.Enum('accessReviewHistoryStatus', accessReviewHistoryStatus_data)


accessReviewInstanceDecisionItemFilterByCurrentUserOptions_data = {
    'reviewer': 1,
    'unknownFutureValue': 2,
}
accessReviewInstanceDecisionItemFilterByCurrentUserOptions = enum.Enum('accessReviewInstanceDecisionItemFilterByCurrentUserOptions', accessReviewInstanceDecisionItemFilterByCurrentUserOptions_data)


accessReviewInstanceFilterByCurrentUserOptions_data = {
    'reviewer': 1,
    'unknownFutureValue': 2,
}
accessReviewInstanceFilterByCurrentUserOptions = enum.Enum('accessReviewInstanceFilterByCurrentUserOptions', accessReviewInstanceFilterByCurrentUserOptions_data)


accessReviewScheduleDefinitionFilterByCurrentUserOptions_data = {
    'reviewer': 1,
    'unknownFutureValue': 2,
}
accessReviewScheduleDefinitionFilterByCurrentUserOptions = enum.Enum('accessReviewScheduleDefinitionFilterByCurrentUserOptions', accessReviewScheduleDefinitionFilterByCurrentUserOptions_data)


accessReviewStageFilterByCurrentUserOptions_data = {
    'reviewer': 1,
    'unknownFutureValue': 2,
}
accessReviewStageFilterByCurrentUserOptions = enum.Enum('accessReviewStageFilterByCurrentUserOptions', accessReviewStageFilterByCurrentUserOptions_data)


approvalFilterByCurrentUserOptions_data = {
    'target': 0,
    'createdBy': 1,
    'approver': 2,
    'unknownFutureValue': 3,
}
approvalFilterByCurrentUserOptions = enum.Enum('approvalFilterByCurrentUserOptions', approvalFilterByCurrentUserOptions_data)


consentRequestFilterByCurrentUserOptions_data = {
    'reviewer': 0,
    'unknownFutureValue': 1,
}
consentRequestFilterByCurrentUserOptions = enum.Enum('consentRequestFilterByCurrentUserOptions', consentRequestFilterByCurrentUserOptions_data)


decisionItemPrincipalResourceMembershipType_data = {
    'direct': 1,
    'indirect': 2,
    'unknownFutureValue': 4,
}
decisionItemPrincipalResourceMembershipType = enum.Enum('decisionItemPrincipalResourceMembershipType', decisionItemPrincipalResourceMembershipType_data)


userSignInRecommendationScope_data = {
    'tenant': 0,
    'application': 1,
    'unknownFutureValue': 2,
}
userSignInRecommendationScope = enum.Enum('userSignInRecommendationScope', userSignInRecommendationScope_data)


agreementAcceptanceState_data = {
    'accepted': 2,
    'declined': 3,
    'unknownFutureValue': 5,
}
agreementAcceptanceState = enum.Enum('agreementAcceptanceState', agreementAcceptanceState_data)


activityType_data = {
    'signin': 0,
    'user': 1,
    'unknownFutureValue': 2,
    'servicePrincipal': 3,
}
activityType = enum.Enum('activityType', activityType_data)


cloudAppSecuritySessionControlType_data = {
    'mcasConfigured': 0,
    'monitorOnly': 1,
    'blockDownloads': 2,
    'unknownFutureValue': 3,
}
cloudAppSecuritySessionControlType = enum.Enum('cloudAppSecuritySessionControlType', cloudAppSecuritySessionControlType_data)


compliantNetworkType_data = {
    'allTenantCompliantNetworks': 0,
    'unknownFutureValue': 1,
}
compliantNetworkType = enum.Enum('compliantNetworkType', compliantNetworkType_data)


conditionalAccessClientApp_data = {
    'all': 0,
    'browser': 1,
    'mobileAppsAndDesktopClients': 2,
    'exchangeActiveSync': 3,
    'easSupported': 4,
    'other': 5,
    'unknownFutureValue': 6,
}
conditionalAccessClientApp = enum.Enum('conditionalAccessClientApp', conditionalAccessClientApp_data)


conditionalAccessDevicePlatform_data = {
    'android': 0,
    'iOS': 1,
    'windows': 2,
    'windowsPhone': 3,
    'macOS': 4,
    'all': 5,
    'unknownFutureValue': 6,
    'linux': 7,
}
conditionalAccessDevicePlatform = enum.Enum('conditionalAccessDevicePlatform', conditionalAccessDevicePlatform_data)


conditionalAccessExternalTenantsMembershipKind_data = {
    'all': 0,
    'enumerated': 1,
    'unknownFutureValue': 2,
}
conditionalAccessExternalTenantsMembershipKind = enum.Enum('conditionalAccessExternalTenantsMembershipKind', conditionalAccessExternalTenantsMembershipKind_data)


conditionalAccessGrantControl_data = {
    'block': 0,
    'mfa': 1,
    'compliantDevice': 2,
    'domainJoinedDevice': 3,
    'approvedApplication': 4,
    'compliantApplication': 5,
    'passwordChange': 6,
    'unknownFutureValue': 7,
}
conditionalAccessGrantControl = enum.Enum('conditionalAccessGrantControl', conditionalAccessGrantControl_data)


conditionalAccessGuestOrExternalUserTypes_data = {
    'none': 0,
    'internalGuest': 1,
    'b2bCollaborationGuest': 2,
    'b2bCollaborationMember': 4,
    'b2bDirectConnectUser': 8,
    'otherExternalUser': 16,
    'serviceProvider': 32,
    'unknownFutureValue': 64,
}
conditionalAccessGuestOrExternalUserTypes = enum.Enum('conditionalAccessGuestOrExternalUserTypes', conditionalAccessGuestOrExternalUserTypes_data)


conditionalAccessInsiderRiskLevels_data = {
    'minor': 1,
    'moderate': 2,
    'elevated': 4,
    'unknownFutureValue': 8,
}
conditionalAccessInsiderRiskLevels = enum.Enum('conditionalAccessInsiderRiskLevels', conditionalAccessInsiderRiskLevels_data)


conditionalAccessPolicyState_data = {
    'enabled': 0,
    'disabled': 1,
    'enabledForReportingButNotEnforced': 2,
}
conditionalAccessPolicyState = enum.Enum('conditionalAccessPolicyState', conditionalAccessPolicyState_data)


conditionalAccessTransferMethods_data = {
    'none': 0,
    'deviceCodeFlow': 1,
    'authenticationTransfer': 2,
    'unknownFutureValue': 4,
}
conditionalAccessTransferMethods = enum.Enum('conditionalAccessTransferMethods', conditionalAccessTransferMethods_data)


conditionalAccessWhatIfReasons_data = {
    'notSet': 0,
    'notEnoughInformation': 1,
    'invalidCondition': 2,
    'users': 3,
    'workloadIdentities': 4,
    'application': 5,
    'userActions': 6,
    'authenticationContext': 7,
    'devicePlatform': 8,
    'devices': 9,
    'clientApps': 10,
    'location': 11,
    'signInRisk': 12,
    'emptyPolicy': 13,
    'invalidPolicy': 14,
    'policyNotEnabled': 15,
    'userRisk': 16,
    'time': 17,
    'insiderRisk': 18,
    'authenticationFlow': 19,
    'unknownFutureValue': 20,
}
conditionalAccessWhatIfReasons = enum.Enum('conditionalAccessWhatIfReasons', conditionalAccessWhatIfReasons_data)


continuousAccessEvaluationMode_data = {
    'strictEnforcement': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
    'strictLocation': 3,
}
continuousAccessEvaluationMode = enum.Enum('continuousAccessEvaluationMode', continuousAccessEvaluationMode_data)


countryLookupMethodType_data = {
    'clientIpAddress': 0,
    'authenticatorAppGps': 1,
    'unknownFutureValue': 2,
}
countryLookupMethodType = enum.Enum('countryLookupMethodType', countryLookupMethodType_data)


filterMode_data = {
    'include': 0,
    'exclude': 1,
}
filterMode = enum.Enum('filterMode', filterMode_data)


insiderRiskLevel_data = {
    'none': 0,
    'minor': 1,
    'moderate': 2,
    'elevated': 3,
    'unknownFutureValue': 4,
}
insiderRiskLevel = enum.Enum('insiderRiskLevel', insiderRiskLevel_data)


persistentBrowserSessionMode_data = {
    'always': 0,
    'never': 1,
}
persistentBrowserSessionMode = enum.Enum('persistentBrowserSessionMode', persistentBrowserSessionMode_data)


riskDetectionTimingType_data = {
    'notDefined': 0,
    'realtime': 1,
    'nearRealtime': 2,
    'offline': 3,
    'unknownFutureValue': 4,
}
riskDetectionTimingType = enum.Enum('riskDetectionTimingType', riskDetectionTimingType_data)


riskEventType_data = {
    'unlikelyTravel': 0,
    'anonymizedIPAddress': 1,
    'maliciousIPAddress': 2,
    'unfamiliarFeatures': 3,
    'malwareInfectedIPAddress': 4,
    'suspiciousIPAddress': 5,
    'leakedCredentials': 6,
    'investigationsThreatIntelligence': 7,
    'generic': 8,
    'adminConfirmedUserCompromised': 9,
    'mcasImpossibleTravel': 10,
    'mcasSuspiciousInboxManipulationRules': 11,
    'investigationsThreatIntelligenceSigninLinked': 12,
    'maliciousIPAddressValidCredentialsBlockedIP': 13,
    'unknownFutureValue': 14,
}
riskEventType = enum.Enum('riskEventType', riskEventType_data)


signInFrequencyAuthenticationType_data = {
    'primaryAndSecondaryAuthentication': 0,
    'secondaryAuthentication': 1,
    'unknownFutureValue': 2,
}
signInFrequencyAuthenticationType = enum.Enum('signInFrequencyAuthenticationType', signInFrequencyAuthenticationType_data)


signInFrequencyInterval_data = {
    'timeBased': 0,
    'everyTime': 1,
    'unknownFutureValue': 2,
}
signInFrequencyInterval = enum.Enum('signInFrequencyInterval', signInFrequencyInterval_data)


signinFrequencyType_data = {
    'days': 0,
    'hours': 1,
}
signinFrequencyType = enum.Enum('signinFrequencyType', signinFrequencyType_data)


templateScenarios_data = {
    'new': 0,
    'secureFoundation': 1,
    'zeroTrust': 2,
    'remoteWork': 4,
    'protectAdmins': 8,
    'emergingThreats': 16,
    'unknownFutureValue': 32,
}
templateScenarios = enum.Enum('templateScenarios', templateScenarios_data)


userAction_data = {
    'registerSecurityInformation': 0,
    'registerOrJoinDevices': 1,
    'unknownFutureValue': 2,
}
userAction = enum.Enum('userAction', userAction_data)


accessPackageAssignmentFilterByCurrentUserOptions_data = {
    'target': 1,
    'createdBy': 2,
    'unknownFutureValue': 99,
}
accessPackageAssignmentFilterByCurrentUserOptions = enum.Enum('accessPackageAssignmentFilterByCurrentUserOptions', accessPackageAssignmentFilterByCurrentUserOptions_data)


accessPackageAssignmentRequestFilterByCurrentUserOptions_data = {
    'target': 1,
    'createdBy': 2,
    'approver': 3,
    'unknownFutureValue': 99,
}
accessPackageAssignmentRequestFilterByCurrentUserOptions = enum.Enum('accessPackageAssignmentRequestFilterByCurrentUserOptions', accessPackageAssignmentRequestFilterByCurrentUserOptions_data)


accessPackageCustomExtensionHandlerStatus_data = {
    'requestSent': 1,
    'requestReceived': 2,
    'unknownFutureValue': 3,
}
accessPackageCustomExtensionHandlerStatus = enum.Enum('accessPackageCustomExtensionHandlerStatus', accessPackageCustomExtensionHandlerStatus_data)


accessPackageCustomExtensionStage_data = {
    'assignmentRequestCreated': 1,
    'assignmentRequestApproved': 2,
    'assignmentRequestGranted': 3,
    'assignmentRequestRemoved': 4,
    'assignmentFourteenDaysBeforeExpiration': 5,
    'assignmentOneDayBeforeExpiration': 6,
    'unknownFutureValue': 7,
}
accessPackageCustomExtensionStage = enum.Enum('accessPackageCustomExtensionStage', accessPackageCustomExtensionStage_data)


accessPackageFilterByCurrentUserOptions_data = {
    'allowedRequestor': 1,
    'unknownFutureValue': 99,
}
accessPackageFilterByCurrentUserOptions = enum.Enum('accessPackageFilterByCurrentUserOptions', accessPackageFilterByCurrentUserOptions_data)


accessPackageSubjectLifecycle_data = {
    'notDefined': 0,
    'notGoverned': 1,
    'governed': 2,
    'unknownFutureValue': 3,
}
accessPackageSubjectLifecycle = enum.Enum('accessPackageSubjectLifecycle', accessPackageSubjectLifecycle_data)


accessReviewTimeoutBehavior_data = {
    'keepAccess': 0,
    'removeAccess': 1,
    'acceptAccessRecommendation': 2,
    'unknownFutureValue': 99,
}
accessReviewTimeoutBehavior = enum.Enum('accessReviewTimeoutBehavior', accessReviewTimeoutBehavior_data)


customExtensionCalloutInstanceStatus_data = {
    'calloutSent': 1,
    'callbackReceived': 2,
    'calloutFailed': 3,
    'callbackTimedOut': 4,
    'waitingForCallback': 5,
    'unknownFutureValue': 6,
}
customExtensionCalloutInstanceStatus = enum.Enum('customExtensionCalloutInstanceStatus', customExtensionCalloutInstanceStatus_data)


expirationPatternType_data = {
    'notSpecified': 0,
    'noExpiration': 1,
    'afterDateTime': 2,
    'afterDuration': 3,
}
expirationPatternType = enum.Enum('expirationPatternType', expirationPatternType_data)


verifiableCredentialPresentationStatusCode_data = {
    'request_retrieved': 0,
    'presentation_verified': 1,
    'unknownFutureValue': 9,
}
verifiableCredentialPresentationStatusCode = enum.Enum('verifiableCredentialPresentationStatusCode', verifiableCredentialPresentationStatusCode_data)


connectedOrganizationState_data = {
    'configured': 0,
    'proposed': 1,
    'unknownFutureValue': 2,
}
connectedOrganizationState = enum.Enum('connectedOrganizationState', connectedOrganizationState_data)


socialIdentitySourceType_data = {
    'facebook': 1,
    'unknownFutureValue': 2,
}
socialIdentitySourceType = enum.Enum('socialIdentitySourceType', socialIdentitySourceType_data)


actionSource_data = {
    'manual': 0,
    'automatic': 1,
    'recommended': 2,
    'default': 3,
}
actionSource = enum.Enum('actionSource', actionSource_data)


assignmentMethod_data = {
    'standard': 0,
    'privileged': 1,
    'auto': 2,
}
assignmentMethod = enum.Enum('assignmentMethod', assignmentMethod_data)


contentAlignment_data = {
    'left': 0,
    'right': 1,
    'center': 2,
}
contentAlignment = enum.Enum('contentAlignment', contentAlignment_data)


contentFormat_data = {
    'default': 0,
    'email': 1,
}
contentFormat = enum.Enum('contentFormat', contentFormat_data)


contentState_data = {
    'rest': 0,
    'motion': 1,
    'use': 2,
}
contentState = enum.Enum('contentState', contentState_data)


watermarkLayout_data = {
    'horizontal': 0,
    'diagonal': 1,
}
watermarkLayout = enum.Enum('watermarkLayout', watermarkLayout_data)


androidDeviceOwnerEnrollmentMode_data = {
    'corporateOwnedDedicatedDevice': 0,
    'corporateOwnedFullyManaged': 1,
    'corporateOwnedWorkProfile': 2,
    'corporateOwnedAOSPUserlessDevice': 3,
    'corporateOwnedAOSPUserAssociatedDevice': 4,
}
androidDeviceOwnerEnrollmentMode = enum.Enum('androidDeviceOwnerEnrollmentMode', androidDeviceOwnerEnrollmentMode_data)


androidDeviceOwnerEnrollmentTokenType_data = {
    'default': 0,
    'corporateOwnedDedicatedDeviceWithAzureADSharedMode': 1,
    'deviceStaging': 2,
}
androidDeviceOwnerEnrollmentTokenType = enum.Enum('androidDeviceOwnerEnrollmentTokenType', androidDeviceOwnerEnrollmentTokenType_data)


androidForWorkAppConfigurationSchemaItemDataType_data = {
    'bool': 0,
    'integer': 1,
    'string': 2,
    'choice': 3,
    'multiselect': 4,
    'bundle': 5,
    'bundleArray': 6,
    'hidden': 7,
}
androidForWorkAppConfigurationSchemaItemDataType = enum.Enum('androidForWorkAppConfigurationSchemaItemDataType', androidForWorkAppConfigurationSchemaItemDataType_data)


androidForWorkBindStatus_data = {
    'notBound': 0,
    'bound': 1,
    'boundAndValidated': 2,
    'unbinding': 3,
}
androidForWorkBindStatus = enum.Enum('androidForWorkBindStatus', androidForWorkBindStatus_data)


androidForWorkEnrollmentTarget_data = {
    'none': 0,
    'all': 1,
    'targeted': 2,
    'targetedAsEnrollmentRestrictions': 3,
}
androidForWorkEnrollmentTarget = enum.Enum('androidForWorkEnrollmentTarget', androidForWorkEnrollmentTarget_data)


androidForWorkSyncStatus_data = {
    'success': 0,
    'credentialsNotValid': 1,
    'androidForWorkApiError': 2,
    'managementServiceError': 3,
    'unknownError': 4,
    'none': 5,
}
androidForWorkSyncStatus = enum.Enum('androidForWorkSyncStatus', androidForWorkSyncStatus_data)


androidManagedStoreAccountAppSyncStatus_data = {
    'success': 0,
    'credentialsNotValid': 1,
    'androidForWorkApiError': 2,
    'managementServiceError': 3,
    'unknownError': 4,
    'none': 5,
}
androidManagedStoreAccountAppSyncStatus = enum.Enum('androidManagedStoreAccountAppSyncStatus', androidManagedStoreAccountAppSyncStatus_data)


androidManagedStoreAccountBindStatus_data = {
    'notBound': 0,
    'bound': 1,
    'boundAndValidated': 2,
    'unbinding': 3,
}
androidManagedStoreAccountBindStatus = enum.Enum('androidManagedStoreAccountBindStatus', androidManagedStoreAccountBindStatus_data)


androidManagedStoreAccountEnrollmentTarget_data = {
    'none': 0,
    'all': 1,
    'targeted': 2,
    'targetedAsEnrollmentRestrictions': 3,
}
androidManagedStoreAccountEnrollmentTarget = enum.Enum('androidManagedStoreAccountEnrollmentTarget', androidManagedStoreAccountEnrollmentTarget_data)


androidManagedStoreAppConfigurationSchemaItemDataType_data = {
    'bool': 0,
    'integer': 1,
    'string': 2,
    'choice': 3,
    'multiselect': 4,
    'bundle': 5,
    'bundleArray': 6,
    'hidden': 7,
}
androidManagedStoreAppConfigurationSchemaItemDataType = enum.Enum('androidManagedStoreAppConfigurationSchemaItemDataType', androidManagedStoreAppConfigurationSchemaItemDataType_data)


aospWifiSecurityType_data = {
    'none': 0,
    'wpa': 1,
    'wep': 2,
}
aospWifiSecurityType = enum.Enum('aospWifiSecurityType', aospWifiSecurityType_data)


enrollmentTimeDeviceMembershipTargetType_data = {
    'unknown': 0,
    'staticSecurityGroup': 1,
    'unknownFutureValue': 2,
}
enrollmentTimeDeviceMembershipTargetType = enum.Enum('enrollmentTimeDeviceMembershipTargetType', enrollmentTimeDeviceMembershipTargetType_data)


enrollmentTimeDeviceMembershipTargetValidationErrorCode_data = {
    'unknown': 0,
    'securityGroupNotFound': 1,
    'notSecurityGroup': 2,
    'notStaticSecurityGroup': 3,
    'firstPartyAppNotAnOwner': 4,
    'securityGroupNotInCallerScope': 5,
    'unknownFutureValue': 6,
}
enrollmentTimeDeviceMembershipTargetValidationErrorCode = enum.Enum('enrollmentTimeDeviceMembershipTargetValidationErrorCode', enrollmentTimeDeviceMembershipTargetValidationErrorCode_data)


deviceAndAppManagementAssignmentFilterType_data = {
    'none': 0,
    'include': 1,
    'exclude': 2,
}
deviceAndAppManagementAssignmentFilterType = enum.Enum('deviceAndAppManagementAssignmentFilterType', deviceAndAppManagementAssignmentFilterType_data)


zebraFotaConnectorState_data = {
    'none': 0,
    'connected': 1,
    'disconnected': 2,
    'unknownFutureValue': 99,
}
zebraFotaConnectorState = enum.Enum('zebraFotaConnectorState', zebraFotaConnectorState_data)


zebraFotaDeploymentState_data = {
    'pendingCreation': 0,
    'createFailed': 1,
    'created': 2,
    'inProgress': 3,
    'completed': 4,
    'pendingCancel': 5,
    'canceled': 6,
    'unknownFutureValue': 99,
}
zebraFotaDeploymentState = enum.Enum('zebraFotaDeploymentState', zebraFotaDeploymentState_data)


zebraFotaErrorCode_data = {
    'success': 0,
    'noDevicesFoundInSelectedAadGroups': 1,
    'noIntuneDevicesFoundInSelectedAadGroups': 2,
    'noZebraFotaEnrolledDevicesFoundForCurrentTenant': 3,
    'noZebraFotaEnrolledDevicesFoundInSelectedAadGroups': 4,
    'noZebraFotaDevicesFoundForSelectedDeviceModel': 5,
    'zebraFotaCreateDeploymentRequestFailure': 6,
    'unknownFutureValue': 7,
}
zebraFotaErrorCode = enum.Enum('zebraFotaErrorCode', zebraFotaErrorCode_data)


zebraFotaNetworkType_data = {
    'any': 0,
    'wifi': 1,
    'cellular': 2,
    'wifiAndCellular': 3,
    'unknownFutureValue': 99,
}
zebraFotaNetworkType = enum.Enum('zebraFotaNetworkType', zebraFotaNetworkType_data)


zebraFotaScheduleMode_data = {
    'installNow': 0,
    'scheduled': 1,
    'unknownFutureValue': 99,
}
zebraFotaScheduleMode = enum.Enum('zebraFotaScheduleMode', zebraFotaScheduleMode_data)


zebraFotaUpdateType_data = {
    'custom': 0,
    'latest': 1,
    'auto': 2,
    'unknownFutureValue': 99,
}
zebraFotaUpdateType = enum.Enum('zebraFotaUpdateType', zebraFotaUpdateType_data)


androidManagedStoreAutoUpdateMode_data = {
    'default': 0,
    'postponed': 1,
    'priority': 2,
    'unknownFutureValue': 3,
}
androidManagedStoreAutoUpdateMode = enum.Enum('androidManagedStoreAutoUpdateMode', androidManagedStoreAutoUpdateMode_data)


androidPermissionActionType_data = {
    'prompt': 0,
    'autoGrant': 1,
    'autoDeny': 2,
}
androidPermissionActionType = enum.Enum('androidPermissionActionType', androidPermissionActionType_data)


androidProfileApplicability_data = {
    'default': 0,
    'androidWorkProfile': 1,
    'androidDeviceOwner': 2,
}
androidProfileApplicability = enum.Enum('androidProfileApplicability', androidProfileApplicability_data)


androidTargetedPlatforms_data = {
    'androidDeviceAdministrator': 1,
    'androidOpenSourceProject': 2,
    'unknownFutureValue': 4,
}
androidTargetedPlatforms = enum.Enum('androidTargetedPlatforms', androidTargetedPlatforms_data)


certificateStatus_data = {
    'notProvisioned': 0,
    'provisioned': 1,
}
certificateStatus = enum.Enum('certificateStatus', certificateStatus_data)


complianceStatus_data = {
    'unknown': 0,
    'notApplicable': 1,
    'compliant': 2,
    'remediated': 3,
    'nonCompliant': 4,
    'error': 5,
    'conflict': 6,
    'notAssigned': 7,
}
complianceStatus = enum.Enum('complianceStatus', complianceStatus_data)


deviceAndAppManagementAssignmentSource_data = {
    'direct': 0,
    'policySets': 1,
}
deviceAndAppManagementAssignmentSource = enum.Enum('deviceAndAppManagementAssignmentSource', deviceAndAppManagementAssignmentSource_data)


installIntent_data = {
    'available': 0,
    'required': 1,
    'uninstall': 2,
    'availableWithoutEnrollment': 3,
}
installIntent = enum.Enum('installIntent', installIntent_data)


managedAppAvailability_data = {
    'global': 0,
    'lineOfBusiness': 1,
}
managedAppAvailability = enum.Enum('managedAppAvailability', managedAppAvailability_data)


mdmAppConfigKeyType_data = {
    'stringType': 0,
    'integerType': 1,
    'realType': 2,
    'booleanType': 3,
    'tokenType': 4,
}
mdmAppConfigKeyType = enum.Enum('mdmAppConfigKeyType', mdmAppConfigKeyType_data)


microsoftEdgeChannel_data = {
    'dev': 0,
    'beta': 1,
    'stable': 2,
    'unknownFutureValue': 3,
}
microsoftEdgeChannel = enum.Enum('microsoftEdgeChannel', microsoftEdgeChannel_data)


microsoftStoreForBusinessLicenseType_data = {
    'offline': 0,
    'online': 1,
}
microsoftStoreForBusinessLicenseType = enum.Enum('microsoftStoreForBusinessLicenseType', microsoftStoreForBusinessLicenseType_data)


mobileAppContentFileUploadState_data = {
    'success': 0,
    'transientError': 1,
    'error': 2,
    'unknown': 3,
    'azureStorageUriRequestSuccess': 100,
    'azureStorageUriRequestPending': 101,
    'azureStorageUriRequestFailed': 102,
    'azureStorageUriRequestTimedOut': 103,
    'azureStorageUriRenewalSuccess': 200,
    'azureStorageUriRenewalPending': 201,
    'azureStorageUriRenewalFailed': 202,
    'azureStorageUriRenewalTimedOut': 203,
    'commitFileSuccess': 300,
    'commitFilePending': 301,
    'commitFileFailed': 302,
    'commitFileTimedOut': 303,
}
mobileAppContentFileUploadState = enum.Enum('mobileAppContentFileUploadState', mobileAppContentFileUploadState_data)


mobileAppDependencyType_data = {
    'detect': 0,
    'autoInstall': 1,
    'unknownFutureValue': 2,
}
mobileAppDependencyType = enum.Enum('mobileAppDependencyType', mobileAppDependencyType_data)


mobileAppPublishingState_data = {
    'notPublished': 0,
    'processing': 1,
    'published': 2,
}
mobileAppPublishingState = enum.Enum('mobileAppPublishingState', mobileAppPublishingState_data)


mobileAppRelationshipType_data = {
    'child': 0,
    'parent': 1,
    'unknownFutureValue': 2,
}
mobileAppRelationshipType = enum.Enum('mobileAppRelationshipType', mobileAppRelationshipType_data)


mobileAppSupersedenceType_data = {
    'update': 0,
    'replace': 1,
    'unknownFutureValue': 2,
}
mobileAppSupersedenceType = enum.Enum('mobileAppSupersedenceType', mobileAppSupersedenceType_data)


officeProductId_data = {
    'o365ProPlusRetail': 0,
    'o365BusinessRetail': 1,
    'visioProRetail': 2,
    'projectProRetail': 3,
}
officeProductId = enum.Enum('officeProductId', officeProductId_data)


officeSuiteDefaultFileFormatType_data = {
    'notConfigured': 0,
    'officeOpenXMLFormat': 1,
    'officeOpenDocumentFormat': 2,
    'unknownFutureValue': 99,
}
officeSuiteDefaultFileFormatType = enum.Enum('officeSuiteDefaultFileFormatType', officeSuiteDefaultFileFormatType_data)


officeSuiteInstallProgressDisplayLevel_data = {
    'none': 0,
    'full': 1,
}
officeSuiteInstallProgressDisplayLevel = enum.Enum('officeSuiteInstallProgressDisplayLevel', officeSuiteInstallProgressDisplayLevel_data)


officeUpdateChannel_data = {
    'none': 0,
    'current': 1,
    'deferred': 2,
    'firstReleaseCurrent': 3,
    'firstReleaseDeferred': 4,
    'monthlyEnterprise': 5,
}
officeUpdateChannel = enum.Enum('officeUpdateChannel', officeUpdateChannel_data)


resultantAppState_data = {
    'notApplicable': -1,
    'installed': 1,
    'failed': 2,
    'notInstalled': 3,
    'uninstallFailed': 4,
    'pendingInstall': 5,
    'unknown': 99,
}
resultantAppState = enum.Enum('resultantAppState', resultantAppState_data)


resultantAppStateDetail_data = {
    'processorArchitectureNotApplicable': -1000,
    'minimumDiskSpaceNotMet': -1001,
    'minimumOsVersionNotMet': -1002,
    'minimumPhysicalMemoryNotMet': -1003,
    'minimumLogicalProcessorCountNotMet': -1004,
    'minimumCpuSpeedNotMet': -1005,
    'platformNotApplicable': -1006,
    'fileSystemRequirementNotMet': -1011,
    'registryRequirementNotMet': -1012,
    'powerShellScriptRequirementNotMet': -1013,
    'supersedingAppsNotApplicable': -1016,
    'noAdditionalDetails': 0,
    'dependencyFailedToInstall': 1,
    'dependencyWithRequirementsNotMet': 2,
    'dependencyPendingReboot': 3,
    'dependencyWithAutoInstallDisabled': 4,
    'supersededAppUninstallFailed': 5,
    'supersededAppUninstallPendingReboot': 6,
    'removingSupersededApps': 7,
    'iosAppStoreUpdateFailedToInstall': 1000,
    'vppAppHasUpdateAvailable': 1001,
    'userRejectedUpdate': 1002,
    'uninstallPendingReboot': 1003,
    'supersedingAppsDetected': 1004,
    'supersededAppsDetected': 1005,
    'seeInstallErrorCode': 2000,
    'autoInstallDisabled': 3000,
    'managedAppNoLongerPresent': 3001,
    'userRejectedInstall': 3002,
    'userIsNotLoggedIntoAppStore': 3003,
    'untargetedSupersedingAppsDetected': 3004,
    'appRemovedBySupersedence': 3005,
    'seeUninstallErrorCode': 4000,
    'pendingReboot': 5000,
    'installingDependencies': 5001,
    'contentDownloaded': 5002,
}
resultantAppStateDetail = enum.Enum('resultantAppStateDetail', resultantAppStateDetail_data)


runAsAccountType_data = {
    'system': 0,
    'user': 1,
}
runAsAccountType = enum.Enum('runAsAccountType', runAsAccountType_data)


vppTokenAccountType_data = {
    'business': 0,
    'education': 1,
}
vppTokenAccountType = enum.Enum('vppTokenAccountType', vppTokenAccountType_data)


vppTokenActionFailureReason_data = {
    'none': 0,
    'appleFailure': 1,
    'internalError': 2,
    'expiredVppToken': 3,
    'expiredApplePushNotificationCertificate': 4,
}
vppTokenActionFailureReason = enum.Enum('vppTokenActionFailureReason', vppTokenActionFailureReason_data)


win32LobAppDeliveryOptimizationPriority_data = {
    'notConfigured': 0,
    'foreground': 1,
}
win32LobAppDeliveryOptimizationPriority = enum.Enum('win32LobAppDeliveryOptimizationPriority', win32LobAppDeliveryOptimizationPriority_data)


win32LobAppDetectionOperator_data = {
    'notConfigured': 0,
    'equal': 1,
    'notEqual': 2,
    'greaterThan': 4,
    'greaterThanOrEqual': 5,
    'lessThan': 8,
    'lessThanOrEqual': 9,
}
win32LobAppDetectionOperator = enum.Enum('win32LobAppDetectionOperator', win32LobAppDetectionOperator_data)


win32LobAppFileSystemDetectionType_data = {
    'notConfigured': 0,
    'exists': 1,
    'modifiedDate': 2,
    'createdDate': 3,
    'version': 4,
    'sizeInMB': 5,
    'doesNotExist': 6,
}
win32LobAppFileSystemDetectionType = enum.Enum('win32LobAppFileSystemDetectionType', win32LobAppFileSystemDetectionType_data)


win32LobAppFileSystemOperationType_data = {
    'notConfigured': 0,
    'exists': 1,
    'modifiedDate': 2,
    'createdDate': 3,
    'version': 4,
    'sizeInMB': 5,
    'doesNotExist': 6,
    'sizeInBytes': 7,
    'appVersion': 8,
    'unknownFutureValue': 9,
}
win32LobAppFileSystemOperationType = enum.Enum('win32LobAppFileSystemOperationType', win32LobAppFileSystemOperationType_data)


win32LobAppMsiPackageType_data = {
    'perMachine': 0,
    'perUser': 1,
    'dualPurpose': 2,
}
win32LobAppMsiPackageType = enum.Enum('win32LobAppMsiPackageType', win32LobAppMsiPackageType_data)


win32LobAppNotification_data = {
    'showAll': 0,
    'showReboot': 1,
    'hideAll': 2,
}
win32LobAppNotification = enum.Enum('win32LobAppNotification', win32LobAppNotification_data)


win32LobAppPowerShellScriptDetectionType_data = {
    'notConfigured': 0,
    'string': 1,
    'dateTime': 2,
    'integer': 3,
    'float': 4,
    'version': 5,
    'boolean': 6,
}
win32LobAppPowerShellScriptDetectionType = enum.Enum('win32LobAppPowerShellScriptDetectionType', win32LobAppPowerShellScriptDetectionType_data)


win32LobAppPowerShellScriptRuleOperationType_data = {
    'notConfigured': 0,
    'string': 1,
    'dateTime': 2,
    'integer': 3,
    'float': 4,
    'version': 5,
    'boolean': 6,
}
win32LobAppPowerShellScriptRuleOperationType = enum.Enum('win32LobAppPowerShellScriptRuleOperationType', win32LobAppPowerShellScriptRuleOperationType_data)


win32LobAppRegistryDetectionType_data = {
    'notConfigured': 0,
    'exists': 1,
    'doesNotExist': 2,
    'string': 3,
    'integer': 4,
    'version': 5,
}
win32LobAppRegistryDetectionType = enum.Enum('win32LobAppRegistryDetectionType', win32LobAppRegistryDetectionType_data)


win32LobAppRegistryRuleOperationType_data = {
    'notConfigured': 0,
    'exists': 1,
    'doesNotExist': 2,
    'string': 3,
    'integer': 4,
    'version': 5,
    'appVersion': 7,
    'unknownFutureValue': 8,
}
win32LobAppRegistryRuleOperationType = enum.Enum('win32LobAppRegistryRuleOperationType', win32LobAppRegistryRuleOperationType_data)


win32LobAppRestartBehavior_data = {
    'basedOnReturnCode': 0,
    'allow': 1,
    'suppress': 2,
    'force': 3,
}
win32LobAppRestartBehavior = enum.Enum('win32LobAppRestartBehavior', win32LobAppRestartBehavior_data)


win32LobAppReturnCodeType_data = {
    'failed': 0,
    'success': 1,
    'softReboot': 2,
    'hardReboot': 3,
    'retry': 4,
}
win32LobAppReturnCodeType = enum.Enum('win32LobAppReturnCodeType', win32LobAppReturnCodeType_data)


win32LobAppRuleOperator_data = {
    'notConfigured': 0,
    'equal': 1,
    'notEqual': 2,
    'greaterThan': 4,
    'greaterThanOrEqual': 5,
    'lessThan': 8,
    'lessThanOrEqual': 9,
}
win32LobAppRuleOperator = enum.Enum('win32LobAppRuleOperator', win32LobAppRuleOperator_data)


win32LobAppRuleType_data = {
    'detection': 0,
    'requirement': 1,
}
win32LobAppRuleType = enum.Enum('win32LobAppRuleType', win32LobAppRuleType_data)


win32LobAutoUpdateSupersededAppsState_data = {
    'notConfigured': 0,
    'enabled': 1,
    'unknownFutureValue': 2,
}
win32LobAutoUpdateSupersededAppsState = enum.Enum('win32LobAutoUpdateSupersededAppsState', win32LobAutoUpdateSupersededAppsState_data)


windowsArchitecture_data = {
    'none': 0,
    'x86': 1,
    'x64': 2,
    'arm': 4,
    'neutral': 8,
    'arm64': 16,
}
windowsArchitecture = enum.Enum('windowsArchitecture', windowsArchitecture_data)


windowsDeviceType_data = {
    'none': 0,
    'desktop': 1,
    'mobile': 2,
    'holographic': 4,
    'team': 8,
    'unknownFutureValue': 16,
}
windowsDeviceType = enum.Enum('windowsDeviceType', windowsDeviceType_data)


winGetAppNotification_data = {
    'showAll': 0,
    'showReboot': 1,
    'hideAll': 2,
    'unknownFutureValue': 3,
}
winGetAppNotification = enum.Enum('winGetAppNotification', winGetAppNotification_data)


installState_data = {
    'notApplicable': 0,
    'installed': 1,
    'failed': 2,
    'notInstalled': 3,
    'uninstallFailed': 4,
    'unknown': 5,
}
installState = enum.Enum('installState', installState_data)


assignmentFilterEvaluationResult_data = {
    'unknown': 0,
    'match': 1,
    'notMatch': 2,
    'inconclusive': 3,
    'failure': 4,
    'notEvaluated': 5,
}
assignmentFilterEvaluationResult = enum.Enum('assignmentFilterEvaluationResult', assignmentFilterEvaluationResult_data)


assignmentFilterManagementType_data = {
    'devices': 0,
    'apps': 1,
    'unknownFutureValue': 2,
}
assignmentFilterManagementType = enum.Enum('assignmentFilterManagementType', assignmentFilterManagementType_data)


assignmentFilterOperator_data = {
    'notSet': 0,
    'equals': 1,
    'notEquals': 2,
    'startsWith': 3,
    'notStartsWith': 4,
    'contains': 5,
    'notContains': 6,
    'in': 7,
    'notIn': 8,
    'endsWith': 9,
    'notEndsWith': 10,
    'greaterThan': 11,
    'greaterThanOrEquals': 12,
    'lessThan': 13,
    'lessThanOrEquals': 14,
    'unknownFutureValue': 15,
}
assignmentFilterOperator = enum.Enum('assignmentFilterOperator', assignmentFilterOperator_data)


assignmentFilterPayloadType_data = {
    'notSet': 0,
    'enrollmentRestrictions': 1,
}
assignmentFilterPayloadType = enum.Enum('assignmentFilterPayloadType', assignmentFilterPayloadType_data)


associatedAssignmentPayloadType_data = {
    'unknown': 0,
    'deviceConfigurationAndCompliance': 1,
    'application': 2,
    'androidEnterpriseApp': 8,
    'enrollmentConfiguration': 9,
    'groupPolicyConfiguration': 12,
    'zeroTouchDeploymentDeviceConfigProfile': 15,
    'androidEnterpriseConfiguration': 16,
    'deviceFirmwareConfigurationInterfacePolicy': 20,
    'resourceAccessPolicy': 23,
    'win32app': 24,
    'deviceManagmentConfigurationAndCompliancePolicy': 29,
}
associatedAssignmentPayloadType = enum.Enum('associatedAssignmentPayloadType', associatedAssignmentPayloadType_data)


devicePlatformType_data = {
    'android': 0,
    'androidForWork': 1,
    'iOS': 2,
    'macOS': 3,
    'windowsPhone81': 4,
    'windows81AndLater': 5,
    'windows10AndLater': 6,
    'androidWorkProfile': 7,
    'unknown': 8,
    'androidAOSP': 9,
    'androidMobileApplicationManagement': 10,
    'iOSMobileApplicationManagement': 11,
    'unknownFutureValue': 12,
    'windowsMobileApplicationManagement': 13,
}
devicePlatformType = enum.Enum('devicePlatformType', devicePlatformType_data)


errorCode_data = {
    'noError': 0,
    'unauthorized': 1,
    'notFound': 2,
    'deleted': 3,
}
errorCode = enum.Enum('errorCode', errorCode_data)


policySetStatus_data = {
    'unknown': 0,
    'validating': 1,
    'partialSuccess': 2,
    'success': 3,
    'error': 4,
    'notAssigned': 5,
}
policySetStatus = enum.Enum('policySetStatus', policySetStatus_data)


chromeOSOnboardingStatus_data = {
    'unknown': 0,
    'inprogress': 1,
    'onboarded': 2,
    'failed': 3,
    'offboarding': 4,
    'unknownFutureValue': 99,
}
chromeOSOnboardingStatus = enum.Enum('chromeOSOnboardingStatus', chromeOSOnboardingStatus_data)


onboardingStatus_data = {
    'unknown': 0,
    'inprogress': 1,
    'onboarded': 2,
    'failed': 3,
    'offboarding': 4,
    'unknownFutureValue': 99,
}
onboardingStatus = enum.Enum('onboardingStatus', onboardingStatus_data)


cloudCertificationAuthorityCertificateKeySize_data = {
    'unknown': 0,
    'rsa2048': 1,
    'rsa3072': 2,
    'rsa4096': 3,
    'eCP256': 4,
    'eCP256k': 5,
    'eCP384': 6,
    'eCP521': 7,
    'unknownFutureValue': 8,
}
cloudCertificationAuthorityCertificateKeySize = enum.Enum('cloudCertificationAuthorityCertificateKeySize', cloudCertificationAuthorityCertificateKeySize_data)


cloudCertificationAuthorityHashingAlgorithm_data = {
    'unknown': 0,
    'sha256': 1,
    'sha384': 2,
    'sha512': 3,
    'unknownFutureValue': 4,
}
cloudCertificationAuthorityHashingAlgorithm = enum.Enum('cloudCertificationAuthorityHashingAlgorithm', cloudCertificationAuthorityHashingAlgorithm_data)


cloudCertificationAuthorityKeyPlatformType_data = {
    'unknown': 0,
    'software': 1,
    'hardwareSecurityModule': 2,
    'unknownFutureValue': 3,
}
cloudCertificationAuthorityKeyPlatformType = enum.Enum('cloudCertificationAuthorityKeyPlatformType', cloudCertificationAuthorityKeyPlatformType_data)


cloudCertificationAuthorityLeafCertificateStatus_data = {
    'unknown': 0,
    'active': 1,
    'revoked': 2,
    'expired': 3,
    'unknownFutureValue': 4,
}
cloudCertificationAuthorityLeafCertificateStatus = enum.Enum('cloudCertificationAuthorityLeafCertificateStatus', cloudCertificationAuthorityLeafCertificateStatus_data)


cloudCertificationAuthorityStatus_data = {
    'unknown': 0,
    'active': 1,
    'paused': 2,
    'revoked': 3,
    'signingPending': 4,
    'unknownFutureValue': 5,
}
cloudCertificationAuthorityStatus = enum.Enum('cloudCertificationAuthorityStatus', cloudCertificationAuthorityStatus_data)


cloudCertificationAuthorityType_data = {
    'unknown': 0,
    'rootCertificationAuthority': 1,
    'issuingCertificationAuthority': 2,
    'issuingCertificationAuthorityWithExternalRoot': 3,
    'unknownFutureValue': 4,
}
cloudCertificationAuthorityType = enum.Enum('cloudCertificationAuthorityType', cloudCertificationAuthorityType_data)


administratorConfiguredDeviceComplianceState_data = {
    'basedOnDeviceCompliancePolicy': 0,
    'nonCompliant': 1,
}
administratorConfiguredDeviceComplianceState = enum.Enum('administratorConfiguredDeviceComplianceState', administratorConfiguredDeviceComplianceState_data)


advancedBitLockerState_data = {
    'success': 0,
    'noUserConsent': 1,
    'osVolumeUnprotected': 2,
    'osVolumeTpmRequired': 4,
    'osVolumeTpmOnlyRequired': 8,
    'osVolumeTpmPinRequired': 16,
    'osVolumeTpmStartupKeyRequired': 32,
    'osVolumeTpmPinStartupKeyRequired': 64,
    'osVolumeEncryptionMethodMismatch': 128,
    'recoveryKeyBackupFailed': 256,
    'fixedDriveNotEncrypted': 512,
    'fixedDriveEncryptionMethodMismatch': 1024,
    'loggedOnUserNonAdmin': 2048,
    'windowsRecoveryEnvironmentNotConfigured': 4096,
    'tpmNotAvailable': 8192,
    'tpmNotReady': 16384,
    'networkError': 32768,
}
advancedBitLockerState = enum.Enum('advancedBitLockerState', advancedBitLockerState_data)


androidDeviceOwnerAppAutoUpdatePolicyType_data = {
    'notConfigured': 0,
    'userChoice': 1,
    'never': 2,
    'wiFiOnly': 3,
    'always': 4,
}
androidDeviceOwnerAppAutoUpdatePolicyType = enum.Enum('androidDeviceOwnerAppAutoUpdatePolicyType', androidDeviceOwnerAppAutoUpdatePolicyType_data)


androidDeviceOwnerBatteryPluggedMode_data = {
    'notConfigured': 0,
    'ac': 1,
    'usb': 2,
    'wireless': 3,
}
androidDeviceOwnerBatteryPluggedMode = enum.Enum('androidDeviceOwnerBatteryPluggedMode', androidDeviceOwnerBatteryPluggedMode_data)


androidDeviceOwnerCertificateAccessType_data = {
    'userApproval': 0,
    'specificApps': 1,
    'unknownFutureValue': 2,
}
androidDeviceOwnerCertificateAccessType = enum.Enum('androidDeviceOwnerCertificateAccessType', androidDeviceOwnerCertificateAccessType_data)


androidDeviceOwnerCrossProfileDataSharing_data = {
    'notConfigured': 0,
    'crossProfileDataSharingBlocked': 1,
    'dataSharingFromWorkToPersonalBlocked': 2,
    'crossProfileDataSharingAllowed': 3,
    'unkownFutureValue': 4,
}
androidDeviceOwnerCrossProfileDataSharing = enum.Enum('androidDeviceOwnerCrossProfileDataSharing', androidDeviceOwnerCrossProfileDataSharing_data)


androidDeviceOwnerDefaultAppPermissionPolicyType_data = {
    'deviceDefault': 0,
    'prompt': 1,
    'autoGrant': 2,
    'autoDeny': 3,
}
androidDeviceOwnerDefaultAppPermissionPolicyType = enum.Enum('androidDeviceOwnerDefaultAppPermissionPolicyType', androidDeviceOwnerDefaultAppPermissionPolicyType_data)


androidDeviceOwnerDelegatedAppScopeType_data = {
    'unspecified': 0,
    'certificateInstall': 1,
    'captureNetworkActivityLog': 2,
    'captureSecurityLog': 3,
    'unknownFutureValue': 4,
}
androidDeviceOwnerDelegatedAppScopeType = enum.Enum('androidDeviceOwnerDelegatedAppScopeType', androidDeviceOwnerDelegatedAppScopeType_data)


androidDeviceOwnerEnrollmentProfileType_data = {
    'notConfigured': 0,
    'dedicatedDevice': 1,
    'fullyManaged': 2,
}
androidDeviceOwnerEnrollmentProfileType = enum.Enum('androidDeviceOwnerEnrollmentProfileType', androidDeviceOwnerEnrollmentProfileType_data)


androidDeviceOwnerKioskCustomizationStatusBar_data = {
    'notConfigured': 0,
    'notificationsAndSystemInfoEnabled': 1,
    'systemInfoOnly': 2,
}
androidDeviceOwnerKioskCustomizationStatusBar = enum.Enum('androidDeviceOwnerKioskCustomizationStatusBar', androidDeviceOwnerKioskCustomizationStatusBar_data)


androidDeviceOwnerKioskCustomizationSystemNavigation_data = {
    'notConfigured': 0,
    'navigationEnabled': 1,
    'homeButtonOnly': 2,
}
androidDeviceOwnerKioskCustomizationSystemNavigation = enum.Enum('androidDeviceOwnerKioskCustomizationSystemNavigation', androidDeviceOwnerKioskCustomizationSystemNavigation_data)


androidDeviceOwnerKioskModeFolderIcon_data = {
    'notConfigured': 0,
    'darkSquare': 1,
    'darkCircle': 2,
    'lightSquare': 3,
    'lightCircle': 4,
}
androidDeviceOwnerKioskModeFolderIcon = enum.Enum('androidDeviceOwnerKioskModeFolderIcon', androidDeviceOwnerKioskModeFolderIcon_data)


androidDeviceOwnerKioskModeIconSize_data = {
    'notConfigured': 0,
    'smallest': 1,
    'small': 2,
    'regular': 3,
    'large': 4,
    'largest': 5,
}
androidDeviceOwnerKioskModeIconSize = enum.Enum('androidDeviceOwnerKioskModeIconSize', androidDeviceOwnerKioskModeIconSize_data)


androidDeviceOwnerKioskModeScreenOrientation_data = {
    'notConfigured': 0,
    'portrait': 1,
    'landscape': 2,
    'autoRotate': 3,
}
androidDeviceOwnerKioskModeScreenOrientation = enum.Enum('androidDeviceOwnerKioskModeScreenOrientation', androidDeviceOwnerKioskModeScreenOrientation_data)


androidDeviceOwnerLocationMode_data = {
    'notConfigured': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
}
androidDeviceOwnerLocationMode = enum.Enum('androidDeviceOwnerLocationMode', androidDeviceOwnerLocationMode_data)


androidDeviceOwnerPlayStoreMode_data = {
    'notConfigured': 0,
    'allowList': 1,
    'blockList': 2,
}
androidDeviceOwnerPlayStoreMode = enum.Enum('androidDeviceOwnerPlayStoreMode', androidDeviceOwnerPlayStoreMode_data)


androidDeviceOwnerRequiredPasswordType_data = {
    'deviceDefault': 0,
    'required': 1,
    'numeric': 2,
    'numericComplex': 3,
    'alphabetic': 4,
    'alphanumeric': 5,
    'alphanumericWithSymbols': 6,
    'lowSecurityBiometric': 7,
    'customPassword': 8,
}
androidDeviceOwnerRequiredPasswordType = enum.Enum('androidDeviceOwnerRequiredPasswordType', androidDeviceOwnerRequiredPasswordType_data)


androidDeviceOwnerRequiredPasswordUnlock_data = {
    'deviceDefault': 0,
    'daily': 1,
    'unkownFutureValue': 2,
}
androidDeviceOwnerRequiredPasswordUnlock = enum.Enum('androidDeviceOwnerRequiredPasswordUnlock', androidDeviceOwnerRequiredPasswordUnlock_data)


androidDeviceOwnerSystemUpdateInstallType_data = {
    'deviceDefault': 0,
    'postpone': 1,
    'windowed': 2,
    'automatic': 3,
}
androidDeviceOwnerSystemUpdateInstallType = enum.Enum('androidDeviceOwnerSystemUpdateInstallType', androidDeviceOwnerSystemUpdateInstallType_data)


androidDeviceOwnerVirtualHomeButtonType_data = {
    'notConfigured': 0,
    'swipeUp': 1,
    'floating': 2,
}
androidDeviceOwnerVirtualHomeButtonType = enum.Enum('androidDeviceOwnerVirtualHomeButtonType', androidDeviceOwnerVirtualHomeButtonType_data)


androidDeviceOwnerWiFiSecurityType_data = {
    'open': 0,
    'wep': 1,
    'wpaPersonal': 2,
    'wpaEnterprise': 4,
}
androidDeviceOwnerWiFiSecurityType = enum.Enum('androidDeviceOwnerWiFiSecurityType', androidDeviceOwnerWiFiSecurityType_data)


androidEapType_data = {
    'eapTls': 13,
    'eapTtls': 21,
    'peap': 25,
}
androidEapType = enum.Enum('androidEapType', androidEapType_data)


androidForWorkCrossProfileDataSharingType_data = {
    'deviceDefault': 0,
    'preventAny': 1,
    'allowPersonalToWork': 2,
    'noRestrictions': 3,
}
androidForWorkCrossProfileDataSharingType = enum.Enum('androidForWorkCrossProfileDataSharingType', androidForWorkCrossProfileDataSharingType_data)


androidForWorkDefaultAppPermissionPolicyType_data = {
    'deviceDefault': 0,
    'prompt': 1,
    'autoGrant': 2,
    'autoDeny': 3,
}
androidForWorkDefaultAppPermissionPolicyType = enum.Enum('androidForWorkDefaultAppPermissionPolicyType', androidForWorkDefaultAppPermissionPolicyType_data)


androidForWorkRequiredPasswordType_data = {
    'deviceDefault': 0,
    'lowSecurityBiometric': 1,
    'required': 2,
    'atLeastNumeric': 3,
    'numericComplex': 4,
    'atLeastAlphabetic': 5,
    'atLeastAlphanumeric': 6,
    'alphanumericWithSymbols': 7,
}
androidForWorkRequiredPasswordType = enum.Enum('androidForWorkRequiredPasswordType', androidForWorkRequiredPasswordType_data)


androidForWorkVpnConnectionType_data = {
    'ciscoAnyConnect': 0,
    'pulseSecure': 1,
    'f5EdgeClient': 2,
    'dellSonicWallMobileConnect': 3,
    'checkPointCapsuleVpn': 4,
    'citrix': 5,
}
androidForWorkVpnConnectionType = enum.Enum('androidForWorkVpnConnectionType', androidForWorkVpnConnectionType_data)


androidKeyguardFeature_data = {
    'notConfigured': 0,
    'camera': 1,
    'notifications': 2,
    'unredactedNotifications': 3,
    'trustAgents': 4,
    'fingerprint': 5,
    'remoteInput': 6,
    'allFeatures': 7,
    'face': 8,
    'iris': 9,
    'biometrics': 10,
}
androidKeyguardFeature = enum.Enum('androidKeyguardFeature', androidKeyguardFeature_data)


androidRequiredPasswordComplexity_data = {
    'none': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
}
androidRequiredPasswordComplexity = enum.Enum('androidRequiredPasswordComplexity', androidRequiredPasswordComplexity_data)


androidRequiredPasswordType_data = {
    'deviceDefault': 0,
    'alphabetic': 1,
    'alphanumeric': 2,
    'alphanumericWithSymbols': 3,
    'lowSecurityBiometric': 4,
    'numeric': 5,
    'numericComplex': 6,
    'any': 7,
}
androidRequiredPasswordType = enum.Enum('androidRequiredPasswordType', androidRequiredPasswordType_data)


androidSafetyNetEvaluationType_data = {
    'basic': 0,
    'hardwareBacked': 1,
}
androidSafetyNetEvaluationType = enum.Enum('androidSafetyNetEvaluationType', androidSafetyNetEvaluationType_data)


androidUsernameSource_data = {
    'username': 0,
    'userPrincipalName': 1,
    'samAccountName': 2,
    'primarySmtpAddress': 3,
}
androidUsernameSource = enum.Enum('androidUsernameSource', androidUsernameSource_data)


androidVpnConnectionType_data = {
    'ciscoAnyConnect': 0,
    'pulseSecure': 1,
    'f5EdgeClient': 2,
    'dellSonicWallMobileConnect': 3,
    'checkPointCapsuleVpn': 4,
    'citrix': 5,
    'microsoftTunnel': 7,
    'netMotionMobility': 8,
    'microsoftProtect': 9,
}
androidVpnConnectionType = enum.Enum('androidVpnConnectionType', androidVpnConnectionType_data)


androidWiFiSecurityType_data = {
    'open': 0,
    'wpaEnterprise': 1,
    'wpa2Enterprise': 2,
    'wep': 3,
    'wpaPersonal': 4,
    'unknownFutureValue': 5,
}
androidWiFiSecurityType = enum.Enum('androidWiFiSecurityType', androidWiFiSecurityType_data)


androidWorkProfileAccountUse_data = {
    'allowAllExceptGoogleAccounts': 0,
    'blockAll': 1,
    'allowAll': 2,
    'unknownFutureValue': 3,
}
androidWorkProfileAccountUse = enum.Enum('androidWorkProfileAccountUse', androidWorkProfileAccountUse_data)


androidWorkProfileCrossProfileDataSharingType_data = {
    'deviceDefault': 0,
    'preventAny': 1,
    'allowPersonalToWork': 2,
    'noRestrictions': 3,
}
androidWorkProfileCrossProfileDataSharingType = enum.Enum('androidWorkProfileCrossProfileDataSharingType', androidWorkProfileCrossProfileDataSharingType_data)


androidWorkProfileDefaultAppPermissionPolicyType_data = {
    'deviceDefault': 0,
    'prompt': 1,
    'autoGrant': 2,
    'autoDeny': 3,
}
androidWorkProfileDefaultAppPermissionPolicyType = enum.Enum('androidWorkProfileDefaultAppPermissionPolicyType', androidWorkProfileDefaultAppPermissionPolicyType_data)


androidWorkProfileRequiredPasswordType_data = {
    'deviceDefault': 0,
    'lowSecurityBiometric': 1,
    'required': 2,
    'atLeastNumeric': 3,
    'numericComplex': 4,
    'atLeastAlphabetic': 5,
    'atLeastAlphanumeric': 6,
    'alphanumericWithSymbols': 7,
}
androidWorkProfileRequiredPasswordType = enum.Enum('androidWorkProfileRequiredPasswordType', androidWorkProfileRequiredPasswordType_data)


androidWorkProfileVpnConnectionType_data = {
    'ciscoAnyConnect': 0,
    'pulseSecure': 1,
    'f5EdgeClient': 2,
    'dellSonicWallMobileConnect': 3,
    'checkPointCapsuleVpn': 4,
    'citrix': 5,
    'paloAltoGlobalProtect': 6,
    'microsoftTunnel': 7,
    'netMotionMobility': 8,
    'microsoftProtect': 9,
}
androidWorkProfileVpnConnectionType = enum.Enum('androidWorkProfileVpnConnectionType', androidWorkProfileVpnConnectionType_data)


aospDeviceOwnerWiFiSecurityType_data = {
    'open': 0,
    'wep': 1,
    'wpaPersonal': 2,
    'wpaEnterprise': 4,
}
aospDeviceOwnerWiFiSecurityType = enum.Enum('aospDeviceOwnerWiFiSecurityType', aospDeviceOwnerWiFiSecurityType_data)


appInstallControlType_data = {
    'notConfigured': 0,
    'anywhere': 1,
    'storeOnly': 2,
    'recommendations': 3,
    'preferStore': 4,
}
appInstallControlType = enum.Enum('appInstallControlType', appInstallControlType_data)


appleDeploymentChannel_data = {
    'deviceChannel': 0,
    'userChannel': 1,
    'unknownFutureValue': 2,
}
appleDeploymentChannel = enum.Enum('appleDeploymentChannel', appleDeploymentChannel_data)


appleSubjectNameFormat_data = {
    'commonName': 0,
    'commonNameAsEmail': 1,
    'custom': 2,
    'commonNameIncludingEmail': 3,
    'commonNameAsIMEI': 5,
    'commonNameAsSerialNumber': 6,
}
appleSubjectNameFormat = enum.Enum('appleSubjectNameFormat', appleSubjectNameFormat_data)


appleVpnConnectionType_data = {
    'ciscoAnyConnect': 0,
    'pulseSecure': 1,
    'f5EdgeClient': 2,
    'dellSonicWallMobileConnect': 3,
    'checkPointCapsuleVpn': 4,
    'customVpn': 5,
    'ciscoIPSec': 6,
    'citrix': 7,
    'ciscoAnyConnectV2': 8,
    'paloAltoGlobalProtect': 9,
    'zscalerPrivateAccess': 10,
    'f5Access2018': 11,
    'citrixSso': 12,
    'paloAltoGlobalProtectV2': 13,
    'ikEv2': 14,
    'alwaysOn': 15,
    'microsoftTunnel': 16,
    'netMotionMobility': 17,
    'microsoftProtect': 18,
}
appleVpnConnectionType = enum.Enum('appleVpnConnectionType', appleVpnConnectionType_data)


applicationGuardBlockClipboardSharingType_data = {
    'notConfigured': 0,
    'blockBoth': 1,
    'blockHostToContainer': 2,
    'blockContainerToHost': 3,
    'blockNone': 4,
}
applicationGuardBlockClipboardSharingType = enum.Enum('applicationGuardBlockClipboardSharingType', applicationGuardBlockClipboardSharingType_data)


applicationGuardBlockFileTransferType_data = {
    'notConfigured': 0,
    'blockImageAndTextFile': 1,
    'blockImageFile': 2,
    'blockNone': 3,
    'blockTextFile': 4,
}
applicationGuardBlockFileTransferType = enum.Enum('applicationGuardBlockFileTransferType', applicationGuardBlockFileTransferType_data)


applicationGuardEnabledOptions_data = {
    'notConfigured': 0,
    'enabledForEdge': 1,
    'enabledForOffice': 2,
    'enabledForEdgeAndOffice': 3,
}
applicationGuardEnabledOptions = enum.Enum('applicationGuardEnabledOptions', applicationGuardEnabledOptions_data)


appListType_data = {
    'none': 0,
    'appsInListCompliant': 1,
    'appsNotInListCompliant': 2,
}
appListType = enum.Enum('appListType', appListType_data)


appLockerApplicationControlType_data = {
    'notConfigured': 0,
    'enforceComponentsAndStoreApps': 1,
    'auditComponentsAndStoreApps': 2,
    'enforceComponentsStoreAppsAndSmartlocker': 3,
    'auditComponentsStoreAppsAndSmartlocker': 4,
}
appLockerApplicationControlType = enum.Enum('appLockerApplicationControlType', appLockerApplicationControlType_data)


authenticationTransformConstant_data = {
    'md5_96': 0,
    'sha1_96': 1,
    'sha_256_128': 2,
    'aes128Gcm': 3,
    'aes192Gcm': 4,
    'aes256Gcm': 5,
}
authenticationTransformConstant = enum.Enum('authenticationTransformConstant', authenticationTransformConstant_data)


automaticUpdateMode_data = {
    'userDefined': 0,
    'notifyDownload': 1,
    'autoInstallAtMaintenanceTime': 2,
    'autoInstallAndRebootAtMaintenanceTime': 3,
    'autoInstallAndRebootAtScheduledTime': 4,
    'autoInstallAndRebootWithoutEndUserControl': 5,
    'windowsDefault': 6,
}
automaticUpdateMode = enum.Enum('automaticUpdateMode', automaticUpdateMode_data)


autoRestartNotificationDismissalMethod_data = {
    'notConfigured': 0,
    'automatic': 1,
    'user': 2,
    'unknownFutureValue': 3,
}
autoRestartNotificationDismissalMethod = enum.Enum('autoRestartNotificationDismissalMethod', autoRestartNotificationDismissalMethod_data)


bitLockerEncryptionMethod_data = {
    'aesCbc128': 3,
    'aesCbc256': 4,
    'xtsAes128': 6,
    'xtsAes256': 7,
}
bitLockerEncryptionMethod = enum.Enum('bitLockerEncryptionMethod', bitLockerEncryptionMethod_data)


bitLockerRecoveryInformationType_data = {
    'passwordAndKey': 1,
    'passwordOnly': 2,
}
bitLockerRecoveryInformationType = enum.Enum('bitLockerRecoveryInformationType', bitLockerRecoveryInformationType_data)


bitLockerRecoveryPasswordRotationType_data = {
    'notConfigured': 0,
    'disabled': 1,
    'enabledForAzureAd': 2,
    'enabledForAzureAdAndHybrid': 3,
}
bitLockerRecoveryPasswordRotationType = enum.Enum('bitLockerRecoveryPasswordRotationType', bitLockerRecoveryPasswordRotationType_data)


browserSyncSetting_data = {
    'notConfigured': 0,
    'blockedWithUserOverride': 1,
    'blocked': 2,
}
browserSyncSetting = enum.Enum('browserSyncSetting', browserSyncSetting_data)


certificateDestinationStore_data = {
    'computerCertStoreRoot': 0,
    'computerCertStoreIntermediate': 1,
    'userCertStoreIntermediate': 2,
}
certificateDestinationStore = enum.Enum('certificateDestinationStore', certificateDestinationStore_data)


certificateIssuanceStates_data = {
    'unknown': 0,
    'challengeIssued': 1,
    'challengeIssueFailed': 2,
    'requestCreationFailed': 3,
    'requestSubmitFailed': 4,
    'challengeValidationSucceeded': 5,
    'challengeValidationFailed': 6,
    'issueFailed': 7,
    'issuePending': 8,
    'issued': 9,
    'responseProcessingFailed': 10,
    'responsePending': 11,
    'enrollmentSucceeded': 12,
    'enrollmentNotNeeded': 13,
    'revoked': 14,
    'removedFromCollection': 15,
    'renewVerified': 16,
    'installFailed': 17,
    'installed': 18,
    'deleteFailed': 19,
    'deleted': 20,
    'renewalRequested': 21,
    'requested': 22,
}
certificateIssuanceStates = enum.Enum('certificateIssuanceStates', certificateIssuanceStates_data)


certificateRevocationStatus_data = {
    'none': 0,
    'pending': 1,
    'issued': 2,
    'failed': 3,
    'revoked': 4,
}
certificateRevocationStatus = enum.Enum('certificateRevocationStatus', certificateRevocationStatus_data)


certificateStore_data = {
    'user': 1,
    'machine': 2,
}
certificateStore = enum.Enum('certificateStore', certificateStore_data)


certificateValidityPeriodScale_data = {
    'days': 0,
    'months': 1,
    'years': 2,
}
certificateValidityPeriodScale = enum.Enum('certificateValidityPeriodScale', certificateValidityPeriodScale_data)


changeUefiSettingsPermission_data = {
    'notConfiguredOnly': 0,
    'none': 1,
}
changeUefiSettingsPermission = enum.Enum('changeUefiSettingsPermission', changeUefiSettingsPermission_data)


code_data = {
    'none': 0,
    'jsonFileInvalid': 1,
    'jsonFileMissing': 2,
    'jsonFileTooLarge': 3,
    'rulesMissing': 4,
    'duplicateRules': 5,
    'tooManyRulesSpecified': 6,
    'operatorMissing': 7,
    'operatorNotSupported': 8,
    'datatypeMissing': 9,
    'datatypeNotSupported': 10,
    'operatorDataTypeCombinationNotSupported': 11,
    'moreInfoUriMissing': 12,
    'moreInfoUriInvalid': 13,
    'moreInfoUriTooLarge': 14,
    'descriptionMissing': 15,
    'descriptionInvalid': 16,
    'descriptionTooLarge': 17,
    'titleMissing': 18,
    'titleInvalid': 19,
    'titleTooLarge': 20,
    'operandMissing': 21,
    'operandInvalid': 22,
    'operandTooLarge': 23,
    'settingNameMissing': 24,
    'settingNameInvalid': 25,
    'settingNameTooLarge': 26,
    'englishLocaleMissing': 27,
    'duplicateLocales': 28,
    'unrecognizedLocale': 29,
    'unknown': 30,
    'remediationStringsMissing': 31,
}
code = enum.Enum('code', code_data)


configurationUsage_data = {
    'blocked': 0,
    'required': 1,
    'allowed': 2,
    'notConfigured': 3,
}
configurationUsage = enum.Enum('configurationUsage', configurationUsage_data)


dataType_data = {
    'none': 0,
    'boolean': 1,
    'int64': 2,
    'double': 3,
    'string': 4,
    'dateTime': 5,
    'version': 6,
    'base64': 7,
    'xml': 8,
    'booleanArray': 9,
    'int64Array': 10,
    'doubleArray': 11,
    'stringArray': 12,
    'dateTimeArray': 13,
    'versionArray': 14,
}
dataType = enum.Enum('dataType', dataType_data)


defenderAttackSurfaceType_data = {
    'userDefined': 0,
    'block': 1,
    'auditMode': 2,
    'warn': 6,
    'disable': 99,
}
defenderAttackSurfaceType = enum.Enum('defenderAttackSurfaceType', defenderAttackSurfaceType_data)


defenderCloudBlockLevelType_data = {
    'notConfigured': 0,
    'high': 1,
    'highPlus': 2,
    'zeroTolerance': 3,
}
defenderCloudBlockLevelType = enum.Enum('defenderCloudBlockLevelType', defenderCloudBlockLevelType_data)


defenderMonitorFileActivity_data = {
    'userDefined': 0,
    'disable': 1,
    'monitorAllFiles': 2,
    'monitorIncomingFilesOnly': 3,
    'monitorOutgoingFilesOnly': 4,
}
defenderMonitorFileActivity = enum.Enum('defenderMonitorFileActivity', defenderMonitorFileActivity_data)


defenderPotentiallyUnwantedAppAction_data = {
    'deviceDefault': 0,
    'block': 1,
    'audit': 2,
}
defenderPotentiallyUnwantedAppAction = enum.Enum('defenderPotentiallyUnwantedAppAction', defenderPotentiallyUnwantedAppAction_data)


defenderPromptForSampleSubmission_data = {
    'userDefined': 0,
    'alwaysPrompt': 1,
    'promptBeforeSendingPersonalData': 2,
    'neverSendData': 3,
    'sendAllDataWithoutPrompting': 4,
}
defenderPromptForSampleSubmission = enum.Enum('defenderPromptForSampleSubmission', defenderPromptForSampleSubmission_data)


defenderProtectionType_data = {
    'userDefined': 0,
    'enable': 1,
    'auditMode': 2,
    'warn': 6,
    'notConfigured': 99,
}
defenderProtectionType = enum.Enum('defenderProtectionType', defenderProtectionType_data)


defenderRealtimeScanDirection_data = {
    'monitorAllFiles': 0,
    'monitorIncomingFilesOnly': 1,
    'monitorOutgoingFilesOnly': 2,
}
defenderRealtimeScanDirection = enum.Enum('defenderRealtimeScanDirection', defenderRealtimeScanDirection_data)


defenderScanType_data = {
    'userDefined': 0,
    'disabled': 1,
    'quick': 2,
    'full': 3,
}
defenderScanType = enum.Enum('defenderScanType', defenderScanType_data)


defenderSecurityCenterITContactDisplayType_data = {
    'notConfigured': 0,
    'displayInAppAndInNotifications': 1,
    'displayOnlyInApp': 2,
    'displayOnlyInNotifications': 3,
}
defenderSecurityCenterITContactDisplayType = enum.Enum('defenderSecurityCenterITContactDisplayType', defenderSecurityCenterITContactDisplayType_data)


defenderSecurityCenterNotificationsFromAppType_data = {
    'notConfigured': 0,
    'blockNoncriticalNotifications': 1,
    'blockAllNotifications': 2,
}
defenderSecurityCenterNotificationsFromAppType = enum.Enum('defenderSecurityCenterNotificationsFromAppType', defenderSecurityCenterNotificationsFromAppType_data)


defenderSubmitSamplesConsentType_data = {
    'sendSafeSamplesAutomatically': 0,
    'alwaysPrompt': 1,
    'neverSend': 2,
    'sendAllSamplesAutomatically': 3,
}
defenderSubmitSamplesConsentType = enum.Enum('defenderSubmitSamplesConsentType', defenderSubmitSamplesConsentType_data)


defenderThreatAction_data = {
    'deviceDefault': 0,
    'clean': 1,
    'quarantine': 2,
    'remove': 3,
    'allow': 4,
    'userDefined': 5,
    'block': 6,
}
defenderThreatAction = enum.Enum('defenderThreatAction', defenderThreatAction_data)


deliveryOptimizationGroupIdOptionsType_data = {
    'notConfigured': 0,
    'adSite': 1,
    'authenticatedDomainSid': 2,
    'dhcpUserOption': 3,
    'dnsSuffix': 4,
}
deliveryOptimizationGroupIdOptionsType = enum.Enum('deliveryOptimizationGroupIdOptionsType', deliveryOptimizationGroupIdOptionsType_data)


deliveryOptimizationRestrictPeerSelectionByOptions_data = {
    'notConfigured': 0,
    'subnetMask': 1,
}
deliveryOptimizationRestrictPeerSelectionByOptions = enum.Enum('deliveryOptimizationRestrictPeerSelectionByOptions', deliveryOptimizationRestrictPeerSelectionByOptions_data)


derivedCredentialProviderType_data = {
    'notConfigured': 0,
    'entrustDataCard': 1,
    'purebred': 2,
    'xTec': 3,
    'intercede': 4,
}
derivedCredentialProviderType = enum.Enum('derivedCredentialProviderType', derivedCredentialProviderType_data)


deviceComplianceActionType_data = {
    'noAction': 0,
    'notification': 1,
    'block': 2,
    'retire': 3,
    'wipe': 4,
    'removeResourceAccessProfiles': 5,
    'pushNotification': 9,
    'remoteLock': 10,
}
deviceComplianceActionType = enum.Enum('deviceComplianceActionType', deviceComplianceActionType_data)


deviceComplianceScriptRuleDataType_data = {
    'none': 0,
    'boolean': 1,
    'int64': 2,
    'double': 3,
    'string': 4,
    'dateTime': 5,
    'version': 6,
    'base64': 7,
    'xml': 8,
    'booleanArray': 9,
    'int64Array': 10,
    'doubleArray': 11,
    'stringArray': 12,
    'dateTimeArray': 13,
    'versionArray': 14,
}
deviceComplianceScriptRuleDataType = enum.Enum('deviceComplianceScriptRuleDataType', deviceComplianceScriptRuleDataType_data)


deviceComplianceScriptRulesValidationError_data = {
    'none': 0,
    'jsonFileInvalid': 1,
    'jsonFileMissing': 2,
    'jsonFileTooLarge': 3,
    'rulesMissing': 4,
    'duplicateRules': 5,
    'tooManyRulesSpecified': 6,
    'operatorMissing': 7,
    'operatorNotSupported': 8,
    'datatypeMissing': 9,
    'datatypeNotSupported': 10,
    'operatorDataTypeCombinationNotSupported': 11,
    'moreInfoUriMissing': 12,
    'moreInfoUriInvalid': 13,
    'moreInfoUriTooLarge': 14,
    'descriptionMissing': 15,
    'descriptionInvalid': 16,
    'descriptionTooLarge': 17,
    'titleMissing': 18,
    'titleInvalid': 19,
    'titleTooLarge': 20,
    'operandMissing': 21,
    'operandInvalid': 22,
    'operandTooLarge': 23,
    'settingNameMissing': 24,
    'settingNameInvalid': 25,
    'settingNameTooLarge': 26,
    'englishLocaleMissing': 27,
    'duplicateLocales': 28,
    'unrecognizedLocale': 29,
    'unknown': 30,
    'remediationStringsMissing': 31,
}
deviceComplianceScriptRulesValidationError = enum.Enum('deviceComplianceScriptRulesValidationError', deviceComplianceScriptRulesValidationError_data)


deviceComplianceScriptRulOperator_data = {
    'none': 0,
    'and': 1,
    'or': 2,
    'isEquals': 3,
    'notEquals': 4,
    'greaterThan': 5,
    'lessThan': 6,
    'between': 7,
    'notBetween': 8,
    'greaterEquals': 9,
    'lessEquals': 10,
    'dayTimeBetween': 11,
    'beginsWith': 12,
    'notBeginsWith': 13,
    'endsWith': 14,
    'notEndsWith': 15,
    'contains': 16,
    'notContains': 17,
    'allOf': 18,
    'oneOf': 19,
    'noneOf': 20,
    'setEquals': 21,
    'orderedSetEquals': 22,
    'subsetOf': 23,
    'excludesAll': 24,
}
deviceComplianceScriptRulOperator = enum.Enum('deviceComplianceScriptRulOperator', deviceComplianceScriptRulOperator_data)


deviceConfigAssignmentIntent_data = {
    'apply': 0,
    'remove': 1,
}
deviceConfigAssignmentIntent = enum.Enum('deviceConfigAssignmentIntent', deviceConfigAssignmentIntent_data)


deviceGuardLocalSystemAuthorityCredentialGuardType_data = {
    'notConfigured': 0,
    'enableWithUEFILock': 1,
    'enableWithoutUEFILock': 2,
    'disable': 3,
}
deviceGuardLocalSystemAuthorityCredentialGuardType = enum.Enum('deviceGuardLocalSystemAuthorityCredentialGuardType', deviceGuardLocalSystemAuthorityCredentialGuardType_data)


deviceManagementApplicabilityRuleType_data = {
    'include': 0,
    'exclude': 1,
}
deviceManagementApplicabilityRuleType = enum.Enum('deviceManagementApplicabilityRuleType', deviceManagementApplicabilityRuleType_data)


deviceManagementCertificationAuthority_data = {
    'notConfigured': 0,
    'microsoft': 1,
    'digiCert': 2,
}
deviceManagementCertificationAuthority = enum.Enum('deviceManagementCertificationAuthority', deviceManagementCertificationAuthority_data)


deviceThreatProtectionLevel_data = {
    'unavailable': 0,
    'secured': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'notSet': 10,
}
deviceThreatProtectionLevel = enum.Enum('deviceThreatProtectionLevel', deviceThreatProtectionLevel_data)


deviceType_data = {
    'desktop': 0,
    'windowsRT': 1,
    'winMO6': 2,
    'nokia': 3,
    'windowsPhone': 4,
    'mac': 5,
    'winCE': 6,
    'winEmbedded': 7,
    'iPhone': 8,
    'iPad': 9,
    'iPod': 10,
    'android': 11,
    'iSocConsumer': 12,
    'unix': 13,
    'macMDM': 14,
    'holoLens': 15,
    'surfaceHub': 16,
    'androidForWork': 17,
    'androidEnterprise': 18,
    'windows10x': 19,
    'androidnGMS': 20,
    'chromeOS': 21,
    'linux': 22,
    'blackberry': 100,
    'palm': 101,
    'unknown': 255,
    'cloudPC': 257,
}
deviceType = enum.Enum('deviceType', deviceType_data)


deviceTypes_data = {
    'desktop': 0,
    'windowsRT': 1,
    'winMO6': 2,
    'nokia': 3,
    'windowsPhone': 4,
    'mac': 5,
    'winCE': 6,
    'winEmbedded': 7,
    'iPhone': 8,
    'iPad': 9,
    'iPod': 10,
    'android': 11,
    'iSocConsumer': 12,
    'unix': 13,
    'macMDM': 14,
    'holoLens': 15,
    'surfaceHub': 16,
    'androidForWork': 17,
    'androidEnterprise': 18,
    'blackberry': 100,
    'palm': 101,
    'unknown': 255,
}
deviceTypes = enum.Enum('deviceTypes', deviceTypes_data)


diagnosticDataSubmissionMode_data = {
    'userDefined': 0,
    'none': 1,
    'basic': 2,
    'enhanced': 3,
    'full': 4,
}
diagnosticDataSubmissionMode = enum.Enum('diagnosticDataSubmissionMode', diagnosticDataSubmissionMode_data)


diffieHellmanGroup_data = {
    'group1': 0,
    'group2': 1,
    'group14': 2,
    'ecp256': 3,
    'ecp384': 4,
    'group24': 5,
}
diffieHellmanGroup = enum.Enum('diffieHellmanGroup', diffieHellmanGroup_data)


dmaGuardDeviceEnumerationPolicyType_data = {
    'deviceDefault': 0,
    'blockAll': 1,
    'allowAll': 2,
}
dmaGuardDeviceEnumerationPolicyType = enum.Enum('dmaGuardDeviceEnumerationPolicyType', dmaGuardDeviceEnumerationPolicyType_data)


domainNameSource_data = {
    'fullDomainName': 0,
    'netBiosDomainName': 1,
}
domainNameSource = enum.Enum('domainNameSource', domainNameSource_data)


eapFastConfiguration_data = {
    'noProtectedAccessCredential': 0,
    'useProtectedAccessCredential': 1,
    'useProtectedAccessCredentialAndProvision': 2,
    'useProtectedAccessCredentialAndProvisionAnonymously': 3,
}
eapFastConfiguration = enum.Enum('eapFastConfiguration', eapFastConfiguration_data)


eapType_data = {
    'eapTls': 13,
    'leap': 17,
    'eapSim': 18,
    'eapTtls': 21,
    'peap': 25,
    'eapFast': 43,
    'teap': 55,
}
eapType = enum.Enum('eapType', eapType_data)


easAuthenticationMethod_data = {
    'usernameAndPassword': 0,
    'certificate': 1,
    'derivedCredential': 2,
}
easAuthenticationMethod = enum.Enum('easAuthenticationMethod', easAuthenticationMethod_data)


easServices_data = {
    'none': 0,
    'calendars': 1,
    'contacts': 2,
    'email': 4,
    'notes': 8,
    'reminders': 16,
}
easServices = enum.Enum('easServices', easServices_data)


edgeCookiePolicy_data = {
    'userDefined': 0,
    'allow': 1,
    'blockThirdParty': 2,
    'blockAll': 3,
}
edgeCookiePolicy = enum.Enum('edgeCookiePolicy', edgeCookiePolicy_data)


edgeKioskModeRestrictionType_data = {
    'notConfigured': 0,
    'digitalSignage': 1,
    'normalMode': 2,
    'publicBrowsingSingleApp': 3,
    'publicBrowsingMultiApp': 4,
}
edgeKioskModeRestrictionType = enum.Enum('edgeKioskModeRestrictionType', edgeKioskModeRestrictionType_data)


edgeOpenOptions_data = {
    'notConfigured': 0,
    'startPage': 1,
    'newTabPage': 2,
    'previousPages': 3,
    'specificPages': 4,
}
edgeOpenOptions = enum.Enum('edgeOpenOptions', edgeOpenOptions_data)


edgeSearchEngineType_data = {
    'default': 0,
    'bing': 1,
}
edgeSearchEngineType = enum.Enum('edgeSearchEngineType', edgeSearchEngineType_data)


edgeTelemetryMode_data = {
    'notConfigured': 0,
    'intranet': 1,
    'internet': 2,
    'intranetAndInternet': 3,
}
edgeTelemetryMode = enum.Enum('edgeTelemetryMode', edgeTelemetryMode_data)


editionUpgradeLicenseType_data = {
    'productKey': 0,
    'licenseFile': 1,
    'notConfigured': 2,
}
editionUpgradeLicenseType = enum.Enum('editionUpgradeLicenseType', editionUpgradeLicenseType_data)


emailCertificateType_data = {
    'none': 0,
    'certificate': 1,
    'derivedCredential': 2,
}
emailCertificateType = enum.Enum('emailCertificateType', emailCertificateType_data)


emailSyncDuration_data = {
    'userDefined': 0,
    'oneDay': 1,
    'threeDays': 2,
    'oneWeek': 3,
    'twoWeeks': 4,
    'oneMonth': 5,
    'unlimited': 6,
}
emailSyncDuration = enum.Enum('emailSyncDuration', emailSyncDuration_data)


emailSyncSchedule_data = {
    'userDefined': 0,
    'asMessagesArrive': 1,
    'manual': 2,
    'fifteenMinutes': 3,
    'thirtyMinutes': 4,
    'sixtyMinutes': 5,
    'basedOnMyUsage': 6,
}
emailSyncSchedule = enum.Enum('emailSyncSchedule', emailSyncSchedule_data)


enablement_data = {
    'notConfigured': 0,
    'enabled': 1,
    'disabled': 2,
}
enablement = enum.Enum('enablement', enablement_data)


encryptionReadinessState_data = {
    'notReady': 0,
    'ready': 1,
}
encryptionReadinessState = enum.Enum('encryptionReadinessState', encryptionReadinessState_data)


encryptionState_data = {
    'notEncrypted': 0,
    'encrypted': 1,
}
encryptionState = enum.Enum('encryptionState', encryptionState_data)


fileVaultState_data = {
    'success': 0,
    'driveEncryptedByUser': 1,
    'userDeferredEncryption': 2,
    'escrowNotEnabled': 4,
}
fileVaultState = enum.Enum('fileVaultState', fileVaultState_data)


firewallCertificateRevocationListCheckMethodType_data = {
    'deviceDefault': 0,
    'none': 1,
    'attempt': 2,
    'require': 3,
}
firewallCertificateRevocationListCheckMethodType = enum.Enum('firewallCertificateRevocationListCheckMethodType', firewallCertificateRevocationListCheckMethodType_data)


firewallPacketQueueingMethodType_data = {
    'deviceDefault': 0,
    'disabled': 1,
    'queueInbound': 2,
    'queueOutbound': 3,
    'queueBoth': 4,
}
firewallPacketQueueingMethodType = enum.Enum('firewallPacketQueueingMethodType', firewallPacketQueueingMethodType_data)


firewallPreSharedKeyEncodingMethodType_data = {
    'deviceDefault': 0,
    'none': 1,
    'utF8': 2,
}
firewallPreSharedKeyEncodingMethodType = enum.Enum('firewallPreSharedKeyEncodingMethodType', firewallPreSharedKeyEncodingMethodType_data)


folderProtectionType_data = {
    'userDefined': 0,
    'enable': 1,
    'auditMode': 2,
    'blockDiskModification': 3,
    'auditDiskModification': 4,
}
folderProtectionType = enum.Enum('folderProtectionType', folderProtectionType_data)


hardwareConfigurationFormat_data = {
    'dell': 1,
    'surface': 2,
    'surfaceDock': 3,
}
hardwareConfigurationFormat = enum.Enum('hardwareConfigurationFormat', hardwareConfigurationFormat_data)


hashAlgorithms_data = {
    'sha1': 1,
    'sha2': 2,
}
hashAlgorithms = enum.Enum('hashAlgorithms', hashAlgorithms_data)


inkAccessSetting_data = {
    'notConfigured': 0,
    'enabled': 1,
    'disabled': 2,
}
inkAccessSetting = enum.Enum('inkAccessSetting', inkAccessSetting_data)


intendedPurpose_data = {
    'unassigned': 1,
    'smimeEncryption': 2,
    'smimeSigning': 3,
    'vpn': 4,
    'wifi': 5,
}
intendedPurpose = enum.Enum('intendedPurpose', intendedPurpose_data)


internetExplorerMessageSetting_data = {
    'notConfigured': 0,
    'disabled': 1,
    'enabled': 2,
    'keepGoing': 3,
}
internetExplorerMessageSetting = enum.Enum('internetExplorerMessageSetting', internetExplorerMessageSetting_data)


internetSiteSecurityLevel_data = {
    'userDefined': 0,
    'medium': 1,
    'mediumHigh': 2,
    'high': 3,
}
internetSiteSecurityLevel = enum.Enum('internetSiteSecurityLevel', internetSiteSecurityLevel_data)


iosKioskModeAppType_data = {
    'notConfigured': 0,
    'appStoreApp': 1,
    'managedApp': 2,
    'builtInApp': 3,
}
iosKioskModeAppType = enum.Enum('iosKioskModeAppType', iosKioskModeAppType_data)


iosNotificationAlertType_data = {
    'deviceDefault': 0,
    'banner': 1,
    'modal': 2,
    'none': 3,
}
iosNotificationAlertType = enum.Enum('iosNotificationAlertType', iosNotificationAlertType_data)


iosNotificationPreviewVisibility_data = {
    'notConfigured': 0,
    'alwaysShow': 1,
    'hideWhenLocked': 2,
    'neverShow': 3,
}
iosNotificationPreviewVisibility = enum.Enum('iosNotificationPreviewVisibility', iosNotificationPreviewVisibility_data)


iosSoftwareUpdateScheduleType_data = {
    'updateOutsideOfActiveHours': 0,
    'alwaysUpdate': 1,
    'updateDuringTimeWindows': 2,
    'updateOutsideOfTimeWindows': 3,
}
iosSoftwareUpdateScheduleType = enum.Enum('iosSoftwareUpdateScheduleType', iosSoftwareUpdateScheduleType_data)


iosUpdatesInstallStatus_data = {
    'updateScanFailed': -2016324062,
    'deviceOsHigherThanDesiredOsVersion': -2016330696,
    'updateError': -2016330697,
    'sharedDeviceUserLoggedInError': -2016330699,
    'notSupportedOperation': -2016330701,
    'installFailed': -2016330702,
    'installPhoneCallInProgress': -2016330703,
    'installInsufficientPower': -2016330704,
    'installInsufficientSpace': -2016330705,
    'installing': -2016330706,
    'downloadInsufficientNetwork': -2016330707,
    'downloadInsufficientPower': -2016330708,
    'downloadInsufficientSpace': -2016330709,
    'downloadRequiresComputer': -2016330710,
    'downloadFailed': -2016330711,
    'downloading': -2016330712,
    'timeout': -2016333898,
    'mdmClientCrashed': -2016336109,
    'success': 0,
    'available': 1,
    'idle': 2,
    'unknown': 3,
}
iosUpdatesInstallStatus = enum.Enum('iosUpdatesInstallStatus', iosUpdatesInstallStatus_data)


iosWallpaperDisplayLocation_data = {
    'notConfigured': 0,
    'lockScreen': 1,
    'homeScreen': 2,
    'lockAndHomeScreens': 3,
}
iosWallpaperDisplayLocation = enum.Enum('iosWallpaperDisplayLocation', iosWallpaperDisplayLocation_data)


keySize_data = {
    'size1024': 0,
    'size2048': 1,
    'size4096': 2,
}
keySize = enum.Enum('keySize', keySize_data)


keyStorageProviderOption_data = {
    'useTpmKspOtherwiseUseSoftwareKsp': 0,
    'useTpmKspOtherwiseFail': 1,
    'usePassportForWorkKspOtherwiseFail': 2,
    'useSoftwareKsp': 3,
}
keyStorageProviderOption = enum.Enum('keyStorageProviderOption', keyStorageProviderOption_data)


keyUsages_data = {
    'keyEncipherment': 1,
    'digitalSignature': 2,
}
keyUsages = enum.Enum('keyUsages', keyUsages_data)


kioskModeManagedHomeScreenPinComplexity_data = {
    'notConfigured': 0,
    'simple': 1,
    'complex': 2,
}
kioskModeManagedHomeScreenPinComplexity = enum.Enum('kioskModeManagedHomeScreenPinComplexity', kioskModeManagedHomeScreenPinComplexity_data)


kioskModeType_data = {
    'notConfigured': 0,
    'singleAppMode': 1,
    'multiAppMode': 2,
}
kioskModeType = enum.Enum('kioskModeType', kioskModeType_data)


lanManagerAuthenticationLevel_data = {
    'lmAndNltm': 0,
    'lmNtlmAndNtlmV2': 1,
    'lmAndNtlmOnly': 2,
    'lmAndNtlmV2': 3,
    'lmNtlmV2AndNotLm': 4,
    'lmNtlmV2AndNotLmOrNtm': 5,
}
lanManagerAuthenticationLevel = enum.Enum('lanManagerAuthenticationLevel', lanManagerAuthenticationLevel_data)


licenseType_data = {
    'notPaid': 0,
    'paid': 1,
    'trial': 2,
    'unknownFutureValue': 3,
}
licenseType = enum.Enum('licenseType', licenseType_data)


localSecurityOptionsAdministratorElevationPromptBehaviorType_data = {
    'notConfigured': 0,
    'elevateWithoutPrompting': 1,
    'promptForCredentialsOnTheSecureDesktop': 2,
    'promptForConsentOnTheSecureDesktop': 3,
    'promptForCredentials': 4,
    'promptForConsent': 5,
    'promptForConsentForNonWindowsBinaries': 6,
}
localSecurityOptionsAdministratorElevationPromptBehaviorType = enum.Enum('localSecurityOptionsAdministratorElevationPromptBehaviorType', localSecurityOptionsAdministratorElevationPromptBehaviorType_data)


localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType_data = {
    'notConfigured': 0,
    'administrators': 1,
    'administratorsAndPowerUsers': 2,
    'administratorsAndInteractiveUsers': 3,
}
localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType = enum.Enum('localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType', localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType_data)


localSecurityOptionsInformationDisplayedOnLockScreenType_data = {
    'notConfigured': 0,
    'administrators': 1,
    'administratorsAndPowerUsers': 2,
    'administratorsAndInteractiveUsers': 3,
}
localSecurityOptionsInformationDisplayedOnLockScreenType = enum.Enum('localSecurityOptionsInformationDisplayedOnLockScreenType', localSecurityOptionsInformationDisplayedOnLockScreenType_data)


localSecurityOptionsInformationShownOnLockScreenType_data = {
    'notConfigured': 0,
    'userDisplayNameDomainUser': 1,
    'userDisplayNameOnly': 2,
    'doNotDisplayUser': 3,
}
localSecurityOptionsInformationShownOnLockScreenType = enum.Enum('localSecurityOptionsInformationShownOnLockScreenType', localSecurityOptionsInformationShownOnLockScreenType_data)


localSecurityOptionsMinimumSessionSecurity_data = {
    'none': 0,
    'requireNtmlV2SessionSecurity': 1,
    'require128BitEncryption': 2,
    'ntlmV2And128BitEncryption': 3,
}
localSecurityOptionsMinimumSessionSecurity = enum.Enum('localSecurityOptionsMinimumSessionSecurity', localSecurityOptionsMinimumSessionSecurity_data)


localSecurityOptionsSmartCardRemovalBehaviorType_data = {
    'noAction': 0,
    'lockWorkstation': 1,
    'forceLogoff': 2,
    'disconnectRemoteDesktopSession': 3,
}
localSecurityOptionsSmartCardRemovalBehaviorType = enum.Enum('localSecurityOptionsSmartCardRemovalBehaviorType', localSecurityOptionsSmartCardRemovalBehaviorType_data)


localSecurityOptionsStandardUserElevationPromptBehaviorType_data = {
    'notConfigured': 0,
    'automaticallyDenyElevationRequests': 1,
    'promptForCredentialsOnTheSecureDesktop': 2,
    'promptForCredentials': 3,
}
localSecurityOptionsStandardUserElevationPromptBehaviorType = enum.Enum('localSecurityOptionsStandardUserElevationPromptBehaviorType', localSecurityOptionsStandardUserElevationPromptBehaviorType_data)


macAddressRandomizationMode_data = {
    'automatic': 0,
    'hardware': 1,
    'unknownFutureValue': 2,
}
macAddressRandomizationMode = enum.Enum('macAddressRandomizationMode', macAddressRandomizationMode_data)


macOSContentCachingClientPolicy_data = {
    'notConfigured': 0,
    'clientsInLocalNetwork': 1,
    'clientsWithSamePublicIpAddress': 2,
    'clientsInCustomLocalNetworks': 3,
    'clientsInCustomLocalNetworksWithFallback': 4,
}
macOSContentCachingClientPolicy = enum.Enum('macOSContentCachingClientPolicy', macOSContentCachingClientPolicy_data)


macOSContentCachingParentSelectionPolicy_data = {
    'notConfigured': 0,
    'roundRobin': 1,
    'firstAvailable': 2,
    'urlPathHash': 3,
    'random': 4,
    'stickyAvailable': 5,
}
macOSContentCachingParentSelectionPolicy = enum.Enum('macOSContentCachingParentSelectionPolicy', macOSContentCachingParentSelectionPolicy_data)


macOSContentCachingPeerPolicy_data = {
    'notConfigured': 0,
    'peersInLocalNetwork': 1,
    'peersWithSamePublicIpAddress': 2,
    'peersInCustomLocalNetworks': 3,
}
macOSContentCachingPeerPolicy = enum.Enum('macOSContentCachingPeerPolicy', macOSContentCachingPeerPolicy_data)


macOSContentCachingType_data = {
    'notConfigured': 0,
    'userContentOnly': 1,
    'sharedContentOnly': 2,
}
macOSContentCachingType = enum.Enum('macOSContentCachingType', macOSContentCachingType_data)


macOSFileVaultRecoveryKeyTypes_data = {
    'notConfigured': 0,
    'institutionalRecoveryKey': 1,
    'personalRecoveryKey': 2,
}
macOSFileVaultRecoveryKeyTypes = enum.Enum('macOSFileVaultRecoveryKeyTypes', macOSFileVaultRecoveryKeyTypes_data)


macOSGatekeeperAppSources_data = {
    'notConfigured': 0,
    'macAppStore': 1,
    'macAppStoreAndIdentifiedDevelopers': 2,
    'anywhere': 3,
}
macOSGatekeeperAppSources = enum.Enum('macOSGatekeeperAppSources', macOSGatekeeperAppSources_data)


macOSPriority_data = {
    'low': 0,
    'high': 1,
    'unknownFutureValue': 2,
}
macOSPriority = enum.Enum('macOSPriority', macOSPriority_data)


macOSProcessIdentifierType_data = {
    'bundleID': 1,
    'path': 2,
}
macOSProcessIdentifierType = enum.Enum('macOSProcessIdentifierType', macOSProcessIdentifierType_data)


macOSSoftwareUpdateBehavior_data = {
    'notConfigured': 0,
    'default': 1,
    'downloadOnly': 2,
    'installASAP': 3,
    'notifyOnly': 4,
    'installLater': 5,
}
macOSSoftwareUpdateBehavior = enum.Enum('macOSSoftwareUpdateBehavior', macOSSoftwareUpdateBehavior_data)


macOSSoftwareUpdateCategory_data = {
    'critical': 0,
    'configurationDataFile': 1,
    'firmware': 2,
    'other': 3,
}
macOSSoftwareUpdateCategory = enum.Enum('macOSSoftwareUpdateCategory', macOSSoftwareUpdateCategory_data)


macOSSoftwareUpdateDelayPolicy_data = {
    'none': 0,
    'delayOSUpdateVisibility': 1,
    'delayAppUpdateVisibility': 2,
    'unknownFutureValue': 4,
    'delayMajorOsUpdateVisibility': 8,
}
macOSSoftwareUpdateDelayPolicy = enum.Enum('macOSSoftwareUpdateDelayPolicy', macOSSoftwareUpdateDelayPolicy_data)


macOSSoftwareUpdateScheduleType_data = {
    'alwaysUpdate': 0,
    'updateDuringTimeWindows': 1,
    'updateOutsideOfTimeWindows': 2,
}
macOSSoftwareUpdateScheduleType = enum.Enum('macOSSoftwareUpdateScheduleType', macOSSoftwareUpdateScheduleType_data)


macOSSoftwareUpdateState_data = {
    'success': 0,
    'downloading': 1000,
    'downloaded': 1001,
    'installing': 1002,
    'idle': 1003,
    'available': 1004,
    'scheduled': 1005,
    'downloadFailed': 2000,
    'downloadInsufficientSpace': 2001,
    'downloadInsufficientPower': 2002,
    'downloadInsufficientNetwork': 2003,
    'installInsufficientSpace': 2004,
    'installInsufficientPower': 2005,
    'installFailed': 2006,
    'commandFailed': 2007,
}
macOSSoftwareUpdateState = enum.Enum('macOSSoftwareUpdateState', macOSSoftwareUpdateState_data)


macOSSystemExtensionType_data = {
    'driverExtensionsAllowed': 1,
    'networkExtensionsAllowed': 2,
    'endpointSecurityExtensionsAllowed': 4,
}
macOSSystemExtensionType = enum.Enum('macOSSystemExtensionType', macOSSystemExtensionType_data)


managedDeviceOwnerType_data = {
    'unknown': 0,
    'company': 1,
    'personal': 2,
    'unknownFutureValue': 3,
}
managedDeviceOwnerType = enum.Enum('managedDeviceOwnerType', managedDeviceOwnerType_data)


managementAgentType_data = {
    'eas': 1,
    'mdm': 2,
    'easMdm': 3,
    'intuneClient': 4,
    'easIntuneClient': 5,
    'configurationManagerClient': 8,
    'configurationManagerClientMdm': 10,
    'configurationManagerClientMdmEas': 11,
    'unknown': 16,
    'jamf': 32,
    'googleCloudDevicePolicyController': 64,
    'microsoft365ManagedMdm': 258,
    'msSense': 1024,
    'intuneAosp': 2048,
    'google': 8192,
    'unknownFutureValue': 8193,
}
managementAgentType = enum.Enum('managementAgentType', managementAgentType_data)


meteredConnectionLimitType_data = {
    'unrestricted': 0,
    'fixed': 1,
    'variable': 2,
}
meteredConnectionLimitType = enum.Enum('meteredConnectionLimitType', meteredConnectionLimitType_data)


microsoftLauncherDockPresence_data = {
    'notConfigured': 0,
    'show': 1,
    'hide': 2,
    'disabled': 3,
}
microsoftLauncherDockPresence = enum.Enum('microsoftLauncherDockPresence', microsoftLauncherDockPresence_data)


microsoftLauncherSearchBarPlacement_data = {
    'notConfigured': 0,
    'top': 1,
    'bottom': 2,
    'hide': 3,
}
microsoftLauncherSearchBarPlacement = enum.Enum('microsoftLauncherSearchBarPlacement', microsoftLauncherSearchBarPlacement_data)


miracastChannel_data = {
    'userDefined': 0,
    'one': 1,
    'two': 2,
    'three': 3,
    'four': 4,
    'five': 5,
    'six': 6,
    'seven': 7,
    'eight': 8,
    'nine': 9,
    'ten': 10,
    'eleven': 11,
    'thirtySix': 36,
    'forty': 40,
    'fortyFour': 44,
    'fortyEight': 48,
    'oneHundredFortyNine': 149,
    'oneHundredFiftyThree': 153,
    'oneHundredFiftySeven': 157,
    'oneHundredSixtyOne': 161,
    'oneHundredSixtyFive': 165,
}
miracastChannel = enum.Enum('miracastChannel', miracastChannel_data)


ndesConnectorState_data = {
    'none': 0,
    'active': 1,
    'inactive': 2,
}
ndesConnectorState = enum.Enum('ndesConnectorState', ndesConnectorState_data)


networkSingleSignOnType_data = {
    'disabled': 0,
    'prelogon': 1,
    'postlogon': 2,
}
networkSingleSignOnType = enum.Enum('networkSingleSignOnType', networkSingleSignOnType_data)


nonEapAuthenticationMethodForEapTtlsType_data = {
    'unencryptedPassword': 0,
    'challengeHandshakeAuthenticationProtocol': 1,
    'microsoftChap': 2,
    'microsoftChapVersionTwo': 3,
}
nonEapAuthenticationMethodForEapTtlsType = enum.Enum('nonEapAuthenticationMethodForEapTtlsType', nonEapAuthenticationMethodForEapTtlsType_data)


nonEapAuthenticationMethodForPeap_data = {
    'none': 0,
    'microsoftChapVersionTwo': 1,
}
nonEapAuthenticationMethodForPeap = enum.Enum('nonEapAuthenticationMethodForPeap', nonEapAuthenticationMethodForPeap_data)


operator_data = {
    'none': 0,
    'and': 1,
    'or': 2,
    'isEquals': 3,
    'notEquals': 4,
    'greaterThan': 5,
    'lessThan': 6,
    'between': 7,
    'notBetween': 8,
    'greaterEquals': 9,
    'lessEquals': 10,
    'dayTimeBetween': 11,
    'beginsWith': 12,
    'notBeginsWith': 13,
    'endsWith': 14,
    'notEndsWith': 15,
    'contains': 16,
    'notContains': 17,
    'allOf': 18,
    'oneOf': 19,
    'noneOf': 20,
    'setEquals': 21,
    'orderedSetEquals': 22,
    'subsetOf': 23,
    'excludesAll': 24,
}
operator = enum.Enum('operator', operator_data)


perfectForwardSecrecyGroup_data = {
    'pfs1': 0,
    'pfs2': 1,
    'pfs2048': 2,
    'ecp256': 3,
    'ecp384': 4,
    'pfsMM': 5,
    'pfs24': 6,
}
perfectForwardSecrecyGroup = enum.Enum('perfectForwardSecrecyGroup', perfectForwardSecrecyGroup_data)


personalProfilePersonalPlayStoreMode_data = {
    'notConfigured': 0,
    'blockedApps': 1,
    'allowedApps': 2,
}
personalProfilePersonalPlayStoreMode = enum.Enum('personalProfilePersonalPlayStoreMode', personalProfilePersonalPlayStoreMode_data)


policyPlatformType_data = {
    'android': 0,
    'androidForWork': 1,
    'iOS': 2,
    'macOS': 3,
    'windowsPhone81': 4,
    'windows81AndLater': 5,
    'windows10AndLater': 6,
    'androidWorkProfile': 7,
    'windows10XProfile': 8,
    'androidAOSP': 9,
    'all': 100,
}
policyPlatformType = enum.Enum('policyPlatformType', policyPlatformType_data)


powerActionType_data = {
    'notConfigured': 0,
    'noAction': 1,
    'sleep': 2,
    'hibernate': 3,
    'shutdown': 4,
}
powerActionType = enum.Enum('powerActionType', powerActionType_data)


prereleaseFeatures_data = {
    'userDefined': 0,
    'settingsOnly': 1,
    'settingsAndExperimentations': 2,
    'notAllowed': 3,
}
prereleaseFeatures = enum.Enum('prereleaseFeatures', prereleaseFeatures_data)


ratingAppsType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'agesAbove4': 2,
    'agesAbove9': 3,
    'agesAbove12': 4,
    'agesAbove17': 5,
}
ratingAppsType = enum.Enum('ratingAppsType', ratingAppsType_data)


ratingAustraliaMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'mature': 4,
    'agesAbove15': 5,
    'agesAbove18': 6,
}
ratingAustraliaMoviesType = enum.Enum('ratingAustraliaMoviesType', ratingAustraliaMoviesType_data)


ratingAustraliaTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'preschoolers': 2,
    'children': 3,
    'general': 4,
    'parentalGuidance': 5,
    'mature': 6,
    'agesAbove15': 7,
    'agesAbove15AdultViolence': 8,
}
ratingAustraliaTelevisionType = enum.Enum('ratingAustraliaTelevisionType', ratingAustraliaTelevisionType_data)


ratingCanadaMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'agesAbove14': 4,
    'agesAbove18': 5,
    'restricted': 6,
}
ratingCanadaMoviesType = enum.Enum('ratingCanadaMoviesType', ratingCanadaMoviesType_data)


ratingCanadaTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'children': 2,
    'childrenAbove8': 3,
    'general': 4,
    'parentalGuidance': 5,
    'agesAbove14': 6,
    'agesAbove18': 7,
}
ratingCanadaTelevisionType = enum.Enum('ratingCanadaTelevisionType', ratingCanadaTelevisionType_data)


ratingFranceMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'agesAbove10': 2,
    'agesAbove12': 3,
    'agesAbove16': 4,
    'agesAbove18': 5,
}
ratingFranceMoviesType = enum.Enum('ratingFranceMoviesType', ratingFranceMoviesType_data)


ratingFranceTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'agesAbove10': 2,
    'agesAbove12': 3,
    'agesAbove16': 4,
    'agesAbove18': 5,
}
ratingFranceTelevisionType = enum.Enum('ratingFranceTelevisionType', ratingFranceTelevisionType_data)


ratingGermanyMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'agesAbove6': 3,
    'agesAbove12': 4,
    'agesAbove16': 5,
    'adults': 6,
}
ratingGermanyMoviesType = enum.Enum('ratingGermanyMoviesType', ratingGermanyMoviesType_data)


ratingGermanyTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'agesAbove6': 3,
    'agesAbove12': 4,
    'agesAbove16': 5,
    'adults': 6,
}
ratingGermanyTelevisionType = enum.Enum('ratingGermanyTelevisionType', ratingGermanyTelevisionType_data)


ratingIrelandMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'agesAbove12': 4,
    'agesAbove15': 5,
    'agesAbove16': 6,
    'adults': 7,
}
ratingIrelandMoviesType = enum.Enum('ratingIrelandMoviesType', ratingIrelandMoviesType_data)


ratingIrelandTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'children': 3,
    'youngAdults': 4,
    'parentalSupervision': 5,
    'mature': 6,
}
ratingIrelandTelevisionType = enum.Enum('ratingIrelandTelevisionType', ratingIrelandTelevisionType_data)


ratingJapanMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'agesAbove15': 4,
    'agesAbove18': 5,
}
ratingJapanMoviesType = enum.Enum('ratingJapanMoviesType', ratingJapanMoviesType_data)


ratingJapanTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'explicitAllowed': 2,
}
ratingJapanTelevisionType = enum.Enum('ratingJapanTelevisionType', ratingJapanTelevisionType_data)


ratingNewZealandMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'mature': 4,
    'agesAbove13': 5,
    'agesAbove15': 6,
    'agesAbove16': 7,
    'agesAbove18': 8,
    'restricted': 9,
    'agesAbove16Restricted': 10,
}
ratingNewZealandMoviesType = enum.Enum('ratingNewZealandMoviesType', ratingNewZealandMoviesType_data)


ratingNewZealandTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'adults': 4,
}
ratingNewZealandTelevisionType = enum.Enum('ratingNewZealandTelevisionType', ratingNewZealandTelevisionType_data)


ratingUnitedKingdomMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'universalChildren': 3,
    'parentalGuidance': 4,
    'agesAbove12Video': 5,
    'agesAbove12Cinema': 6,
    'agesAbove15': 7,
    'adults': 8,
}
ratingUnitedKingdomMoviesType = enum.Enum('ratingUnitedKingdomMoviesType', ratingUnitedKingdomMoviesType_data)


ratingUnitedKingdomTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'caution': 2,
}
ratingUnitedKingdomTelevisionType = enum.Enum('ratingUnitedKingdomTelevisionType', ratingUnitedKingdomTelevisionType_data)


ratingUnitedStatesMoviesType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'general': 2,
    'parentalGuidance': 3,
    'parentalGuidance13': 4,
    'restricted': 5,
    'adults': 6,
}
ratingUnitedStatesMoviesType = enum.Enum('ratingUnitedStatesMoviesType', ratingUnitedStatesMoviesType_data)


ratingUnitedStatesTelevisionType_data = {
    'allAllowed': 0,
    'allBlocked': 1,
    'childrenAll': 2,
    'childrenAbove7': 3,
    'general': 4,
    'parentalGuidance': 5,
    'childrenAbove14': 6,
    'adults': 7,
}
ratingUnitedStatesTelevisionType = enum.Enum('ratingUnitedStatesTelevisionType', ratingUnitedStatesTelevisionType_data)


requiredPasswordType_data = {
    'deviceDefault': 0,
    'alphanumeric': 1,
    'numeric': 2,
}
requiredPasswordType = enum.Enum('requiredPasswordType', requiredPasswordType_data)


restrictedAppsState_data = {
    'prohibitedApps': 0,
    'notApprovedApps': 1,
}
restrictedAppsState = enum.Enum('restrictedAppsState', restrictedAppsState_data)


runState_data = {
    'unknown': 0,
    'success': 1,
    'fail': 2,
    'scriptError': 3,
    'pending': 4,
    'notApplicable': 5,
}
runState = enum.Enum('runState', runState_data)


safeSearchFilterType_data = {
    'userDefined': 0,
    'strict': 1,
    'moderate': 2,
}
safeSearchFilterType = enum.Enum('safeSearchFilterType', safeSearchFilterType_data)


scheduledRetireState_data = {
    'cancelRetire': 0,
    'confirmRetire': 1,
    'unknownFutureValue': 2,
}
scheduledRetireState = enum.Enum('scheduledRetireState', scheduledRetireState_data)


secureAssessmentAccountType_data = {
    'azureADAccount': 0,
    'domainAccount': 1,
    'localAccount': 2,
    'localGuestAccount': 3,
}
secureAssessmentAccountType = enum.Enum('secureAssessmentAccountType', secureAssessmentAccountType_data)


secureBootWithDMAType_data = {
    'notConfigured': 0,
    'withoutDMA': 1,
    'withDMA': 3,
}
secureBootWithDMAType = enum.Enum('secureBootWithDMAType', secureBootWithDMAType_data)


serviceStartType_data = {
    'manual': 0,
    'automatic': 1,
    'disabled': 2,
}
serviceStartType = enum.Enum('serviceStartType', serviceStartType_data)


settingSourceType_data = {
    'deviceConfiguration': 0,
    'deviceIntent': 1,
}
settingSourceType = enum.Enum('settingSourceType', settingSourceType_data)


sharedPCAccountDeletionPolicyType_data = {
    'immediate': 0,
    'diskSpaceThreshold': 1,
    'diskSpaceThresholdOrInactiveThreshold': 2,
}
sharedPCAccountDeletionPolicyType = enum.Enum('sharedPCAccountDeletionPolicyType', sharedPCAccountDeletionPolicyType_data)


sharedPCAllowedAccountType_data = {
    'notConfigured': 0,
    'guest': 1,
    'domain': 2,
}
sharedPCAllowedAccountType = enum.Enum('sharedPCAllowedAccountType', sharedPCAllowedAccountType_data)


signInAssistantOptions_data = {
    'notConfigured': 0,
    'disabled': 1,
}
signInAssistantOptions = enum.Enum('signInAssistantOptions', signInAssistantOptions_data)


siteSecurityLevel_data = {
    'userDefined': 0,
    'low': 1,
    'mediumLow': 2,
    'medium': 3,
    'mediumHigh': 4,
    'high': 5,
}
siteSecurityLevel = enum.Enum('siteSecurityLevel', siteSecurityLevel_data)


stateManagementSetting_data = {
    'notConfigured': 0,
    'blocked': 1,
    'allowed': 2,
}
stateManagementSetting = enum.Enum('stateManagementSetting', stateManagementSetting_data)


subjectAlternativeNameType_data = {
    'none': 0,
    'emailAddress': 1,
    'userPrincipalName': 2,
    'customAzureADAttribute': 4,
    'domainNameService': 8,
    'universalResourceIdentifier': 16,
}
subjectAlternativeNameType = enum.Enum('subjectAlternativeNameType', subjectAlternativeNameType_data)


subjectNameFormat_data = {
    'commonName': 0,
    'commonNameIncludingEmail': 1,
    'commonNameAsEmail': 2,
    'custom': 3,
    'commonNameAsIMEI': 5,
    'commonNameAsSerialNumber': 6,
    'commonNameAsAadDeviceId': 7,
    'commonNameAsIntuneDeviceId': 8,
    'commonNameAsDurableDeviceId': 9,
}
subjectNameFormat = enum.Enum('subjectNameFormat', subjectNameFormat_data)


updateClassification_data = {
    'userDefined': 0,
    'recommendedAndImportant': 1,
    'important': 2,
    'none': 3,
}
updateClassification = enum.Enum('updateClassification', updateClassification_data)


userEmailSource_data = {
    'userPrincipalName': 0,
    'primarySmtpAddress': 1,
}
userEmailSource = enum.Enum('userEmailSource', userEmailSource_data)


usernameSource_data = {
    'userPrincipalName': 0,
    'primarySmtpAddress': 1,
    'samAccountName': 2,
}
usernameSource = enum.Enum('usernameSource', usernameSource_data)


visibilitySetting_data = {
    'notConfigured': 0,
    'hide': 1,
    'show': 2,
}
visibilitySetting = enum.Enum('visibilitySetting', visibilitySetting_data)


vpnAuthenticationMethod_data = {
    'certificate': 0,
    'usernameAndPassword': 1,
    'sharedSecret': 2,
    'derivedCredential': 3,
    'azureAD': 4,
}
vpnAuthenticationMethod = enum.Enum('vpnAuthenticationMethod', vpnAuthenticationMethod_data)


vpnClientAuthenticationType_data = {
    'userAuthentication': 0,
    'deviceAuthentication': 1,
}
vpnClientAuthenticationType = enum.Enum('vpnClientAuthenticationType', vpnClientAuthenticationType_data)


vpnDeadPeerDetectionRate_data = {
    'medium': 0,
    'none': 1,
    'low': 2,
    'high': 3,
}
vpnDeadPeerDetectionRate = enum.Enum('vpnDeadPeerDetectionRate', vpnDeadPeerDetectionRate_data)


vpnEncryptionAlgorithmType_data = {
    'aes256': 0,
    'des': 1,
    'tripleDes': 2,
    'aes128': 3,
    'aes128Gcm': 4,
    'aes256Gcm': 5,
    'aes192': 6,
    'aes192Gcm': 7,
    'chaCha20Poly1305': 8,
}
vpnEncryptionAlgorithmType = enum.Enum('vpnEncryptionAlgorithmType', vpnEncryptionAlgorithmType_data)


vpnIntegrityAlgorithmType_data = {
    'sha2_256': 0,
    'sha1_96': 1,
    'sha1_160': 2,
    'sha2_384': 3,
    'sha2_512': 4,
    'md5': 5,
}
vpnIntegrityAlgorithmType = enum.Enum('vpnIntegrityAlgorithmType', vpnIntegrityAlgorithmType_data)


vpnLocalIdentifier_data = {
    'deviceFQDN': 0,
    'empty': 1,
    'clientCertificateSubjectName': 2,
}
vpnLocalIdentifier = enum.Enum('vpnLocalIdentifier', vpnLocalIdentifier_data)


vpnOnDemandRuleConnectionAction_data = {
    'connect': 0,
    'evaluateConnection': 1,
    'ignore': 2,
    'disconnect': 3,
}
vpnOnDemandRuleConnectionAction = enum.Enum('vpnOnDemandRuleConnectionAction', vpnOnDemandRuleConnectionAction_data)


vpnOnDemandRuleConnectionDomainAction_data = {
    'connectIfNeeded': 0,
    'neverConnect': 1,
}
vpnOnDemandRuleConnectionDomainAction = enum.Enum('vpnOnDemandRuleConnectionDomainAction', vpnOnDemandRuleConnectionDomainAction_data)


vpnOnDemandRuleInterfaceTypeMatch_data = {
    'notConfigured': 0,
    'ethernet': 1,
    'wiFi': 2,
    'cellular': 3,
}
vpnOnDemandRuleInterfaceTypeMatch = enum.Enum('vpnOnDemandRuleInterfaceTypeMatch', vpnOnDemandRuleInterfaceTypeMatch_data)


vpnProviderType_data = {
    'notConfigured': 0,
    'appProxy': 1,
    'packetTunnel': 2,
}
vpnProviderType = enum.Enum('vpnProviderType', vpnProviderType_data)


vpnServerCertificateType_data = {
    'rsa': 0,
    'ecdsa256': 1,
    'ecdsa384': 2,
    'ecdsa521': 3,
}
vpnServerCertificateType = enum.Enum('vpnServerCertificateType', vpnServerCertificateType_data)


vpnServiceExceptionAction_data = {
    'forceTrafficViaVPN': 0,
    'allowTrafficOutside': 1,
    'dropTraffic': 2,
}
vpnServiceExceptionAction = enum.Enum('vpnServiceExceptionAction', vpnServiceExceptionAction_data)


vpnTrafficDirection_data = {
    'outbound': 0,
    'inbound': 1,
    'unknownFutureValue': 2,
}
vpnTrafficDirection = enum.Enum('vpnTrafficDirection', vpnTrafficDirection_data)


vpnTrafficRuleAppType_data = {
    'none': 0,
    'desktop': 1,
    'universal': 2,
}
vpnTrafficRuleAppType = enum.Enum('vpnTrafficRuleAppType', vpnTrafficRuleAppType_data)


vpnTrafficRuleRoutingPolicyType_data = {
    'none': 0,
    'splitTunnel': 1,
    'forceTunnel': 2,
}
vpnTrafficRuleRoutingPolicyType = enum.Enum('vpnTrafficRuleRoutingPolicyType', vpnTrafficRuleRoutingPolicyType_data)


vpnTunnelConfigurationType_data = {
    'wifiAndCellular': 0,
    'cellular': 1,
    'wifi': 2,
}
vpnTunnelConfigurationType = enum.Enum('vpnTunnelConfigurationType', vpnTunnelConfigurationType_data)


webBrowserCookieSettings_data = {
    'browserDefault': 0,
    'blockAlways': 1,
    'allowCurrentWebSite': 2,
    'allowFromWebsitesVisited': 3,
    'allowAlways': 4,
}
webBrowserCookieSettings = enum.Enum('webBrowserCookieSettings', webBrowserCookieSettings_data)


weeklySchedule_data = {
    'userDefined': 0,
    'everyday': 1,
    'sunday': 2,
    'monday': 3,
    'tuesday': 4,
    'wednesday': 5,
    'thursday': 6,
    'friday': 7,
    'saturday': 8,
    'noScheduledScan': 9,
}
weeklySchedule = enum.Enum('weeklySchedule', weeklySchedule_data)


welcomeScreenMeetingInformation_data = {
    'userDefined': 0,
    'showOrganizerAndTimeOnly': 1,
    'showOrganizerAndTimeAndSubject': 2,
}
welcomeScreenMeetingInformation = enum.Enum('welcomeScreenMeetingInformation', welcomeScreenMeetingInformation_data)


wiFiAuthenticationMethod_data = {
    'certificate': 0,
    'usernameAndPassword': 1,
    'derivedCredential': 2,
}
wiFiAuthenticationMethod = enum.Enum('wiFiAuthenticationMethod', wiFiAuthenticationMethod_data)


wifiAuthenticationType_data = {
    'none': 0,
    'user': 1,
    'machine': 2,
    'machineOrUser': 3,
    'guest': 4,
}
wifiAuthenticationType = enum.Enum('wifiAuthenticationType', wifiAuthenticationType_data)


wiFiProxySetting_data = {
    'none': 0,
    'manual': 1,
    'automatic': 2,
    'unknownFutureValue': 3,
}
wiFiProxySetting = enum.Enum('wiFiProxySetting', wiFiProxySetting_data)


wiFiSecurityType_data = {
    'open': 0,
    'wpaPersonal': 1,
    'wpaEnterprise': 2,
    'wep': 3,
    'wpa2Personal': 4,
    'wpa2Enterprise': 5,
}
wiFiSecurityType = enum.Enum('wiFiSecurityType', wiFiSecurityType_data)


windows10AppsUpdateRecurrence_data = {
    'none': 0,
    'daily': 1,
    'weekly': 2,
    'monthly': 3,
}
windows10AppsUpdateRecurrence = enum.Enum('windows10AppsUpdateRecurrence', windows10AppsUpdateRecurrence_data)


windows10AppType_data = {
    'desktop': 0,
    'universal': 1,
}
windows10AppType = enum.Enum('windows10AppType', windows10AppType_data)


windows10DeviceModeType_data = {
    'standardConfiguration': 0,
    'sModeConfiguration': 1,
}
windows10DeviceModeType = enum.Enum('windows10DeviceModeType', windows10DeviceModeType_data)


windows10EditionType_data = {
    'windows10Enterprise': 0,
    'windows10EnterpriseN': 1,
    'windows10Education': 2,
    'windows10EducationN': 3,
    'windows10MobileEnterprise': 4,
    'windows10HolographicEnterprise': 5,
    'windows10Professional': 6,
    'windows10ProfessionalN': 7,
    'windows10ProfessionalEducation': 8,
    'windows10ProfessionalEducationN': 9,
    'windows10ProfessionalWorkstation': 10,
    'windows10ProfessionalWorkstationN': 11,
    'notConfigured': 12,
    'windows10Home': 13,
    'windows10HomeChina': 14,
    'windows10HomeN': 15,
    'windows10HomeSingleLanguage': 16,
    'windows10Mobile': 17,
    'windows10IoTCore': 18,
    'windows10IoTCoreCommercial': 19,
}
windows10EditionType = enum.Enum('windows10EditionType', windows10EditionType_data)


windows10VpnAuthenticationMethod_data = {
    'certificate': 0,
    'usernameAndPassword': 1,
    'customEapXml': 2,
    'derivedCredential': 3,
}
windows10VpnAuthenticationMethod = enum.Enum('windows10VpnAuthenticationMethod', windows10VpnAuthenticationMethod_data)


windows10VpnConnectionType_data = {
    'pulseSecure': 0,
    'f5EdgeClient': 1,
    'dellSonicWallMobileConnect': 2,
    'checkPointCapsuleVpn': 3,
    'automatic': 4,
    'ikEv2': 5,
    'l2tp': 6,
    'pptp': 7,
    'citrix': 8,
    'paloAltoGlobalProtect': 9,
    'ciscoAnyConnect': 10,
    'unknownFutureValue': 11,
    'microsoftTunnel': 12,
}
windows10VpnConnectionType = enum.Enum('windows10VpnConnectionType', windows10VpnConnectionType_data)


windows10VpnProfileTarget_data = {
    'user': 0,
    'device': 1,
    'autoPilotDevice': 2,
}
windows10VpnProfileTarget = enum.Enum('windows10VpnProfileTarget', windows10VpnProfileTarget_data)


windowsAppStartLayoutTileSize_data = {
    'hidden': 0,
    'small': 1,
    'medium': 2,
    'wide': 3,
    'large': 4,
}
windowsAppStartLayoutTileSize = enum.Enum('windowsAppStartLayoutTileSize', windowsAppStartLayoutTileSize_data)


windowsDefenderTamperProtectionOptions_data = {
    'notConfigured': 0,
    'enable': 1,
    'disable': 2,
}
windowsDefenderTamperProtectionOptions = enum.Enum('windowsDefenderTamperProtectionOptions', windowsDefenderTamperProtectionOptions_data)


windowsDeliveryOptimizationMode_data = {
    'userDefined': 0,
    'httpOnly': 1,
    'httpWithPeeringNat': 2,
    'httpWithPeeringPrivateGroup': 3,
    'httpWithInternetPeering': 4,
    'simpleDownload': 99,
    'bypassMode': 100,
}
windowsDeliveryOptimizationMode = enum.Enum('windowsDeliveryOptimizationMode', windowsDeliveryOptimizationMode_data)


windowsEdgeKioskType_data = {
    'publicBrowsing': 0,
    'fullScreen': 1,
}
windowsEdgeKioskType = enum.Enum('windowsEdgeKioskType', windowsEdgeKioskType_data)


windowsFirewallRuleInterfaceTypes_data = {
    'notConfigured': 0,
    'remoteAccess': 1,
    'wireless': 2,
    'lan': 4,
}
windowsFirewallRuleInterfaceTypes = enum.Enum('windowsFirewallRuleInterfaceTypes', windowsFirewallRuleInterfaceTypes_data)


windowsFirewallRuleNetworkProfileTypes_data = {
    'notConfigured': 0,
    'domain': 1,
    'private': 2,
    'public': 4,
}
windowsFirewallRuleNetworkProfileTypes = enum.Enum('windowsFirewallRuleNetworkProfileTypes', windowsFirewallRuleNetworkProfileTypes_data)


windowsFirewallRuleTrafficDirectionType_data = {
    'notConfigured': 0,
    'out': 1,
    'in': 2,
}
windowsFirewallRuleTrafficDirectionType = enum.Enum('windowsFirewallRuleTrafficDirectionType', windowsFirewallRuleTrafficDirectionType_data)


windowsHealthMonitoringScope_data = {
    'undefined': 0,
    'healthMonitoring': 1,
    'bootPerformance': 2,
    'windowsUpdates': 4,
    'privilegeManagement': 8,
}
windowsHealthMonitoringScope = enum.Enum('windowsHealthMonitoringScope', windowsHealthMonitoringScope_data)


windowsKioskAppType_data = {
    'unknown': 0,
    'store': 1,
    'desktop': 2,
    'aumId': 3,
}
windowsKioskAppType = enum.Enum('windowsKioskAppType', windowsKioskAppType_data)


windowsPrivacyDataAccessLevel_data = {
    'notConfigured': 0,
    'forceAllow': 1,
    'forceDeny': 2,
    'userInControl': 3,
}
windowsPrivacyDataAccessLevel = enum.Enum('windowsPrivacyDataAccessLevel', windowsPrivacyDataAccessLevel_data)


windowsPrivacyDataCategory_data = {
    'notConfigured': 0,
    'accountInfo': 1,
    'appsRunInBackground': 2,
    'calendar': 3,
    'callHistory': 4,
    'camera': 5,
    'contacts': 6,
    'diagnosticsInfo': 7,
    'email': 8,
    'location': 9,
    'messaging': 10,
    'microphone': 11,
    'motion': 12,
    'notifications': 13,
    'phone': 14,
    'radios': 15,
    'tasks': 16,
    'syncWithDevices': 17,
    'trustedDevices': 18,
}
windowsPrivacyDataCategory = enum.Enum('windowsPrivacyDataCategory', windowsPrivacyDataCategory_data)


windowsSModeConfiguration_data = {
    'noRestriction': 0,
    'block': 1,
    'unlock': 2,
}
windowsSModeConfiguration = enum.Enum('windowsSModeConfiguration', windowsSModeConfiguration_data)


windowsSpotlightEnablementSettings_data = {
    'notConfigured': 0,
    'disabled': 1,
    'enabled': 2,
}
windowsSpotlightEnablementSettings = enum.Enum('windowsSpotlightEnablementSettings', windowsSpotlightEnablementSettings_data)


windowsStartMenuAppListVisibilityType_data = {
    'userDefined': 0,
    'collapse': 1,
    'remove': 2,
    'disableSettingsApp': 4,
}
windowsStartMenuAppListVisibilityType = enum.Enum('windowsStartMenuAppListVisibilityType', windowsStartMenuAppListVisibilityType_data)


windowsStartMenuModeType_data = {
    'userDefined': 0,
    'fullScreen': 1,
    'nonFullScreen': 2,
}
windowsStartMenuModeType = enum.Enum('windowsStartMenuModeType', windowsStartMenuModeType_data)


windowsUpdateForBusinessUpdateWeeks_data = {
    'userDefined': 0,
    'firstWeek': 1,
    'secondWeek': 2,
    'thirdWeek': 4,
    'fourthWeek': 8,
    'everyWeek': 15,
    'unknownFutureValue': 22,
}
windowsUpdateForBusinessUpdateWeeks = enum.Enum('windowsUpdateForBusinessUpdateWeeks', windowsUpdateForBusinessUpdateWeeks_data)


windowsUpdateNotificationDisplayOption_data = {
    'notConfigured': 0,
    'defaultNotifications': 1,
    'restartWarningsOnly': 2,
    'disableAllNotifications': 3,
    'unknownFutureValue': 4,
}
windowsUpdateNotificationDisplayOption = enum.Enum('windowsUpdateNotificationDisplayOption', windowsUpdateNotificationDisplayOption_data)


windowsUpdateStatus_data = {
    'upToDate': 0,
    'pendingInstallation': 1,
    'pendingReboot': 2,
    'failed': 3,
}
windowsUpdateStatus = enum.Enum('windowsUpdateStatus', windowsUpdateStatus_data)


windowsUpdateType_data = {
    'userDefined': 0,
    'all': 1,
    'businessReadyOnly': 2,
    'windowsInsiderBuildFast': 3,
    'windowsInsiderBuildSlow': 4,
    'windowsInsiderBuildRelease': 5,
}
windowsUpdateType = enum.Enum('windowsUpdateType', windowsUpdateType_data)


windowsUserAccountControlSettings_data = {
    'userDefined': 0,
    'alwaysNotify': 1,
    'notifyOnAppChanges': 2,
    'notifyOnAppChangesWithoutDimming': 3,
    'neverNotify': 4,
}
windowsUserAccountControlSettings = enum.Enum('windowsUserAccountControlSettings', windowsUserAccountControlSettings_data)


windowsVpnConnectionType_data = {
    'pulseSecure': 0,
    'f5EdgeClient': 1,
    'dellSonicWallMobileConnect': 2,
    'checkPointCapsuleVpn': 3,
}
windowsVpnConnectionType = enum.Enum('windowsVpnConnectionType', windowsVpnConnectionType_data)


wiredNetworkAuthenticationMethod_data = {
    'certificate': 0,
    'usernameAndPassword': 1,
    'derivedCredential': 2,
    'unknownFutureValue': 3,
}
wiredNetworkAuthenticationMethod = enum.Enum('wiredNetworkAuthenticationMethod', wiredNetworkAuthenticationMethod_data)


wiredNetworkAuthenticationType_data = {
    'none': 0,
    'user': 1,
    'machine': 2,
    'machineOrUser': 3,
    'guest': 4,
    'unknownFutureValue': 5,
}
wiredNetworkAuthenticationType = enum.Enum('wiredNetworkAuthenticationType', wiredNetworkAuthenticationType_data)


wiredNetworkInterface_data = {
    'anyEthernet': 0,
    'firstActiveEthernet': 1,
    'secondActiveEthernet': 2,
    'thirdActiveEthernet': 3,
    'firstEthernet': 4,
    'secondEthernet': 5,
    'thirdEthernet': 6,
}
wiredNetworkInterface = enum.Enum('wiredNetworkInterface', wiredNetworkInterface_data)


deviceManagementComplianceActionType_data = {
    'noAction': 0,
    'notification': 1,
    'block': 2,
    'retire': 3,
    'wipe': 4,
    'removeResourceAccessProfiles': 5,
    'pushNotification': 9,
    'remoteLock': 10,
}
deviceManagementComplianceActionType = enum.Enum('deviceManagementComplianceActionType', deviceManagementComplianceActionType_data)


deviceManagementConfigurationAzureAdTrustType_data = {
    'none': 0,
    'azureAdJoined': 1,
    'addWorkAccount': 2,
    'mdmOnly': 4,
}
deviceManagementConfigurationAzureAdTrustType = enum.Enum('deviceManagementConfigurationAzureAdTrustType', deviceManagementConfigurationAzureAdTrustType_data)


deviceManagementConfigurationControlType_data = {
    'default': 0,
    'dropdown': 1,
    'smallTextBox': 2,
    'largeTextBox': 3,
    'toggle': 4,
    'multiheaderGrid': 5,
    'contextPane': 6,
    'unknownFutureValue': 7,
}
deviceManagementConfigurationControlType = enum.Enum('deviceManagementConfigurationControlType', deviceManagementConfigurationControlType_data)


deviceManagementConfigurationDeviceMode_data = {
    'none': 0,
    'kiosk': 1,
}
deviceManagementConfigurationDeviceMode = enum.Enum('deviceManagementConfigurationDeviceMode', deviceManagementConfigurationDeviceMode_data)


deviceManagementConfigurationPlatforms_data = {
    'none': 0,
    'android': 1,
    'iOS': 4,
    'macOS': 8,
    'windows10X': 16,
    'windows10': 32,
    'linux': 128,
    'unknownFutureValue': 256,
    'androidEnterprise': 512,
    'aosp': 1024,
}
deviceManagementConfigurationPlatforms = enum.Enum('deviceManagementConfigurationPlatforms', deviceManagementConfigurationPlatforms_data)


deviceManagementConfigurationSecretSettingValueState_data = {
    'invalid': 0,
    'notEncrypted': 1,
    'encryptedValueToken': 2,
}
deviceManagementConfigurationSecretSettingValueState = enum.Enum('deviceManagementConfigurationSecretSettingValueState', deviceManagementConfigurationSecretSettingValueState_data)


deviceManagementConfigurationSettingAccessTypes_data = {
    'none': 0,
    'add': 1,
    'copy': 2,
    'delete': 4,
    'get': 8,
    'replace': 16,
    'execute': 32,
}
deviceManagementConfigurationSettingAccessTypes = enum.Enum('deviceManagementConfigurationSettingAccessTypes', deviceManagementConfigurationSettingAccessTypes_data)


deviceManagementConfigurationSettingRiskLevel_data = {
    'low': 0,
    'medium': 1,
    'high': 2,
}
deviceManagementConfigurationSettingRiskLevel = enum.Enum('deviceManagementConfigurationSettingRiskLevel', deviceManagementConfigurationSettingRiskLevel_data)


deviceManagementConfigurationSettingUsage_data = {
    'none': 0,
    'configuration': 1,
    'compliance': 2,
    'unknownFutureValue': 8,
}
deviceManagementConfigurationSettingUsage = enum.Enum('deviceManagementConfigurationSettingUsage', deviceManagementConfigurationSettingUsage_data)


deviceManagementConfigurationSettingVisibility_data = {
    'none': 0,
    'settingsCatalog': 1,
    'template': 2,
    'unknownFutureValue': 4,
}
deviceManagementConfigurationSettingVisibility = enum.Enum('deviceManagementConfigurationSettingVisibility', deviceManagementConfigurationSettingVisibility_data)


deviceManagementConfigurationStringFormat_data = {
    'none': 0,
    'email': 1,
    'guid': 2,
    'ip': 3,
    'base64': 4,
    'url': 5,
    'version': 6,
    'xml': 7,
    'date': 8,
    'time': 9,
    'binary': 10,
    'regEx': 11,
    'json': 12,
    'dateTime': 13,
    'surfaceHub': 14,
    'bashScript': 19,
    'unknownFutureValue': 20,
}
deviceManagementConfigurationStringFormat = enum.Enum('deviceManagementConfigurationStringFormat', deviceManagementConfigurationStringFormat_data)


deviceManagementConfigurationTechnologies_data = {
    'none': 0,
    'mdm': 1,
    'windows10XManagement': 2,
    'configManager': 4,
    'intuneManagementExtension': 8,
    'thirdParty': 16,
    'documentGateway': 32,
    'appleRemoteManagement': 64,
    'microsoftSense': 128,
    'exchangeOnline': 256,
    'mobileApplicationManagement': 512,
    'linuxMdm': 1024,
    'enrollment': 4096,
    'endpointPrivilegeManagement': 8192,
    'unknownFutureValue': 16384,
    'windowsOsRecovery': 32768,
    'android': 65536,
}
deviceManagementConfigurationTechnologies = enum.Enum('deviceManagementConfigurationTechnologies', deviceManagementConfigurationTechnologies_data)


deviceManagementConfigurationTemplateFamily_data = {
    'none': 0,
    'endpointSecurityAntivirus': 10,
    'endpointSecurityDiskEncryption': 11,
    'endpointSecurityFirewall': 12,
    'endpointSecurityEndpointDetectionAndResponse': 13,
    'endpointSecurityAttackSurfaceReduction': 14,
    'endpointSecurityAccountProtection': 15,
    'endpointSecurityApplicationControl': 16,
    'endpointSecurityEndpointPrivilegeManagement': 17,
    'enrollmentConfiguration': 18,
    'appQuietTime': 19,
    'baseline': 20,
    'unknownFutureValue': 21,
    'deviceConfigurationScripts': 22,
    'deviceConfigurationPolicies': 23,
    'windowsOsRecoveryPolicies': 24,
    'companyPortal': 25,
}
deviceManagementConfigurationTemplateFamily = enum.Enum('deviceManagementConfigurationTemplateFamily', deviceManagementConfigurationTemplateFamily_data)


deviceManagementConfigurationWindowsSkus_data = {
    'unknown': 0,
    'windowsHome': 1,
    'windowsProfessional': 2,
    'windowsEnterprise': 3,
    'windowsEducation': 4,
    'windowsMobile': 5,
    'windowsMobileEnterprise': 6,
    'windowsTeamSurface': 7,
    'iot': 8,
    'iotEnterprise': 9,
    'holoLens': 10,
    'holoLensEnterprise': 11,
    'holographicForBusiness': 12,
    'windowsMultiSession': 13,
    'surfaceHub': 14,
}
deviceManagementConfigurationWindowsSkus = enum.Enum('deviceManagementConfigurationWindowsSkus', deviceManagementConfigurationWindowsSkus_data)


deviceManagementTemplateLifecycleState_data = {
    'invalid': 0,
    'draft': 10,
    'active': 20,
    'superseded': 30,
    'deprecated': 40,
    'retired': 50,
}
deviceManagementTemplateLifecycleState = enum.Enum('deviceManagementTemplateLifecycleState', deviceManagementTemplateLifecycleState_data)


companyPortalAction_data = {
    'unknown': 0,
    'remove': 1,
    'reset': 2,
}
companyPortalAction = enum.Enum('companyPortalAction', companyPortalAction_data)


deviceEnrollmentConfigurationType_data = {
    'unknown': 0,
    'limit': 1,
    'platformRestrictions': 2,
    'windowsHelloForBusiness': 3,
    'defaultLimit': 4,
    'defaultPlatformRestrictions': 5,
    'defaultWindowsHelloForBusiness': 6,
    'defaultWindows10EnrollmentCompletionPageConfiguration': 7,
    'windows10EnrollmentCompletionPageConfiguration': 8,
    'deviceComanagementAuthorityConfiguration': 9,
    'singlePlatformRestriction': 10,
    'unknownFutureValue': 11,
    'enrollmentNotificationsConfiguration': 12,
}
deviceEnrollmentConfigurationType = enum.Enum('deviceEnrollmentConfigurationType', deviceEnrollmentConfigurationType_data)


deviceManagementExchangeAccessLevel_data = {
    'none': 0,
    'allow': 1,
    'block': 2,
    'quarantine': 3,
}
deviceManagementExchangeAccessLevel = enum.Enum('deviceManagementExchangeAccessLevel', deviceManagementExchangeAccessLevel_data)


deviceManagementExchangeAccessRuleType_data = {
    'family': 0,
    'model': 1,
}
deviceManagementExchangeAccessRuleType = enum.Enum('deviceManagementExchangeAccessRuleType', deviceManagementExchangeAccessRuleType_data)


deviceManagementExchangeConnectorStatus_data = {
    'none': 0,
    'connectionPending': 1,
    'connected': 2,
    'disconnected': 3,
    'unknownFutureValue': 4,
}
deviceManagementExchangeConnectorStatus = enum.Enum('deviceManagementExchangeConnectorStatus', deviceManagementExchangeConnectorStatus_data)


deviceManagementExchangeConnectorSyncType_data = {
    'fullSync': 0,
    'deltaSync': 1,
}
deviceManagementExchangeConnectorSyncType = enum.Enum('deviceManagementExchangeConnectorSyncType', deviceManagementExchangeConnectorSyncType_data)


deviceManagementExchangeConnectorType_data = {
    'onPremises': 0,
    'hosted': 1,
    'serviceToService': 2,
    'dedicated': 3,
    'unknownFutureValue': 4,
}
deviceManagementExchangeConnectorType = enum.Enum('deviceManagementExchangeConnectorType', deviceManagementExchangeConnectorType_data)


deviceManagementPartnerAppType_data = {
    'unknown': 0,
    'singleTenantApp': 1,
    'multiTenantApp': 2,
}
deviceManagementPartnerAppType = enum.Enum('deviceManagementPartnerAppType', deviceManagementPartnerAppType_data)


deviceManagementPartnerTenantState_data = {
    'unknown': 0,
    'unavailable': 1,
    'enabled': 2,
    'terminated': 3,
    'rejected': 4,
    'unresponsive': 5,
}
deviceManagementPartnerTenantState = enum.Enum('deviceManagementPartnerTenantState', deviceManagementPartnerTenantState_data)


enrollmentAvailabilityOptions_data = {
    'availableWithPrompts': 0,
    'availableWithoutPrompts': 1,
    'unavailable': 2,
}
enrollmentAvailabilityOptions = enum.Enum('enrollmentAvailabilityOptions', enrollmentAvailabilityOptions_data)


enrollmentNotificationBrandingOptions_data = {
    'none': 0,
    'includeCompanyLogo': 1,
    'includeCompanyName': 2,
    'includeContactInformation': 4,
    'includeCompanyPortalLink': 8,
    'includeDeviceDetails': 16,
    'unknownFutureValue': 32,
}
enrollmentNotificationBrandingOptions = enum.Enum('enrollmentNotificationBrandingOptions', enrollmentNotificationBrandingOptions_data)


enrollmentNotificationTemplateType_data = {
    'email': 1,
    'push': 2,
    'unknownFutureValue': 99,
}
enrollmentNotificationTemplateType = enum.Enum('enrollmentNotificationTemplateType', enrollmentNotificationTemplateType_data)


enrollmentRestrictionPlatformType_data = {
    'allPlatforms': 0,
    'ios': 1,
    'windows': 2,
    'windowsPhone': 3,
    'android': 4,
    'androidForWork': 5,
    'mac': 7,
    'linux': 8,
    'unknownFutureValue': 9,
}
enrollmentRestrictionPlatformType = enum.Enum('enrollmentRestrictionPlatformType', enrollmentRestrictionPlatformType_data)


mdmAuthority_data = {
    'unknown': 0,
    'intune': 1,
    'sccm': 2,
    'office365': 3,
}
mdmAuthority = enum.Enum('mdmAuthority', mdmAuthority_data)


microsoftStoreForBusinessPortalSelectionOptions_data = {
    'none': 0,
    'companyPortal': 1,
    'privateStore': 2,
}
microsoftStoreForBusinessPortalSelectionOptions = enum.Enum('microsoftStoreForBusinessPortalSelectionOptions', microsoftStoreForBusinessPortalSelectionOptions_data)


mobileThreatPartnerTenantState_data = {
    'unavailable': 0,
    'available': 1,
    'enabled': 2,
    'unresponsive': 3,
    'notSetUp': 4,
    'error': 5,
    'unknownFutureValue': 6,
}
mobileThreatPartnerTenantState = enum.Enum('mobileThreatPartnerTenantState', mobileThreatPartnerTenantState_data)


ownerType_data = {
    'unknown': 0,
    'company': 1,
    'personal': 2,
}
ownerType = enum.Enum('ownerType', ownerType_data)


vppTokenState_data = {
    'unknown': 0,
    'valid': 1,
    'expired': 2,
    'invalid': 3,
    'assignedToExternalMDM': 4,
    'duplicateLocationId': 5,
}
vppTokenState = enum.Enum('vppTokenState', vppTokenState_data)


vppTokenSyncStatus_data = {
    'none': 0,
    'inProgress': 1,
    'completed': 2,
    'failed': 3,
}
vppTokenSyncStatus = enum.Enum('vppTokenSyncStatus', vppTokenSyncStatus_data)


windowsHelloForBusinessPinUsage_data = {
    'allowed': 0,
    'required': 1,
    'disallowed': 2,
}
windowsHelloForBusinessPinUsage = enum.Enum('windowsHelloForBusinessPinUsage', windowsHelloForBusinessPinUsage_data)


deviceManagementComparisonResult_data = {
    'unknown': 0,
    'equal': 1,
    'notEqual': 2,
    'added': 3,
    'removed': 4,
}
deviceManagementComparisonResult = enum.Enum('deviceManagementComparisonResult', deviceManagementComparisonResult_data)


deviceManagementTemplateSubtype_data = {
    'none': 0,
    'firewall': 1,
    'diskEncryption': 2,
    'attackSurfaceReduction': 3,
    'endpointDetectionReponse': 4,
    'accountProtection': 5,
    'antivirus': 6,
    'firewallSharedAppList': 7,
    'firewallSharedIpList': 8,
    'firewallSharedPortlist': 9,
}
deviceManagementTemplateSubtype = enum.Enum('deviceManagementTemplateSubtype', deviceManagementTemplateSubtype_data)


deviceManagementTemplateType_data = {
    'securityBaseline': 0,
    'specializedDevices': 1,
    'advancedThreatProtectionSecurityBaseline': 2,
    'deviceConfiguration': 3,
    'custom': 4,
    'securityTemplate': 5,
    'microsoftEdgeSecurityBaseline': 6,
    'microsoftOffice365ProPlusSecurityBaseline': 7,
    'deviceCompliance': 8,
    'deviceConfigurationForOffice365': 9,
    'cloudPC': 10,
    'firewallSharedSettings': 11,
}
deviceManagementTemplateType = enum.Enum('deviceManagementTemplateType', deviceManagementTemplateType_data)


deviceManangementIntentValueType_data = {
    'integer': 0,
    'boolean': 1,
    'string': 2,
    'complex': 3,
    'collection': 4,
    'abstractComplex': 5,
}
deviceManangementIntentValueType = enum.Enum('deviceManangementIntentValueType', deviceManangementIntentValueType_data)


securityBaselineComplianceState_data = {
    'unknown': 0,
    'secure': 1,
    'notApplicable': 2,
    'notSecure': 3,
    'error': 4,
    'conflict': 5,
}
securityBaselineComplianceState = enum.Enum('securityBaselineComplianceState', securityBaselineComplianceState_data)


securityBaselinePolicySourceType_data = {
    'deviceConfiguration': 0,
    'deviceIntent': 1,
}
securityBaselinePolicySourceType = enum.Enum('securityBaselinePolicySourceType', securityBaselinePolicySourceType_data)


adminConsentState_data = {
    'notConfigured': 0,
    'granted': 1,
    'notGranted': 2,
}
adminConsentState = enum.Enum('adminConsentState', adminConsentState_data)


appLogDecryptionAlgorithm_data = {
    'aes256': 0,
    'unknownFutureValue': 1,
}
appLogDecryptionAlgorithm = enum.Enum('appLogDecryptionAlgorithm', appLogDecryptionAlgorithm_data)


appLogUploadState_data = {
    'pending': 0,
    'completed': 1,
    'failed': 2,
    'unknownFutureValue': 3,
}
appLogUploadState = enum.Enum('appLogUploadState', appLogUploadState_data)


azureAttestationSettingStatus_data = {
    'notApplicable': 0,
    'enabled': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
azureAttestationSettingStatus = enum.Enum('azureAttestationSettingStatus', azureAttestationSettingStatus_data)


chassisType_data = {
    'unknown': 0,
    'desktop': 1,
    'laptop': 2,
    'worksWorkstation': 3,
    'enterpriseServer': 4,
    'phone': 100,
    'tablet': 101,
    'mobileOther': 102,
    'mobileUnknown': 103,
}
chassisType = enum.Enum('chassisType', chassisType_data)


comanagementEligibleType_data = {
    'comanaged': 1,
    'eligible': 2,
    'eligibleButNotAzureAdJoined': 3,
    'needsOsUpdate': 4,
    'ineligible': 5,
    'scheduledForEnrollment': 6,
    'unknownFutureValue': 7,
}
comanagementEligibleType = enum.Enum('comanagementEligibleType', comanagementEligibleType_data)


complianceState_data = {
    'unknown': 0,
    'compliant': 1,
    'noncompliant': 2,
    'conflict': 3,
    'error': 4,
    'inGracePeriod': 254,
    'configManager': 255,
}
complianceState = enum.Enum('complianceState', complianceState_data)


configurationManagerActionDeliveryStatus_data = {
    'unknown': 0,
    'pendingDelivery': 1,
    'deliveredToConnectorService': 2,
    'failedToDeliverToConnectorService': 3,
    'deliveredToOnPremisesServer': 4,
}
configurationManagerActionDeliveryStatus = enum.Enum('configurationManagerActionDeliveryStatus', configurationManagerActionDeliveryStatus_data)


configurationManagerActionType_data = {
    'refreshMachinePolicy': 0,
    'refreshUserPolicy': 1,
    'wakeUpClient': 2,
    'appEvaluation': 3,
    'quickScan': 5,
    'fullScan': 6,
    'windowsDefenderUpdateSignatures': 7,
}
configurationManagerActionType = enum.Enum('configurationManagerActionType', configurationManagerActionType_data)


configurationManagerClientState_data = {
    'unknown': 0,
    'installed': 1,
    'healthy': 7,
    'installFailed': 8,
    'updateFailed': 11,
    'communicationError': 19,
}
configurationManagerClientState = enum.Enum('configurationManagerClientState', configurationManagerClientState_data)


detectedAppPlatformType_data = {
    'unknown': 0,
    'windows': 1,
    'windowsMobile': 2,
    'windowsHolographic': 3,
    'ios': 4,
    'macOS': 5,
    'chromeOS': 6,
    'androidOSP': 7,
    'androidDeviceAdministrator': 8,
    'androidWorkProfile': 9,
    'androidDedicatedAndFullyManaged': 10,
    'unknownFutureValue': 11,
}
detectedAppPlatformType = enum.Enum('detectedAppPlatformType', detectedAppPlatformType_data)


deviceActionCategory_data = {
    'single': 0,
    'bulk': 1,
}
deviceActionCategory = enum.Enum('deviceActionCategory', deviceActionCategory_data)


deviceAssignmentItemIntent_data = {
    'remove': 0,
    'restore': 1,
    'unknownFutureValue': 2,
}
deviceAssignmentItemIntent = enum.Enum('deviceAssignmentItemIntent', deviceAssignmentItemIntent_data)


deviceAssignmentItemStatus_data = {
    'initiated': 0,
    'inProgress': 1,
    'removed': 2,
    'error': 3,
    'succeeded': 4,
    'unknownFutureValue': 5,
}
deviceAssignmentItemStatus = enum.Enum('deviceAssignmentItemStatus', deviceAssignmentItemStatus_data)


deviceAssignmentItemType_data = {
    'application': 0,
    'deviceConfiguration': 1,
    'deviceManagementConfigurationPolicy': 2,
    'mobileAppConfiguration': 3,
    'unknownFutureValue': 4,
}
deviceAssignmentItemType = enum.Enum('deviceAssignmentItemType', deviceAssignmentItemType_data)


deviceCleanupRulePlatformType_data = {
    'all': 0,
    'androidAOSP': 1,
    'androidDeviceAdministrator': 2,
    'androidDedicatedAndFullyManagedCorporateOwnedWorkProfile': 3,
    'chromeOS': 4,
    'androidPersonallyOwnedWorkProfile': 5,
    'ios': 6,
    'macOS': 7,
    'windows': 8,
    'windowsHolographic': 9,
    'unknownFutureValue': 10,
}
deviceCleanupRulePlatformType = enum.Enum('deviceCleanupRulePlatformType', deviceCleanupRulePlatformType_data)


deviceCustomAttributeValueType_data = {
    'integer': 0,
    'string': 1,
    'dateTime': 2,
}
deviceCustomAttributeValueType = enum.Enum('deviceCustomAttributeValueType', deviceCustomAttributeValueType_data)


deviceEnrollmentType_data = {
    'unknown': 0,
    'userEnrollment': 1,
    'deviceEnrollmentManager': 2,
    'appleBulkWithUser': 3,
    'appleBulkWithoutUser': 4,
    'windowsAzureADJoin': 5,
    'windowsBulkUserless': 6,
    'windowsAutoEnrollment': 7,
    'windowsBulkAzureDomainJoin': 8,
    'windowsCoManagement': 9,
    'windowsAzureADJoinUsingDeviceAuth': 10,
    'appleUserEnrollment': 11,
    'appleUserEnrollmentWithServiceAccount': 12,
    'azureAdJoinUsingAzureVmExtension': 14,
    'androidEnterpriseDedicatedDevice': 15,
    'androidEnterpriseFullyManaged': 16,
    'androidEnterpriseCorporateWorkProfile': 17,
    'androidAOSPUserOwnedDeviceEnrollment': 18,
    'androidAOSPUserlessDeviceEnrollment': 19,
    'appleAccountDrivenUserEnrollment': 25,
    'unknownFutureValue': 26,
}
deviceEnrollmentType = enum.Enum('deviceEnrollmentType', deviceEnrollmentType_data)


deviceEventLevel_data = {
    'none': 0,
    'verbose': 1,
    'information': 2,
    'warning': 3,
    'error': 4,
    'critical': 5,
    'unknownFutureValue': 6,
}
deviceEventLevel = enum.Enum('deviceEventLevel', deviceEventLevel_data)


deviceGuardLocalSystemAuthorityCredentialGuardState_data = {
    'running': 0,
    'rebootRequired': 1,
    'notLicensed': 2,
    'notConfigured': 3,
    'virtualizationBasedSecurityNotRunning': 4,
}
deviceGuardLocalSystemAuthorityCredentialGuardState = enum.Enum('deviceGuardLocalSystemAuthorityCredentialGuardState', deviceGuardLocalSystemAuthorityCredentialGuardState_data)


deviceGuardVirtualizationBasedSecurityHardwareRequirementState_data = {
    'meetHardwareRequirements': 0,
    'secureBootRequired': 1,
    'dmaProtectionRequired': 2,
    'hyperVNotSupportedForGuestVM': 4,
    'hyperVNotAvailable': 8,
}
deviceGuardVirtualizationBasedSecurityHardwareRequirementState = enum.Enum('deviceGuardVirtualizationBasedSecurityHardwareRequirementState', deviceGuardVirtualizationBasedSecurityHardwareRequirementState_data)


deviceGuardVirtualizationBasedSecurityState_data = {
    'running': 0,
    'rebootRequired': 1,
    'require64BitArchitecture': 2,
    'notLicensed': 3,
    'notConfigured': 4,
    'doesNotMeetHardwareRequirements': 5,
    'other': 42,
}
deviceGuardVirtualizationBasedSecurityState = enum.Enum('deviceGuardVirtualizationBasedSecurityState', deviceGuardVirtualizationBasedSecurityState_data)


deviceHealthScriptType_data = {
    'deviceHealthScript': 0,
    'managedInstallerScript': 1,
}
deviceHealthScriptType = enum.Enum('deviceHealthScriptType', deviceHealthScriptType_data)


deviceIdentityAttestationStatus_data = {
    'unknown': 0,
    'trusted': 1,
    'unTrusted': 2,
    'notSupported': 3,
    'incompleteData': 4,
    'unknownFutureValue': 5,
}
deviceIdentityAttestationStatus = enum.Enum('deviceIdentityAttestationStatus', deviceIdentityAttestationStatus_data)


deviceLicensingStatus_data = {
    'unknown': -1,
    'licenseRefreshStarted': 0,
    'licenseRefreshPending': 1,
    'deviceIsNotAzureActiveDirectoryJoined': 2,
    'verifyingMicrosoftDeviceIdentity': 3,
    'deviceIdentityVerificationFailed': 4,
    'verifyingMicrosoftAccountIdentity': 5,
    'microsoftAccountVerificationFailed': 6,
    'acquiringDeviceLicense': 7,
    'refreshingDeviceLicense': 8,
    'deviceLicenseRefreshSucceed': 9,
    'deviceLicenseRefreshFailed': 10,
    'removingDeviceLicense': 11,
    'deviceLicenseRemoveSucceed': 12,
    'deviceLicenseRemoveFailed': 13,
    'unknownFutureValue': 14,
}
deviceLicensingStatus = enum.Enum('deviceLicensingStatus', deviceLicensingStatus_data)


deviceLogCollectionTemplateType_data = {
    'predefined': 0,
    'unknownFutureValue': 1,
}
deviceLogCollectionTemplateType = enum.Enum('deviceLogCollectionTemplateType', deviceLogCollectionTemplateType_data)


deviceManagementExchangeAccessState_data = {
    'none': 0,
    'unknown': 1,
    'allowed': 2,
    'blocked': 3,
    'quarantined': 4,
}
deviceManagementExchangeAccessState = enum.Enum('deviceManagementExchangeAccessState', deviceManagementExchangeAccessState_data)


deviceManagementExchangeAccessStateReason_data = {
    'none': 0,
    'unknown': 1,
    'exchangeGlobalRule': 2,
    'exchangeIndividualRule': 3,
    'exchangeDeviceRule': 4,
    'exchangeUpgrade': 5,
    'exchangeMailboxPolicy': 6,
    'other': 7,
    'compliant': 8,
    'notCompliant': 9,
    'notEnrolled': 10,
    'unknownLocation': 12,
    'mfaRequired': 13,
    'azureADBlockDueToAccessPolicy': 14,
    'compromisedPassword': 15,
    'deviceNotKnownWithManagedApp': 16,
}
deviceManagementExchangeAccessStateReason = enum.Enum('deviceManagementExchangeAccessStateReason', deviceManagementExchangeAccessStateReason_data)


deviceManagementSubscriptions_data = {
    'none': 0,
    'intune': 1,
    'office365': 2,
    'intunePremium': 4,
    'intune_EDU': 8,
    'intune_SMB': 16,
}
deviceManagementSubscriptions = enum.Enum('deviceManagementSubscriptions', deviceManagementSubscriptions_data)


deviceManagementSubscriptionState_data = {
    'pending': 0,
    'active': 1,
    'warning': 2,
    'disabled': 3,
    'deleted': 4,
    'blocked': 5,
    'lockedOut': 8,
}
deviceManagementSubscriptionState = enum.Enum('deviceManagementSubscriptionState', deviceManagementSubscriptionState_data)


deviceRegistrationState_data = {
    'notRegistered': 0,
    'registered': 2,
    'revoked': 3,
    'keyConflict': 4,
    'approvalPending': 5,
    'certificateReset': 6,
    'notRegisteredPendingEnrollment': 7,
    'unknown': 8,
}
deviceRegistrationState = enum.Enum('deviceRegistrationState', deviceRegistrationState_data)


deviceScopeAction_data = {

}
deviceScopeAction = enum.Enum('deviceScopeAction', deviceScopeAction_data)


deviceScopeActionStatus_data = {
    'failed': 0,
    'succeeded': 1,
    'unknownFutureValue': 2,
}
deviceScopeActionStatus = enum.Enum('deviceScopeActionStatus', deviceScopeActionStatus_data)


deviceScopeOperator_data = {
    'none': 0,
    'equals': 1,
    'unknownFutureValue': 2,
}
deviceScopeOperator = enum.Enum('deviceScopeOperator', deviceScopeOperator_data)


deviceScopeParameter_data = {
    'none': 0,
    'scopeTag': 1,
    'unknownFutureValue': 2,
}
deviceScopeParameter = enum.Enum('deviceScopeParameter', deviceScopeParameter_data)


deviceScopeStatus_data = {
    'none': 0,
    'computing': 1,
    'insufficientData': 2,
    'completed': 3,
    'unknownFutureValue': 4,
}
deviceScopeStatus = enum.Enum('deviceScopeStatus', deviceScopeStatus_data)


diskType_data = {
    'unknown': 0,
    'hdd': 1,
    'ssd': 2,
    'unknownFutureValue': 3,
}
diskType = enum.Enum('diskType', diskType_data)


firmwareProtectionType_data = {
    'notApplicable': 0,
    'systemGuardSecureLaunch': 1,
    'firmwareAttackSurfaceReduction': 2,
    'disabled': 3,
    'unknownFutureValue': 4,
}
firmwareProtectionType = enum.Enum('firmwareProtectionType', firmwareProtectionType_data)


globalDeviceHealthScriptState_data = {
    'notConfigured': 0,
    'pending': 1,
    'enabled': 2,
}
globalDeviceHealthScriptState = enum.Enum('globalDeviceHealthScriptState', globalDeviceHealthScriptState_data)


healthState_data = {
    'unknown': 0,
    'healthy': 1,
    'unhealthy': 2,
}
healthState = enum.Enum('healthState', healthState_data)


joinType_data = {
    'unknown': 0,
    'azureADJoined': 1,
    'azureADRegistered': 2,
    'hybridAzureADJoined': 3,
}
joinType = enum.Enum('joinType', joinType_data)


lostModeState_data = {
    'disabled': 0,
    'enabled': 1,
}
lostModeState = enum.Enum('lostModeState', lostModeState_data)


managedDeviceArchitecture_data = {
    'unknown': 0,
    'x86': 1,
    'x64': 2,
    'arm': 3,
    'arM64': 4,
}
managedDeviceArchitecture = enum.Enum('managedDeviceArchitecture', managedDeviceArchitecture_data)


managedDeviceManagementFeatures_data = {
    'none': 0,
    'microsoftManagedDesktop': 1,
}
managedDeviceManagementFeatures = enum.Enum('managedDeviceManagementFeatures', managedDeviceManagementFeatures_data)


managedDevicePartnerReportedHealthState_data = {
    'unknown': 0,
    'activated': 1,
    'deactivated': 2,
    'secured': 3,
    'lowSeverity': 4,
    'mediumSeverity': 5,
    'highSeverity': 6,
    'unresponsive': 7,
    'compromised': 8,
    'misconfigured': 9,
}
managedDevicePartnerReportedHealthState = enum.Enum('managedDevicePartnerReportedHealthState', managedDevicePartnerReportedHealthState_data)


managedDeviceRemoteAction_data = {
    'retire': 0,
    'delete': 1,
    'fullScan': 2,
    'quickScan': 3,
    'signatureUpdate': 4,
    'wipe': 5,
    'customTextNotification': 6,
    'rebootNow': 7,
    'setDeviceName': 8,
    'syncDevice': 9,
    'deprovision': 10,
    'disable': 11,
    'reenable': 12,
    'moveDeviceToOrganizationalUnit': 13,
    'activateDeviceEsim': 14,
    'collectDiagnostics': 15,
    'initiateMobileDeviceManagementKeyRecovery': 16,
    'initiateOnDemandProactiveRemediation': 17,
    'unknownFutureValue': 18,
    'initiateDeviceAttestation': 19,
}
managedDeviceRemoteAction = enum.Enum('managedDeviceRemoteAction', managedDeviceRemoteAction_data)


managedInstallerStatus_data = {
    'disabled': 0,
    'enabled': 1,
}
managedInstallerStatus = enum.Enum('managedInstallerStatus', managedInstallerStatus_data)


managementState_data = {
    'managed': 0,
    'retirePending': 1,
    'retireFailed': 2,
    'wipePending': 3,
    'wipeFailed': 4,
    'unhealthy': 5,
    'deletePending': 6,
    'retireIssued': 7,
    'wipeIssued': 8,
    'wipeCanceled': 9,
    'retireCanceled': 10,
    'discovered': 11,
}
managementState = enum.Enum('managementState', managementState_data)


obliterationBehavior_data = {
    'default': 0,
    'doNotObliterate': 1,
    'obliterateWithWarning': 2,
    'always': 3,
    'unknownFutureValue': 999,
}
obliterationBehavior = enum.Enum('obliterationBehavior', obliterationBehavior_data)


operatingSystemUpgradeEligibility_data = {
    'upgraded': 0,
    'unknown': 1,
    'notCapable': 2,
    'capable': 3,
    'unknownFutureValue': 4,
}
operatingSystemUpgradeEligibility = enum.Enum('operatingSystemUpgradeEligibility', operatingSystemUpgradeEligibility_data)


privilegeManagementElevationType_data = {
    'undetermined': 0,
    'unmanagedElevation': 1,
    'zeroTouchElevation': 2,
    'userConfirmedElevation': 3,
    'supportApprovedElevation': 4,
    'unknownFutureValue': 5,
}
privilegeManagementElevationType = enum.Enum('privilegeManagementElevationType', privilegeManagementElevationType_data)


privilegeManagementEndUserType_data = {
    'undetermined': 0,
    'azureAd': 1,
    'hybrid': 2,
    'local': 3,
    'unknownFutureValue': 4,
}
privilegeManagementEndUserType = enum.Enum('privilegeManagementEndUserType', privilegeManagementEndUserType_data)


privilegeManagementProcessType_data = {
    'undefined': 0,
    'parent': 1,
    'child': 2,
    'unknownFutureValue': 3,
}
privilegeManagementProcessType = enum.Enum('privilegeManagementProcessType', privilegeManagementProcessType_data)


remediationState_data = {
    'unknown': 0,
    'skipped': 1,
    'success': 2,
    'remediationFailed': 3,
    'scriptError': 4,
    'unknownFutureValue': 5,
}
remediationState = enum.Enum('remediationState', remediationState_data)


remoteAction_data = {
    'unknown': 0,
    'factoryReset': 1,
    'removeCompanyData': 2,
    'resetPasscode': 3,
    'remoteLock': 4,
    'enableLostMode': 5,
    'disableLostMode': 6,
    'locateDevice': 7,
    'rebootNow': 8,
    'recoverPasscode': 9,
    'cleanWindowsDevice': 10,
    'logoutSharedAppleDeviceActiveUser': 11,
    'quickScan': 12,
    'fullScan': 13,
    'windowsDefenderUpdateSignatures': 14,
    'factoryResetKeepEnrollmentData': 15,
    'updateDeviceAccount': 16,
    'automaticRedeployment': 17,
    'shutDown': 18,
    'rotateBitLockerKeys': 19,
    'rotateFileVaultKey': 20,
    'getFileVaultKey': 21,
    'setDeviceName': 22,
    'activateDeviceEsim': 23,
    'deprovision': 24,
    'disable': 25,
    'reenable': 26,
    'moveDeviceToOrganizationalUnit': 27,
    'initiateMobileDeviceManagementKeyRecovery': 28,
    'initiateOnDemandProactiveRemediation': 29,
    'rotateLocalAdminPassword': 32,
    'unknownFutureValue': 33,
    'launchRemoteHelp': 34,
    'revokeAppleVppLicenses': 35,
    'removeDeviceFirmwareConfigurationInterfaceManagement': 36,
    'pauseConfigurationRefresh': 37,
    'initiateDeviceAttestation': 38,
    'changeAssignments': 39,
    'delete': 40,
}
remoteAction = enum.Enum('remoteAction', remoteAction_data)


systemManagementModeLevel_data = {
    'notApplicable': 0,
    'level1': 1,
    'level2': 2,
    'level3': 3,
    'unknownFutureValue': 4,
}
systemManagementModeLevel = enum.Enum('systemManagementModeLevel', systemManagementModeLevel_data)


userExperienceAnalyticsAnomalyCorrelationGroupPrevalence_data = {
    'high': 0,
    'medium': 1,
    'low': 2,
    'unknownFutureValue': 3,
}
userExperienceAnalyticsAnomalyCorrelationGroupPrevalence = enum.Enum('userExperienceAnalyticsAnomalyCorrelationGroupPrevalence', userExperienceAnalyticsAnomalyCorrelationGroupPrevalence_data)


userExperienceAnalyticsAnomalyDeviceFeatureType_data = {
    'manufacturer': 0,
    'model': 1,
    'osVersion': 2,
    'application': 3,
    'driver': 4,
    'unknownFutureValue': 5,
}
userExperienceAnalyticsAnomalyDeviceFeatureType = enum.Enum('userExperienceAnalyticsAnomalyDeviceFeatureType', userExperienceAnalyticsAnomalyDeviceFeatureType_data)


userExperienceAnalyticsAnomalySeverity_data = {
    'high': 0,
    'medium': 1,
    'low': 2,
    'informational': 3,
    'other': 4,
    'unknownFutureValue': 5,
}
userExperienceAnalyticsAnomalySeverity = enum.Enum('userExperienceAnalyticsAnomalySeverity', userExperienceAnalyticsAnomalySeverity_data)


userExperienceAnalyticsAnomalyState_data = {
    'new': 0,
    'active': 1,
    'disabled': 2,
    'removed': 3,
    'other': 4,
    'unknownFutureValue': 5,
}
userExperienceAnalyticsAnomalyState = enum.Enum('userExperienceAnalyticsAnomalyState', userExperienceAnalyticsAnomalyState_data)


userExperienceAnalyticsAnomalyType_data = {
    'device': 0,
    'application': 1,
    'stopError': 2,
    'driver': 3,
    'other': 4,
    'unknownFutureValue': 5,
}
userExperienceAnalyticsAnomalyType = enum.Enum('userExperienceAnalyticsAnomalyType', userExperienceAnalyticsAnomalyType_data)


userExperienceAnalyticsDeviceStatus_data = {
    'anomalous': 0,
    'affected': 1,
    'atRisk': 2,
    'unknownFutureValue': 3,
}
userExperienceAnalyticsDeviceStatus = enum.Enum('userExperienceAnalyticsDeviceStatus', userExperienceAnalyticsDeviceStatus_data)


userExperienceAnalyticsHealthState_data = {
    'unknown': 0,
    'insufficientData': 1,
    'needsAttention': 2,
    'meetingGoals': 3,
    'unknownFutureValue': 4,
}
userExperienceAnalyticsHealthState = enum.Enum('userExperienceAnalyticsHealthState', userExperienceAnalyticsHealthState_data)


userExperienceAnalyticsInsightSeverity_data = {
    'none': 0,
    'informational': 1,
    'warning': 2,
    'error': 3,
    'unknownFutureValue': 4,
}
userExperienceAnalyticsInsightSeverity = enum.Enum('userExperienceAnalyticsInsightSeverity', userExperienceAnalyticsInsightSeverity_data)


userExperienceAnalyticsMachineType_data = {
    'unknown': 0,
    'physical': 1,
    'virtual': 2,
    'unknownFutureValue': 3,
}
userExperienceAnalyticsMachineType = enum.Enum('userExperienceAnalyticsMachineType', userExperienceAnalyticsMachineType_data)


userExperienceAnalyticsOperatingSystemRestartCategory_data = {
    'unknown': 0,
    'restartWithUpdate': 1,
    'restartWithoutUpdate': 2,
    'blueScreen': 3,
    'shutdownWithUpdate': 4,
    'shutdownWithoutUpdate': 5,
    'longPowerButtonPress': 6,
    'bootError': 7,
    'update': 8,
    'unknownFutureValue': 9,
}
userExperienceAnalyticsOperatingSystemRestartCategory = enum.Enum('userExperienceAnalyticsOperatingSystemRestartCategory', userExperienceAnalyticsOperatingSystemRestartCategory_data)


userExperienceAnalyticsSummarizedBy_data = {
    'none': 0,
    'model': 1,
    'allRegressions': 3,
    'modelRegression': 4,
    'manufacturerRegression': 5,
    'operatingSystemVersionRegression': 6,
    'unknownFutureValue': 7,
}
userExperienceAnalyticsSummarizedBy = enum.Enum('userExperienceAnalyticsSummarizedBy', userExperienceAnalyticsSummarizedBy_data)


windowsDefenderProductStatus_data = {
    'noStatus': 0,
    'serviceNotRunning': 1,
    'serviceStartedWithoutMalwareProtection': 2,
    'pendingFullScanDueToThreatAction': 4,
    'pendingRebootDueToThreatAction': 8,
    'pendingManualStepsDueToThreatAction': 16,
    'avSignaturesOutOfDate': 32,
    'asSignaturesOutOfDate': 64,
    'noQuickScanHappenedForSpecifiedPeriod': 128,
    'noFullScanHappenedForSpecifiedPeriod': 256,
    'systemInitiatedScanInProgress': 512,
    'systemInitiatedCleanInProgress': 1024,
    'samplesPendingSubmission': 2048,
    'productRunningInEvaluationMode': 4096,
    'productRunningInNonGenuineMode': 8192,
    'productExpired': 16384,
    'offlineScanRequired': 32768,
    'serviceShutdownAsPartOfSystemShutdown': 65536,
    'threatRemediationFailedCritically': 131072,
    'threatRemediationFailedNonCritically': 262144,
    'noStatusFlagsSet': 524288,
    'platformOutOfDate': 1048576,
    'platformUpdateInProgress': 2097152,
    'platformAboutToBeOutdated': 4194304,
    'signatureOrPlatformEndOfLifeIsPastOrIsImpending': 8388608,
    'windowsSModeSignaturesInUseOnNonWin10SInstall': 16777216,
}
windowsDefenderProductStatus = enum.Enum('windowsDefenderProductStatus', windowsDefenderProductStatus_data)


windowsDeviceHealthState_data = {
    'clean': 0,
    'fullScanPending': 1,
    'rebootPending': 2,
    'manualStepsPending': 4,
    'offlineScanPending': 8,
    'critical': 16,
}
windowsDeviceHealthState = enum.Enum('windowsDeviceHealthState', windowsDeviceHealthState_data)


windowsMalwareCategory_data = {
    'invalid': 0,
    'adware': 1,
    'spyware': 2,
    'passwordStealer': 3,
    'trojanDownloader': 4,
    'worm': 5,
    'backdoor': 6,
    'remoteAccessTrojan': 7,
    'trojan': 8,
    'emailFlooder': 9,
    'keylogger': 10,
    'dialer': 11,
    'monitoringSoftware': 12,
    'browserModifier': 13,
    'cookie': 14,
    'browserPlugin': 15,
    'aolExploit': 16,
    'nuker': 17,
    'securityDisabler': 18,
    'jokeProgram': 19,
    'hostileActiveXControl': 20,
    'softwareBundler': 21,
    'stealthNotifier': 22,
    'settingsModifier': 23,
    'toolBar': 24,
    'remoteControlSoftware': 25,
    'trojanFtp': 26,
    'potentialUnwantedSoftware': 27,
    'icqExploit': 28,
    'trojanTelnet': 29,
    'exploit': 30,
    'filesharingProgram': 31,
    'malwareCreationTool': 32,
    'remote_Control_Software': 33,
    'tool': 34,
    'trojanDenialOfService': 36,
    'trojanDropper': 37,
    'trojanMassMailer': 38,
    'trojanMonitoringSoftware': 39,
    'trojanProxyServer': 40,
    'virus': 42,
    'known': 43,
    'unknown': 44,
    'spp': 45,
    'behavior': 46,
    'vulnerability': 47,
    'policy': 48,
    'enterpriseUnwantedSoftware': 49,
    'ransom': 50,
    'hipsRule': 51,
}
windowsMalwareCategory = enum.Enum('windowsMalwareCategory', windowsMalwareCategory_data)


windowsMalwareExecutionState_data = {
    'unknown': 0,
    'blocked': 1,
    'allowed': 2,
    'running': 3,
    'notRunning': 4,
}
windowsMalwareExecutionState = enum.Enum('windowsMalwareExecutionState', windowsMalwareExecutionState_data)


windowsMalwareSeverity_data = {
    'unknown': 0,
    'low': 1,
    'moderate': 2,
    'high': 4,
    'severe': 5,
}
windowsMalwareSeverity = enum.Enum('windowsMalwareSeverity', windowsMalwareSeverity_data)


windowsMalwareState_data = {
    'unknown': 0,
    'detected': 1,
    'cleaned': 2,
    'quarantined': 3,
    'removed': 4,
    'allowed': 5,
    'blocked': 6,
    'cleanFailed': 102,
    'quarantineFailed': 103,
    'removeFailed': 104,
    'allowFailed': 105,
    'abandoned': 106,
    'blockFailed': 107,
}
windowsMalwareState = enum.Enum('windowsMalwareState', windowsMalwareState_data)


windowsMalwareThreatState_data = {
    'active': 0,
    'actionFailed': 1,
    'manualStepsRequired': 2,
    'fullScanRequired': 3,
    'rebootRequired': 4,
    'remediatedWithNonCriticalFailures': 5,
    'quarantined': 6,
    'removed': 7,
    'cleaned': 8,
    'allowed': 9,
    'noStatusCleared': 10,
}
windowsMalwareThreatState = enum.Enum('windowsMalwareThreatState', windowsMalwareThreatState_data)


deviceManagementDerivedCredentialIssuer_data = {
    'intercede': 0,
    'entrustDatacard': 1,
    'purebred': 2,
    'xTec': 3,
}
deviceManagementDerivedCredentialIssuer = enum.Enum('deviceManagementDerivedCredentialIssuer', deviceManagementDerivedCredentialIssuer_data)


deviceManagementDerivedCredentialNotificationType_data = {
    'none': 0,
    'companyPortal': 1,
    'email': 2,
}
deviceManagementDerivedCredentialNotificationType = enum.Enum('deviceManagementDerivedCredentialNotificationType', deviceManagementDerivedCredentialNotificationType_data)


deviceManagementResourceAccessProfileIntent_data = {
    'apply': 0,
    'remove': 1,
}
deviceManagementResourceAccessProfileIntent = enum.Enum('deviceManagementResourceAccessProfileIntent', deviceManagementResourceAccessProfileIntent_data)


appleUserInitiatedEnrollmentType_data = {
    'unknown': 0,
    'device': 1,
    'user': 2,
    'accountDrivenUserEnrollment': 3,
    'webDeviceEnrollment': 4,
    'unknownFutureValue': 5,
}
appleUserInitiatedEnrollmentType = enum.Enum('appleUserInitiatedEnrollmentType', appleUserInitiatedEnrollmentType_data)


depTokenType_data = {
    'none': 0,
    'dep': 1,
    'appleSchoolManager': 2,
}
depTokenType = enum.Enum('depTokenType', depTokenType_data)


discoverySource_data = {
    'unknown': 0,
    'adminImport': 2,
    'deviceEnrollmentProgram': 4,
}
discoverySource = enum.Enum('discoverySource', discoverySource_data)


enrollmentState_data = {
    'unknown': 0,
    'enrolled': 1,
    'pendingReset': 2,
    'failed': 3,
    'notContacted': 4,
    'blocked': 5,
}
enrollmentState = enum.Enum('enrollmentState', enrollmentState_data)


importedDeviceIdentityType_data = {
    'unknown': 0,
    'imei': 1,
    'serialNumber': 2,
    'manufacturerModelSerial': 3,
}
importedDeviceIdentityType = enum.Enum('importedDeviceIdentityType', importedDeviceIdentityType_data)


importedWindowsAutopilotDeviceIdentityImportStatus_data = {
    'unknown': 0,
    'pending': 1,
    'partial': 2,
    'complete': 3,
    'error': 4,
}
importedWindowsAutopilotDeviceIdentityImportStatus = enum.Enum('importedWindowsAutopilotDeviceIdentityImportStatus', importedWindowsAutopilotDeviceIdentityImportStatus_data)


importedWindowsAutopilotDeviceIdentityUploadStatus_data = {
    'noUpload': 0,
    'pending': 1,
    'complete': 2,
    'error': 3,
}
importedWindowsAutopilotDeviceIdentityUploadStatus = enum.Enum('importedWindowsAutopilotDeviceIdentityUploadStatus', importedWindowsAutopilotDeviceIdentityUploadStatus_data)


iTunesPairingMode_data = {
    'disallow': 0,
    'allow': 1,
    'requiresCertificate': 2,
}
iTunesPairingMode = enum.Enum('iTunesPairingMode', iTunesPairingMode_data)


platform_data = {
    'unknown': 0,
    'ios': 1,
    'android': 2,
    'windows': 3,
    'windowsMobile': 4,
    'macOS': 5,
    'visionOS': 6,
    'tvOS': 7,
    'unknownFutureValue': 8,
}
platform = enum.Enum('platform', platform_data)


windowsAutopilotDeviceRemediationState_data = {
    'unknown': 0,
    'noRemediationRequired': 1,
    'automaticRemediationRequired': 2,
    'manualRemediationRequired': 3,
    'unknownFutureValue': 4,
}
windowsAutopilotDeviceRemediationState = enum.Enum('windowsAutopilotDeviceRemediationState', windowsAutopilotDeviceRemediationState_data)


windowsAutopilotDeviceType_data = {
    'windowsPc': 0,
    'holoLens': 1,
    'surfaceHub2': 2,
    'surfaceHub2S': 3,
    'virtualMachine': 4,
    'unknownFutureValue': 99,
}
windowsAutopilotDeviceType = enum.Enum('windowsAutopilotDeviceType', windowsAutopilotDeviceType_data)


windowsAutopilotProfileAssignmentDetailedStatus_data = {
    'none': 0,
    'hardwareRequirementsNotMet': 1,
    'surfaceHubProfileNotSupported': 2,
    'holoLensProfileNotSupported': 3,
    'windowsPcProfileNotSupported': 4,
    'surfaceHub2SProfileNotSupported': 5,
    'unknownFutureValue': 99,
}
windowsAutopilotProfileAssignmentDetailedStatus = enum.Enum('windowsAutopilotProfileAssignmentDetailedStatus', windowsAutopilotProfileAssignmentDetailedStatus_data)


windowsAutopilotProfileAssignmentStatus_data = {
    'unknown': 0,
    'assignedInSync': 1,
    'assignedOutOfSync': 2,
    'assignedUnkownSyncState': 3,
    'notAssigned': 4,
    'pending': 5,
    'failed': 6,
}
windowsAutopilotProfileAssignmentStatus = enum.Enum('windowsAutopilotProfileAssignmentStatus', windowsAutopilotProfileAssignmentStatus_data)


windowsAutopilotSyncStatus_data = {
    'unknown': 0,
    'inProgress': 1,
    'completed': 2,
    'failed': 3,
}
windowsAutopilotSyncStatus = enum.Enum('windowsAutopilotSyncStatus', windowsAutopilotSyncStatus_data)


windowsAutopilotUserlessEnrollmentStatus_data = {
    'unknown': 0,
    'allowed': 1,
    'blocked': 2,
    'unknownFutureValue': 3,
}
windowsAutopilotUserlessEnrollmentStatus = enum.Enum('windowsAutopilotUserlessEnrollmentStatus', windowsAutopilotUserlessEnrollmentStatus_data)


windowsDeviceUsageType_data = {
    'singleUser': 0,
    'shared': 1,
    'unknownFutureValue': 2,
}
windowsDeviceUsageType = enum.Enum('windowsDeviceUsageType', windowsDeviceUsageType_data)


windowsUserType_data = {
    'administrator': 0,
    'standard': 1,
    'unknownFutureValue': 2,
}
windowsUserType = enum.Enum('windowsUserType', windowsUserType_data)


elevationRequestState_data = {
    'none': 0,
    'pending': 1,
    'approved': 2,
    'denied': 3,
    'expired': 4,
    'unknownFutureValue': 5,
    'revoked': 6,
    'completed': 7,
}
elevationRequestState = enum.Enum('elevationRequestState', elevationRequestState_data)


groupPolicyMigrationReadiness_data = {
    'none': 1,
    'partial': 2,
    'complete': 3,
    'error': 4,
    'notApplicable': 5,
}
groupPolicyMigrationReadiness = enum.Enum('groupPolicyMigrationReadiness', groupPolicyMigrationReadiness_data)


groupPolicySettingScope_data = {
    'unknown': 0,
    'device': 1,
    'user': 2,
}
groupPolicySettingScope = enum.Enum('groupPolicySettingScope', groupPolicySettingScope_data)


groupPolicySettingType_data = {
    'unknown': 0,
    'policy': 1,
    'account': 2,
    'securityOptions': 3,
    'userRightsAssignment': 4,
    'auditSetting': 5,
    'windowsFirewallSettings': 6,
    'appLockerRuleCollection': 7,
    'dataSourcesSettings': 8,
    'devicesSettings': 9,
    'driveMapSettings': 10,
    'environmentVariables': 11,
    'filesSettings': 12,
    'folderOptions': 13,
    'folders': 14,
    'iniFiles': 15,
    'internetOptions': 16,
    'localUsersAndGroups': 17,
    'networkOptions': 18,
    'networkShares': 19,
    'ntServices': 20,
    'powerOptions': 21,
    'printers': 22,
    'regionalOptionsSettings': 23,
    'registrySettings': 24,
    'scheduledTasks': 25,
    'shortcutSettings': 26,
    'startMenuSettings': 27,
}
groupPolicySettingType = enum.Enum('groupPolicySettingType', groupPolicySettingType_data)


mdmSupportedState_data = {
    'unknown': 0,
    'supported': 1,
    'unsupported': 2,
    'deprecated': 3,
}
mdmSupportedState = enum.Enum('mdmSupportedState', mdmSupportedState_data)


groupPolicyConfigurationIngestionType_data = {
    'unknown': 0,
    'custom': 1,
    'builtIn': 2,
    'mixed': 3,
    'unknownFutureValue': 4,
}
groupPolicyConfigurationIngestionType = enum.Enum('groupPolicyConfigurationIngestionType', groupPolicyConfigurationIngestionType_data)


groupPolicyConfigurationType_data = {
    'policy': 0,
    'preference': 1,
}
groupPolicyConfigurationType = enum.Enum('groupPolicyConfigurationType', groupPolicyConfigurationType_data)


groupPolicyDefinitionClassType_data = {
    'user': 0,
    'machine': 1,
}
groupPolicyDefinitionClassType = enum.Enum('groupPolicyDefinitionClassType', groupPolicyDefinitionClassType_data)


groupPolicyOperationStatus_data = {
    'unknown': 0,
    'inProgress': 1,
    'success': 2,
    'failed': 3,
}
groupPolicyOperationStatus = enum.Enum('groupPolicyOperationStatus', groupPolicyOperationStatus_data)


groupPolicyOperationType_data = {
    'none': 0,
    'upload': 1,
    'uploadNewVersion': 2,
    'addLanguageFiles': 3,
    'removeLanguageFiles': 4,
    'updateLanguageFiles': 5,
    'remove': 6,
}
groupPolicyOperationType = enum.Enum('groupPolicyOperationType', groupPolicyOperationType_data)


groupPolicyType_data = {
    'admxBacked': 0,
    'admxIngested': 1,
}
groupPolicyType = enum.Enum('groupPolicyType', groupPolicyType_data)


groupPolicyUploadedDefinitionFileStatus_data = {
    'none': 0,
    'uploadInProgress': 1,
    'available': 2,
    'assigned': 3,
    'removalInProgress': 4,
    'uploadFailed': 5,
    'removalFailed': 6,
}
groupPolicyUploadedDefinitionFileStatus = enum.Enum('groupPolicyUploadedDefinitionFileStatus', groupPolicyUploadedDefinitionFileStatus_data)


ingestionSource_data = {
    'unknown': 0,
    'custom': 1,
    'builtIn': 2,
    'unknownFutureValue': 3,
}
ingestionSource = enum.Enum('ingestionSource', ingestionSource_data)


serviceNowConnectionStatus_data = {
    'disabled': 0,
    'enabled': 1,
    'unknownFutureValue': 2,
}
serviceNowConnectionStatus = enum.Enum('serviceNowConnectionStatus', serviceNowConnectionStatus_data)


androidManagedAppSafetyNetAppsVerificationType_data = {
    'none': 0,
    'enabled': 1,
}
androidManagedAppSafetyNetAppsVerificationType = enum.Enum('androidManagedAppSafetyNetAppsVerificationType', androidManagedAppSafetyNetAppsVerificationType_data)


androidManagedAppSafetyNetDeviceAttestationType_data = {
    'none': 0,
    'basicIntegrity': 1,
    'basicIntegrityAndDeviceCertification': 2,
}
androidManagedAppSafetyNetDeviceAttestationType = enum.Enum('androidManagedAppSafetyNetDeviceAttestationType', androidManagedAppSafetyNetDeviceAttestationType_data)


androidManagedAppSafetyNetEvaluationType_data = {
    'basic': 0,
    'hardwareBacked': 1,
}
androidManagedAppSafetyNetEvaluationType = enum.Enum('androidManagedAppSafetyNetEvaluationType', androidManagedAppSafetyNetEvaluationType_data)


appManagementLevel_data = {
    'unspecified': 0,
    'unmanaged': 1,
    'mdm': 2,
    'androidEnterprise': 4,
    'androidEnterpriseDedicatedDevicesWithAzureAdSharedMode': 8,
    'androidOpenSourceProjectUserAssociated': 16,
    'androidOpenSourceProjectUserless': 32,
    'unknownFutureValue': 64,
}
appManagementLevel = enum.Enum('appManagementLevel', appManagementLevel_data)


managedAppClipboardSharingLevel_data = {
    'allApps': 0,
    'managedAppsWithPasteIn': 1,
    'managedApps': 2,
    'blocked': 3,
}
managedAppClipboardSharingLevel = enum.Enum('managedAppClipboardSharingLevel', managedAppClipboardSharingLevel_data)


managedAppDataEncryptionType_data = {
    'useDeviceSettings': 0,
    'afterDeviceRestart': 1,
    'whenDeviceLockedExceptOpenFiles': 2,
    'whenDeviceLocked': 3,
}
managedAppDataEncryptionType = enum.Enum('managedAppDataEncryptionType', managedAppDataEncryptionType_data)


managedAppDataIngestionLocation_data = {
    'oneDriveForBusiness': 1,
    'sharePoint': 2,
    'camera': 3,
    'photoLibrary': 4,
}
managedAppDataIngestionLocation = enum.Enum('managedAppDataIngestionLocation', managedAppDataIngestionLocation_data)


managedAppDataStorageLocation_data = {
    'oneDriveForBusiness': 1,
    'sharePoint': 2,
    'box': 3,
    'localStorage': 6,
    'photoLibrary': 7,
}
managedAppDataStorageLocation = enum.Enum('managedAppDataStorageLocation', managedAppDataStorageLocation_data)


managedAppDataTransferLevel_data = {
    'allApps': 0,
    'managedApps': 1,
    'none': 2,
}
managedAppDataTransferLevel = enum.Enum('managedAppDataTransferLevel', managedAppDataTransferLevel_data)


managedAppDeviceThreatLevel_data = {
    'notConfigured': 0,
    'secured': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
}
managedAppDeviceThreatLevel = enum.Enum('managedAppDeviceThreatLevel', managedAppDeviceThreatLevel_data)


managedAppFlaggedReason_data = {
    'none': 0,
    'rootedDevice': 1,
    'androidBootloaderUnlocked': 2,
    'androidFactoryRomModified': 3,
}
managedAppFlaggedReason = enum.Enum('managedAppFlaggedReason', managedAppFlaggedReason_data)


managedAppLogUploadConsent_data = {
    'unknown': 0,
    'declined': 1,
    'accepted': 2,
    'unknownFutureValue': 3,
}
managedAppLogUploadConsent = enum.Enum('managedAppLogUploadConsent', managedAppLogUploadConsent_data)


managedAppLogUploadState_data = {
    'pending': 0,
    'inProgress': 1,
    'completed': 2,
    'declinedByUser': 3,
    'timedOut': 4,
    'failed': 5,
    'unknownFutureValue': 6,
}
managedAppLogUploadState = enum.Enum('managedAppLogUploadState', managedAppLogUploadState_data)


managedAppNotificationRestriction_data = {
    'allow': 0,
    'blockOrganizationalData': 1,
    'block': 2,
}
managedAppNotificationRestriction = enum.Enum('managedAppNotificationRestriction', managedAppNotificationRestriction_data)


managedAppPhoneNumberRedirectLevel_data = {
    'allApps': 0,
    'managedApps': 1,
    'customApp': 2,
    'blocked': 3,
}
managedAppPhoneNumberRedirectLevel = enum.Enum('managedAppPhoneNumberRedirectLevel', managedAppPhoneNumberRedirectLevel_data)


managedAppPinCharacterSet_data = {
    'numeric': 0,
    'alphanumericAndSymbol': 1,
}
managedAppPinCharacterSet = enum.Enum('managedAppPinCharacterSet', managedAppPinCharacterSet_data)


managedAppRemediationAction_data = {
    'block': 0,
    'wipe': 1,
    'warn': 2,
    'blockWhenSettingIsSupported': 3,
}
managedAppRemediationAction = enum.Enum('managedAppRemediationAction', managedAppRemediationAction_data)


managedBrowserType_data = {
    'notConfigured': 0,
    'microsoftEdge': 1,
}
managedBrowserType = enum.Enum('managedBrowserType', managedBrowserType_data)


messagingRedirectAppType_data = {
    'anyApp': 0,
    'anyManagedApp': 1,
    'specificApps': 2,
    'blocked': 3,
}
messagingRedirectAppType = enum.Enum('messagingRedirectAppType', messagingRedirectAppType_data)


mobileThreatDefensePartnerPriority_data = {
    'defenderOverThirdPartyPartner': 0,
    'thirdPartyPartnerOverDefender': 1,
    'unknownFutureValue': 2,
}
mobileThreatDefensePartnerPriority = enum.Enum('mobileThreatDefensePartnerPriority', mobileThreatDefensePartnerPriority_data)


targetedManagedAppGroupType_data = {
    'selectedPublicApps': 0,
    'allCoreMicrosoftApps': 1,
    'allMicrosoftApps': 2,
    'allApps': 4,
}
targetedManagedAppGroupType = enum.Enum('targetedManagedAppGroupType', targetedManagedAppGroupType_data)


windowsInformationProtectionEnforcementLevel_data = {
    'noProtection': 0,
    'encryptAndAuditOnly': 1,
    'encryptAuditAndPrompt': 2,
    'encryptAuditAndBlock': 3,
}
windowsInformationProtectionEnforcementLevel = enum.Enum('windowsInformationProtectionEnforcementLevel', windowsInformationProtectionEnforcementLevel_data)


windowsInformationProtectionPinCharacterRequirements_data = {
    'notAllow': 0,
    'requireAtLeastOne': 1,
    'allow': 2,
}
windowsInformationProtectionPinCharacterRequirements = enum.Enum('windowsInformationProtectionPinCharacterRequirements', windowsInformationProtectionPinCharacterRequirements_data)


windowsManagedAppClipboardSharingLevel_data = {
    'anyDestinationAnySource': 0,
    'none': 1,
}
windowsManagedAppClipboardSharingLevel = enum.Enum('windowsManagedAppClipboardSharingLevel', windowsManagedAppClipboardSharingLevel_data)


windowsManagedAppDataTransferLevel_data = {
    'allApps': 0,
    'none': 1,
}
windowsManagedAppDataTransferLevel = enum.Enum('windowsManagedAppDataTransferLevel', windowsManagedAppDataTransferLevel_data)


microsoftTunnelDeploymentMode_data = {
    'standaloneRootful': 0,
    'standaloneRootless': 1,
    'podRootful': 2,
    'podRootless': 3,
    'unknownFutureValue': 4,
}
microsoftTunnelDeploymentMode = enum.Enum('microsoftTunnelDeploymentMode', microsoftTunnelDeploymentMode_data)


microsoftTunnelLogCollectionStatus_data = {
    'pending': 0,
    'completed': 1,
    'failed': 2,
    'unknownFutureValue': 3,
}
microsoftTunnelLogCollectionStatus = enum.Enum('microsoftTunnelLogCollectionStatus', microsoftTunnelLogCollectionStatus_data)


microsoftTunnelServerHealthStatus_data = {
    'unknown': 0,
    'healthy': 1,
    'unhealthy': 2,
    'warning': 3,
    'offline': 4,
    'upgradeInProgress': 5,
    'upgradeFailed': 6,
    'unknownFutureValue': 7,
}
microsoftTunnelServerHealthStatus = enum.Enum('microsoftTunnelServerHealthStatus', microsoftTunnelServerHealthStatus_data)


notificationTemplateBrandingOptions_data = {
    'none': 0,
    'includeCompanyLogo': 1,
    'includeCompanyName': 2,
    'includeContactInformation': 4,
    'includeCompanyPortalLink': 8,
    'includeDeviceDetails': 16,
    'unknownFutureValue': 32,
}
notificationTemplateBrandingOptions = enum.Enum('notificationTemplateBrandingOptions', notificationTemplateBrandingOptions_data)


deviceManagementDomainJoinConnectorState_data = {
    'active': 0,
    'error': 1,
    'inactive': 2,
}
deviceManagementDomainJoinConnectorState = enum.Enum('deviceManagementDomainJoinConnectorState', deviceManagementDomainJoinConnectorState_data)


managedDeviceWindowsOperatingSystemEditionType_data = {
    'professional': 0,
    'professionalN': 1,
    'enterprise': 2,
    'enterpriseN': 3,
    'education': 4,
    'educationN': 5,
    'proEducation': 6,
    'proEducationN': 7,
    'proWorkstation': 8,
    'proWorkstationN': 9,
    'unknownFutureValue': 10,
}
managedDeviceWindowsOperatingSystemEditionType = enum.Enum('managedDeviceWindowsOperatingSystemEditionType', managedDeviceWindowsOperatingSystemEditionType_data)


appVulnerabilityTaskMitigationType_data = {
    'unknown': 0,
    'update': 1,
    'uninstall': 2,
    'securityConfiguration': 3,
}
appVulnerabilityTaskMitigationType = enum.Enum('appVulnerabilityTaskMitigationType', appVulnerabilityTaskMitigationType_data)


deviceAppManagementTaskCategory_data = {
    'unknown': 0,
    'advancedThreatProtection': 1,
}
deviceAppManagementTaskCategory = enum.Enum('deviceAppManagementTaskCategory', deviceAppManagementTaskCategory_data)


deviceAppManagementTaskPriority_data = {
    'none': 0,
    'high': 1,
    'low': 2,
}
deviceAppManagementTaskPriority = enum.Enum('deviceAppManagementTaskPriority', deviceAppManagementTaskPriority_data)


deviceAppManagementTaskStatus_data = {
    'unknown': 0,
    'pending': 1,
    'active': 2,
    'completed': 3,
    'rejected': 4,
}
deviceAppManagementTaskStatus = enum.Enum('deviceAppManagementTaskStatus', deviceAppManagementTaskStatus_data)


endpointSecurityConfigurationApplicablePlatform_data = {
    'unknown': 0,
    'macOS': 1,
    'windows10AndLater': 2,
    'windows10AndWindowsServer': 3,
}
endpointSecurityConfigurationApplicablePlatform = enum.Enum('endpointSecurityConfigurationApplicablePlatform', endpointSecurityConfigurationApplicablePlatform_data)


endpointSecurityConfigurationProfileType_data = {
    'unknown': 0,
    'antivirus': 1,
    'windowsSecurity': 2,
    'bitLocker': 3,
    'fileVault': 4,
    'firewall': 5,
    'firewallRules': 6,
    'endpointDetectionAndResponse': 7,
    'deviceControl': 8,
    'appAndBrowserIsolation': 9,
    'exploitProtection': 10,
    'webProtection': 11,
    'applicationControl': 12,
    'attackSurfaceReductionRules': 13,
    'accountProtection': 14,
}
endpointSecurityConfigurationProfileType = enum.Enum('endpointSecurityConfigurationProfileType', endpointSecurityConfigurationProfileType_data)


endpointSecurityConfigurationType_data = {
    'unknown': 0,
    'antivirus': 1,
    'diskEncryption': 2,
    'firewall': 3,
    'endpointDetectionAndResponse': 4,
    'attackSurfaceReduction': 5,
    'accountProtection': 6,
}
endpointSecurityConfigurationType = enum.Enum('endpointSecurityConfigurationType', endpointSecurityConfigurationType_data)


operationApprovalPolicyPlatform_data = {
    'notApplicable': 0,
    'androidDeviceAdministrator': 1,
    'androidEnterprise': 2,
    'iOSiPadOS': 4,
    'macOS': 8,
    'windows10AndLater': 16,
    'windows81AndLater': 32,
    'windows10X': 64,
    'unknownFutureValue': 128,
}
operationApprovalPolicyPlatform = enum.Enum('operationApprovalPolicyPlatform', operationApprovalPolicyPlatform_data)


operationApprovalPolicyType_data = {
    'unknown': 0,
    'app': 16,
    'script': 17,
    'unknownFutureValue': 21,
}
operationApprovalPolicyType = enum.Enum('operationApprovalPolicyType', operationApprovalPolicyType_data)


operationApprovalRequestStatus_data = {
    'unknown': 0,
    'needsApproval': 1,
    'approved': 2,
    'rejected': 3,
    'cancelled': 4,
    'completed': 5,
    'expired': 6,
    'unknownFutureValue': 7,
}
operationApprovalRequestStatus = enum.Enum('operationApprovalRequestStatus', operationApprovalRequestStatus_data)


operationApprovalSource_data = {
    'unknown': 0,
    'adminConsole': 1,
    'email': 2,
    'unknownFutureValue': 3,
}
operationApprovalSource = enum.Enum('operationApprovalSource', operationApprovalSource_data)


roleAssignmentScopeType_data = {
    'resourceScope': 0,
    'allDevices': 1,
    'allLicensedUsers': 2,
    'allDevicesAndLicensedUsers': 3,
}
roleAssignmentScopeType = enum.Enum('roleAssignmentScopeType', roleAssignmentScopeType_data)


remoteAssistanceOnboardingStatus_data = {
    'notOnboarded': 0,
    'onboarding': 1,
    'onboarded': 2,
}
remoteAssistanceOnboardingStatus = enum.Enum('remoteAssistanceOnboardingStatus', remoteAssistanceOnboardingStatus_data)


remoteAssistanceState_data = {
    'disabled': 1,
    'enabled': 2,
}
remoteAssistanceState = enum.Enum('remoteAssistanceState', remoteAssistanceState_data)


deviceManagementExportJobLocalizationType_data = {
    'localizedValuesAsAdditionalColumn': 0,
    'replaceLocalizableValues': 1,
}
deviceManagementExportJobLocalizationType = enum.Enum('deviceManagementExportJobLocalizationType', deviceManagementExportJobLocalizationType_data)


deviceManagementReportFileFormat_data = {
    'csv': 0,
    'pdf': 1,
    'json': 2,
    'unknownFutureValue': 3,
}
deviceManagementReportFileFormat = enum.Enum('deviceManagementReportFileFormat', deviceManagementReportFileFormat_data)


deviceManagementReportStatus_data = {
    'unknown': 0,
    'notStarted': 1,
    'inProgress': 2,
    'completed': 3,
    'failed': 4,
}
deviceManagementReportStatus = enum.Enum('deviceManagementReportStatus', deviceManagementReportStatus_data)


embeddedSIMDeviceStateValue_data = {
    'notEvaluated': 0,
    'failed': 1,
    'installing': 2,
    'installed': 3,
    'deleting': 4,
    'error': 5,
    'deleted': 6,
    'removedByUser': 7,
}
embeddedSIMDeviceStateValue = enum.Enum('embeddedSIMDeviceStateValue', embeddedSIMDeviceStateValue_data)


connectorHealthState_data = {
    'healthy': 0,
    'warning': 1,
    'unhealthy': 2,
    'unknown': 3,
}
connectorHealthState = enum.Enum('connectorHealthState', connectorHealthState_data)


connectorName_data = {
    'applePushNotificationServiceExpirationDateTime': 0,
    'vppTokenExpirationDateTime': 1,
    'vppTokenLastSyncDateTime': 2,
    'windowsAutopilotLastSyncDateTime': 3,
    'windowsStoreForBusinessLastSyncDateTime': 4,
    'jamfLastSyncDateTime': 5,
    'ndesConnectorLastConnectionDateTime': 6,
    'appleDepExpirationDateTime': 7,
    'appleDepLastSyncDateTime': 8,
    'onPremConnectorLastSyncDateTime': 9,
    'googlePlayAppLastSyncDateTime': 10,
    'googlePlayConnectorLastModifiedDateTime': 11,
    'windowsDefenderATPConnectorLastHeartbeatDateTime': 12,
    'mobileThreatDefenceConnectorLastHeartbeatDateTime': 13,
    'chromebookLastDirectorySyncDateTime': 14,
    'futureValue': 15,
}
connectorName = enum.Enum('connectorName', connectorName_data)


deviceEnrollmentFailureReason_data = {
    'unknown': 0,
    'authentication': 1,
    'authorization': 2,
    'accountValidation': 3,
    'userValidation': 4,
    'deviceNotSupported': 5,
    'inMaintenance': 6,
    'badRequest': 7,
    'featureNotSupported': 8,
    'enrollmentRestrictionsEnforced': 9,
    'clientDisconnected': 10,
    'userAbandonment': 11,
}
deviceEnrollmentFailureReason = enum.Enum('deviceEnrollmentFailureReason', deviceEnrollmentFailureReason_data)


deviceManagementAutopilotPolicyComplianceStatus_data = {
    'unknown': 0,
    'compliant': 1,
    'installed': 2,
    'notCompliant': 3,
    'notInstalled': 4,
    'error': 5,
}
deviceManagementAutopilotPolicyComplianceStatus = enum.Enum('deviceManagementAutopilotPolicyComplianceStatus', deviceManagementAutopilotPolicyComplianceStatus_data)


deviceManagementAutopilotPolicyType_data = {
    'unknown': 0,
    'application': 3,
    'appModel': 7,
    'configurationPolicy': 12,
}
deviceManagementAutopilotPolicyType = enum.Enum('deviceManagementAutopilotPolicyType', deviceManagementAutopilotPolicyType_data)


deviceManagementScriptRunState_data = {
    'unknown': 0,
    'success': 1,
    'fail': 2,
    'scriptError': 3,
    'pending': 4,
    'notApplicable': 5,
    'unknownFutureValue': 6,
}
deviceManagementScriptRunState = enum.Enum('deviceManagementScriptRunState', deviceManagementScriptRunState_data)


mobileAppActionType_data = {
    'unknown': 0,
    'installCommandSent': 1,
    'installed': 3,
    'uninstalled': 4,
    'userRequestedInstall': 5,
}
mobileAppActionType = enum.Enum('mobileAppActionType', mobileAppActionType_data)


mobileAppIntent_data = {
    'available': 0,
    'notAvailable': 1,
    'requiredInstall': 2,
    'requiredUninstall': 3,
    'requiredAndAvailableInstall': 4,
    'availableInstallWithoutEnrollment': 5,
    'exclude': 6,
}
mobileAppIntent = enum.Enum('mobileAppIntent', mobileAppIntent_data)


windowsAutopilotDeploymentState_data = {
    'unknown': 0,
    'success': 1,
    'inProgress': 2,
    'failure': 3,
    'successWithTimeout': 4,
    'notAttempted': 5,
    'disabled': 6,
    'successOnRetry': 7,
}
windowsAutopilotDeploymentState = enum.Enum('windowsAutopilotDeploymentState', windowsAutopilotDeploymentState_data)


windowsAutopilotEnrollmentType_data = {
    'unknown': 0,
    'azureADJoinedWithAutopilotProfile': 1,
    'offlineDomainJoined': 2,
    'azureADJoinedUsingDeviceAuthWithAutopilotProfile': 3,
    'azureADJoinedUsingDeviceAuthWithoutAutopilotProfile': 4,
    'azureADJoinedWithOfflineAutopilotProfile': 5,
    'azureADJoinedWithWhiteGlove': 6,
    'offlineDomainJoinedWithWhiteGlove': 7,
    'offlineDomainJoinedWithOfflineAutopilotProfile': 8,
}
windowsAutopilotEnrollmentType = enum.Enum('windowsAutopilotEnrollmentType', windowsAutopilotEnrollmentType_data)


windowsDefenderApplicationControlSupplementalPolicyStatuses_data = {
    'unknown': 0,
    'success': 1,
    'tokenError': 2,
    'notAuthorizedByToken': 3,
    'policyNotFound': 4,
}
windowsDefenderApplicationControlSupplementalPolicyStatuses = enum.Enum('windowsDefenderApplicationControlSupplementalPolicyStatuses', windowsDefenderApplicationControlSupplementalPolicyStatuses_data)


driverApprovalAction_data = {
    'approve': 0,
    'decline': 1,
    'suspend': 2,
}
driverApprovalAction = enum.Enum('driverApprovalAction', driverApprovalAction_data)


driverApprovalStatus_data = {
    'needsReview': 0,
    'declined': 1,
    'approved': 2,
    'suspended': 3,
}
driverApprovalStatus = enum.Enum('driverApprovalStatus', driverApprovalStatus_data)


driverCategory_data = {
    'recommended': 0,
    'previouslyApproved': 1,
    'other': 2,
}
driverCategory = enum.Enum('driverCategory', driverCategory_data)


driverUpdateProfileApprovalType_data = {
    'manual': 0,
    'automatic': 1,
}
driverUpdateProfileApprovalType = enum.Enum('driverUpdateProfileApprovalType', driverUpdateProfileApprovalType_data)


windowsDriverUpdateProfileInventorySyncState_data = {
    'pending': 0,
    'success': 1,
    'failure': 2,
}
windowsDriverUpdateProfileInventorySyncState = enum.Enum('windowsDriverUpdateProfileInventorySyncState', windowsDriverUpdateProfileInventorySyncState_data)


windowsQualityUpdateCadence_data = {
    'monthly': 0,
    'outOfBand': 1,
    'unknownFutureValue': 2,
}
windowsQualityUpdateCadence = enum.Enum('windowsQualityUpdateCadence', windowsQualityUpdateCadence_data)


windowsQualityUpdateCategory_data = {
    'all': 0,
    'security': 1,
    'nonSecurity': 2,
}
windowsQualityUpdateCategory = enum.Enum('windowsQualityUpdateCategory', windowsQualityUpdateCategory_data)


applicationType_data = {
    'universal': 1,
    'desktop': 2,
}
applicationType = enum.Enum('applicationType', applicationType_data)


userPfxIntendedPurpose_data = {
    'unassigned': 0,
    'smimeEncryption': 1,
    'smimeSigning': 2,
    'vpn': 4,
    'wifi': 8,
}
userPfxIntendedPurpose = enum.Enum('userPfxIntendedPurpose', userPfxIntendedPurpose_data)


userPfxPaddingScheme_data = {
    'none': 0,
    'pkcs1': 1,
    'oaepSha1': 2,
    'oaepSha256': 3,
    'oaepSha384': 4,
    'oaepSha512': 5,
}
userPfxPaddingScheme = enum.Enum('userPfxPaddingScheme', userPfxPaddingScheme_data)


appsUpdateChannelType_data = {
    'current': 0,
    'monthlyEnterprise': 1,
    'semiAnnual': 2,
    'unknownFutureValue': 3,
}
appsUpdateChannelType = enum.Enum('appsUpdateChannelType', appsUpdateChannelType_data)


postType_data = {
    'regular': 0,
    'quick': 1,
    'strategic': 2,
    'unknownFutureValue': 3,
}
postType = enum.Enum('postType', postType_data)


serviceHealthClassificationType_data = {
    'advisory': 1,
    'incident': 2,
    'unknownFutureValue': 3,
}
serviceHealthClassificationType = enum.Enum('serviceHealthClassificationType', serviceHealthClassificationType_data)


serviceHealthOrigin_data = {
    'microsoft': 1,
    'thirdParty': 2,
    'customer': 3,
    'unknownFutureValue': 4,
}
serviceHealthOrigin = enum.Enum('serviceHealthOrigin', serviceHealthOrigin_data)


serviceHealthStatus_data = {
    'serviceOperational': 0,
    'investigating': 1,
    'restoringService': 2,
    'verifyingService': 3,
    'serviceRestored': 4,
    'postIncidentReviewPublished': 5,
    'serviceDegradation': 6,
    'serviceInterruption': 7,
    'extendedRecovery': 8,
    'falsePositive': 9,
    'investigationSuspended': 10,
    'resolved': 11,
    'mitigatedExternal': 12,
    'mitigated': 13,
    'resolvedExternal': 14,
    'confirmed': 15,
    'reported': 16,
    'unknownFutureValue': 17,
}
serviceHealthStatus = enum.Enum('serviceHealthStatus', serviceHealthStatus_data)


serviceUpdateCategory_data = {
    'preventOrFixIssue': 1,
    'planForChange': 2,
    'stayInformed': 3,
    'unknownFutureValue': 4,
}
serviceUpdateCategory = enum.Enum('serviceUpdateCategory', serviceUpdateCategory_data)


serviceUpdateSeverity_data = {
    'normal': 1,
    'high': 2,
    'critical': 3,
    'unknownFutureValue': 4,
}
serviceUpdateSeverity = enum.Enum('serviceUpdateSeverity', serviceUpdateSeverity_data)


nonAdminSetting_data = {
    'false': 0,
    'true': 1,
    'unknownFutureValue': 2,
}
nonAdminSetting = enum.Enum('nonAdminSetting', nonAdminSetting_data)


dataCollectionStatus_data = {
    'online': 0,
    'offline': 1,
    'unknownFutureValue': 2,
}
dataCollectionStatus = enum.Enum('dataCollectionStatus', dataCollectionStatus_data)


permissionsModificationCapability_data = {
    'enabled': 0,
    'notConfigured': 1,
    'noRecentDataCollected': 2,
    'unknownFutureValue': 3,
}
permissionsModificationCapability = enum.Enum('permissionsModificationCapability', permissionsModificationCapability_data)


authorizationSystemActionSeverity_data = {
    'normal': 0,
    'high': 1,
    'unknownFutureValue': 2,
}
authorizationSystemActionSeverity = enum.Enum('authorizationSystemActionSeverity', authorizationSystemActionSeverity_data)


authorizationSystemActionType_data = {
    'delete': 0,
    'read': 1,
    'unknownFutureValue': 2,
}
authorizationSystemActionType = enum.Enum('authorizationSystemActionType', authorizationSystemActionType_data)


awsPolicyType_data = {
    'system': 0,
    'custom': 1,
    'unknownFutureValue': 2,
}
awsPolicyType = enum.Enum('awsPolicyType', awsPolicyType_data)


awsRoleTrustEntityType_data = {
    'none': 0,
    'service': 1,
    'sso': 2,
    'crossAccount': 4,
    'webIdentity': 8,
    'unknownFutureValue': 16,
}
awsRoleTrustEntityType = enum.Enum('awsRoleTrustEntityType', awsRoleTrustEntityType_data)


awsRoleType_data = {
    'system': 0,
    'custom': 1,
    'unknownFutureValue': 2,
}
awsRoleType = enum.Enum('awsRoleType', awsRoleType_data)


azureRoleDefinitionType_data = {
    'system': 0,
    'custom': 1,
    'unknownFutureValue': 2,
}
azureRoleDefinitionType = enum.Enum('azureRoleDefinitionType', azureRoleDefinitionType_data)


gcpRoleType_data = {
    'system': 0,
    'custom': 1,
    'unknownFutureValue': 2,
}
gcpRoleType = enum.Enum('gcpRoleType', gcpRoleType_data)


authorizationSystemType_data = {
    'azure': 0,
    'gcp': 1,
    'aws': 2,
    'unknownFutureValue': 3,
}
authorizationSystemType = enum.Enum('authorizationSystemType', authorizationSystemType_data)


awsAccessType_data = {
    'public': 0,
    'restricted': 1,
    'crossAccount': 2,
    'private': 3,
    'unknownFutureValue': 4,
}
awsAccessType = enum.Enum('awsAccessType', awsAccessType_data)


awsSecretInformationWebServices_data = {
    'secretsManager': 0,
    'certificateAuthority': 1,
    'cloudHsm': 2,
    'certificateManager': 4,
    'unknownFutureValue': 8,
}
awsSecretInformationWebServices = enum.Enum('awsSecretInformationWebServices', awsSecretInformationWebServices_data)


awsSecurityToolWebServices_data = {
    'macie': 0,
    'wafShield': 1,
    'cloudTrail': 2,
    'inspector': 4,
    'securityHub': 8,
    'detective': 16,
    'guardDuty': 32,
    'unknownFutureValue': 64,
}
awsSecurityToolWebServices = enum.Enum('awsSecurityToolWebServices', awsSecurityToolWebServices_data)


azureAccessType_data = {
    'public': 0,
    'private': 1,
    'unknownFutureValue': 2,
}
azureAccessType = enum.Enum('azureAccessType', azureAccessType_data)


azureEncryption_data = {
    'microsoftStorage': 0,
    'microsoftKeyVault': 1,
    'customer': 2,
    'unknownFutureValue': 3,
}
azureEncryption = enum.Enum('azureEncryption', azureEncryption_data)


externalSystemAccessMethods_data = {
    'direct': 0,
    'roleChaining': 1,
    'unknownFutureValue': 2,
}
externalSystemAccessMethods = enum.Enum('externalSystemAccessMethods', externalSystemAccessMethods_data)


gcpAccessType_data = {
    'public': 0,
    'subjectToObjectAcls': 1,
    'private': 2,
    'unknownFutureValue': 3,
}
gcpAccessType = enum.Enum('gcpAccessType', gcpAccessType_data)


gcpEncryption_data = {
    'google': 0,
    'customer': 1,
    'unknownFutureValue': 2,
}
gcpEncryption = enum.Enum('gcpEncryption', gcpEncryption_data)


iamStatus_data = {
    'active': 0,
    'inactive': 1,
    'disabled': 2,
    'unknownFutureValue': 3,
}
iamStatus = enum.Enum('iamStatus', iamStatus_data)


awsStatementEffect_data = {
    'allow': 0,
    'deny': 1,
    'unknownFutureValue': 2,
}
awsStatementEffect = enum.Enum('awsStatementEffect', awsStatementEffect_data)


permissionsDefinitionIdentityType_data = {
    'user': 0,
    'role': 1,
    'application': 2,
    'managedIdentity': 3,
    'serviceAccount': 4,
    'unknownFutureValue': 5,
}
permissionsDefinitionIdentityType = enum.Enum('permissionsDefinitionIdentityType', permissionsDefinitionIdentityType_data)


permissionsRequestOccurrenceStatus_data = {
    'grantingFailed': 0,
    'granted': 1,
    'granting': 2,
    'revoked': 3,
    'revoking': 4,
    'revokingFailed': 5,
    'unknownFutureValue': 6,
}
permissionsRequestOccurrenceStatus = enum.Enum('permissionsRequestOccurrenceStatus', permissionsRequestOccurrenceStatus_data)


statusDetail_data = {
    'submitted': 0,
    'approved': 1,
    'completed': 2,
    'canceled': 3,
    'rejected': 4,
    'unknownFutureValue': 5,
}
statusDetail = enum.Enum('statusDetail', statusDetail_data)


scheduledPermissionsRequestFilterByCurrentUserOptions_data = {
    'principal': 1,
    'createdBy': 2,
    'approver': 3,
    'unknownFutureValue': 4,
}
scheduledPermissionsRequestFilterByCurrentUserOptions = enum.Enum('scheduledPermissionsRequestFilterByCurrentUserOptions', scheduledPermissionsRequestFilterByCurrentUserOptions_data)


unifiedRoleScheduleRequestActions_data = {
    'adminAssign': 1,
    'adminUpdate': 2,
    'adminRemove': 3,
    'selfActivate': 4,
    'selfDeactivate': 5,
    'adminExtend': 6,
    'adminRenew': 7,
    'selfExtend': 8,
    'selfRenew': 9,
    'unknownFutureValue': 10,
}
unifiedRoleScheduleRequestActions = enum.Enum('unifiedRoleScheduleRequestActions', unifiedRoleScheduleRequestActions_data)


bucketAggregationSortProperty_data = {
    'count': 0,
    'keyAsString': 1,
    'keyAsNumber': 2,
    'unknownFutureValue': 3,
}
bucketAggregationSortProperty = enum.Enum('bucketAggregationSortProperty', bucketAggregationSortProperty_data)


groundingEntityType_data = {
    'site': 0,
    'list': 1,
    'listItem': 2,
    'drive': 3,
    'driveItem': 4,
    'unknownFutureValue': 5,
}
groundingEntityType = enum.Enum('groundingEntityType', groundingEntityType_data)


searchAlterationType_data = {
    'suggestion': 0,
    'modification': 1,
    'unknownFutureValue': 2,
}
searchAlterationType = enum.Enum('searchAlterationType', searchAlterationType_data)


searchContent_data = {
    'sharedContent': 1,
    'privateContent': 2,
    'unknownFutureValue': 4,
}
searchContent = enum.Enum('searchContent', searchContent_data)


policyScope_data = {
    'none': 0,
    'all': 1,
    'selected': 2,
    'unknownFutureValue': 3,
}
policyScope = enum.Enum('policyScope', policyScope_data)


priority_data = {
    'None': 0,
    'High': 1,
    'Low': 2,
}
priority = enum.Enum('priority', priority_data)


plannerApprovalStatus_data = {
    'requested': 0,
    'approved': 1,
    'rejected': 2,
    'cancelled': 3,
    'unknownFutureValue': 4,
}
plannerApprovalStatus = enum.Enum('plannerApprovalStatus', plannerApprovalStatus_data)


plannerContainerType_data = {
    'group': 1,
    'unknownFutureValue': 2,
    'roster': 3,
    'project': 4,
    'driveItem': 5,
    'user': 6,
    'teamsChannel': 7,
}
plannerContainerType = enum.Enum('plannerContainerType', plannerContainerType_data)


plannerContextState_data = {
    'active': 0,
    'delinked': 1,
    'unknownFutureValue': 2,
}
plannerContextState = enum.Enum('plannerContextState', plannerContextState_data)


plannerCreationSourceKind_data = {
    'none': 0,
    'external': 1,
    'publication': 2,
    'unknownFutureValue': 3,
}
plannerCreationSourceKind = enum.Enum('plannerCreationSourceKind', plannerCreationSourceKind_data)


plannerExternalTaskSourceDisplayType_data = {
    'none': 1,
    'default': 2,
    'unknownFutureValue': 3,
}
plannerExternalTaskSourceDisplayType = enum.Enum('plannerExternalTaskSourceDisplayType', plannerExternalTaskSourceDisplayType_data)


plannerPlanAccessLevel_data = {
    'readAccess': 0,
    'readWriteAccess': 1,
    'fullAccess': 2,
    'unknownFutureValue': 3,
}
plannerPlanAccessLevel = enum.Enum('plannerPlanAccessLevel', plannerPlanAccessLevel_data)


plannerPlanContextType_data = {
    'teamsTab': 1,
    'sharePointPage': 2,
    'meetingNotes': 3,
    'other': 4,
    'unknownFutureValue': 5,
    'loopPage': 6,
    'project': 7,
}
plannerPlanContextType = enum.Enum('plannerPlanContextType', plannerPlanContextType_data)


plannerPreviewType_data = {
    'automatic': 0,
    'noPreview': 1,
    'checklist': 2,
    'description': 3,
    'reference': 4,
}
plannerPreviewType = enum.Enum('plannerPreviewType', plannerPreviewType_data)


plannerTaskCompletionRequirements_data = {
    'none': 0,
    'checklistCompletion': 1,
    'unknownFutureValue': 2,
    'formCompletion': 4,
    'approvalCompletion': 8,
    'completionInHostedApp': 16,
}
plannerTaskCompletionRequirements = enum.Enum('plannerTaskCompletionRequirements', plannerTaskCompletionRequirements_data)


plannerTaskTargetKind_data = {
    'group': 1,
    'unknownFutureValue': 2,
}
plannerTaskTargetKind = enum.Enum('plannerTaskTargetKind', plannerTaskTargetKind_data)


onenotePatchActionType_data = {
    'Replace': 0,
    'Append': 1,
    'Delete': 2,
    'Insert': 3,
    'Prepend': 4,
}
onenotePatchActionType = enum.Enum('onenotePatchActionType', onenotePatchActionType_data)


onenotePatchInsertPosition_data = {
    'After': 0,
    'Before': 1,
}
onenotePatchInsertPosition = enum.Enum('onenotePatchInsertPosition', onenotePatchInsertPosition_data)


onenoteSourceService_data = {
    'Unknown': 0,
    'OneDrive': 1,
    'OneDriveForBusiness': 2,
    'OnPremOneDriveForBusiness': 3,
}
onenoteSourceService = enum.Enum('onenoteSourceService', onenoteSourceService_data)


onenoteUserRole_data = {
    'None': -1,
    'Owner': 0,
    'Contributor': 1,
    'Reader': 2,
}
onenoteUserRole = enum.Enum('onenoteUserRole', onenoteUserRole_data)


operationStatus_data = {
    'NotStarted': 0,
    'Running': 1,
    'Completed': 2,
    'Failed': 3,
}
operationStatus = enum.Enum('operationStatus', operationStatus_data)


delegatedAdminAccessAssignmentStatus_data = {
    'pending': 0,
    'active': 1,
    'deleting': 2,
    'deleted': 3,
    'error': 4,
    'unknownFutureValue': 5,
}
delegatedAdminAccessAssignmentStatus = enum.Enum('delegatedAdminAccessAssignmentStatus', delegatedAdminAccessAssignmentStatus_data)


delegatedAdminAccessContainerType_data = {
    'securityGroup': 0,
    'unknownFutureValue': 1,
}
delegatedAdminAccessContainerType = enum.Enum('delegatedAdminAccessContainerType', delegatedAdminAccessContainerType_data)


delegatedAdminRelationshipOperationType_data = {
    'delegatedAdminAccessAssignmentUpdate': 0,
    'unknownFutureValue': 1,
    'delegatedAdminRelationshipUpdate': 2,
}
delegatedAdminRelationshipOperationType = enum.Enum('delegatedAdminRelationshipOperationType', delegatedAdminRelationshipOperationType_data)


delegatedAdminRelationshipRequestAction_data = {
    'lockForApproval': 0,
    'approve': 1,
    'terminate': 2,
    'unknownFutureValue': 3,
    'reject': 4,
}
delegatedAdminRelationshipRequestAction = enum.Enum('delegatedAdminRelationshipRequestAction', delegatedAdminRelationshipRequestAction_data)


delegatedAdminRelationshipRequestStatus_data = {
    'created': 0,
    'pending': 1,
    'succeeded': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
delegatedAdminRelationshipRequestStatus = enum.Enum('delegatedAdminRelationshipRequestStatus', delegatedAdminRelationshipRequestStatus_data)


delegatedAdminRelationshipStatus_data = {
    'activating': 0,
    'active': 1,
    'approvalPending': 2,
    'approved': 3,
    'created': 4,
    'expired': 5,
    'expiring': 6,
    'terminated': 7,
    'terminating': 8,
    'terminationRequested': 9,
    'unknownFutureValue': 10,
}
delegatedAdminRelationshipStatus = enum.Enum('delegatedAdminRelationshipStatus', delegatedAdminRelationshipStatus_data)


windowsSettingType_data = {
    'roaming': 0,
    'backup': 1,
    'unknownFutureValue': 2,
}
windowsSettingType = enum.Enum('windowsSettingType', windowsSettingType_data)


allowedAudiences_data = {
    'me': 0,
    'family': 1,
    'contacts': 2,
    'groupMembers': 4,
    'organization': 8,
    'federatedOrganizations': 16,
    'everyone': 32,
    'unknownFutureValue': 64,
}
allowedAudiences = enum.Enum('allowedAudiences', allowedAudiences_data)


languageProficiencyLevel_data = {
    'elementary': 0,
    'conversational': 1,
    'limitedWorking': 2,
    'professionalWorking': 3,
    'fullProfessional': 4,
    'nativeOrBilingual': 5,
    'unknownFutureValue': 6,
}
languageProficiencyLevel = enum.Enum('languageProficiencyLevel', languageProficiencyLevel_data)


personAnnualEventType_data = {
    'birthday': 0,
    'wedding': 1,
    'work': 2,
    'other': 3,
    'unknownFutureValue': 5,
}
personAnnualEventType = enum.Enum('personAnnualEventType', personAnnualEventType_data)


personRelationship_data = {
    'manager': 0,
    'colleague': 1,
    'directReport': 2,
    'dotLineReport': 3,
    'assistant': 4,
    'dotLineManager': 5,
    'alternateContact': 6,
    'friend': 7,
    'spouse': 8,
    'sibling': 9,
    'child': 10,
    'parent': 11,
    'sponsor': 12,
    'emergencyContact': 13,
    'other': 14,
    'unknownFutureValue': 15,
}
personRelationship = enum.Enum('personRelationship', personRelationship_data)


skillProficiencyLevel_data = {
    'elementary': 0,
    'limitedWorking': 1,
    'generalProfessional': 2,
    'advancedProfessional': 3,
    'expert': 4,
    'unknownFutureValue': 5,
}
skillProficiencyLevel = enum.Enum('skillProficiencyLevel', skillProficiencyLevel_data)


translationBehavior_data = {
    'Ask': 0,
    'Yes': 1,
    'No': 2,
}
translationBehavior = enum.Enum('translationBehavior', translationBehavior_data)


alertSeverity_data = {
    'unknown': 0,
    'informational': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'unknownFutureValue': 127,
}
alertSeverity = enum.Enum('alertSeverity', alertSeverity_data)


assignmentScheduleFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
assignmentScheduleFilterByCurrentUserOptions = enum.Enum('assignmentScheduleFilterByCurrentUserOptions', assignmentScheduleFilterByCurrentUserOptions_data)


assignmentScheduleInstanceFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
assignmentScheduleInstanceFilterByCurrentUserOptions = enum.Enum('assignmentScheduleInstanceFilterByCurrentUserOptions', assignmentScheduleInstanceFilterByCurrentUserOptions_data)


assignmentScheduleRequestFilterByCurrentUserOptions_data = {
    'principal': 1,
    'createdBy': 2,
    'approver': 3,
    'unknownFutureValue': 4,
}
assignmentScheduleRequestFilterByCurrentUserOptions = enum.Enum('assignmentScheduleRequestFilterByCurrentUserOptions', assignmentScheduleRequestFilterByCurrentUserOptions_data)


eligibilityScheduleFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
eligibilityScheduleFilterByCurrentUserOptions = enum.Enum('eligibilityScheduleFilterByCurrentUserOptions', eligibilityScheduleFilterByCurrentUserOptions_data)


eligibilityScheduleInstanceFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
eligibilityScheduleInstanceFilterByCurrentUserOptions = enum.Enum('eligibilityScheduleInstanceFilterByCurrentUserOptions', eligibilityScheduleInstanceFilterByCurrentUserOptions_data)


eligibilityScheduleRequestFilterByCurrentUserOptions_data = {
    'principal': 1,
    'createdBy': 2,
    'approver': 3,
    'unknownFutureValue': 4,
}
eligibilityScheduleRequestFilterByCurrentUserOptions = enum.Enum('eligibilityScheduleRequestFilterByCurrentUserOptions', eligibilityScheduleRequestFilterByCurrentUserOptions_data)


privilegedAccessGroupAssignmentType_data = {
    'assigned': 1,
    'activated': 2,
    'unknownFutureValue': 3,
}
privilegedAccessGroupAssignmentType = enum.Enum('privilegedAccessGroupAssignmentType', privilegedAccessGroupAssignmentType_data)


privilegedAccessGroupMemberType_data = {
    'direct': 1,
    'group': 2,
    'unknownFutureValue': 3,
}
privilegedAccessGroupMemberType = enum.Enum('privilegedAccessGroupMemberType', privilegedAccessGroupMemberType_data)


privilegedAccessGroupRelationships_data = {
    'owner': 1,
    'member': 2,
    'unknownFutureValue': 3,
}
privilegedAccessGroupRelationships = enum.Enum('privilegedAccessGroupRelationships', privilegedAccessGroupRelationships_data)


roleAssignmentScheduleFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
roleAssignmentScheduleFilterByCurrentUserOptions = enum.Enum('roleAssignmentScheduleFilterByCurrentUserOptions', roleAssignmentScheduleFilterByCurrentUserOptions_data)


roleAssignmentScheduleInstanceFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
roleAssignmentScheduleInstanceFilterByCurrentUserOptions = enum.Enum('roleAssignmentScheduleInstanceFilterByCurrentUserOptions', roleAssignmentScheduleInstanceFilterByCurrentUserOptions_data)


roleAssignmentScheduleRequestFilterByCurrentUserOptions_data = {
    'principal': 1,
    'createdBy': 2,
    'approver': 3,
    'unknownFutureValue': 4,
}
roleAssignmentScheduleRequestFilterByCurrentUserOptions = enum.Enum('roleAssignmentScheduleRequestFilterByCurrentUserOptions', roleAssignmentScheduleRequestFilterByCurrentUserOptions_data)


roleEligibilityScheduleFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
roleEligibilityScheduleFilterByCurrentUserOptions = enum.Enum('roleEligibilityScheduleFilterByCurrentUserOptions', roleEligibilityScheduleFilterByCurrentUserOptions_data)


roleEligibilityScheduleInstanceFilterByCurrentUserOptions_data = {
    'principal': 1,
    'unknownFutureValue': 2,
}
roleEligibilityScheduleInstanceFilterByCurrentUserOptions = enum.Enum('roleEligibilityScheduleInstanceFilterByCurrentUserOptions', roleEligibilityScheduleInstanceFilterByCurrentUserOptions_data)


roleEligibilityScheduleRequestFilterByCurrentUserOptions_data = {
    'principal': 1,
    'createdBy': 2,
    'approver': 3,
    'unknownFutureValue': 4,
}
roleEligibilityScheduleRequestFilterByCurrentUserOptions = enum.Enum('roleEligibilityScheduleRequestFilterByCurrentUserOptions', roleEligibilityScheduleRequestFilterByCurrentUserOptions_data)


scheduleRequestActions_data = {
    'adminAssign': 1,
    'adminUpdate': 2,
    'adminRemove': 3,
    'selfActivate': 4,
    'selfDeactivate': 5,
    'adminExtend': 6,
    'adminRenew': 7,
    'selfExtend': 8,
    'selfRenew': 9,
    'unknownFutureValue': 10,
}
scheduleRequestActions = enum.Enum('scheduleRequestActions', scheduleRequestActions_data)


approvalState_data = {
    'pending': 0,
    'approved': 1,
    'denied': 2,
    'aborted': 3,
    'canceled': 4,
}
approvalState = enum.Enum('approvalState', approvalState_data)


roleSummaryStatus_data = {
    'ok': 0,
    'bad': 1,
}
roleSummaryStatus = enum.Enum('roleSummaryStatus', roleSummaryStatus_data)


setupStatus_data = {
    'unknown': 0,
    'notRegisteredYet': 1,
    'registeredSetupNotStarted': 2,
    'registeredSetupInProgress': 3,
    'registrationAndSetupCompleted': 4,
    'registrationFailed': 5,
    'registrationTimedOut': 6,
    'disabled': 7,
}
setupStatus = enum.Enum('setupStatus', setupStatus_data)


incompatiblePrinterSettings_data = {
    'show': 0,
    'hide': 1,
    'unknownFutureValue': 2,
}
incompatiblePrinterSettings = enum.Enum('incompatiblePrinterSettings', incompatiblePrinterSettings_data)


printColorConfiguration_data = {
    'blackAndWhite': 0,
    'grayscale': 1,
    'color': 2,
    'auto': 3,
}
printColorConfiguration = enum.Enum('printColorConfiguration', printColorConfiguration_data)


printColorMode_data = {
    'blackAndWhite': 0,
    'grayscale': 1,
    'color': 2,
    'auto': 3,
    'unknownFutureValue': 4,
}
printColorMode = enum.Enum('printColorMode', printColorMode_data)


printDuplexConfiguration_data = {
    'twoSidedLongEdge': 0,
    'twoSidedShortEdge': 1,
    'oneSided': 2,
}
printDuplexConfiguration = enum.Enum('printDuplexConfiguration', printDuplexConfiguration_data)


printDuplexMode_data = {
    'flipOnLongEdge': 0,
    'flipOnShortEdge': 1,
    'oneSided': 2,
    'unknownFutureValue': 3,
}
printDuplexMode = enum.Enum('printDuplexMode', printDuplexMode_data)


printerFeedDirection_data = {
    'longEdgeFirst': 0,
    'shortEdgeFirst': 1,
}
printerFeedDirection = enum.Enum('printerFeedDirection', printerFeedDirection_data)


printerFeedOrientation_data = {
    'longEdgeFirst': 0,
    'shortEdgeFirst': 1,
}
printerFeedOrientation = enum.Enum('printerFeedOrientation', printerFeedOrientation_data)


printerProcessingState_data = {
    'unknown': 0,
    'idle': 1,
    'processing': 2,
    'stopped': 3,
    'unknownFutureValue': 4,
}
printerProcessingState = enum.Enum('printerProcessingState', printerProcessingState_data)


printerProcessingStateDetail_data = {
    'paused': 0,
    'mediaJam': 2,
    'mediaNeeded': 3,
    'mediaLow': 4,
    'mediaEmpty': 5,
    'coverOpen': 6,
    'interlockOpen': 7,
    'outputTrayMissing': 9,
    'outputAreaFull': 10,
    'markerSupplyLow': 11,
    'markerSupplyEmpty': 12,
    'inputTrayMissing': 13,
    'outputAreaAlmostFull': 14,
    'markerWasteAlmostFull': 15,
    'markerWasteFull': 16,
    'fuserOverTemp': 17,
    'fuserUnderTemp': 18,
    'other': 19,
    'none': 20,
    'movingToPaused': 21,
    'shutdown': 22,
    'connectingToDevice': 23,
    'timedOut': 24,
    'stopping': 25,
    'stoppedPartially': 26,
    'tonerLow': 27,
    'tonerEmpty': 28,
    'spoolAreaFull': 29,
    'doorOpen': 30,
    'opticalPhotoConductorNearEndOfLife': 31,
    'opticalPhotoConductorLifeOver': 32,
    'developerLow': 33,
    'developerEmpty': 34,
    'interpreterResourceUnavailable': 35,
    'unknownFutureValue': 36,
    'alertRemovalOfBinaryChangeEntry': 37,
    'banderAdded': 38,
    'banderAlmostEmpty': 39,
    'banderAlmostFull': 40,
    'banderAtLimit': 41,
    'banderClosed': 42,
    'banderConfigurationChange': 43,
    'banderCoverClosed': 44,
    'banderCoverOpen': 45,
    'banderEmpty': 46,
    'banderFull': 47,
    'banderInterlockClosed': 48,
    'banderInterlockOpen': 49,
    'banderJam': 50,
    'banderLifeAlmostOver': 51,
    'banderLifeOver': 52,
    'banderMemoryExhausted': 53,
    'banderMissing': 54,
    'banderMotorFailure': 55,
    'banderNearLimit': 56,
    'banderOffline': 57,
    'banderOpened': 58,
    'banderOverTemperature': 59,
    'banderPowerSaver': 60,
    'banderRecoverableFailure': 61,
    'banderRecoverableStorage': 62,
    'banderRemoved': 63,
    'banderResourceAdded': 64,
    'banderResourceRemoved': 65,
    'banderThermistorFailure': 66,
    'banderTimingFailure': 67,
    'banderTurnedOff': 68,
    'banderTurnedOn': 69,
    'banderUnderTemperature': 70,
    'banderUnrecoverableFailure': 71,
    'banderUnrecoverableStorageError': 72,
    'banderWarmingUp': 73,
    'binderAdded': 74,
    'binderAlmostEmpty': 75,
    'binderAlmostFull': 76,
    'binderAtLimit': 77,
    'binderClosed': 78,
    'binderConfigurationChange': 79,
    'binderCoverClosed': 80,
    'binderCoverOpen': 81,
    'binderEmpty': 82,
    'binderFull': 83,
    'binderInterlockClosed': 84,
    'binderInterlockOpen': 85,
    'binderJam': 86,
    'binderLifeAlmostOver': 87,
    'binderLifeOver': 88,
    'binderMemoryExhausted': 89,
    'binderMissing': 90,
    'binderMotorFailure': 91,
    'binderNearLimit': 92,
    'binderOffline': 93,
    'binderOpened': 94,
    'binderOverTemperature': 95,
    'binderPowerSaver': 96,
    'binderRecoverableFailure': 97,
    'binderRecoverableStorage': 98,
    'binderRemoved': 99,
    'binderResourceAdded': 100,
    'binderResourceRemoved': 101,
    'binderThermistorFailure': 102,
    'binderTimingFailure': 103,
    'binderTurnedOff': 104,
    'binderTurnedOn': 105,
    'binderUnderTemperature': 106,
    'binderUnrecoverableFailure': 107,
    'binderUnrecoverableStorageError': 108,
    'binderWarmingUp': 109,
    'cameraFailure': 110,
    'chamberCooling': 111,
    'chamberFailure': 112,
    'chamberHeating': 113,
    'chamberTemperatureHigh': 114,
    'chamberTemperatureLow': 115,
    'cleanerLifeAlmostOver': 116,
    'cleanerLifeOver': 117,
    'configurationChange': 118,
    'deactivated': 119,
    'deleted': 120,
    'dieCutterAdded': 121,
    'dieCutterAlmostEmpty': 122,
    'dieCutterAlmostFull': 123,
    'dieCutterAtLimit': 124,
    'dieCutterClosed': 125,
    'dieCutterConfigurationChange': 126,
    'dieCutterCoverClosed': 127,
    'dieCutterCoverOpen': 128,
    'dieCutterEmpty': 129,
    'dieCutterFull': 130,
    'dieCutterInterlockClosed': 131,
    'dieCutterInterlockOpen': 132,
    'dieCutterJam': 133,
    'dieCutterLifeAlmostOver': 134,
    'dieCutterLifeOver': 135,
    'dieCutterMemoryExhausted': 136,
    'dieCutterMissing': 137,
    'dieCutterMotorFailure': 138,
    'dieCutterNearLimit': 139,
    'dieCutterOffline': 140,
    'dieCutterOpened': 141,
    'dieCutterOverTemperature': 142,
    'dieCutterPowerSaver': 143,
    'dieCutterRecoverableFailure': 144,
    'dieCutterRecoverableStorage': 145,
    'dieCutterRemoved': 146,
    'dieCutterResourceAdded': 147,
    'dieCutterResourceRemoved': 148,
    'dieCutterThermistorFailure': 149,
    'dieCutterTimingFailure': 150,
    'dieCutterTurnedOff': 151,
    'dieCutterTurnedOn': 152,
    'dieCutterUnderTemperature': 153,
    'dieCutterUnrecoverableFailure': 154,
    'dieCutterUnrecoverableStorageError': 155,
    'dieCutterWarmingUp': 156,
    'extruderCooling': 157,
    'extruderFailure': 158,
    'extruderHeating': 159,
    'extruderJam': 160,
    'extruderTemperatureHigh': 161,
    'extruderTemperatureLow': 162,
    'fanFailure': 163,
    'faxModemLifeAlmostOver': 164,
    'faxModemLifeOver': 165,
    'faxModemMissing': 166,
    'faxModemTurnedOff': 167,
    'faxModemTurnedOn': 168,
    'folderAdded': 169,
    'folderAlmostEmpty': 170,
    'folderAlmostFull': 171,
    'folderAtLimit': 172,
    'folderClosed': 173,
    'folderConfigurationChange': 174,
    'folderCoverClosed': 175,
    'folderCoverOpen': 176,
    'folderEmpty': 177,
    'folderFull': 178,
    'folderInterlockClosed': 179,
    'folderInterlockOpen': 180,
    'folderJam': 181,
    'folderLifeAlmostOver': 182,
    'folderLifeOver': 183,
    'folderMemoryExhausted': 184,
    'folderMissing': 185,
    'folderMotorFailure': 186,
    'folderNearLimit': 187,
    'folderOffline': 188,
    'folderOpened': 189,
    'folderOverTemperature': 190,
    'folderPowerSaver': 191,
    'folderRecoverableFailure': 192,
    'folderRecoverableStorage': 193,
    'folderRemoved': 194,
    'folderResourceAdded': 195,
    'folderResourceRemoved': 196,
    'folderThermistorFailure': 197,
    'folderTimingFailure': 198,
    'folderTurnedOff': 199,
    'folderTurnedOn': 200,
    'folderUnderTemperature': 201,
    'folderUnrecoverableFailure': 202,
    'folderUnrecoverableStorageError': 203,
    'folderWarmingUp': 204,
    'hibernate': 205,
    'holdNewJobs': 206,
    'identifyPrinterRequested': 207,
    'imprinterAdded': 208,
    'imprinterAlmostEmpty': 209,
    'imprinterAlmostFull': 210,
    'imprinterAtLimit': 211,
    'imprinterClosed': 212,
    'imprinterConfigurationChange': 213,
    'imprinterCoverClosed': 214,
    'imprinterCoverOpen': 215,
    'imprinterEmpty': 216,
    'imprinterFull': 217,
    'imprinterInterlockClosed': 218,
    'imprinterInterlockOpen': 219,
    'imprinterJam': 220,
    'imprinterLifeAlmostOver': 221,
    'imprinterLifeOver': 222,
    'imprinterMemoryExhausted': 223,
    'imprinterMissing': 224,
    'imprinterMotorFailure': 225,
    'imprinterNearLimit': 226,
    'imprinterOffline': 227,
    'imprinterOpened': 228,
    'imprinterOverTemperature': 229,
    'imprinterPowerSaver': 230,
    'imprinterRecoverableFailure': 231,
    'imprinterRecoverableStorage': 232,
    'imprinterRemoved': 233,
    'imprinterResourceAdded': 234,
    'imprinterResourceRemoved': 235,
    'imprinterThermistorFailure': 236,
    'imprinterTimingFailure': 237,
    'imprinterTurnedOff': 238,
    'imprinterTurnedOn': 239,
    'imprinterUnderTemperature': 240,
    'imprinterUnrecoverableFailure': 241,
    'imprinterUnrecoverableStorageError': 242,
    'imprinterWarmingUp': 243,
    'inputCannotFeedSizeSelected': 244,
    'inputManualInputRequest': 245,
    'inputMediaColorChange': 246,
    'inputMediaFormPartsChange': 247,
    'inputMediaSizeChange': 248,
    'inputMediaTrayFailure': 249,
    'inputMediaTrayFeedError': 250,
    'inputMediaTrayJam': 251,
    'inputMediaTypeChange': 252,
    'inputMediaWeightChange': 253,
    'inputPickRollerFailure': 254,
    'inputPickRollerLifeOver': 255,
    'inputPickRollerLifeWarn': 256,
    'inputPickRollerMissing': 257,
    'inputTrayElevationFailure': 258,
    'inputTrayPositionFailure': 259,
    'inserterAdded': 260,
    'inserterAlmostEmpty': 261,
    'inserterAlmostFull': 262,
    'inserterAtLimit': 263,
    'inserterClosed': 264,
    'inserterConfigurationChange': 265,
    'inserterCoverClosed': 266,
    'inserterCoverOpen': 267,
    'inserterEmpty': 268,
    'inserterFull': 269,
    'inserterInterlockClosed': 270,
    'inserterInterlockOpen': 271,
    'inserterJam': 272,
    'inserterLifeAlmostOver': 273,
    'inserterLifeOver': 274,
    'inserterMemoryExhausted': 275,
    'inserterMissing': 276,
    'inserterMotorFailure': 277,
    'inserterNearLimit': 278,
    'inserterOffline': 279,
    'inserterOpened': 280,
    'inserterOverTemperature': 281,
    'inserterPowerSaver': 282,
    'inserterRecoverableFailure': 283,
    'inserterRecoverableStorage': 284,
    'inserterRemoved': 285,
    'inserterResourceAdded': 286,
    'inserterResourceRemoved': 287,
    'inserterThermistorFailure': 288,
    'inserterTimingFailure': 289,
    'inserterTurnedOff': 290,
    'inserterTurnedOn': 291,
    'inserterUnderTemperature': 292,
    'inserterUnrecoverableFailure': 293,
    'inserterUnrecoverableStorageError': 294,
    'inserterWarmingUp': 295,
    'interlockClosed': 296,
    'interpreterCartridgeAdded': 297,
    'interpreterCartridgeDeleted': 298,
    'interpreterComplexPageEncountered': 299,
    'interpreterMemoryDecrease': 300,
    'interpreterMemoryIncrease': 301,
    'interpreterResourceAdded': 302,
    'interpreterResourceDeleted': 303,
    'lampAtEol': 304,
    'lampFailure': 305,
    'lampNearEol': 306,
    'laserAtEol': 307,
    'laserFailure': 308,
    'laserNearEol': 309,
    'makeEnvelopeAdded': 310,
    'makeEnvelopeAlmostEmpty': 311,
    'makeEnvelopeAlmostFull': 312,
    'makeEnvelopeAtLimit': 313,
    'makeEnvelopeClosed': 314,
    'makeEnvelopeConfigurationChange': 315,
    'makeEnvelopeCoverClosed': 316,
    'makeEnvelopeCoverOpen': 317,
    'makeEnvelopeEmpty': 318,
    'makeEnvelopeFull': 319,
    'makeEnvelopeInterlockClosed': 320,
    'makeEnvelopeInterlockOpen': 321,
    'makeEnvelopeJam': 322,
    'makeEnvelopeLifeAlmostOver': 323,
    'makeEnvelopeLifeOver': 324,
    'makeEnvelopeMemoryExhausted': 325,
    'makeEnvelopeMissing': 326,
    'makeEnvelopeMotorFailure': 327,
    'makeEnvelopeNearLimit': 328,
    'makeEnvelopeOffline': 329,
    'makeEnvelopeOpened': 330,
    'makeEnvelopeOverTemperature': 331,
    'makeEnvelopePowerSaver': 332,
    'makeEnvelopeRecoverableFailure': 333,
    'makeEnvelopeRecoverableStorage': 334,
    'makeEnvelopeRemoved': 335,
    'makeEnvelopeResourceAdded': 336,
    'makeEnvelopeResourceRemoved': 337,
    'makeEnvelopeThermistorFailure': 338,
    'makeEnvelopeTimingFailure': 339,
    'makeEnvelopeTurnedOff': 340,
    'makeEnvelopeTurnedOn': 341,
    'makeEnvelopeUnderTemperature': 342,
    'makeEnvelopeUnrecoverableFailure': 343,
    'makeEnvelopeUnrecoverableStorageError': 344,
    'makeEnvelopeWarmingUp': 345,
    'markerAdjustingPrintQuality': 346,
    'markerCleanerMissing': 347,
    'markerDeveloperAlmostEmpty': 348,
    'markerDeveloperEmpty': 349,
    'markerDeveloperMissing': 350,
    'markerFuserMissing': 351,
    'markerFuserThermistorFailure': 352,
    'markerFuserTimingFailure': 353,
    'markerInkAlmostEmpty': 354,
    'markerInkEmpty': 355,
    'markerInkMissing': 356,
    'markerOpcMissing': 357,
    'markerPrintRibbonAlmostEmpty': 358,
    'markerPrintRibbonEmpty': 359,
    'markerPrintRibbonMissing': 360,
    'markerSupplyAlmostEmpty': 361,
    'markerSupplyMissing': 362,
    'markerTonerCartridgeMissing': 363,
    'markerTonerMissing': 364,
    'markerWasteInkReceptacleAlmostFull': 365,
    'markerWasteInkReceptacleFull': 366,
    'markerWasteInkReceptacleMissing': 367,
    'markerWasteMissing': 368,
    'markerWasteTonerReceptacleAlmostFull': 369,
    'markerWasteTonerReceptacleFull': 370,
    'markerWasteTonerReceptacleMissing': 371,
    'materialEmpty': 372,
    'materialLow': 373,
    'materialNeeded': 374,
    'mediaDrying': 375,
    'mediaPathCannotDuplexMediaSelected': 376,
    'mediaPathFailure': 377,
    'mediaPathInputEmpty': 378,
    'mediaPathInputFeedError': 379,
    'mediaPathInputJam': 380,
    'mediaPathInputRequest': 381,
    'mediaPathJam': 382,
    'mediaPathMediaTrayAlmostFull': 383,
    'mediaPathMediaTrayFull': 384,
    'mediaPathMediaTrayMissing': 385,
    'mediaPathOutputFeedError': 386,
    'mediaPathOutputFull': 387,
    'mediaPathOutputJam': 388,
    'mediaPathPickRollerFailure': 389,
    'mediaPathPickRollerLifeOver': 390,
    'mediaPathPickRollerLifeWarn': 391,
    'mediaPathPickRollerMissing': 392,
    'motorFailure': 393,
    'outputMailboxSelectFailure': 394,
    'outputMediaTrayFailure': 395,
    'outputMediaTrayFeedError': 396,
    'outputMediaTrayJam': 397,
    'perforaterAdded': 398,
    'perforaterAlmostEmpty': 399,
    'perforaterAlmostFull': 400,
    'perforaterAtLimit': 401,
    'perforaterClosed': 402,
    'perforaterConfigurationChange': 403,
    'perforaterCoverClosed': 404,
    'perforaterCoverOpen': 405,
    'perforaterEmpty': 406,
    'perforaterFull': 407,
    'perforaterInterlockClosed': 408,
    'perforaterInterlockOpen': 409,
    'perforaterJam': 410,
    'perforaterLifeAlmostOver': 411,
    'perforaterLifeOver': 412,
    'perforaterMemoryExhausted': 413,
    'perforaterMissing': 414,
    'perforaterMotorFailure': 415,
    'perforaterNearLimit': 416,
    'perforaterOffline': 417,
    'perforaterOpened': 418,
    'perforaterOverTemperature': 419,
    'perforaterPowerSaver': 420,
    'perforaterRecoverableFailure': 421,
    'perforaterRecoverableStorage': 422,
    'perforaterRemoved': 423,
    'perforaterResourceAdded': 424,
    'perforaterResourceRemoved': 425,
    'perforaterThermistorFailure': 426,
    'perforaterTimingFailure': 427,
    'perforaterTurnedOff': 428,
    'perforaterTurnedOn': 429,
    'perforaterUnderTemperature': 430,
    'perforaterUnrecoverableFailure': 431,
    'perforaterUnrecoverableStorageError': 432,
    'perforaterWarmingUp': 433,
    'platformCooling': 434,
    'platformFailure': 435,
    'platformHeating': 436,
    'platformTemperatureHigh': 437,
    'platformTemperatureLow': 438,
    'powerDown': 439,
    'powerUp': 440,
    'printerManualReset': 441,
    'printerNmsReset': 442,
    'printerReadyToPrint': 443,
    'puncherAdded': 444,
    'puncherAlmostEmpty': 445,
    'puncherAlmostFull': 446,
    'puncherAtLimit': 447,
    'puncherClosed': 448,
    'puncherConfigurationChange': 449,
    'puncherCoverClosed': 450,
    'puncherCoverOpen': 451,
    'puncherEmpty': 452,
    'puncherFull': 453,
    'puncherInterlockClosed': 454,
    'puncherInterlockOpen': 455,
    'puncherJam': 456,
    'puncherLifeAlmostOver': 457,
    'puncherLifeOver': 458,
    'puncherMemoryExhausted': 459,
    'puncherMissing': 460,
    'puncherMotorFailure': 461,
    'puncherNearLimit': 462,
    'puncherOffline': 463,
    'puncherOpened': 464,
    'puncherOverTemperature': 465,
    'puncherPowerSaver': 466,
    'puncherRecoverableFailure': 467,
    'puncherRecoverableStorage': 468,
    'puncherRemoved': 469,
    'puncherResourceAdded': 470,
    'puncherResourceRemoved': 471,
    'puncherThermistorFailure': 472,
    'puncherTimingFailure': 473,
    'puncherTurnedOff': 474,
    'puncherTurnedOn': 475,
    'puncherUnderTemperature': 476,
    'puncherUnrecoverableFailure': 477,
    'puncherUnrecoverableStorageError': 478,
    'puncherWarmingUp': 479,
    'resuming': 480,
    'scanMediaPathFailure': 481,
    'scanMediaPathInputEmpty': 482,
    'scanMediaPathInputFeedError': 483,
    'scanMediaPathInputJam': 484,
    'scanMediaPathInputRequest': 485,
    'scanMediaPathJam': 486,
    'scanMediaPathOutputFeedError': 487,
    'scanMediaPathOutputFull': 488,
    'scanMediaPathOutputJam': 489,
    'scanMediaPathPickRollerFailure': 490,
    'scanMediaPathPickRollerLifeOver': 491,
    'scanMediaPathPickRollerLifeWarn': 492,
    'scanMediaPathPickRollerMissing': 493,
    'scanMediaPathTrayAlmostFull': 494,
    'scanMediaPathTrayFull': 495,
    'scanMediaPathTrayMissing': 496,
    'scannerLightFailure': 497,
    'scannerLightLifeAlmostOver': 498,
    'scannerLightLifeOver': 499,
    'scannerLightMissing': 500,
    'scannerSensorFailure': 501,
    'scannerSensorLifeAlmostOver': 502,
    'scannerSensorLifeOver': 503,
    'scannerSensorMissing': 504,
    'separationCutterAdded': 505,
    'separationCutterAlmostEmpty': 506,
    'separationCutterAlmostFull': 507,
    'separationCutterAtLimit': 508,
    'separationCutterClosed': 509,
    'separationCutterConfigurationChange': 510,
    'separationCutterCoverClosed': 511,
    'separationCutterCoverOpen': 512,
    'separationCutterEmpty': 513,
    'separationCutterFull': 514,
    'separationCutterInterlockClosed': 515,
    'separationCutterInterlockOpen': 516,
    'separationCutterJam': 517,
    'separationCutterLifeAlmostOver': 518,
    'separationCutterLifeOver': 519,
    'separationCutterMemoryExhausted': 520,
    'separationCutterMissing': 521,
    'separationCutterMotorFailure': 522,
    'separationCutterNearLimit': 523,
    'separationCutterOffline': 524,
    'separationCutterOpened': 525,
    'separationCutterOverTemperature': 526,
    'separationCutterPowerSaver': 527,
    'separationCutterRecoverableFailure': 528,
    'separationCutterRecoverableStorage': 529,
    'separationCutterRemoved': 530,
    'separationCutterResourceAdded': 531,
    'separationCutterResourceRemoved': 532,
    'separationCutterThermistorFailure': 533,
    'separationCutterTimingFailure': 534,
    'separationCutterTurnedOff': 535,
    'separationCutterTurnedOn': 536,
    'separationCutterUnderTemperature': 537,
    'separationCutterUnrecoverableFailure': 538,
    'separationCutterUnrecoverableStorageError': 539,
    'separationCutterWarmingUp': 540,
    'sheetRotatorAdded': 541,
    'sheetRotatorAlmostEmpty': 542,
    'sheetRotatorAlmostFull': 543,
    'sheetRotatorAtLimit': 544,
    'sheetRotatorClosed': 545,
    'sheetRotatorConfigurationChange': 546,
    'sheetRotatorCoverClosed': 547,
    'sheetRotatorCoverOpen': 548,
    'sheetRotatorEmpty': 549,
    'sheetRotatorFull': 550,
    'sheetRotatorInterlockClosed': 551,
    'sheetRotatorInterlockOpen': 552,
    'sheetRotatorJam': 553,
    'sheetRotatorLifeAlmostOver': 554,
    'sheetRotatorLifeOver': 555,
    'sheetRotatorMemoryExhausted': 556,
    'sheetRotatorMissing': 557,
    'sheetRotatorMotorFailure': 558,
    'sheetRotatorNearLimit': 559,
    'sheetRotatorOffline': 560,
    'sheetRotatorOpened': 561,
    'sheetRotatorOverTemperature': 562,
    'sheetRotatorPowerSaver': 563,
    'sheetRotatorRecoverableFailure': 564,
    'sheetRotatorRecoverableStorage': 565,
    'sheetRotatorRemoved': 566,
    'sheetRotatorResourceAdded': 567,
    'sheetRotatorResourceRemoved': 568,
    'sheetRotatorThermistorFailure': 569,
    'sheetRotatorTimingFailure': 570,
    'sheetRotatorTurnedOff': 571,
    'sheetRotatorTurnedOn': 572,
    'sheetRotatorUnderTemperature': 573,
    'sheetRotatorUnrecoverableFailure': 574,
    'sheetRotatorUnrecoverableStorageError': 575,
    'sheetRotatorWarmingUp': 576,
    'slitterAdded': 577,
    'slitterAlmostEmpty': 578,
    'slitterAlmostFull': 579,
    'slitterAtLimit': 580,
    'slitterClosed': 581,
    'slitterConfigurationChange': 582,
    'slitterCoverClosed': 583,
    'slitterCoverOpen': 584,
    'slitterEmpty': 585,
    'slitterFull': 586,
    'slitterInterlockClosed': 587,
    'slitterInterlockOpen': 588,
    'slitterJam': 589,
    'slitterLifeAlmostOver': 590,
    'slitterLifeOver': 591,
    'slitterMemoryExhausted': 592,
    'slitterMissing': 593,
    'slitterMotorFailure': 594,
    'slitterNearLimit': 595,
    'slitterOffline': 596,
    'slitterOpened': 597,
    'slitterOverTemperature': 598,
    'slitterPowerSaver': 599,
    'slitterRecoverableFailure': 600,
    'slitterRecoverableStorage': 601,
    'slitterRemoved': 602,
    'slitterResourceAdded': 603,
    'slitterResourceRemoved': 604,
    'slitterThermistorFailure': 605,
    'slitterTimingFailure': 606,
    'slitterTurnedOff': 607,
    'slitterTurnedOn': 608,
    'slitterUnderTemperature': 609,
    'slitterUnrecoverableFailure': 610,
    'slitterUnrecoverableStorageError': 611,
    'slitterWarmingUp': 612,
    'stackerAdded': 613,
    'stackerAlmostEmpty': 614,
    'stackerAlmostFull': 615,
    'stackerAtLimit': 616,
    'stackerClosed': 617,
    'stackerConfigurationChange': 618,
    'stackerCoverClosed': 619,
    'stackerCoverOpen': 620,
    'stackerEmpty': 621,
    'stackerFull': 622,
    'stackerInterlockClosed': 623,
    'stackerInterlockOpen': 624,
    'stackerJam': 625,
    'stackerLifeAlmostOver': 626,
    'stackerLifeOver': 627,
    'stackerMemoryExhausted': 628,
    'stackerMissing': 629,
    'stackerMotorFailure': 630,
    'stackerNearLimit': 631,
    'stackerOffline': 632,
    'stackerOpened': 633,
    'stackerOverTemperature': 634,
    'stackerPowerSaver': 635,
    'stackerRecoverableFailure': 636,
    'stackerRecoverableStorage': 637,
    'stackerRemoved': 638,
    'stackerResourceAdded': 639,
    'stackerResourceRemoved': 640,
    'stackerThermistorFailure': 641,
    'stackerTimingFailure': 642,
    'stackerTurnedOff': 643,
    'stackerTurnedOn': 644,
    'stackerUnderTemperature': 645,
    'stackerUnrecoverableFailure': 646,
    'stackerUnrecoverableStorageError': 647,
    'stackerWarmingUp': 648,
    'standby': 649,
    'staplerAdded': 650,
    'staplerAlmostEmpty': 651,
    'staplerAlmostFull': 652,
    'staplerAtLimit': 653,
    'staplerClosed': 654,
    'staplerConfigurationChange': 655,
    'staplerCoverClosed': 656,
    'staplerCoverOpen': 657,
    'staplerEmpty': 658,
    'staplerFull': 659,
    'staplerInterlockClosed': 660,
    'staplerInterlockOpen': 661,
    'staplerJam': 662,
    'staplerLifeAlmostOver': 663,
    'staplerLifeOver': 664,
    'staplerMemoryExhausted': 665,
    'staplerMissing': 666,
    'staplerMotorFailure': 667,
    'staplerNearLimit': 668,
    'staplerOffline': 669,
    'staplerOpened': 670,
    'staplerOverTemperature': 671,
    'staplerPowerSaver': 672,
    'staplerRecoverableFailure': 673,
    'staplerRecoverableStorage': 674,
    'staplerRemoved': 675,
    'staplerResourceAdded': 676,
    'staplerResourceRemoved': 677,
    'staplerThermistorFailure': 678,
    'staplerTimingFailure': 679,
    'staplerTurnedOff': 680,
    'staplerTurnedOn': 681,
    'staplerUnderTemperature': 682,
    'staplerUnrecoverableFailure': 683,
    'staplerUnrecoverableStorageError': 684,
    'staplerWarmingUp': 685,
    'stitcherAdded': 686,
    'stitcherAlmostEmpty': 687,
    'stitcherAlmostFull': 688,
    'stitcherAtLimit': 689,
    'stitcherClosed': 690,
    'stitcherConfigurationChange': 691,
    'stitcherCoverClosed': 692,
    'stitcherCoverOpen': 693,
    'stitcherEmpty': 694,
    'stitcherFull': 695,
    'stitcherInterlockClosed': 696,
    'stitcherInterlockOpen': 697,
    'stitcherJam': 698,
    'stitcherLifeAlmostOver': 699,
    'stitcherLifeOver': 700,
    'stitcherMemoryExhausted': 701,
    'stitcherMissing': 702,
    'stitcherMotorFailure': 703,
    'stitcherNearLimit': 704,
    'stitcherOffline': 705,
    'stitcherOpened': 706,
    'stitcherOverTemperature': 707,
    'stitcherPowerSaver': 708,
    'stitcherRecoverableFailure': 709,
    'stitcherRecoverableStorage': 710,
    'stitcherRemoved': 711,
    'stitcherResourceAdded': 712,
    'stitcherResourceRemoved': 713,
    'stitcherThermistorFailure': 714,
    'stitcherTimingFailure': 715,
    'stitcherTurnedOff': 716,
    'stitcherTurnedOn': 717,
    'stitcherUnderTemperature': 718,
    'stitcherUnrecoverableFailure': 719,
    'stitcherUnrecoverableStorageError': 720,
    'stitcherWarmingUp': 721,
    'subunitAdded': 722,
    'subunitAlmostEmpty': 723,
    'subunitAlmostFull': 724,
    'subunitAtLimit': 725,
    'subunitClosed': 726,
    'subunitCoolingDown': 727,
    'subunitEmpty': 728,
    'subunitFull': 729,
    'subunitLifeAlmostOver': 730,
    'subunitLifeOver': 731,
    'subunitMemoryExhausted': 732,
    'subunitMissing': 733,
    'subunitMotorFailure': 734,
    'subunitNearLimit': 735,
    'subunitOffline': 736,
    'subunitOpened': 737,
    'subunitOverTemperature': 738,
    'subunitPowerSaver': 739,
    'subunitRecoverableFailure': 740,
    'subunitRecoverableStorage': 741,
    'subunitRemoved': 742,
    'subunitResourceAdded': 743,
    'subunitResourceRemoved': 744,
    'subunitThermistorFailure': 745,
    'subunitTimingFailure': 746,
    'subunitTurnedOff': 747,
    'subunitTurnedOn': 748,
    'subunitUnderTemperature': 749,
    'subunitUnrecoverableFailure': 750,
    'subunitUnrecoverableStorage': 751,
    'subunitWarmingUp': 752,
    'suspend': 753,
    'testing': 754,
    'trimmerAdded': 755,
    'trimmerAlmostEmpty': 756,
    'trimmerAlmostFull': 757,
    'trimmerAtLimit': 758,
    'trimmerClosed': 759,
    'trimmerConfigurationChange': 760,
    'trimmerCoverClosed': 761,
    'trimmerCoverOpen': 762,
    'trimmerEmpty': 763,
    'trimmerFull': 764,
    'trimmerInterlockClosed': 765,
    'trimmerInterlockOpen': 766,
    'trimmerJam': 767,
    'trimmerLifeAlmostOver': 768,
    'trimmerLifeOver': 769,
    'trimmerMemoryExhausted': 770,
    'trimmerMissing': 771,
    'trimmerMotorFailure': 772,
    'trimmerNearLimit': 773,
    'trimmerOffline': 774,
    'trimmerOpened': 775,
    'trimmerOverTemperature': 776,
    'trimmerPowerSaver': 777,
    'trimmerRecoverableFailure': 778,
    'trimmerRecoverableStorage': 779,
    'trimmerRemoved': 780,
    'trimmerResourceAdded': 781,
    'trimmerResourceRemoved': 782,
    'trimmerThermistorFailure': 783,
    'trimmerTimingFailure': 784,
    'trimmerTurnedOff': 785,
    'trimmerTurnedOn': 786,
    'trimmerUnderTemperature': 787,
    'trimmerUnrecoverableFailure': 788,
    'trimmerUnrecoverableStorageError': 789,
    'trimmerWarmingUp': 790,
    'unknown': 791,
    'wrapperAdded': 792,
    'wrapperAlmostEmpty': 793,
    'wrapperAlmostFull': 794,
    'wrapperAtLimit': 795,
    'wrapperClosed': 796,
    'wrapperConfigurationChange': 797,
    'wrapperCoverClosed': 798,
    'wrapperCoverOpen': 799,
    'wrapperEmpty': 800,
    'wrapperFull': 801,
    'wrapperInterlockClosed': 802,
    'wrapperInterlockOpen': 803,
    'wrapperJam': 804,
    'wrapperLifeAlmostOver': 805,
    'wrapperLifeOver': 806,
    'wrapperMemoryExhausted': 807,
    'wrapperMissing': 808,
    'wrapperMotorFailure': 809,
    'wrapperNearLimit': 810,
    'wrapperOffline': 811,
    'wrapperOpened': 812,
    'wrapperOverTemperature': 813,
    'wrapperPowerSaver': 814,
    'wrapperRecoverableFailure': 815,
    'wrapperRecoverableStorage': 816,
    'wrapperRemoved': 817,
    'wrapperResourceAdded': 818,
    'wrapperResourceRemoved': 819,
    'wrapperThermistorFailure': 820,
    'wrapperTimingFailure': 821,
    'wrapperTurnedOff': 822,
    'wrapperTurnedOn': 823,
    'wrapperUnderTemperature': 824,
    'wrapperUnrecoverableFailure': 825,
    'wrapperUnrecoverableStorageError': 826,
    'wrapperWarmingUp': 827,
}
printerProcessingStateDetail = enum.Enum('printerProcessingStateDetail', printerProcessingStateDetail_data)


printerProcessingStateReason_data = {
    'paused': 0,
    'mediaJam': 2,
    'mediaNeeded': 3,
    'mediaLow': 4,
    'mediaEmpty': 5,
    'coverOpen': 6,
    'interlockOpen': 7,
    'outputTrayMissing': 9,
    'outputAreaFull': 10,
    'markerSupplyLow': 11,
    'markerSupplyEmpty': 12,
    'inputTrayMissing': 13,
    'outputAreaAlmostFull': 14,
    'markerWasteAlmostFull': 15,
    'markerWasteFull': 16,
    'fuserOverTemp': 17,
    'fuserUnderTemp': 18,
    'other': 19,
    'none': 20,
    'movingToPaused': 21,
    'shutdown': 22,
    'connectingToDevice': 23,
    'timedOut': 24,
    'stopping': 25,
    'stoppedPartially': 26,
    'tonerLow': 27,
    'tonerEmpty': 28,
    'spoolAreaFull': 29,
    'doorOpen': 30,
    'opticalPhotoConductorNearEndOfLife': 31,
    'opticalPhotoConductorLifeOver': 32,
    'developerLow': 33,
    'developerEmpty': 34,
    'interpreterResourceUnavailable': 35,
    'unknownFutureValue': 36,
}
printerProcessingStateReason = enum.Enum('printerProcessingStateReason', printerProcessingStateReason_data)


printEvent_data = {
    'jobStarted': 0,
    'unknownFutureValue': 1,
}
printEvent = enum.Enum('printEvent', printEvent_data)


printFinishing_data = {
    'none': 3,
    'staple': 4,
    'punch': 5,
    'cover': 6,
    'bind': 7,
    'saddleStitch': 8,
    'stitchEdge': 9,
    'stapleTopLeft': 20,
    'stapleBottomLeft': 21,
    'stapleTopRight': 22,
    'stapleBottomRight': 23,
    'stitchLeftEdge': 24,
    'stitchTopEdge': 25,
    'stitchRightEdge': 26,
    'stitchBottomEdge': 27,
    'stapleDualLeft': 28,
    'stapleDualTop': 29,
    'stapleDualRight': 30,
    'stapleDualBottom': 31,
    'unknownFutureValue': 32,
    'stapleTripleLeft': 33,
    'stapleTripleTop': 34,
    'stapleTripleRight': 35,
    'stapleTripleBottom': 36,
    'bindLeft': 37,
    'bindTop': 38,
    'bindRight': 39,
    'bindBottom': 40,
    'foldAccordion': 41,
    'foldDoubleGate': 42,
    'foldGate': 43,
    'foldHalf': 44,
    'foldHalfZ': 45,
    'foldLeftGate': 46,
    'foldLetter': 47,
    'foldParallel': 48,
    'foldPoster': 49,
    'foldRightGate': 50,
    'foldZ': 51,
    'foldEngineeringZ': 52,
    'punchTopLeft': 53,
    'punchBottomLeft': 54,
    'punchTopRight': 55,
    'punchBottomRight': 56,
    'punchDualLeft': 57,
    'punchDualTop': 58,
    'punchDualRight': 59,
    'punchDualBottom': 60,
    'punchTripleLeft': 61,
    'punchTripleTop': 62,
    'punchTripleRight': 63,
    'punchTripleBottom': 64,
    'punchQuadLeft': 65,
    'punchQuadTop': 66,
    'punchQuadRight': 67,
    'punchQuadBottom': 68,
    'fold': 69,
    'trim': 70,
    'bale': 71,
    'bookletMaker': 72,
    'coat': 73,
    'laminate': 74,
    'trimAfterPages': 75,
    'trimAfterDocuments': 76,
    'trimAfterCopies': 77,
    'trimAfterJob': 78,
}
printFinishing = enum.Enum('printFinishing', printFinishing_data)


printJobProcessingState_data = {
    'unknown': 0,
    'pending': 1,
    'processing': 2,
    'paused': 3,
    'stopped': 4,
    'completed': 5,
    'canceled': 6,
    'aborted': 7,
    'unknownFutureValue': 8,
}
printJobProcessingState = enum.Enum('printJobProcessingState', printJobProcessingState_data)


printJobStateDetail_data = {
    'uploadPending': 0,
    'transforming': 1,
    'completedSuccessfully': 2,
    'completedWithWarnings': 3,
    'completedWithErrors': 4,
    'releaseWait': 5,
    'interpreting': 6,
    'unknownFutureValue': 7,
}
printJobStateDetail = enum.Enum('printJobStateDetail', printJobStateDetail_data)


printMediaType_data = {
    'stationery': 0,
    'transparency': 1,
    'envelope': 2,
    'envelopePlain': 3,
    'continuous': 4,
    'screen': 5,
    'screenPaged': 6,
    'continuousLong': 7,
    'continuousShort': 8,
    'envelopeWindow': 9,
    'multiPartForm': 10,
    'multiLayer': 11,
    'labels': 12,
}
printMediaType = enum.Enum('printMediaType', printMediaType_data)


printMultipageLayout_data = {
    'clockwiseFromTopLeft': 0,
    'counterclockwiseFromTopLeft': 1,
    'counterclockwiseFromTopRight': 2,
    'clockwiseFromTopRight': 3,
    'counterclockwiseFromBottomLeft': 4,
    'clockwiseFromBottomLeft': 5,
    'counterclockwiseFromBottomRight': 6,
    'clockwiseFromBottomRight': 7,
    'unknownFutureValue': 8,
}
printMultipageLayout = enum.Enum('printMultipageLayout', printMultipageLayout_data)


printOperationProcessingState_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
printOperationProcessingState = enum.Enum('printOperationProcessingState', printOperationProcessingState_data)


printOrientation_data = {
    'portrait': 3,
    'landscape': 4,
    'reverseLandscape': 5,
    'reversePortrait': 6,
    'unknownFutureValue': 7,
}
printOrientation = enum.Enum('printOrientation', printOrientation_data)


printPresentationDirection_data = {
    'clockwiseFromTopLeft': 0,
    'counterClockwiseFromTopLeft': 1,
    'counterClockwiseFromTopRight': 2,
    'clockwiseFromTopRight': 3,
    'counterClockwiseFromBottomLeft': 4,
    'clockwiseFromBottomLeft': 5,
    'counterClockwiseFromBottomRight': 6,
    'clockwiseFromBottomRight': 7,
}
printPresentationDirection = enum.Enum('printPresentationDirection', printPresentationDirection_data)


printQuality_data = {
    'low': 0,
    'medium': 1,
    'high': 2,
    'unknownFutureValue': 3,
}
printQuality = enum.Enum('printQuality', printQuality_data)


printScaling_data = {
    'auto': 0,
    'shrinkToFit': 1,
    'fill': 2,
    'fit': 3,
    'none': 4,
    'unknownFutureValue': 5,
}
printScaling = enum.Enum('printScaling', printScaling_data)


printTaskProcessingState_data = {
    'pending': 0,
    'processing': 1,
    'completed': 2,
    'aborted': 3,
    'unknownFutureValue': 4,
}
printTaskProcessingState = enum.Enum('printTaskProcessingState', printTaskProcessingState_data)


status_data = {
    'active': 0,
    'updated': 1,
    'deleted': 2,
    'ignored': 3,
    'unknownFutureValue': 4,
}
status = enum.Enum('status', status_data)


dataPolicyOperationStatus_data = {
    'notStarted': 0,
    'running': 1,
    'complete': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
dataPolicyOperationStatus = enum.Enum('dataPolicyOperationStatus', dataPolicyOperationStatus_data)


accountTargetContentType_data = {
    'unknown': 0,
    'includeAll': 1,
    'addressBook': 2,
    'unknownFutureValue': 3,
}
accountTargetContentType = enum.Enum('accountTargetContentType', accountTargetContentType_data)


attackSimulationOperationType_data = {
    'createSimualation': 0,
    'updateSimulation': 1,
    'unknownFutureValue': 2,
}
attackSimulationOperationType = enum.Enum('attackSimulationOperationType', attackSimulationOperationType_data)


campaignStatus_data = {
    'unknown': 0,
    'draft': 1,
    'inProgress': 2,
    'scheduled': 3,
    'completed': 4,
    'failed': 5,
    'cancelled': 6,
    'excluded': 7,
    'deleted': 8,
    'unknownFutureValue': 9,
}
campaignStatus = enum.Enum('campaignStatus', campaignStatus_data)


clickSource_data = {
    'unknown': 0,
    'qrCode': 1,
    'phishingUrl': 2,
    'unknownFutureValue': 3,
}
clickSource = enum.Enum('clickSource', clickSource_data)


coachmarkLocationType_data = {
    'unknown': 0,
    'fromEmail': 1,
    'subject': 2,
    'externalTag': 3,
    'displayName': 4,
    'messageBody': 5,
    'unknownFutureValue': 6,
}
coachmarkLocationType = enum.Enum('coachmarkLocationType', coachmarkLocationType_data)


endUserNotificationPreference_data = {
    'unknown': 0,
    'microsoft': 1,
    'custom': 2,
    'unknownFutureValue': 3,
}
endUserNotificationPreference = enum.Enum('endUserNotificationPreference', endUserNotificationPreference_data)


endUserNotificationSettingType_data = {
    'unknown': 0,
    'noTraining': 1,
    'trainingSelected': 2,
    'noNotification': 3,
    'unknownFutureValue': 4,
}
endUserNotificationSettingType = enum.Enum('endUserNotificationSettingType', endUserNotificationSettingType_data)


endUserNotificationType_data = {
    'unknown': 0,
    'positiveReinforcement': 1,
    'noTraining': 2,
    'trainingAssignment': 3,
    'trainingReminder': 4,
    'unknownFutureValue': 5,
}
endUserNotificationType = enum.Enum('endUserNotificationType', endUserNotificationType_data)


notificationDeliveryFrequency_data = {
    'unknown': 0,
    'weekly': 1,
    'biWeekly': 2,
    'unknownFutureValue': 3,
}
notificationDeliveryFrequency = enum.Enum('notificationDeliveryFrequency', notificationDeliveryFrequency_data)


notificationDeliveryPreference_data = {
    'unknown': 0,
    'deliverImmedietly': 1,
    'deliverAfterCampaignEnd': 2,
    'unknownFutureValue': 3,
}
notificationDeliveryPreference = enum.Enum('notificationDeliveryPreference', notificationDeliveryPreference_data)


oAuthAppScope_data = {
    'unknown': 0,
    'readCalendar': 1,
    'readContact': 2,
    'readMail': 3,
    'readAllChat': 4,
    'readAllFile': 5,
    'readAndWriteMail': 6,
    'sendMail': 7,
    'unknownFutureValue': 8,
}
oAuthAppScope = enum.Enum('oAuthAppScope', oAuthAppScope_data)


payloadBrand_data = {
    'unknown': 0,
    'other': 1,
    'americanExpress': 2,
    'capitalOne': 3,
    'dhl': 4,
    'docuSign': 5,
    'dropbox': 6,
    'facebook': 7,
    'firstAmerican': 8,
    'microsoft': 9,
    'netflix': 10,
    'scotiabank': 11,
    'sendGrid': 12,
    'stewartTitle': 13,
    'tesco': 14,
    'wellsFargo': 15,
    'syrinxCloud': 16,
    'adobe': 17,
    'teams': 18,
    'zoom': 19,
    'unknownFutureValue': 20,
}
payloadBrand = enum.Enum('payloadBrand', payloadBrand_data)


payloadComplexity_data = {
    'unknown': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'unknownFutureValue': 4,
}
payloadComplexity = enum.Enum('payloadComplexity', payloadComplexity_data)


payloadDeliveryPlatform_data = {
    'unknown': 0,
    'sms': 1,
    'email': 2,
    'teams': 3,
    'unknownFutureValue': 4,
}
payloadDeliveryPlatform = enum.Enum('payloadDeliveryPlatform', payloadDeliveryPlatform_data)


payloadIndustry_data = {
    'unknown': 0,
    'other': 1,
    'banking': 2,
    'businessServices': 3,
    'consumerServices': 4,
    'education': 5,
    'energy': 6,
    'construction': 7,
    'consulting': 8,
    'financialServices': 9,
    'government': 10,
    'hospitality': 11,
    'insurance': 12,
    'legal': 13,
    'courierServices': 14,
    'IT': 15,
    'healthcare': 16,
    'manufacturing': 17,
    'retail': 18,
    'telecom': 19,
    'realEstate': 20,
    'unknownFutureValue': 21,
}
payloadIndustry = enum.Enum('payloadIndustry', payloadIndustry_data)


payloadTheme_data = {
    'unknown': 0,
    'other': 1,
    'accountActivation': 2,
    'accountVerification': 3,
    'billing': 4,
    'cleanUpMail': 5,
    'controversial': 6,
    'documentReceived': 7,
    'expense': 8,
    'fax': 9,
    'financeReport': 10,
    'incomingMessages': 11,
    'invoice': 12,
    'itemReceived': 13,
    'loginAlert': 14,
    'mailReceived': 15,
    'password': 16,
    'payment': 17,
    'payroll': 18,
    'personalizedOffer': 19,
    'quarantine': 20,
    'remoteWork': 21,
    'reviewMessage': 22,
    'securityUpdate': 23,
    'serviceSuspended': 24,
    'signatureRequired': 25,
    'upgradeMailboxStorage': 26,
    'verifyMailbox': 27,
    'voicemail': 28,
    'advertisement': 29,
    'employeeEngagement': 30,
    'unknownFutureValue': 31,
}
payloadTheme = enum.Enum('payloadTheme', payloadTheme_data)


simulationAttackTechnique_data = {
    'unknown': 0,
    'credentialHarvesting': 1,
    'attachmentMalware': 2,
    'driveByUrl': 3,
    'linkInAttachment': 4,
    'linkToMalwareFile': 5,
    'unknownFutureValue': 6,
    'oAuthConsentGrant': 7,
    'phishTraining': 8,
}
simulationAttackTechnique = enum.Enum('simulationAttackTechnique', simulationAttackTechnique_data)


simulationAttackType_data = {
    'unknown': 0,
    'social': 1,
    'cloud': 2,
    'endpoint': 3,
    'unknownFutureValue': 4,
}
simulationAttackType = enum.Enum('simulationAttackType', simulationAttackType_data)


simulationAutomationRunStatus_data = {
    'unknown': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'skipped': 4,
    'unknownFutureValue': 5,
}
simulationAutomationRunStatus = enum.Enum('simulationAutomationRunStatus', simulationAutomationRunStatus_data)


simulationAutomationStatus_data = {
    'unknown': 0,
    'draft': 1,
    'notRunning': 2,
    'running': 3,
    'completed': 4,
    'unknownFutureValue': 5,
}
simulationAutomationStatus = enum.Enum('simulationAutomationStatus', simulationAutomationStatus_data)


simulationContentSource_data = {
    'unknown': 0,
    'global': 1,
    'tenant': 2,
    'unknownFutureValue': 3,
}
simulationContentSource = enum.Enum('simulationContentSource', simulationContentSource_data)


simulationContentStatus_data = {
    'unknown': 0,
    'draft': 1,
    'ready': 2,
    'archive': 3,
    'delete': 4,
    'unknownFutureValue': 5,
}
simulationContentStatus = enum.Enum('simulationContentStatus', simulationContentStatus_data)


simulationStatus_data = {
    'unknown': 0,
    'draft': 1,
    'running': 2,
    'scheduled': 3,
    'succeeded': 4,
    'failed': 5,
    'cancelled': 6,
    'excluded': 7,
    'unknownFutureValue': 8,
}
simulationStatus = enum.Enum('simulationStatus', simulationStatus_data)


targettedUserType_data = {
    'unknown': 0,
    'clicked': 1,
    'compromised': 2,
    'allUsers': 3,
    'unknownFutureValue': 4,
}
targettedUserType = enum.Enum('targettedUserType', targettedUserType_data)


trainingAssignedTo_data = {
    'none': 0,
    'allUsers': 1,
    'clickedPayload': 2,
    'compromised': 3,
    'reportedPhish': 4,
    'readButNotClicked': 5,
    'didNothing': 6,
    'unknownFutureValue': 8,
}
trainingAssignedTo = enum.Enum('trainingAssignedTo', trainingAssignedTo_data)


trainingAvailabilityStatus_data = {
    'unknown': 0,
    'notAvailable': 1,
    'available': 2,
    'archive': 3,
    'delete': 4,
    'unknownFutureValue': 5,
}
trainingAvailabilityStatus = enum.Enum('trainingAvailabilityStatus', trainingAvailabilityStatus_data)


trainingCompletionDuration_data = {
    'week': 7,
    'fortnite': 14,
    'month': 30,
    'unknownFutureValue': 100,
}
trainingCompletionDuration = enum.Enum('trainingCompletionDuration', trainingCompletionDuration_data)


trainingSettingType_data = {
    'microsoftCustom': 0,
    'microsoftManaged': 1,
    'noTraining': 2,
    'custom': 3,
    'unknownFutureValue': 4,
}
trainingSettingType = enum.Enum('trainingSettingType', trainingSettingType_data)


trainingStatus_data = {
    'unknown': 0,
    'assigned': 1,
    'inProgress': 2,
    'completed': 3,
    'overdue': 4,
    'unknownFutureValue': 5,
}
trainingStatus = enum.Enum('trainingStatus', trainingStatus_data)


trainingType_data = {
    'unknown': 0,
    'phishing': 1,
    'unknownFutureValue': 2,
}
trainingType = enum.Enum('trainingType', trainingType_data)


accountStatus_data = {
    'unknown': 0,
    'staged': 1,
    'active': 2,
    'suspended': 3,
    'deleted': 4,
    'unknownFutureValue': 127,
}
accountStatus = enum.Enum('accountStatus', accountStatus_data)


alertFeedback_data = {
    'unknown': 0,
    'truePositive': 1,
    'falsePositive': 2,
    'benignPositive': 3,
    'unknownFutureValue': 127,
}
alertFeedback = enum.Enum('alertFeedback', alertFeedback_data)


alertStatus_data = {
    'unknown': 0,
    'newAlert': 1,
    'inProgress': 2,
    'resolved': 3,
    'dismissed': 4,
    'unknownFutureValue': 127,
}
alertStatus = enum.Enum('alertStatus', alertStatus_data)


applicationPermissionsRequired_data = {
    'unknown': 0,
    'anonymous': 1,
    'guest': 2,
    'user': 3,
    'administrator': 4,
    'system': 5,
    'unknownFutureValue': 127,
}
applicationPermissionsRequired = enum.Enum('applicationPermissionsRequired', applicationPermissionsRequired_data)


connectionDirection_data = {
    'unknown': 0,
    'inbound': 1,
    'outbound': 2,
    'unknownFutureValue': 127,
}
connectionDirection = enum.Enum('connectionDirection', connectionDirection_data)


connectionStatus_data = {
    'unknown': 0,
    'attempted': 1,
    'succeeded': 2,
    'blocked': 3,
    'failed': 4,
    'unknownFutureValue': 127,
}
connectionStatus = enum.Enum('connectionStatus', connectionStatus_data)


diamondModel_data = {
    'unknown': 0,
    'adversary': 1,
    'capability': 2,
    'infrastructure': 3,
    'victim': 4,
    'unknownFutureValue': 127,
}
diamondModel = enum.Enum('diamondModel', diamondModel_data)


emailRole_data = {
    'unknown': 0,
    'sender': 1,
    'recipient': 2,
    'unknownFutureValue': 127,
}
emailRole = enum.Enum('emailRole', emailRole_data)


fileHashType_data = {
    'unknown': 0,
    'sha1': 1,
    'sha256': 2,
    'md5': 3,
    'authenticodeHash256': 4,
    'lsHash': 5,
    'ctph': 6,
    'unknownFutureValue': 127,
}
fileHashType = enum.Enum('fileHashType', fileHashType_data)


logonType_data = {
    'unknown': 0,
    'interactive': 1,
    'remoteInteractive': 2,
    'network': 3,
    'batch': 4,
    'service': 5,
    'unknownFutureValue': 127,
}
logonType = enum.Enum('logonType', logonType_data)


processIntegrityLevel_data = {
    'unknown': 0,
    'untrusted': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'system': 5,
    'unknownFutureValue': 127,
}
processIntegrityLevel = enum.Enum('processIntegrityLevel', processIntegrityLevel_data)


registryHive_data = {
    'unknown': 0,
    'currentConfig': 1,
    'currentUser': 2,
    'localMachineSam': 3,
    'localMachineSecurity': 4,
    'localMachineSoftware': 5,
    'localMachineSystem': 6,
    'usersDefault': 7,
    'unknownFutureValue': 127,
}
registryHive = enum.Enum('registryHive', registryHive_data)


registryOperation_data = {
    'unknown': 0,
    'create': 1,
    'modify': 2,
    'delete': 3,
    'unknownFutureValue': 127,
}
registryOperation = enum.Enum('registryOperation', registryOperation_data)


registryValueType_data = {
    'unknown': 0,
    'binary': 1,
    'dword': 2,
    'dwordLittleEndian': 3,
    'dwordBigEndian': 4,
    'expandSz': 5,
    'link': 6,
    'multiSz': 7,
    'none': 8,
    'qword': 9,
    'qwordlittleEndian': 10,
    'sz': 11,
    'unknownFutureValue': 127,
}
registryValueType = enum.Enum('registryValueType', registryValueType_data)


securityNetworkProtocol_data = {
    'unknown': -1,
    'ip': 0,
    'icmp': 1,
    'igmp': 2,
    'ggp': 3,
    'ipv4': 4,
    'tcp': 6,
    'pup': 12,
    'udp': 17,
    'idp': 22,
    'ipv6': 41,
    'ipv6RoutingHeader': 43,
    'ipv6FragmentHeader': 44,
    'ipSecEncapsulatingSecurityPayload': 50,
    'ipSecAuthenticationHeader': 51,
    'icmpV6': 58,
    'ipv6NoNextHeader': 59,
    'ipv6DestinationOptions': 60,
    'nd': 77,
    'raw': 255,
    'ipx': 1000,
    'spx': 1256,
    'spxII': 1257,
    'unknownFutureValue': 32767,
}
securityNetworkProtocol = enum.Enum('securityNetworkProtocol', securityNetworkProtocol_data)


securityResourceType_data = {
    'unknown': 0,
    'attacked': 1,
    'related': 2,
    'unknownFutureValue': 3,
}
securityResourceType = enum.Enum('securityResourceType', securityResourceType_data)


tiAction_data = {
    'unknown': 0,
    'allow': 1,
    'block': 2,
    'alert': 3,
    'unknownFutureValue': 127,
}
tiAction = enum.Enum('tiAction', tiAction_data)


tlpLevel_data = {
    'unknown': 0,
    'white': 1,
    'green': 2,
    'amber': 3,
    'red': 4,
    'unknownFutureValue': 127,
}
tlpLevel = enum.Enum('tlpLevel', tlpLevel_data)


userAccountSecurityType_data = {
    'unknown': 0,
    'standard': 1,
    'power': 2,
    'administrator': 3,
    'unknownFutureValue': 127,
}
userAccountSecurityType = enum.Enum('userAccountSecurityType', userAccountSecurityType_data)


accessLevel_data = {
    'everyone': 0,
    'invited': 1,
    'locked': 2,
    'sameEnterprise': 3,
    'sameEnterpriseAndFederated': 4,
}
accessLevel = enum.Enum('accessLevel', accessLevel_data)


allowedLobbyAdmitterRoles_data = {
    'organizerAndCoOrganizersAndPresenters': 0,
    'organizerAndCoOrganizers': 1,
    'unknownFutureValue': 2,
}
allowedLobbyAdmitterRoles = enum.Enum('allowedLobbyAdmitterRoles', allowedLobbyAdmitterRoles_data)


autoAdmittedUsersType_data = {
    'everyoneInCompany': 0,
    'everyone': 1,
}
autoAdmittedUsersType = enum.Enum('autoAdmittedUsersType', autoAdmittedUsersType_data)


broadcastMeetingAudience_data = {
    'roleIsAttendee': 0,
    'organization': 1,
    'everyone': 2,
    'unknownFutureValue': 3,
}
broadcastMeetingAudience = enum.Enum('broadcastMeetingAudience', broadcastMeetingAudience_data)


callDirection_data = {
    'incoming': 0,
    'outgoing': 1,
}
callDirection = enum.Enum('callDirection', callDirection_data)


callDisposition_data = {
    'default': 0,
    'simultaneousRing': 1,
    'forward': 2,
}
callDisposition = enum.Enum('callDisposition', callDisposition_data)


callEventType_data = {
    'callStarted': 0,
    'callEnded': 1,
    'unknownFutureValue': 2,
    'rosterUpdated': 3,
}
callEventType = enum.Enum('callEventType', callEventType_data)


callState_data = {
    'incoming': 0,
    'establishing': 1,
    'ringing': 2,
    'established': 3,
    'hold': 4,
    'transferring': 5,
    'transferAccepted': 6,
    'redirecting': 7,
    'terminating': 8,
    'terminated': 9,
    'unknownFutureValue': 10,
}
callState = enum.Enum('callState', callState_data)


callTranscriptionState_data = {
    'notStarted': 0,
    'active': 1,
    'inactive': 2,
    'unknownFutureValue': 3,
}
callTranscriptionState = enum.Enum('callTranscriptionState', callTranscriptionState_data)


changeType_data = {
    'created': 0,
    'updated': 1,
    'deleted': 2,
}
changeType = enum.Enum('changeType', changeType_data)


mediaDirection_data = {
    'inactive': 0,
    'sendOnly': 1,
    'receiveOnly': 2,
    'sendReceive': 3,
}
mediaDirection = enum.Enum('mediaDirection', mediaDirection_data)


mediaState_data = {
    'active': 0,
    'inactive': 1,
    'unknownFutureValue': 2,
}
mediaState = enum.Enum('mediaState', mediaState_data)


meetingAudience_data = {
    'everyone': 0,
    'organization': 1,
    'unknownFutureValue': 2,
}
meetingAudience = enum.Enum('meetingAudience', meetingAudience_data)


meetingCapabilities_data = {
    'questionAndAnswer': 0,
    'unknownFutureValue': 1,
}
meetingCapabilities = enum.Enum('meetingCapabilities', meetingCapabilities_data)


meetingChatHistoryDefaultMode_data = {
    'none': 0,
    'all': 1,
    'unknownFutureValue': 2,
}
meetingChatHistoryDefaultMode = enum.Enum('meetingChatHistoryDefaultMode', meetingChatHistoryDefaultMode_data)


meetingLiveShareOptions_data = {
    'enabled': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
}
meetingLiveShareOptions = enum.Enum('meetingLiveShareOptions', meetingLiveShareOptions_data)


meetingRegistrantStatus_data = {
    'registered': 0,
    'canceled': 1,
    'processing': 2,
    'unknownFutureValue': 3,
}
meetingRegistrantStatus = enum.Enum('meetingRegistrantStatus', meetingRegistrantStatus_data)


modality_data = {
    'unknown': 0,
    'audio': 1,
    'video': 2,
    'videoBasedScreenSharing': 3,
    'data': 4,
    'unknownFutureValue': 5,
}
modality = enum.Enum('modality', modality_data)


onlineMeetingContentSharingDisabledReason_data = {
    'watermarkProtection': 1,
    'unknownFutureValue': 2,
}
onlineMeetingContentSharingDisabledReason = enum.Enum('onlineMeetingContentSharingDisabledReason', onlineMeetingContentSharingDisabledReason_data)


onlineMeetingRole_data = {
    'attendee': 0,
    'presenter': 1,
    'unknownFutureValue': 3,
    'producer': 2,
    'coorganizer': 4,
}
onlineMeetingRole = enum.Enum('onlineMeetingRole', onlineMeetingRole_data)


onlineMeetingVideoDisabledReason_data = {
    'watermarkProtection': 1,
    'unknownFutureValue': 2,
}
onlineMeetingVideoDisabledReason = enum.Enum('onlineMeetingVideoDisabledReason', onlineMeetingVideoDisabledReason_data)


playPromptCompletionReason_data = {
    'unknown': 0,
    'completedSuccessfully': 1,
    'mediaOperationCanceled': 2,
    'unknownFutureValue': 3,
}
playPromptCompletionReason = enum.Enum('playPromptCompletionReason', playPromptCompletionReason_data)


recordCompletionReason_data = {
    'operationCanceled': 0,
    'stopToneDetected': 1,
    'maxRecordDurationReached': 2,
    'initialSilenceTimeout': 3,
    'maxSilenceTimeout': 4,
    'playPromptFailed': 5,
    'playBeepFailed': 6,
    'mediaReceiveTimeout': 7,
    'unspecifiedError': 8,
}
recordCompletionReason = enum.Enum('recordCompletionReason', recordCompletionReason_data)


recordingStatus_data = {
    'unknown': 0,
    'notRecording': 1,
    'recording': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
recordingStatus = enum.Enum('recordingStatus', recordingStatus_data)


rejectReason_data = {
    'none': 0,
    'busy': 1,
    'forbidden': 2,
    'unknownFutureValue': 3,
}
rejectReason = enum.Enum('rejectReason', rejectReason_data)


routingMode_data = {
    'oneToOne': 0,
    'multicast': 1,
}
routingMode = enum.Enum('routingMode', routingMode_data)


routingPolicy_data = {
    'none': 0,
    'noMissedCall': 1,
    'disableForwardingExceptPhone': 2,
    'disableForwarding': 3,
    'preferSkypeForBusiness': 5,
    'unknownFutureValue': 6,
}
routingPolicy = enum.Enum('routingPolicy', routingPolicy_data)


routingType_data = {
    'forwarded': 0,
    'lookup': 1,
    'selfFork': 2,
    'unknownFutureValue': 3,
}
routingType = enum.Enum('routingType', routingType_data)


screenSharingRole_data = {
    'viewer': 0,
    'sharer': 1,
}
screenSharingRole = enum.Enum('screenSharingRole', screenSharingRole_data)


sendDtmfCompletionReason_data = {
    'unknown': 0,
    'completedSuccessfully': 1,
    'mediaOperationCanceled': 2,
    'unknownFutureValue': 3,
}
sendDtmfCompletionReason = enum.Enum('sendDtmfCompletionReason', sendDtmfCompletionReason_data)


tone_data = {
    'tone0': 0,
    'tone1': 1,
    'tone2': 2,
    'tone3': 3,
    'tone4': 4,
    'tone5': 5,
    'tone6': 6,
    'tone7': 7,
    'tone8': 8,
    'tone9': 9,
    'star': 10,
    'pound': 11,
    'a': 12,
    'b': 13,
    'c': 14,
    'd': 15,
    'flash': 16,
}
tone = enum.Enum('tone', tone_data)


virtualEventAttendeeRegistrationStatus_data = {
    'registered': 0,
    'canceled': 1,
    'waitlisted': 2,
    'pendingApproval': 3,
    'rejectedByOrganizer': 4,
    'unknownFutureValue': 11,
}
virtualEventAttendeeRegistrationStatus = enum.Enum('virtualEventAttendeeRegistrationStatus', virtualEventAttendeeRegistrationStatus_data)


virtualEventRegistrationPredefinedQuestionLabel_data = {
    'street': 0,
    'city': 1,
    'state': 2,
    'postalCode': 3,
    'countryOrRegion': 4,
    'industry': 5,
    'jobTitle': 6,
    'organization': 7,
    'unknownFutureValue': 8,
}
virtualEventRegistrationPredefinedQuestionLabel = enum.Enum('virtualEventRegistrationPredefinedQuestionLabel', virtualEventRegistrationPredefinedQuestionLabel_data)


virtualEventRegistrationQuestionAnswerInputType_data = {
    'text': 0,
    'multilineText': 1,
    'singleChoice': 2,
    'multiChoice': 3,
    'boolean': 4,
    'unknownFutureValue': 5,
}
virtualEventRegistrationQuestionAnswerInputType = enum.Enum('virtualEventRegistrationQuestionAnswerInputType', virtualEventRegistrationQuestionAnswerInputType_data)


virtualEventStatus_data = {
    'draft': 0,
    'published': 1,
    'canceled': 2,
    'unknownFutureValue': 3,
}
virtualEventStatus = enum.Enum('virtualEventStatus', virtualEventStatus_data)


attestationLevel_data = {
    'attested': 0,
    'notAttested': 1,
    'unknownFutureValue': 2,
}
attestationLevel = enum.Enum('attestationLevel', attestationLevel_data)


authenticationMethodKeyStrength_data = {
    'normal': 0,
    'weak': 1,
    'unknown': 2,
}
authenticationMethodKeyStrength = enum.Enum('authenticationMethodKeyStrength', authenticationMethodKeyStrength_data)


authenticationMethodPlatform_data = {
    'unknown': 0,
    'windows': 1,
    'macOS': 2,
    'iOS': 3,
    'android': 4,
    'linux': 5,
    'unknownFutureValue': 6,
}
authenticationMethodPlatform = enum.Enum('authenticationMethodPlatform', authenticationMethodPlatform_data)


authenticationMethodSignInState_data = {
    'notSupported': 0,
    'notAllowedByPolicy': 1,
    'notEnabled': 2,
    'phoneNumberNotUnique': 3,
    'ready': 4,
    'notConfigured': 5,
    'unknownFutureValue': 6,
}
authenticationMethodSignInState = enum.Enum('authenticationMethodSignInState', authenticationMethodSignInState_data)


authenticationPhoneType_data = {
    'mobile': 0,
    'alternateMobile': 1,
    'office': 2,
    'unknownFutureValue': 3,
}
authenticationPhoneType = enum.Enum('authenticationPhoneType', authenticationPhoneType_data)


hardwareOathTokenHashFunction_data = {
    'hmacsha1': 0,
    'hmacsha256': 1,
    'unknownFutureValue': 2,
}
hardwareOathTokenHashFunction = enum.Enum('hardwareOathTokenHashFunction', hardwareOathTokenHashFunction_data)


hardwareOathTokenStatus_data = {
    'available': 0,
    'assigned': 1,
    'activated': 2,
    'failedActivation': 3,
    'unknownFutureValue': 4,
}
hardwareOathTokenStatus = enum.Enum('hardwareOathTokenStatus', hardwareOathTokenStatus_data)


microsoftAuthenticatorAuthenticationMethodClientAppName_data = {
    'microsoftAuthenticator': 0,
    'outlookMobile': 1,
    'unknownFutureValue': 2,
}
microsoftAuthenticatorAuthenticationMethodClientAppName = enum.Enum('microsoftAuthenticatorAuthenticationMethodClientAppName', microsoftAuthenticatorAuthenticationMethodClientAppName_data)


userDefaultAuthenticationMethodType_data = {
    'push': 0,
    'oath': 1,
    'voiceMobile': 2,
    'voiceAlternateMobile': 3,
    'voiceOffice': 4,
    'sms': 5,
    'unknownFutureValue': 6,
}
userDefaultAuthenticationMethodType = enum.Enum('userDefaultAuthenticationMethodType', userDefaultAuthenticationMethodType_data)


lifecycleEventType_data = {
    'missed': 0,
    'subscriptionRemoved': 1,
    'reauthorizationRequired': 2,
}
lifecycleEventType = enum.Enum('lifecycleEventType', lifecycleEventType_data)


binaryOperator_data = {
    'or': 0,
    'and': 1,
}
binaryOperator = enum.Enum('binaryOperator', binaryOperator_data)


accessType_data = {
    'grant': 1,
    'deny': 2,
}
accessType = enum.Enum('accessType', accessType_data)


aclType_data = {
    'user': 1,
    'group': 2,
    'everyone': 3,
    'everyoneExceptGuests': 4,
    'externalGroup': 5,
    'unknownFutureValue': 6,
}
aclType = enum.Enum('aclType', aclType_data)


connectionOperationStatus_data = {
    'unspecified': 0,
    'inprogress': 1,
    'completed': 2,
    'failed': 3,
}
connectionOperationStatus = enum.Enum('connectionOperationStatus', connectionOperationStatus_data)


connectionState_data = {
    'draft': 1,
    'ready': 2,
    'obsolete': 3,
    'limitExceeded': 4,
    'unknownFutureValue': 5,
}
connectionState = enum.Enum('connectionState', connectionState_data)


externalItemContentType_data = {
    'text': 1,
    'html': 2,
    'unknownFutureValue': 3,
}
externalItemContentType = enum.Enum('externalItemContentType', externalItemContentType_data)


identitySourceType_data = {
    'azureActiveDirectory': 1,
    'external': 2,
}
identitySourceType = enum.Enum('identitySourceType', identitySourceType_data)


label_data = {
    'title': 0,
    'url': 1,
    'createdBy': 2,
    'lastModifiedBy': 3,
    'authors': 4,
    'createdDateTime': 5,
    'lastModifiedDateTime': 6,
    'fileName': 7,
    'fileExtension': 8,
}
label = enum.Enum('label', label_data)


propertyType_data = {
    'string': 0,
    'int64': 1,
    'double': 2,
    'dateTime': 3,
    'boolean': 4,
    'stringCollection': 5,
    'int64Collection': 6,
    'doubleCollection': 7,
    'dateTimeCollection': 8,
}
propertyType = enum.Enum('propertyType', propertyType_data)


aiInteractionType_data = {
    'userPrompt': 0,
    'aiResponse': 1,
    'unknownFutureValue': 2,
}
aiInteractionType = enum.Enum('aiInteractionType', aiInteractionType_data)


appDevelopmentPlatforms_data = {
    'developerPortal': 1,
    'unknownFutureValue': 2,
}
appDevelopmentPlatforms = enum.Enum('appDevelopmentPlatforms', appDevelopmentPlatforms_data)


callRecordingStatus_data = {
    'success': 0,
    'failure': 1,
    'initial': 2,
    'chunkFinished': 3,
    'unknownFutureValue': 4,
}
callRecordingStatus = enum.Enum('callRecordingStatus', callRecordingStatus_data)


channelLayoutType_data = {
    'post': 0,
    'chat': 1,
    'unknownFutureValue': 2,
}
channelLayoutType = enum.Enum('channelLayoutType', channelLayoutType_data)


channelMembershipType_data = {
    'standard': 0,
    'private': 1,
    'unknownFutureValue': 2,
    'shared': 3,
}
channelMembershipType = enum.Enum('channelMembershipType', channelMembershipType_data)


chatMessageActions_data = {
    'reactionAdded': 1,
    'reactionRemoved': 2,
    'actionUndefined': 4,
    'unknownFutureValue': 8,
}
chatMessageActions = enum.Enum('chatMessageActions', chatMessageActions_data)


chatMessageImportance_data = {
    'normal': 0,
    'high': 1,
    'urgent': 2,
}
chatMessageImportance = enum.Enum('chatMessageImportance', chatMessageImportance_data)


chatMessagePolicyViolationDlpActionTypes_data = {
    'none': 0,
    'notifySender': 1,
    'blockAccess': 2,
    'blockAccessExternal': 4,
}
chatMessagePolicyViolationDlpActionTypes = enum.Enum('chatMessagePolicyViolationDlpActionTypes', chatMessagePolicyViolationDlpActionTypes_data)


chatMessagePolicyViolationUserActionTypes_data = {
    'none': 0,
    'override': 1,
    'reportFalsePositive': 2,
}
chatMessagePolicyViolationUserActionTypes = enum.Enum('chatMessagePolicyViolationUserActionTypes', chatMessagePolicyViolationUserActionTypes_data)


chatMessagePolicyViolationVerdictDetailsTypes_data = {
    'none': 0,
    'allowFalsePositiveOverride': 1,
    'allowOverrideWithoutJustification': 2,
    'allowOverrideWithJustification': 4,
}
chatMessagePolicyViolationVerdictDetailsTypes = enum.Enum('chatMessagePolicyViolationVerdictDetailsTypes', chatMessagePolicyViolationVerdictDetailsTypes_data)


chatMessageType_data = {
    'message': 0,
    'chatEvent': 1,
    'typing': 2,
    'unknownFutureValue': 3,
    'systemEventMessage': 4,
}
chatMessageType = enum.Enum('chatMessageType', chatMessageType_data)


chatType_data = {
    'oneOnOne': 0,
    'group': 1,
    'meeting': 2,
    'unknownFutureValue': 3,
}
chatType = enum.Enum('chatType', chatType_data)


clonableTeamParts_data = {
    'apps': 1,
    'tabs': 2,
    'settings': 4,
    'channels': 8,
    'members': 16,
}
clonableTeamParts = enum.Enum('clonableTeamParts', clonableTeamParts_data)


giphyRatingType_data = {
    'strict': 0,
    'moderate': 1,
    'unknownFutureValue': 2,
}
giphyRatingType = enum.Enum('giphyRatingType', giphyRatingType_data)


replyRestriction_data = {
    'everyone': 0,
    'authorAndModerators': 1,
    'unknownFutureValue': 2,
}
replyRestriction = enum.Enum('replyRestriction', replyRestriction_data)


teamsAppDashboardCardSize_data = {
    'medium': 0,
    'large': 1,
    'unknownFutureValue': 2,
}
teamsAppDashboardCardSize = enum.Enum('teamsAppDashboardCardSize', teamsAppDashboardCardSize_data)


teamsAppDashboardCardSourceType_data = {
    'bot': 0,
    'unknownFutureValue': 1,
}
teamsAppDashboardCardSourceType = enum.Enum('teamsAppDashboardCardSourceType', teamsAppDashboardCardSourceType_data)


teamsAppDistributionMethod_data = {
    'store': 0,
    'organization': 1,
    'sideloaded': 2,
    'unknownFutureValue': 3,
}
teamsAppDistributionMethod = enum.Enum('teamsAppDistributionMethod', teamsAppDistributionMethod_data)


teamsAppInstallationScopes_data = {
    'team': 1,
    'groupChat': 2,
    'personal': 4,
    'unknownFutureValue': 8,
}
teamsAppInstallationScopes = enum.Enum('teamsAppInstallationScopes', teamsAppInstallationScopes_data)


teamsAppPublishingState_data = {
    'submitted': 0,
    'rejected': 1,
    'published': 2,
    'unknownFutureValue': 3,
}
teamsAppPublishingState = enum.Enum('teamsAppPublishingState', teamsAppPublishingState_data)


teamsAppResourceSpecificPermissionType_data = {
    'delegated': 0,
    'application': 1,
    'unknownFutureValue': 2,
}
teamsAppResourceSpecificPermissionType = enum.Enum('teamsAppResourceSpecificPermissionType', teamsAppResourceSpecificPermissionType_data)


teamsAsyncOperationStatus_data = {
    'invalid': 0,
    'notStarted': 1,
    'inProgress': 2,
    'succeeded': 3,
    'failed': 4,
    'unknownFutureValue': 5,
}
teamsAsyncOperationStatus = enum.Enum('teamsAsyncOperationStatus', teamsAsyncOperationStatus_data)


teamsAsyncOperationType_data = {
    'invalid': 0,
    'cloneTeam': 1,
    'archiveTeam': 2,
    'unarchiveTeam': 3,
    'createTeam': 4,
    'unknownFutureValue': 5,
    'teamifyGroup': 6,
    'createChannel': 7,
    'createChat': 8,
    'archiveChannel': 9,
    'unarchiveChannel': 10,
}
teamsAsyncOperationType = enum.Enum('teamsAsyncOperationType', teamsAsyncOperationType_data)


teamSpecialization_data = {
    'none': 0,
    'educationStandard': 1,
    'educationClass': 2,
    'educationProfessionalLearningCommunity': 3,
    'educationStaff': 4,
    'healthcareStandard': 5,
    'healthcareCareCoordination': 6,
    'unknownFutureValue': 7,
}
teamSpecialization = enum.Enum('teamSpecialization', teamSpecialization_data)


teamTemplateAudience_data = {
    'organization': 0,
    'user': 1,
    'public': 2,
    'unknownFutureValue': 3,
}
teamTemplateAudience = enum.Enum('teamTemplateAudience', teamTemplateAudience_data)


teamVisibilityType_data = {
    'private': 0,
    'public': 1,
    'hiddenMembership': 2,
    'unknownFutureValue': 3,
}
teamVisibilityType = enum.Enum('teamVisibilityType', teamVisibilityType_data)


teamworkActivityTopicSource_data = {
    'entityUrl': 0,
    'text': 1,
}
teamworkActivityTopicSource = enum.Enum('teamworkActivityTopicSource', teamworkActivityTopicSource_data)


teamworkApplicationIdentityType_data = {
    'aadApplication': 0,
    'bot': 1,
    'tenantBot': 2,
    'office365Connector': 3,
    'outgoingWebhook': 4,
    'unknownFutureValue': 5,
}
teamworkApplicationIdentityType = enum.Enum('teamworkApplicationIdentityType', teamworkApplicationIdentityType_data)


teamworkCallEventType_data = {
    'call': 0,
    'meeting': 1,
    'screenShare': 2,
    'unknownFutureValue': 3,
}
teamworkCallEventType = enum.Enum('teamworkCallEventType', teamworkCallEventType_data)


teamworkConnectionStatus_data = {
    'unknown': 0,
    'connected': 1,
    'disconnected': 2,
    'unknownFutureValue': 3,
}
teamworkConnectionStatus = enum.Enum('teamworkConnectionStatus', teamworkConnectionStatus_data)


teamworkConversationIdentityType_data = {
    'team': 0,
    'channel': 1,
    'chat': 2,
    'unknownFutureValue': 3,
}
teamworkConversationIdentityType = enum.Enum('teamworkConversationIdentityType', teamworkConversationIdentityType_data)


teamworkDeviceActivityState_data = {
    'unknown': 0,
    'busy': 1,
    'idle': 2,
    'unavailable': 3,
    'unknownFutureValue': 4,
}
teamworkDeviceActivityState = enum.Enum('teamworkDeviceActivityState', teamworkDeviceActivityState_data)


teamworkDeviceHealthStatus_data = {
    'unknown': 0,
    'offline': 1,
    'critical': 2,
    'nonUrgent': 3,
    'healthy': 4,
    'unknownFutureValue': 5,
}
teamworkDeviceHealthStatus = enum.Enum('teamworkDeviceHealthStatus', teamworkDeviceHealthStatus_data)


teamworkDeviceOperationType_data = {
    'deviceRestart': 0,
    'configUpdate': 1,
    'deviceDiagnostics': 2,
    'softwareUpdate': 3,
    'deviceManagementAgentConfigUpdate': 4,
    'remoteLogin': 5,
    'remoteLogout': 6,
    'unknownFutureValue': 7,
}
teamworkDeviceOperationType = enum.Enum('teamworkDeviceOperationType', teamworkDeviceOperationType_data)


teamworkDeviceType_data = {
    'unknown': 0,
    'ipPhone': 1,
    'teamsRoom': 2,
    'surfaceHub': 3,
    'collaborationBar': 4,
    'teamsDisplay': 5,
    'touchConsole': 6,
    'lowCostPhone': 7,
    'teamsPanel': 8,
    'sip': 9,
    'unknownFutureValue': 10,
}
teamworkDeviceType = enum.Enum('teamworkDeviceType', teamworkDeviceType_data)


teamworkSoftwareFreshness_data = {
    'unknown': 0,
    'latest': 1,
    'updateAvailable': 2,
    'unknownFutureValue': 3,
}
teamworkSoftwareFreshness = enum.Enum('teamworkSoftwareFreshness', teamworkSoftwareFreshness_data)


teamworkSoftwareType_data = {
    'adminAgent': 0,
    'operatingSystem': 1,
    'teamsClient': 2,
    'firmware': 3,
    'partnerAgent': 4,
    'companyPortal': 5,
    'unknownFutureValue': 6,
}
teamworkSoftwareType = enum.Enum('teamworkSoftwareType', teamworkSoftwareType_data)


teamworkSupportedClient_data = {
    'unknown': 0,
    'skypeDefaultAndTeams': 1,
    'teamsDefaultAndSkype': 2,
    'skypeOnly': 3,
    'teamsOnly': 4,
    'unknownFutureValue': 5,
}
teamworkSupportedClient = enum.Enum('teamworkSupportedClient', teamworkSupportedClient_data)


teamworkTagType_data = {
    'standard': 0,
    'unknownFutureValue': 1,
}
teamworkTagType = enum.Enum('teamworkTagType', teamworkTagType_data)


teamworkUserIdentityType_data = {
    'aadUser': 0,
    'onPremiseAadUser': 1,
    'anonymousGuest': 2,
    'federatedUser': 3,
    'personalMicrosoftAccountUser': 4,
    'skypeUser': 5,
    'phoneUser': 6,
    'unknownFutureValue': 7,
    'emailUser': 8,
    'azureCommunicationServicesUser': 9,
}
teamworkUserIdentityType = enum.Enum('teamworkUserIdentityType', teamworkUserIdentityType_data)


userNewMessageRestriction_data = {
    'everyone': 0,
    'everyoneExceptGuests': 1,
    'moderators': 2,
    'unknownFutureValue': 3,
}
userNewMessageRestriction = enum.Enum('userNewMessageRestriction', userNewMessageRestriction_data)


confirmedBy_data = {
    'none': 0,
    'user': 1,
    'manager': 2,
    'unknownFutureValue': 1024,
}
confirmedBy = enum.Enum('confirmedBy', confirmedBy_data)


eligibilityFilteringEnabledEntities_data = {
    'none': 0,
    'swapRequest': 1,
    'offerShiftRequest': 2,
    'unknownFutureValue': 4,
    'timeOffReason': 8,
}
eligibilityFilteringEnabledEntities = enum.Enum('eligibilityFilteringEnabledEntities', eligibilityFilteringEnabledEntities_data)


scheduleChangeRequestActor_data = {
    'sender': 0,
    'recipient': 1,
    'manager': 2,
    'system': 3,
    'unknownFutureValue': 4,
}
scheduleChangeRequestActor = enum.Enum('scheduleChangeRequestActor', scheduleChangeRequestActor_data)


scheduleChangeState_data = {
    'pending': 0,
    'approved': 1,
    'declined': 2,
    'unknownFutureValue': 3,
}
scheduleChangeState = enum.Enum('scheduleChangeState', scheduleChangeState_data)


scheduleEntityTheme_data = {
    'white': 0,
    'blue': 1,
    'green': 2,
    'purple': 3,
    'pink': 4,
    'yellow': 5,
    'gray': 6,
    'darkBlue': 7,
    'darkGreen': 8,
    'darkPurple': 9,
    'darkPink': 10,
    'darkYellow': 11,
    'unknownFutureValue': 12,
}
scheduleEntityTheme = enum.Enum('scheduleEntityTheme', scheduleEntityTheme_data)


timeCardState_data = {
    'clockedIn': 0,
    'onBreak': 1,
    'clockedOut': 2,
    'unknownFutureValue': 3,
}
timeCardState = enum.Enum('timeCardState', timeCardState_data)


timeOffReasonIconType_data = {
    'none': 0,
    'car': 1,
    'calendar': 2,
    'running': 3,
    'plane': 4,
    'firstAid': 5,
    'doctor': 6,
    'notWorking': 7,
    'clock': 8,
    'juryDuty': 9,
    'globe': 10,
    'cup': 11,
    'phone': 12,
    'weather': 13,
    'umbrella': 14,
    'piggyBank': 15,
    'dog': 16,
    'cake': 17,
    'trafficCone': 18,
    'pin': 19,
    'sunny': 20,
    'unknownFutureValue': 21,
}
timeOffReasonIconType = enum.Enum('timeOffReasonIconType', timeOffReasonIconType_data)


workforceIntegrationEncryptionProtocol_data = {
    'sharedSecret': 0,
    'unknownFutureValue': 1,
}
workforceIntegrationEncryptionProtocol = enum.Enum('workforceIntegrationEncryptionProtocol', workforceIntegrationEncryptionProtocol_data)


workforceIntegrationSupportedEntities_data = {
    'none': 0,
    'shift': 1,
    'swapRequest': 2,
    'userShiftPreferences': 8,
    'openShift': 16,
    'openShiftRequest': 32,
    'offerShiftRequest': 64,
    'unknownFutureValue': 1024,
    'timeCard': 2048,
    'timeOffReason': 4096,
    'timeOff': 8192,
    'timeOffRequest': 16384,
}
workforceIntegrationSupportedEntities = enum.Enum('workforceIntegrationSupportedEntities', workforceIntegrationSupportedEntities_data)


mailDestinationRoutingReason_data = {
    'none': 0,
    'mailFlowRule': 1,
    'safeSender': 2,
    'blockedSender': 3,
    'advancedSpamFiltering': 4,
    'domainAllowList': 5,
    'domainBlockList': 6,
    'notInAddressBook': 7,
    'firstTimeSender': 8,
    'autoPurgeToInbox': 9,
    'autoPurgeToJunk': 10,
    'autoPurgeToDeleted': 11,
    'outbound': 12,
    'notJunk': 13,
    'junk': 14,
    'unknownFutureValue': 15,
}
mailDestinationRoutingReason = enum.Enum('mailDestinationRoutingReason', mailDestinationRoutingReason_data)


threatAssessmentContentType_data = {
    'mail': 1,
    'url': 2,
    'file': 3,
}
threatAssessmentContentType = enum.Enum('threatAssessmentContentType', threatAssessmentContentType_data)


threatAssessmentRequestPivotProperty_data = {
    'threatCategory': 1,
    'mailDestinationRoutingReason': 2,
}
threatAssessmentRequestPivotProperty = enum.Enum('threatAssessmentRequestPivotProperty', threatAssessmentRequestPivotProperty_data)


threatAssessmentRequestSource_data = {
    'undefined': 0,
    'user': 1,
    'administrator': 2,
}
threatAssessmentRequestSource = enum.Enum('threatAssessmentRequestSource', threatAssessmentRequestSource_data)


threatAssessmentResultType_data = {
    'checkPolicy': 1,
    'rescan': 2,
    'unknownFutureValue': 3,
}
threatAssessmentResultType = enum.Enum('threatAssessmentResultType', threatAssessmentResultType_data)


threatAssessmentStatus_data = {
    'pending': 1,
    'completed': 2,
}
threatAssessmentStatus = enum.Enum('threatAssessmentStatus', threatAssessmentStatus_data)


threatCategory_data = {
    'undefined': 0,
    'spam': 1,
    'phishing': 2,
    'malware': 3,
    'unknownFutureValue': 4,
}
threatCategory = enum.Enum('threatCategory', threatCategory_data)


threatExpectedAssessment_data = {
    'block': 1,
    'unblock': 2,
}
threatExpectedAssessment = enum.Enum('threatExpectedAssessment', threatExpectedAssessment_data)


wellknownListName_data = {
    'none': 0,
    'defaultList': 1,
    'flaggedEmails': 2,
    'unknownFutureValue': 3,
}
wellknownListName = enum.Enum('wellknownListName', wellknownListName_data)


communityPrivacy_data = {
    'public': 0,
    'private': 1,
    'unknownFutureValue': 2,
}
communityPrivacy = enum.Enum('communityPrivacy', communityPrivacy_data)


engagementAsyncOperationType_data = {
    'createCommunity': 0,
    'unknownFutureValue': 1,
}
engagementAsyncOperationType = enum.Enum('engagementAsyncOperationType', engagementAsyncOperationType_data)


assignmentType_data = {
    'required': 0,
    'recommended': 1,
    'unknownFutureValue': 2,
    'peerRecommended': 3,
}
assignmentType = enum.Enum('assignmentType', assignmentType_data)


courseStatus_data = {
    'notStarted': 0,
    'inProgress': 1,
    'completed': 2,
    'unknownFutureValue': 3,
}
courseStatus = enum.Enum('courseStatus', courseStatus_data)


level_data = {
    'beginner': 0,
    'intermediate': 1,
    'advanced': 2,
    'unknownFutureValue': 3,
}
level = enum.Enum('level', level_data)


healthMonitoring_alertState_data = {
    'active': 0,
    'resolved': 1,
    'unknownFutureValue': 2,
}
healthMonitoring_alertState = enum.Enum('healthMonitoring_alertState', healthMonitoring_alertState_data)


healthMonitoring_alertType_data = {
    'unknown': 0,
    'mfaSignInFailure': 1,
    'managedDeviceSignInFailure': 2,
    'compliantDeviceSignInFailure': 3,
    'unknownFutureValue': 4,
}
healthMonitoring_alertType = enum.Enum('healthMonitoring_alertType', healthMonitoring_alertType_data)


healthMonitoring_category_data = {
    'unknown': 0,
    'authentication': 1,
    'unknownFutureValue': 2,
}
healthMonitoring_category = enum.Enum('healthMonitoring_category', healthMonitoring_category_data)


healthMonitoring_enrichmentState_data = {
    'none': 0,
    'inProgress': 1,
    'enriched': 2,
    'unknownFutureValue': 3,
}
healthMonitoring_enrichmentState = enum.Enum('healthMonitoring_enrichmentState', healthMonitoring_enrichmentState_data)


healthMonitoring_scenario_data = {
    'unknown': 0,
    'mfa': 1,
    'devices': 2,
    'unknownFutureValue': 3,
}
healthMonitoring_scenario = enum.Enum('healthMonitoring_scenario', healthMonitoring_scenario_data)


networkaccess_accessType_data = {
    'quickAccess': 0,
    'privateAccess': 1,
    'unknownFutureValue': 2,
    'appAccess': 3,
}
networkaccess_accessType = enum.Enum('networkaccess_accessType', networkaccess_accessType_data)


networkaccess_aggregationFilter_data = {
    'transactions': 0,
    'users': 1,
    'devices': 2,
    'unknownFutureValue': 3,
    'bytesSent': 4,
    'bytesReceived': 5,
    'totalBytes': 6,
}
networkaccess_aggregationFilter = enum.Enum('networkaccess_aggregationFilter', networkaccess_aggregationFilter_data)


networkaccess_alertSeverity_data = {
    'informational': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'unknownFutureValue': 5,
}
networkaccess_alertSeverity = enum.Enum('networkaccess_alertSeverity', networkaccess_alertSeverity_data)


networkaccess_alertType_data = {
    'unhealthyRemoteNetworks': 0,
    'unhealthyConnectors': 1,
    'deviceTokenInconsistency': 2,
    'crossTenantAnomaly': 3,
    'suspiciousProcess': 4,
    'threatIntelligenceTransactions': 5,
    'unknownFutureValue': 6,
    'webContentBlocked': 7,
    'malware': 8,
    'patientZero': 9,
    'dlp': 10,
}
networkaccess_alertType = enum.Enum('networkaccess_alertType', networkaccess_alertType_data)


networkaccess_algorithm_data = {
    'md5': 0,
    'sha1': 1,
    'sha256': 2,
    'sha256ac': 3,
    'unknownFutureValue': 4,
}
networkaccess_algorithm = enum.Enum('networkaccess_algorithm', networkaccess_algorithm_data)


networkaccess_confidenceLevel_data = {
    'unknown': 0,
    'low': 1,
    'high': 2,
    'unknownFutureValue': 3,
}
networkaccess_confidenceLevel = enum.Enum('networkaccess_confidenceLevel', networkaccess_confidenceLevel_data)


networkaccess_connectionStatus_data = {
    'open': 0,
    'active': 1,
    'closed': 2,
    'unknownFutureValue': 3,
}
networkaccess_connectionStatus = enum.Enum('networkaccess_connectionStatus', networkaccess_connectionStatus_data)


networkaccess_deviceCategory_data = {
    'client': 0,
    'branch': 1,
    'unknownFutureValue': 2,
    'remoteNetwork': 3,
}
networkaccess_deviceCategory = enum.Enum('networkaccess_deviceCategory', networkaccess_deviceCategory_data)


networkaccess_filteringPolicyAction_data = {
    'block': 0,
    'allow': 1,
    'unknownFutureValue': 2,
    'bypass': 3,
    'alert': 4,
}
networkaccess_filteringPolicyAction = enum.Enum('networkaccess_filteringPolicyAction', networkaccess_filteringPolicyAction_data)


networkaccess_httpMethod_data = {
    'get': 0,
    'post': 1,
    'put': 2,
    'delete': 3,
    'head': 4,
    'options': 5,
    'connect': 6,
    'patch': 7,
    'trace': 8,
    'unknownFutureValue': 9,
}
networkaccess_httpMethod = enum.Enum('networkaccess_httpMethod', networkaccess_httpMethod_data)


networkaccess_intentCategory_data = {
    'initialAccess': 0,
    'persistence': 1,
    'privilegeEscalation': 2,
    'defenseEvasion': 3,
    'credentialAccess': 4,
    'discovery': 5,
    'lateralMovement': 6,
    'execution': 7,
    'collection': 8,
    'exfiltration': 9,
    'commandAndControl': 10,
    'impact': 11,
    'impairProcessControl': 12,
    'inhibitResponseFunction': 13,
    'reconnaissance': 14,
    'resourceDevelopment': 15,
    'evasion': 16,
    'unknownFutureValue': 17,
}
networkaccess_intentCategory = enum.Enum('networkaccess_intentCategory', networkaccess_intentCategory_data)


networkaccess_malwareCategory_data = {
    'adware': 0,
    'backdoor': 1,
    'behavior': 2,
    'bot': 3,
    'browserModifier': 4,
    'constructor': 5,
    'cryptojacking': 6,
    'ddos': 7,
    'dropper': 8,
    'dropperMalware': 9,
    'exploit': 10,
    'filelessMalware': 11,
    'hackTool': 12,
    'hybridMalware': 13,
    'joke': 14,
    'keylogger': 15,
    'misleading': 16,
    'monitoringTool': 17,
    'polymorphicMalware': 18,
    'passwordStealer': 19,
    'program': 20,
    'ransomware': 21,
    'remoteAccess': 22,
    'rogue': 23,
    'rootkit': 24,
    'settingsModifier': 25,
    'softwareBundler': 26,
    'spammer': 27,
    'spoofer': 28,
    'spyware': 29,
    'tool': 30,
    'trojan': 31,
    'trojanClicker': 32,
    'trojanDownloader': 33,
    'trojanNotifier': 34,
    'trojanProxy': 35,
    'trojanSpy': 36,
    'virus': 37,
    'wiperMalware': 38,
    'worm': 39,
    'unknownFutureValue': 40,
}
networkaccess_malwareCategory = enum.Enum('networkaccess_malwareCategory', networkaccess_malwareCategory_data)


networkaccess_networkingProtocol_data = {
    'ip': 0,
    'icmp': 1,
    'igmp': 2,
    'ggp': 3,
    'ipv4': 4,
    'tcp': 6,
    'pup': 12,
    'udp': 17,
    'idp': 22,
    'ipv6': 41,
    'ipv6RoutingHeader': 43,
    'ipv6FragmentHeader': 44,
    'ipSecEncapsulatingSecurityPayload': 50,
    'ipSecAuthenticationHeader': 51,
    'icmpV6': 58,
    'ipv6NoNextHeader': 59,
    'ipv6DestinationOptions': 60,
    'nd': 77,
    'ipx': 100,
    'raw': 255,
    'spx': 1256,
    'spxII': 1257,
    'unknownFutureValue': 1258,
}
networkaccess_networkingProtocol = enum.Enum('networkaccess_networkingProtocol', networkaccess_networkingProtocol_data)


networkaccess_networkTrafficOperationStatus_data = {
    'success': 0,
    'failure': 1,
    'unknownFutureValue': 2,
}
networkaccess_networkTrafficOperationStatus = enum.Enum('networkaccess_networkTrafficOperationStatus', networkaccess_networkTrafficOperationStatus_data)


networkaccess_remoteNetworkStatus_data = {
    'tunnelDisconnected': 0,
    'tunnelConnected': 1,
    'bgpDisconnected': 2,
    'bgpConnected': 3,
    'remoteNetworkAlive': 4,
    'unknownFutureValue': 5,
}
networkaccess_remoteNetworkStatus = enum.Enum('networkaccess_remoteNetworkStatus', networkaccess_remoteNetworkStatus_data)


networkaccess_threatSeverity_data = {
    'low': 0,
    'medium': 1,
    'high': 2,
    'critical': 3,
    'unknownFutureValue': 5,
}
networkaccess_threatSeverity = enum.Enum('networkaccess_threatSeverity', networkaccess_threatSeverity_data)


networkaccess_tlsAction_data = {
    'bypassed': 0,
    'intercepted': 1,
    'unknownFutureValue': 2,
}
networkaccess_tlsAction = enum.Enum('networkaccess_tlsAction', networkaccess_tlsAction_data)


networkaccess_tlsStatus_data = {
    'success': 0,
    'failure': 1,
    'unknownFutureValue': 2,
}
networkaccess_tlsStatus = enum.Enum('networkaccess_tlsStatus', networkaccess_tlsStatus_data)


networkaccess_trafficType_data = {
    'internet': 0,
    'private': 1,
    'microsoft365': 2,
    'all': 3,
    'unknownFutureValue': 4,
}
networkaccess_trafficType = enum.Enum('networkaccess_trafficType', networkaccess_trafficType_data)


networkaccess_usageStatus_data = {
    'frequentlyUsed': 0,
    'rarelyUsed': 1,
    'unknownFutureValue': 2,
}
networkaccess_usageStatus = enum.Enum('networkaccess_usageStatus', networkaccess_usageStatus_data)


networkaccess_userType_data = {
    'member': 0,
    'guest': 1,
    'unknownFutureValue': 2,
}
networkaccess_userType = enum.Enum('networkaccess_userType', networkaccess_userType_data)


networkaccess_bandwidthCapacityInMbps_data = {
    'mbps250': 0,
    'mbps500': 1,
    'mbps750': 2,
    'mbps1000': 3,
    'unknownFutureValue': 4,
}
networkaccess_bandwidthCapacityInMbps = enum.Enum('networkaccess_bandwidthCapacityInMbps', networkaccess_bandwidthCapacityInMbps_data)


networkaccess_connectivityState_data = {
    'pending': 0,
    'connected': 1,
    'inactive': 2,
    'error': 3,
    'unknownFutureValue': 4,
}
networkaccess_connectivityState = enum.Enum('networkaccess_connectivityState', networkaccess_connectivityState_data)


networkaccess_deviceVendor_data = {
    'barracudaNetworks': 0,
    'checkPoint': 1,
    'ciscoMeraki': 2,
    'citrix': 3,
    'fortinet': 4,
    'hpeAruba': 5,
    'netFoundry': 6,
    'nuage': 7,
    'openSystems': 8,
    'paloAltoNetworks': 9,
    'riverbedTechnology': 10,
    'silverPeak': 11,
    'vmWareSdWan': 12,
    'versa': 13,
    'other': 14,
    'ciscoCatalyst': 15,
    'unknownFutureValue': 16,
}
networkaccess_deviceVendor = enum.Enum('networkaccess_deviceVendor', networkaccess_deviceVendor_data)


networkaccess_dhGroup_data = {
    'dhGroup14': 0,
    'dhGroup24': 1,
    'dhGroup2048': 2,
    'ecp256': 3,
    'ecp384': 4,
    'unknownFutureValue': 5,
}
networkaccess_dhGroup = enum.Enum('networkaccess_dhGroup', networkaccess_dhGroup_data)


networkaccess_forwardingCategory_data = {
    'default': 0,
    'optimized': 1,
    'allow': 2,
    'unknownFutureValue': 3,
}
networkaccess_forwardingCategory = enum.Enum('networkaccess_forwardingCategory', networkaccess_forwardingCategory_data)


networkaccess_forwardingRuleAction_data = {
    'bypass': 0,
    'forward': 1,
    'unknownFutureValue': 2,
}
networkaccess_forwardingRuleAction = enum.Enum('networkaccess_forwardingRuleAction', networkaccess_forwardingRuleAction_data)


networkaccess_ikeEncryption_data = {
    'aes128': 0,
    'aes192': 1,
    'aes256': 2,
    'gcmAes128': 3,
    'gcmAes256': 4,
    'unknownFutureValue': 5,
}
networkaccess_ikeEncryption = enum.Enum('networkaccess_ikeEncryption', networkaccess_ikeEncryption_data)


networkaccess_ikeIntegrity_data = {
    'sha256': 0,
    'sha384': 1,
    'gcmAes128': 2,
    'gcmAes256': 3,
    'unknownFutureValue': 4,
}
networkaccess_ikeIntegrity = enum.Enum('networkaccess_ikeIntegrity', networkaccess_ikeIntegrity_data)


networkaccess_ipSecEncryption_data = {
    'none': 0,
    'gcmAes128': 1,
    'gcmAes192': 2,
    'gcmAes256': 3,
    'unknownFutureValue': 4,
}
networkaccess_ipSecEncryption = enum.Enum('networkaccess_ipSecEncryption', networkaccess_ipSecEncryption_data)


networkaccess_ipSecIntegrity_data = {
    'gcmAes128': 0,
    'gcmAes192': 1,
    'gcmAes256': 2,
    'sha256': 3,
    'unknownFutureValue': 4,
}
networkaccess_ipSecIntegrity = enum.Enum('networkaccess_ipSecIntegrity', networkaccess_ipSecIntegrity_data)


networkaccess_networkDestinationType_data = {
    'url': 0,
    'fqdn': 1,
    'ipAddress': 2,
    'ipRange': 3,
    'ipSubnet': 4,
    'webCategory': 5,
    'unknownFutureValue': 6,
}
networkaccess_networkDestinationType = enum.Enum('networkaccess_networkDestinationType', networkaccess_networkDestinationType_data)


networkaccess_onboardingStatus_data = {
    'offboarded': 0,
    'offboardingInProgress': 1,
    'onboardingInProgress': 2,
    'onboarded': 3,
    'onboardingErrorOccurred': 4,
    'offboardingErrorOccurred': 5,
    'unknownFutureValue': 6,
}
networkaccess_onboardingStatus = enum.Enum('networkaccess_onboardingStatus', networkaccess_onboardingStatus_data)


networkaccess_pfsGroup_data = {
    'none': 0,
    'pfs1': 1,
    'pfs2': 2,
    'pfs14': 3,
    'pfs24': 4,
    'pfs2048': 5,
    'pfsmm': 6,
    'ecp256': 7,
    'ecp384': 8,
    'unknownFutureValue': 9,
}
networkaccess_pfsGroup = enum.Enum('networkaccess_pfsGroup', networkaccess_pfsGroup_data)


networkaccess_redundancyTier_data = {
    'noRedundancy': 0,
    'zoneRedundancy': 1,
    'unknownFutureValue': 4,
}
networkaccess_redundancyTier = enum.Enum('networkaccess_redundancyTier', networkaccess_redundancyTier_data)


networkaccess_region_data = {
    'eastUS': 0,
    'eastUS2': 1,
    'westUS': 2,
    'westUS2': 3,
    'westUS3': 4,
    'centralUS': 5,
    'northCentralUS': 6,
    'southCentralUS': 7,
    'northEurope': 8,
    'westEurope': 9,
    'franceCentral': 10,
    'germanyWestCentral': 11,
    'switzerlandNorth': 12,
    'ukSouth': 13,
    'canadaEast': 14,
    'canadaCentral': 15,
    'southAfricaWest': 16,
    'southAfricaNorth': 17,
    'uaeNorth': 18,
    'australiaEast': 19,
    'westCentralUS': 20,
    'centralIndia': 21,
    'southEastAsia': 22,
    'swedenCentral': 23,
    'southIndia': 24,
    'australiaSouthEast': 25,
    'koreaCentral': 26,
    'polandCentral': 27,
    'brazilSouth': 28,
    'japanEast': 29,
    'japanWest': 30,
    'koreaSouth': 31,
    'italyNorth': 32,
    'franceSouth': 33,
    'israelCentral': 34,
    'unknownFutureValue': 35,
}
networkaccess_region = enum.Enum('networkaccess_region', networkaccess_region_data)


networkaccess_status_data = {
    'enabled': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
}
networkaccess_status = enum.Enum('networkaccess_status', networkaccess_status_data)


networkaccess_trafficForwardingType_data = {
    'm365': 0,
    'internet': 1,
    'private': 2,
    'unknownFutureValue': 3,
}
networkaccess_trafficForwardingType = enum.Enum('networkaccess_trafficForwardingType', networkaccess_trafficForwardingType_data)


cloudLicensing_assigneeTypes_data = {
    'none': 0,
    'user': 1,
    'group': 2,
    'device': 4,
    'unknownFutureValue': 8,
}
cloudLicensing_assigneeTypes = enum.Enum('cloudLicensing_assigneeTypes', cloudLicensing_assigneeTypes_data)


ediscovery_additionalDataOptions_data = {
    'allVersions': 1,
    'linkedFiles': 2,
    'unknownFutureValue': 4,
}
ediscovery_additionalDataOptions = enum.Enum('ediscovery_additionalDataOptions', ediscovery_additionalDataOptions_data)


ediscovery_caseAction_data = {
    'contentExport': 0,
    'applyTags': 1,
    'convertToPdf': 2,
    'index': 3,
    'estimateStatistics': 4,
    'addToReviewSet': 5,
    'holdUpdate': 6,
    'unknownFutureValue': 7,
    'purgeData': 8,
}
ediscovery_caseAction = enum.Enum('ediscovery_caseAction', ediscovery_caseAction_data)


ediscovery_caseOperationStatus_data = {
    'notStarted': 0,
    'submissionFailed': 1,
    'running': 2,
    'succeeded': 3,
    'partiallySucceeded': 4,
    'failed': 5,
}
ediscovery_caseOperationStatus = enum.Enum('ediscovery_caseOperationStatus', ediscovery_caseOperationStatus_data)


ediscovery_caseStatus_data = {
    'unknown': 0,
    'active': 1,
    'pendingDelete': 2,
    'closing': 3,
    'closed': 4,
    'closedWithError': 5,
}
ediscovery_caseStatus = enum.Enum('ediscovery_caseStatus', ediscovery_caseStatus_data)


ediscovery_childSelectability_data = {
    'One': 0,
    'Many': 1,
}
ediscovery_childSelectability = enum.Enum('ediscovery_childSelectability', ediscovery_childSelectability_data)


ediscovery_custodianStatus_data = {
    'active': 1,
    'released': 2,
}
ediscovery_custodianStatus = enum.Enum('ediscovery_custodianStatus', ediscovery_custodianStatus_data)


ediscovery_dataSourceContainerStatus_data = {
    'Active': 1,
    'Released': 2,
    'UnknownFutureValue': 3,
}
ediscovery_dataSourceContainerStatus = enum.Enum('ediscovery_dataSourceContainerStatus', ediscovery_dataSourceContainerStatus_data)


ediscovery_dataSourceHoldStatus_data = {
    'notApplied': 1,
    'applied': 2,
    'applying': 3,
    'removing': 4,
    'partial': 5,
    'unknownFutureValue': 6,
}
ediscovery_dataSourceHoldStatus = enum.Enum('ediscovery_dataSourceHoldStatus', ediscovery_dataSourceHoldStatus_data)


ediscovery_dataSourceScopes_data = {
    'none': 0,
    'allTenantMailboxes': 1,
    'allTenantSites': 2,
    'allCaseCustodians': 4,
    'allCaseNoncustodialDataSources': 8,
    'unknownFutureValue': 16,
}
ediscovery_dataSourceScopes = enum.Enum('ediscovery_dataSourceScopes', ediscovery_dataSourceScopes_data)


ediscovery_exportFileStructure_data = {
    'none': 0,
    'directory': 1,
    'pst': 2,
    'unknownFutureValue': 3,
}
ediscovery_exportFileStructure = enum.Enum('ediscovery_exportFileStructure', ediscovery_exportFileStructure_data)


ediscovery_exportOptions_data = {
    'originalFiles': 1,
    'text': 2,
    'pdfReplacement': 4,
    'fileInfo': 8,
    'tags': 16,
    'unknownFutureValue': 32,
}
ediscovery_exportOptions = enum.Enum('ediscovery_exportOptions', ediscovery_exportOptions_data)


ediscovery_legalHoldStatus_data = {
    'Pending': 0,
    'Error': 1,
    'Success': 2,
    'UnknownFutureValue': 3,
}
ediscovery_legalHoldStatus = enum.Enum('ediscovery_legalHoldStatus', ediscovery_legalHoldStatus_data)


ediscovery_sourceType_data = {
    'mailbox': 1,
    'site': 2,
}
ediscovery_sourceType = enum.Enum('ediscovery_sourceType', ediscovery_sourceType_data)


security_additionalDataOptions_data = {
    'allVersions': 1,
    'linkedFiles': 2,
    'unknownFutureValue': 4,
    'advancedIndexing': 8,
    'listAttachments': 16,
    'htmlTranscripts': 32,
    'messageConversationExpansion': 64,
    'locationsWithoutHits': 256,
    'allItemsInFolder': 512,
}
security_additionalDataOptions = enum.Enum('security_additionalDataOptions', security_additionalDataOptions_data)


security_additionalOptions_data = {
    'none': 0,
    'teamsAndYammerConversations': 1,
    'cloudAttachments': 2,
    'allDocumentVersions': 4,
    'subfolderContents': 8,
    'listAttachments': 16,
    'unknownFutureValue': 32,
    'htmlTranscripts': 64,
    'advancedIndexing': 128,
    'allItemsInFolder': 256,
    'includeFolderAndPath': 512,
    'condensePaths': 1024,
    'friendlyName': 2048,
    'splitSource': 4096,
    'optimizedPartitionSize': 8192,
    'includeReport': 16384,
}
security_additionalOptions = enum.Enum('security_additionalOptions', security_additionalOptions_data)


security_caseAction_data = {
    'contentExport': 0,
    'applyTags': 1,
    'convertToPdf': 2,
    'index': 3,
    'estimateStatistics': 4,
    'addToReviewSet': 5,
    'holdUpdate': 6,
    'unknownFutureValue': 7,
    'purgeData': 8,
    'exportReport': 9,
    'exportResult': 10,
}
security_caseAction = enum.Enum('security_caseAction', security_caseAction_data)


security_caseOperationStatus_data = {
    'notStarted': 0,
    'submissionFailed': 1,
    'running': 2,
    'succeeded': 3,
    'partiallySucceeded': 4,
    'failed': 5,
    'unknownFutureValue': 6,
}
security_caseOperationStatus = enum.Enum('security_caseOperationStatus', security_caseOperationStatus_data)


security_caseStatus_data = {
    'unknown': 0,
    'active': 1,
    'pendingDelete': 2,
    'closing': 3,
    'closed': 4,
    'closedWithError': 5,
    'unknownFutureValue': 6,
}
security_caseStatus = enum.Enum('security_caseStatus', security_caseStatus_data)


security_childSelectability_data = {
    'One': 0,
    'Many': 1,
    'unknownFutureValue': 2,
}
security_childSelectability = enum.Enum('security_childSelectability', security_childSelectability_data)


security_cloudAttachmentVersion_data = {
    'latest': 1,
    'recent10': 2,
    'recent100': 3,
    'all': 4,
    'unknownFutureValue': 5,
}
security_cloudAttachmentVersion = enum.Enum('security_cloudAttachmentVersion', security_cloudAttachmentVersion_data)


security_dataSourceContainerStatus_data = {
    'active': 1,
    'released': 2,
    'unknownFutureValue': 3,
}
security_dataSourceContainerStatus = enum.Enum('security_dataSourceContainerStatus', security_dataSourceContainerStatus_data)


security_dataSourceHoldStatus_data = {
    'notApplied': 1,
    'applied': 2,
    'applying': 3,
    'removing': 4,
    'partial': 5,
    'unknownFutureValue': 6,
}
security_dataSourceHoldStatus = enum.Enum('security_dataSourceHoldStatus', security_dataSourceHoldStatus_data)


security_dataSourceScopes_data = {
    'none': 0,
    'allTenantMailboxes': 1,
    'allTenantSites': 2,
    'allCaseCustodians': 4,
    'allCaseNoncustodialDataSources': 8,
    'unknownFutureValue': 16,
}
security_dataSourceScopes = enum.Enum('security_dataSourceScopes', security_dataSourceScopes_data)


security_documentVersion_data = {
    'latest': 1,
    'recent10': 2,
    'recent100': 3,
    'all': 4,
    'unknownFutureValue': 5,
}
security_documentVersion = enum.Enum('security_documentVersion', security_documentVersion_data)


security_exportCriteria_data = {
    'searchHits': 1,
    'partiallyIndexed': 2,
    'unknownFutureValue': 4,
}
security_exportCriteria = enum.Enum('security_exportCriteria', security_exportCriteria_data)


security_exportFileStructure_data = {
    'none': 0,
    'directory': 1,
    'pst': 2,
    'unknownFutureValue': 3,
    'msg': 4,
}
security_exportFileStructure = enum.Enum('security_exportFileStructure', security_exportFileStructure_data)


security_exportFormat_data = {
    'pst': 0,
    'msg': 1,
    'eml': 2,
    'unknownFutureValue': 3,
}
security_exportFormat = enum.Enum('security_exportFormat', security_exportFormat_data)


security_exportLocation_data = {
    'responsiveLocations': 1,
    'nonresponsiveLocations': 2,
    'unknownFutureValue': 4,
}
security_exportLocation = enum.Enum('security_exportLocation', security_exportLocation_data)


security_exportOptions_data = {
    'originalFiles': 1,
    'text': 2,
    'pdfReplacement': 4,
    'fileInfo': 8,
    'tags': 16,
    'unknownFutureValue': 64,
    'splitSource': 128,
    'includeFolderAndPath': 256,
    'friendlyName': 512,
    'condensePaths': 1024,
    'optimizedPartitionSize': 2048,
}
security_exportOptions = enum.Enum('security_exportOptions', security_exportOptions_data)


security_fileProcessingStatus_data = {
    'success': 0,
    'internalError': 1,
    'unknownError': 2,
    'processingTimeout': 3,
    'invalidFileId': 4,
    'fileSizeIsZero': 5,
    'fileSizeIsTooLarge': 6,
    'fileDepthLimitExceeded': 7,
    'fileBodyIsTooLong': 8,
    'fileTypeIsUnknown': 9,
    'fileTypeIsNotSupported': 10,
    'malformedFile': 11,
    'protectedFile': 12,
    'poisonFile': 13,
    'noReviewSetSummaryGenerated': 14,
    'extractionException': 15,
    'ocrProcessingTimeout': 16,
    'ocrFileSizeExceedsLimit': 17,
    'unknownFutureValue': 18,
}
security_fileProcessingStatus = enum.Enum('security_fileProcessingStatus', security_fileProcessingStatus_data)


security_itemsToInclude_data = {
    'searchHits': 1,
    'partiallyIndexed': 2,
    'unknownFutureValue': 4,
}
security_itemsToInclude = enum.Enum('security_itemsToInclude', security_itemsToInclude_data)


security_policyStatus_data = {
    'pending': 0,
    'error': 1,
    'success': 2,
    'unknownFutureValue': 3,
}
security_policyStatus = enum.Enum('security_policyStatus', security_policyStatus_data)


security_purgeAreas_data = {
    'mailboxes': 1,
    'teamsMessages': 2,
    'unknownFutureValue': 4,
}
security_purgeAreas = enum.Enum('security_purgeAreas', security_purgeAreas_data)


security_purgeType_data = {
    'recoverable': 0,
    'unknownFutureValue': 1,
    'permanentlyDelete': 2,
}
security_purgeType = enum.Enum('security_purgeType', security_purgeType_data)


security_recipientType_data = {
    'user': 1,
    'roleGroup': 2,
    'unknownFutureValue': 4,
}
security_recipientType = enum.Enum('security_recipientType', security_recipientType_data)


security_sourceType_data = {
    'mailbox': 1,
    'site': 2,
    'unknownFutureValue': 4,
}
security_sourceType = enum.Enum('security_sourceType', security_sourceType_data)


security_statisticsOptions_data = {
    'includeRefiners': 1,
    'includeQueryStats': 2,
    'includeUnindexedStats': 4,
    'advancedIndexing': 8,
    'locationsWithoutHits': 16,
    'unknownFutureValue': 32,
}
security_statisticsOptions = enum.Enum('security_statisticsOptions', security_statisticsOptions_data)


security_appCategory_data = {
    'security': 1,
    'collaboration': 2,
    'hostingServices': 3,
    'onlineMeetings': 4,
    'newsAndEntertainment': 5,
    'eCommerce': 6,
    'education': 7,
    'cloudStorage': 8,
    'marketing': 9,
    'operationsManagement': 10,
    'health': 11,
    'advertising': 12,
    'productivity': 13,
    'accountingAndFinance': 14,
    'contentManagement': 15,
    'contentSharing': 16,
    'businessManagement': 17,
    'communications': 18,
    'dataAnalytics': 19,
    'businessIntelligence': 20,
    'webemail': 21,
    'codeHosting': 22,
    'webAnalytics': 23,
    'socialNetwork': 24,
    'crm': 25,
    'forums': 26,
    'humanResourceManagement': 27,
    'transportationAndTravel': 28,
    'productDesign': 29,
    'sales': 30,
    'cloudComputingPlatform': 31,
    'projectManagement': 32,
    'personalInstantMessaging': 33,
    'developmentTools': 34,
    'itServices': 35,
    'supplyChainAndLogistics': 36,
    'propertyManagement': 37,
    'customerSupport': 38,
    'internetOfThings': 39,
    'vendorManagementSystems': 40,
    'websiteMonitoring': 41,
    'generativeAi': 42,
    'unknown': 43,
    'unknownFutureValue': 44,
}
security_appCategory = enum.Enum('security_appCategory', security_appCategory_data)


security_appInfoCsaStarLevel_data = {
    'selfAssessment': 1,
    'certification': 2,
    'attestation': 3,
    'cStarAssessment': 4,
    'continuousMonitoring': 5,
    'unknown': 6,
    'unknownFutureValue': 7,
}
security_appInfoCsaStarLevel = enum.Enum('security_appInfoCsaStarLevel', security_appInfoCsaStarLevel_data)


security_appInfoDataAtRestEncryptionMethod_data = {
    'aes': 1,
    'bitLocker': 2,
    'blowfish': 3,
    'des3': 4,
    'des': 5,
    'rc4': 6,
    'rsA': 7,
    'notSupported': 8,
    'unknown': 9,
    'unknownFutureValue': 10,
}
security_appInfoDataAtRestEncryptionMethod = enum.Enum('security_appInfoDataAtRestEncryptionMethod', security_appInfoDataAtRestEncryptionMethod_data)


security_appInfoDataRetentionPolicy_data = {
    'dataRetained': 1,
    'deletedImmediately': 2,
    'deletedWithinTwoWeeks': 3,
    'deletedWithinOneMonth': 4,
    'deletedWithinThreeMonths': 5,
    'deletedWithinMoreThanThreeMonths': 6,
    'unknown': 7,
    'unknownFutureValue': 8,
}
security_appInfoDataRetentionPolicy = enum.Enum('security_appInfoDataRetentionPolicy', security_appInfoDataRetentionPolicy_data)


security_appInfoEncryptionProtocol_data = {
    'tls1_0': 1,
    'tls1_1': 2,
    'tls1_2': 3,
    'tls1_3': 4,
    'notApplicable': 5,
    'notSupported': 6,
    'unknown': 7,
    'unknownFutureValue': 8,
    'ssl3': 9,
}
security_appInfoEncryptionProtocol = enum.Enum('security_appInfoEncryptionProtocol', security_appInfoEncryptionProtocol_data)


security_appInfoFedRampLevel_data = {
    'high': 1,
    'moderate': 2,
    'low': 3,
    'liSaaS': 4,
    'unknown': 5,
    'unknownFutureValue': 6,
    'notSupported': 7,
}
security_appInfoFedRampLevel = enum.Enum('security_appInfoFedRampLevel', security_appInfoFedRampLevel_data)


security_appInfoHolding_data = {
    'private': 1,
    'public': 2,
    'unknown': 3,
    'unknownFutureValue': 4,
}
security_appInfoHolding = enum.Enum('security_appInfoHolding', security_appInfoHolding_data)


security_appInfoPciDssVersion_data = {
    'v1': 1,
    'v2': 2,
    'v3': 3,
    'v3_1': 4,
    'v3_2': 5,
    'v3_2_1': 6,
    'notSupported': 7,
    'unknown': 8,
    'unknownFutureValue': 9,
    'v4': 10,
}
security_appInfoPciDssVersion = enum.Enum('security_appInfoPciDssVersion', security_appInfoPciDssVersion_data)


security_appInfoUploadedDataTypes_data = {
    'documents': 1,
    'mediaFiles': 2,
    'codingFiles': 3,
    'creditCards': 4,
    'databaseFiles': 5,
    'none': 6,
    'unknown': 7,
    'unknownFutureValue': 8,
}
security_appInfoUploadedDataTypes = enum.Enum('security_appInfoUploadedDataTypes', security_appInfoUploadedDataTypes_data)


security_cloudAppInfoState_data = {
    'true': 1,
    'false': 2,
    'unknown': 3,
    'unknownFutureValue': 4,
}
security_cloudAppInfoState = enum.Enum('security_cloudAppInfoState', security_cloudAppInfoState_data)


security_entityType_data = {
    'userName': 1,
    'ipAddress': 2,
    'machineName': 3,
    'other': 4,
    'unknown': 5,
    'unknownFutureValue': 6,
}
security_entityType = enum.Enum('security_entityType', security_entityType_data)


security_logDataProvider_data = {
    'barracuda': 101,
    'bluecoat': 102,
    'checkpoint': 103,
    'ciscoAsa': 104,
    'ciscoIronportProxy': 106,
    'fortigate': 108,
    'paloAlto': 112,
    'squid': 114,
    'zscaler': 120,
    'mcafeeSwg': 121,
    'ciscoScanSafe': 124,
    'juniperSrx': 129,
    'sophosSg': 130,
    'websenseV75': 135,
    'websenseSiemCef': 138,
    'machineZoneMeraki': 153,
    'squidNative': 155,
    'ciscoFwsm': 157,
    'microsoftIsaW3C': 159,
    'sonicwall': 160,
    'sophosCyberoam': 162,
    'clavister': 164,
    'customParser': 167,
    'juniperSsg': 168,
    'zscalerQradar': 170,
    'juniperSrxSd': 172,
    'juniperSrxWelf': 174,
    'microsoftConditionalAppAccess': 176,
    'ciscoAsaFirepower': 177,
    'genericCef': 179,
    'genericLeef': 181,
    'genericW3C': 183,
    'iFilter': 185,
    'checkpointXml': 187,
    'checkpointSmartViewTracker': 189,
    'barracudaNextGenFw': 191,
    'barracudaNextGenFwWeblog': 193,
    'microsoftDefenderForEndpoint': 195,
    'zscalerCef': 196,
    'sophosXg': 198,
    'iboss': 200,
    'forcepoint': 202,
    'fortios': 204,
    'ciscoIronportWsaIi': 206,
    'paloAltoLeef': 208,
    'forcepointLeef': 210,
    'stormshield': 212,
    'contentkeeper': 214,
    'ciscoIronportWsaIii': 216,
    'checkpointCef': 219,
    'corrata': 220,
    'ciscoFirepowerV6': 223,
    'menloSecurityCef': 224,
    'watchguardXtm': 225,
    'openSystemsSecureWebGateway': 227,
    'wandera': 229,
    'unknownFutureValue': 231,
}
security_logDataProvider = enum.Enum('security_logDataProvider', security_logDataProvider_data)


security_receiverProtocol_data = {
    'ftp': 0,
    'ftps': 1,
    'syslogUdp': 2,
    'syslogTcp': 3,
    'syslogTls': 4,
    'unknownFutureValue': 5,
}
security_receiverProtocol = enum.Enum('security_receiverProtocol', security_receiverProtocol_data)


security_trafficType_data = {
    'downloadedBytes': 2,
    'uploadedBytes': 3,
    'unknown': 4,
    'unknownFutureValue': 5,
}
security_trafficType = enum.Enum('security_trafficType', security_trafficType_data)


security_deploymentStatus_data = {
    'upToDate': 1,
    'outdated': 2,
    'updating': 3,
    'updateFailed': 4,
    'notConfigured': 5,
    'unreachable': 6,
    'disconnected': 7,
    'startFailure': 8,
    'syncing': 9,
    'unknownFutureValue': 10,
}
security_deploymentStatus = enum.Enum('security_deploymentStatus', security_deploymentStatus_data)


security_healthIssueSeverity_data = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'unknownFutureValue': 4,
}
security_healthIssueSeverity = enum.Enum('security_healthIssueSeverity', security_healthIssueSeverity_data)


security_healthIssueStatus_data = {
    'open': 1,
    'closed': 2,
    'suppressed': 3,
    'unknownFutureValue': 4,
}
security_healthIssueStatus = enum.Enum('security_healthIssueStatus', security_healthIssueStatus_data)


security_healthIssueType_data = {
    'sensor': 1,
    'global': 2,
    'unknownFutureValue': 3,
}
security_healthIssueType = enum.Enum('security_healthIssueType', security_healthIssueType_data)


security_sensorHealthStatus_data = {
    'healthy': 1,
    'notHealthyLow': 2,
    'notHealthyMedium': 3,
    'notHealthyHigh': 4,
    'unknownFutureValue': 5,
}
security_sensorHealthStatus = enum.Enum('security_sensorHealthStatus', security_sensorHealthStatus_data)


security_sensorType_data = {
    'adConnectIntegrated': 1,
    'adcsIntegrated': 2,
    'adfsIntegrated': 3,
    'domainControllerIntegrated': 4,
    'domainControllerStandalone': 5,
    'unknownFutureValue': 6,
}
security_sensorType = enum.Enum('security_sensorType', security_sensorType_data)


security_behaviorDuringRetentionPeriod_data = {
    'doNotRetain': 0,
    'retain': 1,
    'retainAsRecord': 2,
    'retainAsRegulatoryRecord': 3,
    'unknownFutureValue': 4,
}
security_behaviorDuringRetentionPeriod = enum.Enum('security_behaviorDuringRetentionPeriod', security_behaviorDuringRetentionPeriod_data)


security_actionSource_data = {
    'manual': 0,
    'automatic': 1,
    'recommended': 2,
    'default': 3,
}
security_actionSource = enum.Enum('security_actionSource', security_actionSource_data)


security_assignmentMethod_data = {
    'standard': 0,
    'privileged': 1,
    'auto': 2,
}
security_assignmentMethod = enum.Enum('security_assignmentMethod', security_assignmentMethod_data)


security_contentAlignment_data = {
    'left': 0,
    'right': 1,
    'center': 2,
}
security_contentAlignment = enum.Enum('security_contentAlignment', security_contentAlignment_data)


security_contentState_data = {
    'rest': 0,
    'motion': 1,
    'use': 2,
}
security_contentState = enum.Enum('security_contentState', security_contentState_data)


security_watermarkLayout_data = {
    'horizontal': 0,
    'diagonal': 1,
}
security_watermarkLayout = enum.Enum('security_watermarkLayout', security_watermarkLayout_data)


security_auditLogQueryStatus_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'cancelled': 4,
    'unknownFutureValue': 5,
}
security_auditLogQueryStatus = enum.Enum('security_auditLogQueryStatus', security_auditLogQueryStatus_data)


security_auditLogRecordType_data = {
    'ExchangeAdmin': 1,
    'ExchangeItem': 2,
    'ExchangeItemGroup': 3,
    'SharePoint': 4,
    'SyntheticProbe': 5,
    'SharePointFileOperation': 6,
    'OneDrive': 7,
    'AzureActiveDirectory': 8,
    'AzureActiveDirectoryAccountLogon': 9,
    'DataCenterSecurityCmdlet': 10,
    'ComplianceDLPSharePoint': 11,
    'Sway': 12,
    'ComplianceDLPExchange': 13,
    'SharePointSharingOperation': 14,
    'AzureActiveDirectoryStsLogon': 15,
    'SkypeForBusinessPSTNUsage': 16,
    'SkypeForBusinessUsersBlocked': 17,
    'SecurityComplianceCenterEOPCmdlet': 18,
    'ExchangeAggregatedOperation': 19,
    'PowerBIAudit': 20,
    'CRM': 21,
    'Yammer': 22,
    'SkypeForBusinessCmdlets': 23,
    'Discovery': 24,
    'MicrosoftTeams': 25,
    'ThreatIntelligence': 28,
    'MailSubmission': 29,
    'MicrosoftFlow': 30,
    'AeD': 31,
    'MicrosoftStream': 32,
    'ComplianceDLPSharePointClassification': 33,
    'ThreatFinder': 34,
    'Project': 35,
    'SharePointListOperation': 36,
    'SharePointCommentOperation': 37,
    'DataGovernance': 38,
    'Kaizala': 39,
    'SecurityComplianceAlerts': 40,
    'ThreatIntelligenceUrl': 41,
    'SecurityComplianceInsights': 42,
    'MIPLabel': 43,
    'WorkplaceAnalytics': 44,
    'PowerAppsApp': 45,
    'PowerAppsPlan': 46,
    'ThreatIntelligenceAtpContent': 47,
    'LabelContentExplorer': 48,
    'TeamsHealthcare': 49,
    'ExchangeItemAggregated': 50,
    'HygieneEvent': 51,
    'DataInsightsRestApiAudit': 52,
    'InformationBarrierPolicyApplication': 53,
    'SharePointListItemOperation': 54,
    'SharePointContentTypeOperation': 55,
    'SharePointFieldOperation': 56,
    'MicrosoftTeamsAdmin': 57,
    'HRSignal': 58,
    'MicrosoftTeamsDevice': 59,
    'MicrosoftTeamsAnalytics': 60,
    'InformationWorkerProtection': 61,
    'Campaign': 62,
    'DLPEndpoint': 63,
    'AirInvestigation': 64,
    'Quarantine': 65,
    'MicrosoftForms': 66,
    'ApplicationAudit': 67,
    'ComplianceSupervisionExchange': 68,
    'CustomerKeyServiceEncryption': 69,
    'OfficeNative': 70,
    'MipAutoLabelSharePointItem': 71,
    'MipAutoLabelSharePointPolicyLocation': 72,
    'MicrosoftTeamsShifts': 73,
    'SecureScore': 74,
    'MipAutoLabelExchangeItem': 75,
    'CortanaBriefing': 76,
    'Search': 77,
    'WDATPAlerts': 78,
    'PowerPlatformAdminDlp': 79,
    'PowerPlatformAdminEnvironment': 80,
    'MDATPAudit': 81,
    'SensitivityLabelPolicyMatch': 82,
    'SensitivityLabelAction': 83,
    'SensitivityLabeledFileAction': 84,
    'AttackSim': 85,
    'AirManualInvestigation': 86,
    'SecurityComplianceRBAC': 87,
    'UserTraining': 88,
    'AirAdminActionInvestigation': 89,
    'MSTIC': 90,
    'PhysicalBadgingSignal': 91,
    'TeamsEasyApprovals': 92,
    'AipDiscover': 93,
    'AipSensitivityLabelAction': 94,
    'AipProtectionAction': 95,
    'AipFileDeleted': 96,
    'AipHeartBeat': 97,
    'MCASAlerts': 98,
    'OnPremisesFileShareScannerDlp': 99,
    'OnPremisesSharePointScannerDlp': 100,
    'ExchangeSearch': 101,
    'SharePointSearch': 102,
    'PrivacyDataMinimization': 103,
    'LabelAnalyticsAggregate': 104,
    'MyAnalyticsSettings': 105,
    'SecurityComplianceUserChange': 106,
    'ComplianceDLPExchangeClassification': 107,
    'ComplianceDLPEndpoint': 108,
    'MipExactDataMatch': 109,
    'MSDEResponseActions': 110,
    'MSDEGeneralSettings': 111,
    'MSDEIndicatorsSettings': 112,
    'MS365DCustomDetection': 113,
    'MSDERolesSettings': 114,
    'MAPGAlerts': 115,
    'MAPGPolicy': 116,
    'MAPGRemediation': 117,
    'PrivacyRemediationAction': 118,
    'PrivacyDigestEmail': 119,
    'MipAutoLabelSimulationProgress': 120,
    'MipAutoLabelSimulationCompletion': 121,
    'MipAutoLabelProgressFeedback': 122,
    'DlpSensitiveInformationType': 123,
    'MipAutoLabelSimulationStatistics': 124,
    'LargeContentMetadata': 125,
    'Microsoft365Group': 126,
    'CDPMlInferencingResult': 127,
    'FilteringMailMetadata': 128,
    'CDPClassificationMailItem': 129,
    'CDPClassificationDocument': 130,
    'OfficeScriptsRunAction': 131,
    'FilteringPostMailDeliveryAction': 132,
    'CDPUnifiedFeedback': 133,
    'TenantAllowBlockList': 134,
    'ConsumptionResource': 135,
    'HealthcareSignal': 136,
    'DlpImportResult': 138,
    'CDPCompliancePolicyExecution': 139,
    'MultiStageDisposition': 140,
    'PrivacyDataMatch': 141,
    'FilteringDocMetadata': 142,
    'FilteringEmailFeatures': 143,
    'PowerBIDlp': 144,
    'FilteringUrlInfo': 145,
    'FilteringAttachmentInfo': 146,
    'CoreReportingSettings': 147,
    'ComplianceConnector': 148,
    'PowerPlatformLockboxResourceAccessRequest': 149,
    'PowerPlatformLockboxResourceCommand': 150,
    'CDPPredictiveCodingLabel': 151,
    'CDPCompliancePolicyUserFeedback': 152,
    'WebpageActivityEndpoint': 153,
    'OMEPortal': 154,
    'CMImprovementActionChange': 155,
    'FilteringUrlClick': 156,
    'MipLabelAnalyticsAuditRecord': 157,
    'FilteringEntityEvent': 158,
    'FilteringRuleHits': 159,
    'FilteringMailSubmission': 160,
    'LabelExplorer': 161,
    'MicrosoftManagedServicePlatform': 162,
    'PowerPlatformServiceActivity': 163,
    'ScorePlatformGenericAuditRecord': 164,
    'FilteringTimeTravelDocMetadata': 165,
    'Alert': 166,
    'AlertStatus': 167,
    'AlertIncident': 168,
    'IncidentStatus': 169,
    'Case': 170,
    'CaseInvestigation': 171,
    'RecordsManagement': 172,
    'PrivacyRemediation': 173,
    'DataShareOperation': 174,
    'CdpDlpSensitive': 175,
    'EHRConnector': 176,
    'FilteringMailGradingResult': 177,
    'PublicFolder': 178,
    'PrivacyTenantAuditHistoryRecord': 179,
    'AipScannerDiscoverEvent': 180,
    'EduDataLakeDownloadOperation': 181,
    'M365ComplianceConnector': 182,
    'MicrosoftGraphDataConnectOperation': 183,
    'MicrosoftPurview': 184,
    'FilteringEmailContentFeatures': 185,
    'PowerPagesSite': 186,
    'PowerAppsResource': 187,
    'PlannerPlan': 188,
    'PlannerCopyPlan': 189,
    'PlannerTask': 190,
    'PlannerRoster': 191,
    'PlannerPlanList': 192,
    'PlannerTaskList': 193,
    'PlannerTenantSettings': 194,
    'ProjectForTheWebProject': 195,
    'ProjectForTheWebTask': 196,
    'ProjectForTheWebRoadmap': 197,
    'ProjectForTheWebRoadmapItem': 198,
    'ProjectForTheWebProjectSettings': 199,
    'ProjectForTheWebRoadmapSettings': 200,
    'QuarantineMetadata': 201,
    'MicrosoftTodoAudit': 202,
    'TimeTravelFilteringDocMetadata': 203,
    'TeamsQuarantineMetadata': 204,
    'SharePointAppPermissionOperation': 205,
    'MicrosoftTeamsSensitivityLabelAction': 206,
    'FilteringTeamsMetadata': 207,
    'FilteringTeamsUrlInfo': 208,
    'FilteringTeamsPostDeliveryAction': 209,
    'MDCAssessments': 210,
    'MDCRegulatoryComplianceStandards': 211,
    'MDCRegulatoryComplianceControls': 212,
    'MDCRegulatoryComplianceAssessments': 213,
    'MDCSecurityConnectors': 214,
    'MDADataSecuritySignal': 215,
    'VivaGoals': 216,
    'FilteringRuntimeInfo': 217,
    'AttackSimAdmin': 218,
    'MicrosoftGraphDataConnectConsent': 219,
    'FilteringAtpDetonationInfo': 220,
    'PrivacyPortal': 221,
    'ManagedTenants': 222,
    'UnifiedSimulationMatchedItem': 223,
    'UnifiedSimulationSummary': 224,
    'UpdateQuarantineMetadata': 225,
    'MS365DSuppressionRule': 226,
    'PurviewDataMapOperation': 227,
    'FilteringUrlPostClickAction': 228,
    'IrmUserDefinedDetectionSignal': 229,
    'TeamsUpdates': 230,
    'PlannerRosterSensitivityLabel': 231,
    'MS365DIncident': 232,
    'FilteringDelistingMetadata': 233,
    'ComplianceDLPSharePointClassificationExtended': 234,
    'MicrosoftDefenderForIdentityAudit': 235,
    'SupervisoryReviewDayXInsight': 236,
    'DefenderExpertsforXDRAdmin': 237,
    'CDPEdgeBlockedMessage': 238,
    'HostedRpa': 239,
    'CdpContentExplorerAggregateRecord': 240,
    'CDPHygieneAttachmentInfo': 241,
    'CDPHygieneSummary': 242,
    'CDPPostMailDeliveryAction': 243,
    'CDPEmailFeatures': 244,
    'CDPHygieneUrlInfo': 245,
    'CDPUrlClick': 246,
    'CDPPackageManagerHygieneEvent': 247,
    'FilteringDocScan': 248,
    'TimeTravelFilteringDocScan': 249,
    'MAPGOnboard': 250,
    'VfamCreatePolicy': 251,
    'VfamUpdatePolicy': 252,
    'VfamDeletePolicy': 253,
    'M365DAAD': 254,
    'CdpColdCrawlStatus': 255,
    'PowerPlatformAdministratorActivity': 256,
    'Windows365CustomerLockbox': 257,
    'CdpResourceScopeChangeEvent': 258,
    'ComplianceCCExchangeExecutionResult': 259,
    'CdpOcrCostEstimatorRecord': 260,
    'CopilotInteraction': 261,
    'CdpOcrBillingRecord': 262,
    'ComplianceDLPApplications': 263,
    'UAMOperation': 264,
    'VivaLearning': 265,
    'VivaLearningAdmin': 266,
    'PurviewPolicyOperation': 267,
    'PurviewMetadataPolicyOperation': 268,
    'PeopleAdminSettings': 269,
    'CdpComplianceDLPExchangeClassification': 270,
    'CdpComplianceDLPSharePointClassification': 271,
    'FilteringBulkSenderInsightData': 272,
    'FilteringBulkThresholdInsightData': 273,
    'PrivacyOpenAccess': 274,
    'OWAAuth': 275,
    'ComplianceDLPApplicationsClassification': 276,
    'SharePointESignature': 277,
    'Dynamics365BusinessCentral': 278,
    'MeshWorlds': 279,
    'VivaPulseResponse': 280,
    'VivaPulseOrganizer': 281,
    'VivaPulseAdmin': 282,
    'VivaPulseReport': 283,
    'AIAppInteraction': 284,
    'ComplianceDLMExchange': 285,
    'ComplianceDLMSharePoint': 286,
    'ProjectForTheWebAssignedToMeSettings': 287,
    'CPSOperation': 288,
    'ComplianceDLPExchangeDiscovery': 289,
    'PurviewMCRecommendation': 290,
    'unknownFutureValue': 291,
}
security_auditLogRecordType = enum.Enum('security_auditLogRecordType', security_auditLogRecordType_data)


security_auditLogUserType_data = {
    'Regular': 0,
    'Reserved': 1,
    'Admin': 2,
    'DcAdmin': 3,
    'System': 4,
    'Application': 5,
    'ServicePrincipal': 6,
    'CustomPolicy': 7,
    'SystemPolicy': 8,
    'PartnerTechnician': 9,
    'Guest': 10,
    'unknownFutureValue': 11,
}
security_auditLogUserType = enum.Enum('security_auditLogUserType', security_auditLogUserType_data)


security_alertClassification_data = {
    'unknown': 0,
    'falsePositive': 10,
    'truePositive': 20,
    'informationalExpectedActivity': 30,
    'unknownFutureValue': 39,
}
security_alertClassification = enum.Enum('security_alertClassification', security_alertClassification_data)


security_alertDetermination_data = {
    'unknown': 0,
    'apt': 10,
    'malware': 20,
    'securityPersonnel': 30,
    'securityTesting': 40,
    'unwantedSoftware': 50,
    'other': 60,
    'multiStagedAttack': 70,
    'compromisedAccount': 80,
    'phishing': 90,
    'maliciousUserActivity': 100,
    'notMalicious': 110,
    'notEnoughDataToValidate': 120,
    'confirmedActivity': 130,
    'lineOfBusinessApplication': 140,
    'unknownFutureValue': 149,
}
security_alertDetermination = enum.Enum('security_alertDetermination', security_alertDetermination_data)


security_alertSeverity_data = {
    'unknown': 0,
    'informational': 32,
    'low': 64,
    'medium': 128,
    'high': 256,
    'unknownFutureValue': 511,
}
security_alertSeverity = enum.Enum('security_alertSeverity', security_alertSeverity_data)


security_alertStatus_data = {
    'unknown': 0,
    'new': 2,
    'inProgress': 4,
    'resolved': 8,
    'unknownFutureValue': 31,
}
security_alertStatus = enum.Enum('security_alertStatus', security_alertStatus_data)


security_containerPortProtocol_data = {
    'udp': 0,
    'tcp': 1,
    'sctp': 2,
    'unknownFutureValue': 3,
}
security_containerPortProtocol = enum.Enum('security_containerPortProtocol', security_containerPortProtocol_data)


security_defenderAvStatus_data = {
    'notReporting': 0,
    'disabled': 1,
    'notUpdated': 2,
    'updated': 3,
    'unknown': 4,
    'notSupported': 1000,
    'unknownFutureValue': 1023,
}
security_defenderAvStatus = enum.Enum('security_defenderAvStatus', security_defenderAvStatus_data)


security_detectionSource_data = {
    'unknown': 0,
    'microsoftDefenderForEndpoint': 1,
    'antivirus': 2,
    'smartScreen': 4,
    'customTi': 8,
    'microsoftDefenderForOffice365': 512,
    'automatedInvestigation': 1024,
    'microsoftThreatExperts': 2048,
    'customDetection': 4096,
    'microsoftDefenderForIdentity': 8192,
    'cloudAppSecurity': 16384,
    'microsoft365Defender': 32768,
    'azureAdIdentityProtection': 65536,
    'manual': 262144,
    'microsoftDataLossPrevention': 524288,
    'appGovernancePolicy': 1048576,
    'appGovernanceDetection': 2097152,
    'unknownFutureValue': 4194303,
    'microsoftDefenderForCloud': 4194304,
    'microsoftDefenderForIoT': 1073741833,
    'microsoftDefenderForServers': 1073741834,
    'microsoftDefenderForStorage': 1073741835,
    'microsoftDefenderForDNS': 1073741836,
    'microsoftDefenderForDatabases': 1073741837,
    'microsoftDefenderForContainers': 1073741838,
    'microsoftDefenderForNetwork': 1073741839,
    'microsoftDefenderForAppService': 1073741840,
    'microsoftDefenderForKeyVault': 1073741841,
    'microsoftDefenderForResourceManager': 1073741842,
    'microsoftDefenderForApiManagement': 1073741843,
    'nrtAlerts': 1073741844,
    'scheduledAlerts': 1073741845,
    'microsoftDefenderThreatIntelligenceAnalytics': 1073741846,
    'builtInMl': 1073741847,
    'microsoftInsiderRiskManagement': 1073741848,
    'microsoftSentinel': 268435456,
}
security_detectionSource = enum.Enum('security_detectionSource', security_detectionSource_data)


security_detectionStatus_data = {
    'detected': 0,
    'blocked': 1,
    'prevented': 2,
    'unknownFutureValue': 31,
}
security_detectionStatus = enum.Enum('security_detectionStatus', security_detectionStatus_data)


security_deviceAssetIdentifier_data = {
    'deviceId': 0,
    'deviceName': 1,
    'remoteDeviceName': 2,
    'targetDeviceName': 3,
    'destinationDeviceName': 4,
    'unknownFutureValue': 5,
}
security_deviceAssetIdentifier = enum.Enum('security_deviceAssetIdentifier', security_deviceAssetIdentifier_data)


security_deviceHealthStatus_data = {
    'active': 0,
    'inactive': 1,
    'impairedCommunication': 2,
    'noSensorData': 3,
    'noSensorDataImpairedCommunication': 4,
    'unknown': 5,
    'unknownFutureValue': 31,
}
security_deviceHealthStatus = enum.Enum('security_deviceHealthStatus', security_deviceHealthStatus_data)


security_deviceIdEntityIdentifier_data = {
    'deviceId': 1,
    'unknownFutureValue': 2,
}
security_deviceIdEntityIdentifier = enum.Enum('security_deviceIdEntityIdentifier', security_deviceIdEntityIdentifier_data)


security_deviceRiskScore_data = {
    'none': 0,
    'informational': 5,
    'low': 10,
    'medium': 20,
    'high': 30,
    'unknownFutureValue': 31,
}
security_deviceRiskScore = enum.Enum('security_deviceRiskScore', security_deviceRiskScore_data)


security_disableUserEntityIdentifier_data = {
    'accountSid': 1,
    'initiatingProcessAccountSid': 2,
    'requestAccountSid': 4,
    'onPremSid': 8,
    'unknownFutureValue': 16,
}
security_disableUserEntityIdentifier = enum.Enum('security_disableUserEntityIdentifier', security_disableUserEntityIdentifier_data)


security_emailEntityIdentifier_data = {
    'networkMessageId': 1,
    'recipientEmailAddress': 2,
    'unknownFutureValue': 4,
}
security_emailEntityIdentifier = enum.Enum('security_emailEntityIdentifier', security_emailEntityIdentifier_data)


security_evidenceRemediationStatus_data = {
    'none': 0,
    'remediated': 1,
    'prevented': 2,
    'blocked': 3,
    'notFound': 4,
    'unknownFutureValue': 5,
    'active': 6,
    'pendingApproval': 7,
    'declined': 8,
    'unremediated': 9,
    'running': 10,
    'partiallyRemediated': 11,
}
security_evidenceRemediationStatus = enum.Enum('security_evidenceRemediationStatus', security_evidenceRemediationStatus_data)


security_evidenceRole_data = {
    'unknown': 0,
    'contextual': 1,
    'scanned': 2,
    'source': 3,
    'destination': 4,
    'created': 5,
    'added': 6,
    'compromised': 7,
    'edited': 8,
    'attacked': 9,
    'attacker': 10,
    'commandAndControl': 11,
    'loaded': 12,
    'suspicious': 13,
    'policyViolator': 14,
    'unknownFutureValue': 31,
}
security_evidenceRole = enum.Enum('security_evidenceRole', security_evidenceRole_data)


security_evidenceVerdict_data = {
    'unknown': 0,
    'suspicious': 1,
    'malicious': 2,
    'noThreatsFound': 3,
    'unknownFutureValue': 4,
}
security_evidenceVerdict = enum.Enum('security_evidenceVerdict', security_evidenceVerdict_data)


security_fileEntityIdentifier_data = {
    'sha1': 1,
    'initiatingProcessSHA1': 2,
    'sha256': 4,
    'initiatingProcessSHA256': 8,
    'unknownFutureValue': 16,
}
security_fileEntityIdentifier = enum.Enum('security_fileEntityIdentifier', security_fileEntityIdentifier_data)


security_fileHashAlgorithm_data = {
    'unknown': 0,
    'md5': 1,
    'sha1': 2,
    'sha256': 3,
    'sha256ac': 4,
    'unknownFutureValue': 5,
}
security_fileHashAlgorithm = enum.Enum('security_fileHashAlgorithm', security_fileHashAlgorithm_data)


security_forceUserPasswordResetEntityIdentifier_data = {
    'accountSid': 1,
    'initiatingProcessAccountSid': 2,
    'requestAccountSid': 4,
    'onPremSid': 8,
    'unknownFutureValue': 16,
}
security_forceUserPasswordResetEntityIdentifier = enum.Enum('security_forceUserPasswordResetEntityIdentifier', security_forceUserPasswordResetEntityIdentifier_data)


security_googleCloudLocationType_data = {
    'unknown': 0,
    'regional': 1,
    'zonal': 2,
    'global': 3,
    'unknownFutureValue': 31,
}
security_googleCloudLocationType = enum.Enum('security_googleCloudLocationType', security_googleCloudLocationType_data)


security_huntingRuleErrorCode_data = {
    'queryExecutionFailed': 0,
    'queryExecutionThrottling': 1,
    'queryExceededResultSize': 2,
    'queryLimitsExceeded': 3,
    'queryTimeout': 4,
    'alertCreationFailed': 5,
    'alertReportNotFound': 6,
    'partialRowsFailed': 7,
    'unknownFutureValue': 8,
    'noImpactedEntity': 9,
}
security_huntingRuleErrorCode = enum.Enum('security_huntingRuleErrorCode', security_huntingRuleErrorCode_data)


security_huntingRuleRunStatus_data = {
    'running': 0,
    'completed': 1,
    'failed': 2,
    'partiallyFailed': 3,
    'unknownFutureValue': 4,
}
security_huntingRuleRunStatus = enum.Enum('security_huntingRuleRunStatus', security_huntingRuleRunStatus_data)


security_incidentStatus_data = {
    'active': 1,
    'resolved': 2,
    'inProgress': 4,
    'redirected': 64,
    'unknownFutureValue': 127,
    'awaitingAction': 128,
}
security_incidentStatus = enum.Enum('security_incidentStatus', security_incidentStatus_data)


security_ioTDeviceImportanceType_data = {
    'unknown': 0,
    'low': 1,
    'normal': 2,
    'high': 3,
    'unknownFutureValue': 4,
}
security_ioTDeviceImportanceType = enum.Enum('security_ioTDeviceImportanceType', security_ioTDeviceImportanceType_data)


security_isolationType_data = {
    'full': 0,
    'selective': 1,
    'unknownFutureValue': 2,
}
security_isolationType = enum.Enum('security_isolationType', security_isolationType_data)


security_kubernetesPlatform_data = {
    'unknown': 0,
    'aks': 1,
    'eks': 2,
    'gke': 3,
    'arc': 4,
    'unknownFutureValue': 5,
}
security_kubernetesPlatform = enum.Enum('security_kubernetesPlatform', security_kubernetesPlatform_data)


security_kubernetesServiceType_data = {
    'unknown': 0,
    'clusterIP': 1,
    'externalName': 2,
    'nodePort': 3,
    'loadBalancer': 4,
    'unknownFutureValue': 31,
}
security_kubernetesServiceType = enum.Enum('security_kubernetesServiceType', security_kubernetesServiceType_data)


security_mailboxAssetIdentifier_data = {
    'accountUpn': 0,
    'fileOwnerUpn': 1,
    'initiatingProcessAccountUpn': 2,
    'lastModifyingAccountUpn': 3,
    'targetAccountUpn': 4,
    'senderFromAddress': 5,
    'senderDisplayName': 6,
    'recipientEmailAddress': 7,
    'senderMailFromAddress': 8,
    'unknownFutureValue': 9,
}
security_mailboxAssetIdentifier = enum.Enum('security_mailboxAssetIdentifier', security_mailboxAssetIdentifier_data)


security_mailboxConfigurationType_data = {
    'mailForwardingRule': 0,
    'owaSettings': 1,
    'ewsSettings': 2,
    'mailDelegation': 3,
    'userInboxRule': 4,
    'unknownFutureValue': 31,
}
security_mailboxConfigurationType = enum.Enum('security_mailboxConfigurationType', security_mailboxConfigurationType_data)


security_markUserAsCompromisedEntityIdentifier_data = {
    'accountObjectId': 1,
    'initiatingProcessAccountObjectId': 2,
    'servicePrincipalId': 4,
    'recipientObjectId': 8,
    'unknownFutureValue': 16,
}
security_markUserAsCompromisedEntityIdentifier = enum.Enum('security_markUserAsCompromisedEntityIdentifier', security_markUserAsCompromisedEntityIdentifier_data)


security_onboardingStatus_data = {
    'insufficientInfo': 0,
    'onboarded': 1,
    'canBeOnboarded': 2,
    'unsupported': 3,
    'unknownFutureValue': 31,
}
security_onboardingStatus = enum.Enum('security_onboardingStatus', security_onboardingStatus_data)


security_protocolType_data = {
    'tcp': 0,
    'udp': 1,
    'unknownFutureValue': 2,
}
security_protocolType = enum.Enum('security_protocolType', security_protocolType_data)


security_scopeType_data = {
    'deviceGroup': 0,
    'unknownFutureValue': 1,
}
security_scopeType = enum.Enum('security_scopeType', security_scopeType_data)


security_servicePrincipalType_data = {
    'unknown': 0,
    'application': 1,
    'managedIdentity': 2,
    'legacy': 3,
    'unknownFutureValue': 4,
}
security_servicePrincipalType = enum.Enum('security_servicePrincipalType', security_servicePrincipalType_data)


security_serviceSource_data = {
    'unknown': 0,
    'microsoftDefenderForEndpoint': 1,
    'microsoftDefenderForIdentity': 2,
    'microsoftDefenderForCloudApps': 4,
    'microsoftDefenderForOffice365': 8,
    'microsoft365Defender': 16,
    'azureAdIdentityProtection': 32,
    'microsoftAppGovernance': 64,
    'dataLossPrevention': 128,
    'unknownFutureValue': 255,
    'microsoftDefenderForCloud': 256,
    'microsoftSentinel': 512,
    'microsoftInsiderRiskManagement': 1024,
}
security_serviceSource = enum.Enum('security_serviceSource', security_serviceSource_data)


security_stopAndQuarantineFileEntityIdentifier_data = {
    'deviceId': 1,
    'sha1': 2,
    'initiatingProcessSHA1': 4,
    'unknownFutureValue': 8,
}
security_stopAndQuarantineFileEntityIdentifier = enum.Enum('security_stopAndQuarantineFileEntityIdentifier', security_stopAndQuarantineFileEntityIdentifier_data)


security_userAssetIdentifier_data = {
    'accountObjectId': 0,
    'accountSid': 1,
    'accountUpn': 2,
    'accountName': 3,
    'accountDomain': 4,
    'accountId': 5,
    'requestAccountSid': 6,
    'requestAccountName': 7,
    'requestAccountDomain': 8,
    'recipientObjectId': 9,
    'processAccountObjectId': 10,
    'initiatingAccountSid': 11,
    'initiatingProcessAccountUpn': 12,
    'initiatingAccountName': 13,
    'initiatingAccountDomain': 14,
    'servicePrincipalId': 15,
    'servicePrincipalName': 16,
    'targetAccountUpn': 17,
    'unknownFutureValue': 18,
}
security_userAssetIdentifier = enum.Enum('security_userAssetIdentifier', security_userAssetIdentifier_data)


security_vmCloudProvider_data = {
    'unknown': 0,
    'azure': 1,
    'unknownFutureValue': 15,
}
security_vmCloudProvider = enum.Enum('security_vmCloudProvider', security_vmCloudProvider_data)


security_antispamDirectionality_data = {
    'unknown': 0,
    'inbound': 1,
    'outbound': 2,
    'intraOrg': 3,
    'unknownFutureValue': 127,
}
security_antispamDirectionality = enum.Enum('security_antispamDirectionality', security_antispamDirectionality_data)


security_deliveryAction_data = {
    'unknown': 0,
    'deliveredToJunk': 1,
    'delivered': 2,
    'blocked': 3,
    'replaced': 4,
    'unknownFutureValue': 127,
}
security_deliveryAction = enum.Enum('security_deliveryAction', security_deliveryAction_data)


security_deliveryLocation_data = {
    'unknown': 0,
    'inbox_folder': 1,
    'junkFolder': 2,
    'deletedFolder': 3,
    'quarantine': 4,
    'onprem_external': 5,
    'failed': 6,
    'dropped': 7,
    'others': 10,
    'unknownFutureValue': 127,
}
security_deliveryLocation = enum.Enum('security_deliveryLocation', security_deliveryLocation_data)


security_eventSource_data = {
    'system': 0,
    'admin': 1,
    'user': 2,
    'unknownFutureValue': 127,
}
security_eventSource = enum.Enum('security_eventSource', security_eventSource_data)


security_remediationAction_data = {
    'moveToJunk': 1,
    'moveToInbox': 2,
    'hardDelete': 5,
    'softDelete': 6,
    'moveToDeletedItems': 7,
    'unknownFutureValue': 127,
}
security_remediationAction = enum.Enum('security_remediationAction', security_remediationAction_data)


security_remediationSeverity_data = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'unknownFutureValue': 127,
}
security_remediationSeverity = enum.Enum('security_remediationSeverity', security_remediationSeverity_data)


security_threatType_data = {
    'unknown': 0,
    'spam': 1,
    'malware': 2,
    'phish': 3,
    'none': 4,
    'unknownFutureValue': 127,
}
security_threatType = enum.Enum('security_threatType', security_threatType_data)


security_timelineEventType_data = {
    'originalDelivery': 0,
    'systemTimeTravel': 1,
    'dynamicDelivery': 2,
    'userUrlClick': 3,
    'reprocessed': 4,
    'zap': 5,
    'quarantineRelease': 6,
    'air': 7,
    'unknown': 8,
    'unknownFutureValue': 127,
}
security_timelineEventType = enum.Enum('security_timelineEventType', security_timelineEventType_data)


security_verdictCategory_data = {
    'none': 0,
    'malware': 1,
    'phish': 2,
    'siteUnavailable': 3,
    'spam': 4,
    'decryptionFailed': 5,
    'unsupportedUriScheme': 6,
    'unsupportedFileType': 7,
    'undefined': 8,
    'unknownFutureValue': 127,
}
security_verdictCategory = enum.Enum('security_verdictCategory', security_verdictCategory_data)


security_actionAfterRetentionPeriod_data = {
    'none': 0,
    'delete': 1,
    'startDispositionReview': 2,
    'relabel': 3,
    'unknownFutureValue': 4,
}
security_actionAfterRetentionPeriod = enum.Enum('security_actionAfterRetentionPeriod', security_actionAfterRetentionPeriod_data)


security_defaultRecordBehavior_data = {
    'startLocked': 0,
    'startUnlocked': 1,
    'unknownFutureValue': 2,
}
security_defaultRecordBehavior = enum.Enum('security_defaultRecordBehavior', security_defaultRecordBehavior_data)


security_eventPropagationStatus_data = {
    'none': 0,
    'inProcessing': 1,
    'failed': 2,
    'success': 3,
    'unknownFutureValue': 4,
}
security_eventPropagationStatus = enum.Enum('security_eventPropagationStatus', security_eventPropagationStatus_data)


security_eventStatusType_data = {
    'pending': 0,
    'error': 1,
    'success': 2,
    'notAvaliable': 3,
    'unknownFutureValue': 4,
}
security_eventStatusType = enum.Enum('security_eventStatusType', security_eventStatusType_data)


security_queryType_data = {
    'files': 0,
    'messages': 1,
    'unknownFutureValue': 2,
}
security_queryType = enum.Enum('security_queryType', security_queryType_data)


security_retentionTrigger_data = {
    'dateLabeled': 0,
    'dateCreated': 1,
    'dateModified': 2,
    'dateOfEvent': 3,
    'unknownFutureValue': 4,
}
security_retentionTrigger = enum.Enum('security_retentionTrigger', security_retentionTrigger_data)


security_longRunningOperationStatus_data = {
    'notStarted': 0,
    'running': 1,
    'succeeded': 2,
    'failed': 3,
    'skipped': 4,
    'unknownFutureValue': 5,
}
security_longRunningOperationStatus = enum.Enum('security_longRunningOperationStatus', security_longRunningOperationStatus_data)


security_submissionCategory_data = {
    'notJunk': 0,
    'spam': 1,
    'phishing': 2,
    'malware': 3,
    'unknownFutureValue': 4,
}
security_submissionCategory = enum.Enum('security_submissionCategory', security_submissionCategory_data)


security_submissionClientSource_data = {
    'microsoft': 0,
    'other': 1,
    'unknownFutureValue': 2,
}
security_submissionClientSource = enum.Enum('security_submissionClientSource', security_submissionClientSource_data)


security_submissionContentType_data = {
    'email': 0,
    'url': 1,
    'file': 2,
    'app': 3,
    'unknownFutureValue': 4,
}
security_submissionContentType = enum.Enum('security_submissionContentType', security_submissionContentType_data)


security_submissionResultCategory_data = {
    'notJunk': 0,
    'spam': 1,
    'phishing': 2,
    'malware': 3,
    'allowedByPolicy': 4,
    'blockedByPolicy': 5,
    'spoof': 6,
    'unknown': 7,
    'noResultAvailable': 8,
    'unknownFutureValue': 9,
    'beingAnalyzed': 10,
    'notSubmittedToMicrosoft': 11,
    'phishingSimulation': 12,
    'allowedDueToOrganizationOverride': 13,
    'blockedDueToOrganizationOverride': 14,
    'allowedDueToUserOverride': 15,
    'blockedDueToUserOverride': 16,
    'itemNotfound': 17,
    'threatsFound': 18,
    'noThreatsFound': 19,
    'domainImpersonation': 20,
    'userImpersonation': 21,
    'brandImpersonation': 22,
    'authenticationFailure': 23,
    'spoofedBlocked': 24,
    'spoofedAllowed': 25,
    'reasonLostInTransit': 26,
    'bulk': 27,
}
security_submissionResultCategory = enum.Enum('security_submissionResultCategory', security_submissionResultCategory_data)


security_submissionResultDetail_data = {
    'none': 0,
    'underInvestigation': 1,
    'simulatedThreat': 2,
    'allowedBySecOps': 3,
    'allowedByThirdPartyFilters': 4,
    'messageNotFound': 5,
    'urlFileShouldNotBeBlocked': 6,
    'urlFileShouldBeBlocked': 7,
    'urlFileCannotMakeDecision': 8,
    'domainImpersonation': 9,
    'userImpersonation': 10,
    'brandImpersonation': 11,
    'outboundShouldNotBeBlocked': 12,
    'outboundShouldBeBlocked': 13,
    'outboundBulk': 14,
    'outboundCannotMakeDecision': 15,
    'outboundNotRescanned': 16,
    'zeroHourAutoPurgeAllowed': 17,
    'zeroHourAutoPurgeBlocked': 18,
    'zeroHourAutoPurgeQuarantineReleased': 19,
    'onPremisesSkip': 20,
    'allowedByTenantAllowBlockList': 21,
    'blockedByTenantAllowBlockList': 22,
    'allowedUrlByTenantAllowBlockList': 23,
    'allowedFileByTenantAllowBlockList': 24,
    'allowedSenderByTenantAllowBlockList': 25,
    'allowedRecipientByTenantAllowBlockList': 26,
    'blockedUrlByTenantAllowBlockList': 27,
    'blockedFileByTenantAllowBlockList': 28,
    'blockedSenderByTenantAllowBlockList': 29,
    'blockedRecipientByTenantAllowBlockList': 30,
    'allowedByConnection': 31,
    'blockedByConnection': 32,
    'allowedByExchangeTransportRule': 33,
    'blockedByExchangeTransportRule': 34,
    'quarantineReleased': 35,
    'quarantineReleasedThenBlocked': 36,
    'junkMailRuleDisabled': 37,
    'allowedByUserSetting': 38,
    'blockedByUserSetting': 39,
    'allowedByTenant': 40,
    'blockedByTenant': 41,
    'invalidFalsePositive': 42,
    'invalidFalseNegative': 43,
    'spoofBlocked': 44,
    'goodReclassifiedAsBad': 45,
    'goodReclassifiedAsBulk': 46,
    'goodReclassifiedAsGood': 47,
    'goodReclassifiedAsCannotMakeDecision': 48,
    'badReclassifiedAsGood': 49,
    'badReclassifiedAsBulk': 50,
    'badReclassifiedAsBad': 51,
    'badReclassifiedAsCannotMakeDecision': 52,
    'unknownFutureValue': 53,
    'willNotifyOnceDone': 54,
    'checkUserReportedSettings': 55,
    'partOfEducationCampaign': 56,
    'allowedByAdvancedDelivery': 57,
    'allowedByEnhancedFiltering': 58,
    'itemDeleted': 59,
    'itemFoundClean': 60,
    'itemFoundMalicious': 61,
    'unableToMakeDecision': 62,
    'domainResembledYourOrganization': 63,
    'endUserBeingImpersonated': 64,
    'associatedWithBrand': 65,
    'senderFailedAuthentication': 66,
    'endUserBeingSpoofed': 67,
    'itemFoundBulk': 68,
    'itemNotReceivedByService': 69,
    'itemFoundSpam': 70,
}
security_submissionResultDetail = enum.Enum('security_submissionResultDetail', security_submissionResultDetail_data)


security_submissionSource_data = {
    'user': 0,
    'administrator': 1,
    'unknownFutureValue': 2,
}
security_submissionSource = enum.Enum('security_submissionSource', security_submissionSource_data)


security_tenantAllowBlockListAction_data = {
    'allow': 0,
    'block': 1,
    'unknownFutureValue': 2,
}
security_tenantAllowBlockListAction = enum.Enum('security_tenantAllowBlockListAction', security_tenantAllowBlockListAction_data)


security_tenantAllowBlockListEntryType_data = {
    'url': 0,
    'fileHash': 1,
    'sender': 2,
    'recipient': 3,
    'unknownFutureValue': 4,
}
security_tenantAllowBlockListEntryType = enum.Enum('security_tenantAllowBlockListEntryType', security_tenantAllowBlockListEntryType_data)


security_userMailboxSetting_data = {
    'none': 0,
    'junkMailDeletion': 1,
    'isFromAddressInAddressBook': 2,
    'isFromAddressInAddressSafeList': 4,
    'isFromAddressInAddressBlockList': 8,
    'isFromAddressInAddressImplicitSafeList': 16,
    'isFromAddressInAddressImplicitJunkList': 32,
    'isFromDomainInDomainSafeList': 64,
    'isFromDomainInDomainBlockList': 128,
    'isRecipientInRecipientSafeList': 256,
    'customRule': 512,
    'junkMailRule': 1024,
    'senderPraPresent': 2048,
    'fromFirstTimeSender': 4096,
    'exclusive': 8192,
    'priorSeenPass': 16384,
    'senderAuthenticationSucceeded': 32768,
    'isJunkMailRuleEnabled': 65536,
    'unknownFutureValue': 131072,
}
security_userMailboxSetting = enum.Enum('security_userMailboxSetting', security_userMailboxSetting_data)


security_contentFormat_data = {
    'text': 0,
    'html': 1,
    'markdown': 2,
    'unknownFutureValue': 3,
}
security_contentFormat = enum.Enum('security_contentFormat', security_contentFormat_data)


security_hostPortProtocol_data = {
    'tcp': 0,
    'udp': 1,
    'unknownFutureValue': 2,
}
security_hostPortProtocol = enum.Enum('security_hostPortProtocol', security_hostPortProtocol_data)


security_hostPortStatus_data = {
    'open': 0,
    'filtered': 1,
    'closed': 2,
    'unknownFutureValue': 3,
}
security_hostPortStatus = enum.Enum('security_hostPortStatus', security_hostPortStatus_data)


security_hostReputationClassification_data = {
    'unknown': 0,
    'neutral': 1,
    'suspicious': 2,
    'malicious': 3,
    'unknownFutureValue': 4,
}
security_hostReputationClassification = enum.Enum('security_hostReputationClassification', security_hostReputationClassification_data)


security_hostReputationRuleSeverity_data = {
    'unknown': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'unknownFutureValue': 4,
}
security_hostReputationRuleSeverity = enum.Enum('security_hostReputationRuleSeverity', security_hostReputationRuleSeverity_data)


security_indicatorSource_data = {
    'microsoft': 0,
    'osint': 1,
    'public': 2,
    'unknownFutureValue': 3,
}
security_indicatorSource = enum.Enum('security_indicatorSource', security_indicatorSource_data)


security_intelligenceProfileKind_data = {
    'actor': 0,
    'tool': 1,
    'unknownFutureValue': 2,
}
security_intelligenceProfileKind = enum.Enum('security_intelligenceProfileKind', security_intelligenceProfileKind_data)


security_vulnerabilitySeverity_data = {
    'none': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
    'unknownFutureValue': 5,
}
security_vulnerabilitySeverity = enum.Enum('security_vulnerabilitySeverity', security_vulnerabilitySeverity_data)


security_whoisDomainStatus_data = {
    'clientDeleteProhibited': 0,
    'clientHold': 1,
    'clientRenewProhibited': 2,
    'clientTransferProhibited': 3,
    'clientUpdateProhibited': 4,
    'unknownFutureValue': 5,
}
security_whoisDomainStatus = enum.Enum('security_whoisDomainStatus', security_whoisDomainStatus_data)


deviceManagement_aggregationType_data = {
    'count': 0,
    'percentage': 1,
    'affectedCloudPcCount': 2,
    'affectedCloudPcPercentage': 3,
    'unknownFutureValue': 4,
    'durationInMinutes': 5,
}
deviceManagement_aggregationType = enum.Enum('deviceManagement_aggregationType', deviceManagement_aggregationType_data)


deviceManagement_alertRuleTemplate_data = {
    'cloudPcProvisionScenario': 0,
    'cloudPcImageUploadScenario': 1,
    'cloudPcOnPremiseNetworkConnectionCheckScenario': 2,
    'unknownFutureValue': 3,
    'cloudPcInGracePeriodScenario': 4,
    'cloudPcFrontlineInsufficientLicensesScenario': 5,
    'cloudPcInaccessibleScenario': 6,
    'cloudPcFrontlineConcurrencyScenario': 7,
}
deviceManagement_alertRuleTemplate = enum.Enum('deviceManagement_alertRuleTemplate', deviceManagement_alertRuleTemplate_data)


deviceManagement_alertStatusType_data = {
    'active': 0,
    'resolved': 1,
    'unknownFutureValue': 999,
}
deviceManagement_alertStatusType = enum.Enum('deviceManagement_alertStatusType', deviceManagement_alertStatusType_data)


deviceManagement_conditionCategory_data = {
    'provisionFailures': 0,
    'imageUploadFailures': 1,
    'azureNetworkConnectionCheckFailures': 2,
    'cloudPcInGracePeriod': 3,
    'frontlineInsufficientLicenses': 4,
    'cloudPcConnectionErrors': 5,
    'cloudPcHostHealthCheckFailures': 6,
    'cloudPcZoneOutage': 7,
    'unknownFutureValue': 8,
    'frontlineBufferUsageDuration': 9,
    'frontlineBufferUsageThreshold': 10,
}
deviceManagement_conditionCategory = enum.Enum('deviceManagement_conditionCategory', deviceManagement_conditionCategory_data)


deviceManagement_notificationChannelType_data = {
    'portal': 0,
    'email': 1,
    'phoneCall': 2,
    'sms': 3,
    'unknownFutureValue': 4,
}
deviceManagement_notificationChannelType = enum.Enum('deviceManagement_notificationChannelType', deviceManagement_notificationChannelType_data)


deviceManagement_operatorType_data = {
    'greaterOrEqual': 0,
    'equal': 1,
    'greater': 2,
    'less': 3,
    'lessOrEqual': 4,
    'notEqual': 5,
    'unknownFutureValue': 6,
}
deviceManagement_operatorType = enum.Enum('deviceManagement_operatorType', deviceManagement_operatorType_data)


deviceManagement_relationshipType_data = {
    'and': 0,
    'or': 1,
    'unknownFutureValue': 2,
}
deviceManagement_relationshipType = enum.Enum('deviceManagement_relationshipType', deviceManagement_relationshipType_data)


deviceManagement_ruleSeverityType_data = {
    'unknown': 0,
    'informational': 1,
    'warning': 2,
    'critical': 3,
    'unknownFutureValue': 4,
}
deviceManagement_ruleSeverityType = enum.Enum('deviceManagement_ruleSeverityType', deviceManagement_ruleSeverityType_data)


termStore_relationType_data = {
    'pin': 0,
    'reuse': 1,
}
termStore_relationType = enum.Enum('termStore_relationType', termStore_relationType_data)


termStore_termGroupScope_data = {
    'global': 0,
    'system': 1,
    'siteCollection': 2,
}
termStore_termGroupScope = enum.Enum('termStore_termGroupScope', termStore_termGroupScope_data)


callRecords_audioCodec_data = {
    'unknown': 0,
    'invalid': 1,
    'cn': 2,
    'pcma': 3,
    'pcmu': 4,
    'amrWide': 5,
    'g722': 6,
    'g7221': 7,
    'g7221c': 8,
    'g729': 9,
    'multiChannelAudio': 10,
    'muchv2': 11,
    'opus': 12,
    'satin': 13,
    'satinFullband': 14,
    'rtAudio8': 15,
    'rtAudio16': 16,
    'silk': 17,
    'silkNarrow': 18,
    'silkWide': 19,
    'siren': 20,
    'xmsRta': 21,
    'unknownFutureValue': 22,
}
callRecords_audioCodec = enum.Enum('callRecords_audioCodec', callRecords_audioCodec_data)


callRecords_callType_data = {
    'unknown': 0,
    'groupCall': 1,
    'peerToPeer': 2,
    'unknownFutureValue': 3,
}
callRecords_callType = enum.Enum('callRecords_callType', callRecords_callType_data)


callRecords_clientPlatform_data = {
    'unknown': 0,
    'windows': 1,
    'macOS': 2,
    'iOS': 3,
    'android': 4,
    'web': 5,
    'ipPhone': 6,
    'roomSystem': 7,
    'surfaceHub': 8,
    'holoLens': 9,
    'unknownFutureValue': 10,
}
callRecords_clientPlatform = enum.Enum('callRecords_clientPlatform', callRecords_clientPlatform_data)


callRecords_failureStage_data = {
    'unknown': 0,
    'callSetup': 1,
    'midcall': 2,
    'unknownFutureValue': 3,
}
callRecords_failureStage = enum.Enum('callRecords_failureStage', callRecords_failureStage_data)


callRecords_mediaStreamDirection_data = {
    'callerToCallee': 0,
    'calleeToCaller': 1,
}
callRecords_mediaStreamDirection = enum.Enum('callRecords_mediaStreamDirection', callRecords_mediaStreamDirection_data)


callRecords_modality_data = {
    'audio': 0,
    'video': 1,
    'videoBasedScreenSharing': 2,
    'data': 3,
    'screenSharing': 4,
    'unknownFutureValue': 5,
}
callRecords_modality = enum.Enum('callRecords_modality', callRecords_modality_data)


callRecords_networkConnectionType_data = {
    'unknown': 0,
    'wired': 1,
    'wifi': 2,
    'mobile': 3,
    'tunnel': 4,
    'unknownFutureValue': 5,
}
callRecords_networkConnectionType = enum.Enum('callRecords_networkConnectionType', callRecords_networkConnectionType_data)


callRecords_networkTransportProtocol_data = {
    'unknown': 0,
    'udp': 1,
    'tcp': 2,
    'unknownFutureValue': 3,
}
callRecords_networkTransportProtocol = enum.Enum('callRecords_networkTransportProtocol', callRecords_networkTransportProtocol_data)


callRecords_productFamily_data = {
    'unknown': 0,
    'teams': 1,
    'skypeForBusiness': 2,
    'lync': 3,
    'unknownFutureValue': 4,
    'azureCommunicationServices': 5,
}
callRecords_productFamily = enum.Enum('callRecords_productFamily', callRecords_productFamily_data)


callRecords_pstnCallDurationSource_data = {
    'microsoft': 0,
    'operator': 1,
}
callRecords_pstnCallDurationSource = enum.Enum('callRecords_pstnCallDurationSource', callRecords_pstnCallDurationSource_data)


callRecords_pstnUserBlockMode_data = {
    'blocked': 0,
    'unblocked': 1,
    'unknownFutureValue': 2,
}
callRecords_pstnUserBlockMode = enum.Enum('callRecords_pstnUserBlockMode', callRecords_pstnUserBlockMode_data)


callRecords_serviceRole_data = {
    'unknown': 0,
    'customBot': 1,
    'skypeForBusinessMicrosoftTeamsGateway': 2,
    'skypeForBusinessAudioVideoMcu': 3,
    'skypeForBusinessApplicationSharingMcu': 4,
    'skypeForBusinessCallQueues': 5,
    'skypeForBusinessAutoAttendant': 6,
    'mediationServer': 7,
    'mediationServerCloudConnectorEdition': 8,
    'exchangeUnifiedMessagingService': 9,
    'mediaController': 10,
    'conferencingAnnouncementService': 11,
    'conferencingAttendant': 12,
    'audioTeleconferencerController': 13,
    'skypeForBusinessUnifiedCommunicationApplicationPlatform': 14,
    'responseGroupServiceAnnouncementService': 15,
    'gateway': 16,
    'skypeTranslator': 17,
    'skypeForBusinessAttendant': 18,
    'responseGroupService': 19,
    'voicemail': 20,
    'unknownFutureValue': 21,
}
callRecords_serviceRole = enum.Enum('callRecords_serviceRole', callRecords_serviceRole_data)


callRecords_userFeedbackRating_data = {
    'notRated': 0,
    'bad': 1,
    'poor': 2,
    'fair': 3,
    'good': 4,
    'excellent': 5,
    'unknownFutureValue': 6,
}
callRecords_userFeedbackRating = enum.Enum('callRecords_userFeedbackRating', callRecords_userFeedbackRating_data)


callRecords_videoCodec_data = {
    'unknown': 0,
    'invalid': 1,
    'av1': 2,
    'h263': 3,
    'h264': 4,
    'h264s': 5,
    'h264uc': 6,
    'h265': 7,
    'rtvc1': 8,
    'rtVideo': 9,
    'xrtvc1': 10,
    'unknownFutureValue': 11,
}
callRecords_videoCodec = enum.Enum('callRecords_videoCodec', callRecords_videoCodec_data)


callRecords_wifiBand_data = {
    'unknown': 0,
    'frequency24GHz': 1,
    'frequency50GHz': 2,
    'frequency60GHz': 3,
    'unknownFutureValue': 4,
}
callRecords_wifiBand = enum.Enum('callRecords_wifiBand', callRecords_wifiBand_data)


callRecords_wifiRadioType_data = {
    'unknown': 0,
    'wifi80211a': 1,
    'wifi80211b': 2,
    'wifi80211g': 3,
    'wifi80211n': 4,
    'wifi80211ac': 5,
    'wifi80211ax': 6,
    'unknownFutureValue': 7,
}
callRecords_wifiRadioType = enum.Enum('callRecords_wifiRadioType', callRecords_wifiRadioType_data)


teamsAdministration_accountType_data = {
    'user': 0,
    'resourceAccount': 1,
    'guest': 2,
    'sfbOnPremUser': 3,
    'unknown': 4,
    'unknownFutureValue': 5,
}
teamsAdministration_accountType = enum.Enum('teamsAdministration_accountType', teamsAdministration_accountType_data)


teamsAdministration_assignmentCategory_data = {
    'primary': 0,
    'private': 1,
    'alternate': 2,
    'unknownFutureValue': 3,
}
teamsAdministration_assignmentCategory = enum.Enum('teamsAdministration_assignmentCategory', teamsAdministration_assignmentCategory_data)


teamsAdministration_assignmentType_data = {
    'direct': 0,
    'group': 1,
    'unknownFutureValue': 2,
}
teamsAdministration_assignmentType = enum.Enum('teamsAdministration_assignmentType', teamsAdministration_assignmentType_data)


industryData_additionalClassGroupAttributes_data = {
    'courseTitle': 0,
    'courseCode': 1,
    'courseSubject': 2,
    'courseGradeLevel': 3,
    'courseExternalId': 4,
    'academicSessionTitle': 5,
    'academicSessionExternalId': 6,
    'classCode': 7,
    'unknownFutureValue': 8,
}
industryData_additionalClassGroupAttributes = enum.Enum('industryData_additionalClassGroupAttributes', industryData_additionalClassGroupAttributes_data)


industryData_additionalUserAttributes_data = {
    'userGradeLevel': 0,
    'userNumber': 1,
    'unknownFutureValue': 2,
}
industryData_additionalUserAttributes = enum.Enum('industryData_additionalUserAttributes', industryData_additionalUserAttributes_data)


industryData_apiFormat_data = {
    'oneRoster': 0,
    'unknownFutureValue': 1,
}
industryData_apiFormat = enum.Enum('industryData_apiFormat', industryData_apiFormat_data)


industryData_filterOptions_data = {
    'orgExternalId': 1,
    'unknownFutureValue': 2,
}
industryData_filterOptions = enum.Enum('industryData_filterOptions', industryData_filterOptions_data)


industryData_inboundDomain_data = {
    'educationRostering': 0,
    'unknownFutureValue': 1,
}
industryData_inboundDomain = enum.Enum('industryData_inboundDomain', industryData_inboundDomain_data)


industryData_industryDataActivityStatus_data = {
    'inProgress': 0,
    'skipped': 1,
    'failed': 2,
    'completed': 3,
    'completedWithErrors': 4,
    'completedWithWarnings': 5,
    'unknownFutureValue': 6,
}
industryData_industryDataActivityStatus = enum.Enum('industryData_industryDataActivityStatus', industryData_industryDataActivityStatus_data)


industryData_industryDataRunStatus_data = {
    'running': 0,
    'failed': 1,
    'completed': 2,
    'completedWithErrors': 3,
    'completedWithWarnings': 4,
    'unknownFutureValue': 5,
}
industryData_industryDataRunStatus = enum.Enum('industryData_industryDataRunStatus', industryData_industryDataRunStatus_data)


industryData_readinessStatus_data = {
    'notReady': 0,
    'ready': 1,
    'failed': 2,
    'disabled': 3,
    'expired': 4,
    'unknownFutureValue': 5,
}
industryData_readinessStatus = enum.Enum('industryData_readinessStatus', industryData_readinessStatus_data)


managedTenants_alertSeverity_data = {
    'unknown': 0,
    'informational': 1,
    'low': 2,
    'medium': 3,
    'high': 4,
    'unknownFutureValue': 5,
}
managedTenants_alertSeverity = enum.Enum('managedTenants_alertSeverity', managedTenants_alertSeverity_data)


managedTenants_alertStatus_data = {
    'unknown': 0,
    'newAlert': 1,
    'inProgress': 2,
    'resolved': 3,
    'dismissed': 4,
    'unknownFutureValue': 5,
}
managedTenants_alertStatus = enum.Enum('managedTenants_alertStatus', managedTenants_alertStatus_data)


managedTenants_delegatedPrivilegeStatus_data = {
    'none': 0,
    'delegatedAdminPrivileges': 1,
    'unknownFutureValue': 2,
    'granularDelegatedAdminPrivileges': 3,
    'delegatedAndGranularDelegetedAdminPrivileges': 4,
}
managedTenants_delegatedPrivilegeStatus = enum.Enum('managedTenants_delegatedPrivilegeStatus', managedTenants_delegatedPrivilegeStatus_data)


managedTenants_managementActionStatus_data = {
    'toAddress': 0,
    'completed': 5,
    'error': 10,
    'timeOut': 15,
    'inProgress': 20,
    'planned': 25,
    'resolvedBy3rdParty': 30,
    'resolvedThroughAlternateMitigation': 35,
    'riskAccepted': 40,
    'unknownFutureValue': 45,
}
managedTenants_managementActionStatus = enum.Enum('managedTenants_managementActionStatus', managedTenants_managementActionStatus_data)


managedTenants_managementCategory_data = {
    'custom': 0,
    'devices': 1,
    'identity': 2,
    'data': 3,
    'unknownFutureValue': 4,
}
managedTenants_managementCategory = enum.Enum('managedTenants_managementCategory', managedTenants_managementCategory_data)


managedTenants_managementParameterValueType_data = {
    'string': 0,
    'integer': 1,
    'boolean': 2,
    'guid': 3,
    'stringCollection': 4,
    'integerCollection': 5,
    'booleanCollection': 6,
    'guidCollection': 7,
    'unknownFutureValue': 8,
}
managedTenants_managementParameterValueType = enum.Enum('managedTenants_managementParameterValueType', managedTenants_managementParameterValueType_data)


managedTenants_managementProvider_data = {
    'microsoft': 0,
    'community': 1,
    'indirectProvider': 2,
    'self': 3,
    'unknownFutureValue': 4,
}
managedTenants_managementProvider = enum.Enum('managedTenants_managementProvider', managedTenants_managementProvider_data)


managedTenants_managementTemplateDeploymentStatus_data = {
    'unknown': 0,
    'inProgress': 5,
    'completed': 10,
    'failed': 15,
    'ineligible': 20,
    'unknownFutureValue': 45,
}
managedTenants_managementTemplateDeploymentStatus = enum.Enum('managedTenants_managementTemplateDeploymentStatus', managedTenants_managementTemplateDeploymentStatus_data)


managedTenants_notificationDestination_data = {
    'none': 0,
    'api': 1,
    'email': 2,
    'sms': 4,
    'unknownFutureValue': 8,
}
managedTenants_notificationDestination = enum.Enum('managedTenants_notificationDestination', managedTenants_notificationDestination_data)


managedTenants_tenantOnboardingEligibilityReason_data = {
    'none': 0,
    'contractType': 1,
    'delegatedAdminPrivileges': 2,
    'usersCount': 3,
    'license': 4,
    'unknownFutureValue': 8,
}
managedTenants_tenantOnboardingEligibilityReason = enum.Enum('managedTenants_tenantOnboardingEligibilityReason', managedTenants_tenantOnboardingEligibilityReason_data)


managedTenants_tenantOnboardingStatus_data = {
    'ineligible': 0,
    'inProcess': 1,
    'active': 2,
    'inactive': 3,
    'unknownFutureValue': 4,
    'disabled': 5,
}
managedTenants_tenantOnboardingStatus = enum.Enum('managedTenants_tenantOnboardingStatus', managedTenants_tenantOnboardingStatus_data)


managedTenants_workloadActionCategory_data = {
    'automated': 0,
    'manual': 1,
    'unknownFutureValue': 2,
}
managedTenants_workloadActionCategory = enum.Enum('managedTenants_workloadActionCategory', managedTenants_workloadActionCategory_data)


managedTenants_workloadActionStatus_data = {
    'toAddress': 0,
    'completed': 5,
    'error': 10,
    'timeOut': 15,
    'inProgress': 20,
    'unknownFutureValue': 25,
}
managedTenants_workloadActionStatus = enum.Enum('managedTenants_workloadActionStatus', managedTenants_workloadActionStatus_data)


managedTenants_workloadOnboardingStatus_data = {
    'notOnboarded': 0,
    'onboarded': 1,
    'unknownFutureValue': 2,
}
managedTenants_workloadOnboardingStatus = enum.Enum('managedTenants_workloadOnboardingStatus', managedTenants_workloadOnboardingStatus_data)


partners_billing_attributeSet_data = {
    'full': 1,
    'basic': 2,
    'unknownFutureValue': 3,
}
partners_billing_attributeSet = enum.Enum('partners_billing_attributeSet', partners_billing_attributeSet_data)


partners_billing_billingPeriod_data = {
    'current': 1,
    'last': 2,
    'unknownFutureValue': 3,
}
partners_billing_billingPeriod = enum.Enum('partners_billing_billingPeriod', partners_billing_billingPeriod_data)


partner_security_securityAlertConfidence_data = {
    'low': 0,
    'medium': 1,
    'high': 2,
    'unknownFutureValue': 3,
}
partner_security_securityAlertConfidence = enum.Enum('partner_security_securityAlertConfidence', partner_security_securityAlertConfidence_data)


partner_security_securityAlertResolvedReason_data = {
    'legitimate': 0,
    'ignore': 1,
    'fraud': 2,
    'unknownFutureValue': 3,
}
partner_security_securityAlertResolvedReason = enum.Enum('partner_security_securityAlertResolvedReason', partner_security_securityAlertResolvedReason_data)


partner_security_securityAlertSeverity_data = {
    'informational': 0,
    'high': 1,
    'medium': 2,
    'low': 3,
    'unknownFutureValue': 4,
}
partner_security_securityAlertSeverity = enum.Enum('partner_security_securityAlertSeverity', partner_security_securityAlertSeverity_data)


partner_security_securityAlertStatus_data = {
    'active': 0,
    'resolved': 1,
    'investigating': 2,
    'unknownFutureValue': 3,
}
partner_security_securityAlertStatus = enum.Enum('partner_security_securityAlertStatus', partner_security_securityAlertStatus_data)


partner_security_complianceStatus_data = {
    'compliant': 0,
    'noncomplaint': 1,
    'unknownFutureValue': 2,
}
partner_security_complianceStatus = enum.Enum('partner_security_complianceStatus', partner_security_complianceStatus_data)


partner_security_policyStatus_data = {
    'enabled': 0,
    'disabled': 1,
    'unknownFutureValue': 2,
}
partner_security_policyStatus = enum.Enum('partner_security_policyStatus', partner_security_policyStatus_data)


partner_security_securityRequirementState_data = {
    'active': 0,
    'preview': 1,
    'unknownFutureValue': 2,
}
partner_security_securityRequirementState = enum.Enum('partner_security_securityRequirementState', partner_security_securityRequirementState_data)


partner_security_securityRequirementType_data = {
    'mfaEnforcedForAdmins': 0,
    'mfaEnforcedForAdminsOfCustomers': 1,
    'securityAlertsPromptlyResolved': 2,
    'securityContactProvided': 3,
    'spendingBudgetSetForCustomerAzureSubscriptions': 4,
    'unknownFutureValue': 5,
}
partner_security_securityRequirementType = enum.Enum('partner_security_securityRequirementType', partner_security_securityRequirementType_data)


search_answerState_data = {
    'published': 0,
    'draft': 1,
    'excluded': 2,
    'unknownFutureValue': 3,
}
search_answerState = enum.Enum('search_answerState', search_answerState_data)


externalConnectors_accessType_data = {
    'grant': 1,
    'deny': 2,
    'unknownFutureValue': 3,
}
externalConnectors_accessType = enum.Enum('externalConnectors_accessType', externalConnectors_accessType_data)


externalConnectors_aclType_data = {
    'user': 1,
    'group': 2,
    'everyone': 3,
    'everyoneExceptGuests': 4,
    'externalGroup': 5,
    'unknownFutureValue': 6,
}
externalConnectors_aclType = enum.Enum('externalConnectors_aclType', externalConnectors_aclType_data)


externalConnectors_connectionOperationStatus_data = {
    'unspecified': 0,
    'inprogress': 1,
    'completed': 2,
    'failed': 3,
    'unknownFutureValue': 4,
}
externalConnectors_connectionOperationStatus = enum.Enum('externalConnectors_connectionOperationStatus', externalConnectors_connectionOperationStatus_data)


externalConnectors_connectionState_data = {
    'draft': 1,
    'ready': 2,
    'obsolete': 3,
    'limitExceeded': 4,
    'unknownFutureValue': 5,
}
externalConnectors_connectionState = enum.Enum('externalConnectors_connectionState', externalConnectors_connectionState_data)


externalConnectors_contentExperienceType_data = {
    'search': 1,
    'compliance': 32,
    'unknownFutureValue': 2048,
}
externalConnectors_contentExperienceType = enum.Enum('externalConnectors_contentExperienceType', externalConnectors_contentExperienceType_data)


externalConnectors_externalActivityType_data = {
    'viewed': 1,
    'modified': 2,
    'created': 3,
    'commented': 4,
    'unknownFutureValue': 5,
}
externalConnectors_externalActivityType = enum.Enum('externalConnectors_externalActivityType', externalConnectors_externalActivityType_data)


externalConnectors_externalItemContentType_data = {
    'text': 1,
    'html': 2,
    'unknownFutureValue': 3,
}
externalConnectors_externalItemContentType = enum.Enum('externalConnectors_externalItemContentType', externalConnectors_externalItemContentType_data)


externalConnectors_identitySourceType_data = {
    'azureActiveDirectory': 1,
    'external': 2,
    'unknownFutureValue': 3,
}
externalConnectors_identitySourceType = enum.Enum('externalConnectors_identitySourceType', externalConnectors_identitySourceType_data)


externalConnectors_identityType_data = {
    'user': 1,
    'group': 2,
    'externalGroup': 3,
    'unknownFutureValue': 4,
}
externalConnectors_identityType = enum.Enum('externalConnectors_identityType', externalConnectors_identityType_data)


externalConnectors_importanceScore_data = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'veryHigh': 4,
    'unknownFutureValue': 5,
}
externalConnectors_importanceScore = enum.Enum('externalConnectors_importanceScore', externalConnectors_importanceScore_data)


externalConnectors_label_data = {
    'title': 0,
    'url': 1,
    'createdBy': 2,
    'lastModifiedBy': 3,
    'authors': 4,
    'createdDateTime': 5,
    'lastModifiedDateTime': 6,
    'fileName': 7,
    'fileExtension': 8,
    'unknownFutureValue': 12,
    'containerName': 13,
    'containerUrl': 14,
    'iconUrl': 15,
}
externalConnectors_label = enum.Enum('externalConnectors_label', externalConnectors_label_data)


externalConnectors_propertyType_data = {
    'string': 0,
    'int64': 1,
    'double': 2,
    'dateTime': 3,
    'boolean': 4,
    'stringCollection': 5,
    'int64Collection': 6,
    'doubleCollection': 7,
    'dateTimeCollection': 8,
    'unknownFutureValue': 9,
}
externalConnectors_propertyType = enum.Enum('externalConnectors_propertyType', externalConnectors_propertyType_data)


externalConnectors_ruleOperation_data = {
    'null': 0,
    'equals': 1,
    'notEquals': 2,
    'contains': 3,
    'notContains': 4,
    'lessThan': 5,
    'greaterThan': 6,
    'startsWith': 7,
    'unknownFutureValue': 8,
}
externalConnectors_ruleOperation = enum.Enum('externalConnectors_ruleOperation', externalConnectors_ruleOperation_data)


windowsUpdates_azureADDeviceRegistrationErrorReason_data = {
    'invalidGlobalDeviceId': 0,
    'invalidAzureADDeviceId': 1,
    'missingTrustType': 2,
    'invalidAzureADJoin': 3,
    'unknownFutureValue': 4,
}
windowsUpdates_azureADDeviceRegistrationErrorReason = enum.Enum('windowsUpdates_azureADDeviceRegistrationErrorReason', windowsUpdates_azureADDeviceRegistrationErrorReason_data)


windowsUpdates_bodyType_data = {
    'text': 0,
    'html': 1,
    'unknownFutureValue': 2,
}
windowsUpdates_bodyType = enum.Enum('windowsUpdates_bodyType', windowsUpdates_bodyType_data)


windowsUpdates_cveSeverityLevel_data = {
    'critical': 0,
    'important': 1,
    'moderate': 2,
    'unknownFutureValue': 3,
}
windowsUpdates_cveSeverityLevel = enum.Enum('windowsUpdates_cveSeverityLevel', windowsUpdates_cveSeverityLevel_data)


windowsUpdates_deploymentStateReasonValue_data = {
    'scheduledByOfferWindow': 0,
    'offeringByRequest': 2,
    'pausedByRequest': 3,
    'pausedByMonitoring': 4,
    'unknownFutureValue': 5,
    'faultedByContentOutdated': 6,
}
windowsUpdates_deploymentStateReasonValue = enum.Enum('windowsUpdates_deploymentStateReasonValue', windowsUpdates_deploymentStateReasonValue_data)


windowsUpdates_deploymentStateValue_data = {
    'scheduled': 0,
    'offering': 1,
    'paused': 2,
    'faulted': 3,
    'archived': 4,
    'unknownFutureValue': 5,
}
windowsUpdates_deploymentStateValue = enum.Enum('windowsUpdates_deploymentStateValue', windowsUpdates_deploymentStateValue_data)


windowsUpdates_enrollmentState_data = {
    'notEnrolled': 0,
    'enrolled': 1,
    'enrolledWithPolicy': 2,
    'enrolling': 3,
    'unenrolling': 4,
    'unknownFutureValue': 5,
}
windowsUpdates_enrollmentState = enum.Enum('windowsUpdates_enrollmentState', windowsUpdates_enrollmentState_data)


windowsUpdates_monitoringAction_data = {
    'alertError': 0,
    'offerFallback': 1,
    'pauseDeployment': 3,
    'unknownFutureValue': 4,
}
windowsUpdates_monitoringAction = enum.Enum('windowsUpdates_monitoringAction', windowsUpdates_monitoringAction_data)


windowsUpdates_monitoringSignal_data = {
    'rollback': 0,
    'ineligible': 1,
    'unknownFutureValue': 2,
}
windowsUpdates_monitoringSignal = enum.Enum('windowsUpdates_monitoringSignal', windowsUpdates_monitoringSignal_data)


windowsUpdates_qualityUpdateCadence_data = {
    'monthly': 0,
    'outOfBand': 1,
    'unknownFutureValue': 2,
}
windowsUpdates_qualityUpdateCadence = enum.Enum('windowsUpdates_qualityUpdateCadence', windowsUpdates_qualityUpdateCadence_data)


windowsUpdates_qualityUpdateClassification_data = {
    'all': 0,
    'security': 1,
    'nonSecurity': 2,
    'unknownFutureValue': 3,
}
windowsUpdates_qualityUpdateClassification = enum.Enum('windowsUpdates_qualityUpdateClassification', windowsUpdates_qualityUpdateClassification_data)


windowsUpdates_requestedDeploymentStateValue_data = {
    'none': 0,
    'paused': 1,
    'archived': 2,
    'unknownFutureValue': 3,
}
windowsUpdates_requestedDeploymentStateValue = enum.Enum('windowsUpdates_requestedDeploymentStateValue', windowsUpdates_requestedDeploymentStateValue_data)


windowsUpdates_resourceConnectionState_data = {
    'connected': 0,
    'notAuthorized': 1,
    'notFound': 2,
    'unknownFutureValue': 3,
}
windowsUpdates_resourceConnectionState = enum.Enum('windowsUpdates_resourceConnectionState', windowsUpdates_resourceConnectionState_data)


windowsUpdates_safeguardCategory_data = {
    'likelyIssues': 0,
    'unknownFutureValue': 1,
}
windowsUpdates_safeguardCategory = enum.Enum('windowsUpdates_safeguardCategory', windowsUpdates_safeguardCategory_data)


windowsUpdates_updateCategory_data = {
    'feature': 0,
    'quality': 1,
    'unknownFutureValue': 2,
    'driver': 3,
}
windowsUpdates_updateCategory = enum.Enum('windowsUpdates_updateCategory', windowsUpdates_updateCategory_data)


windowsUpdates_windowsReleaseHealthStatus_data = {
    'resolved': 0,
    'mitigatedExternal': 1,
    'mitigated': 2,
    'resolvedExternal': 3,
    'confirmed': 4,
    'reported': 5,
    'investigating': 6,
    'unknownFutureValue': 7,
}
windowsUpdates_windowsReleaseHealthStatus = enum.Enum('windowsUpdates_windowsReleaseHealthStatus', windowsUpdates_windowsReleaseHealthStatus_data)


class identityGovernance_workflowExecutionTrigger(object):
    props = {

    }


class identityGovernance_attributeChangeTrigger(object):
    props = {
        'triggerAttributes': Collection,
    }


class identityGovernance_triggerAttribute(object):
    props = {
        'name': Edm.String,
    }


class identityGovernance_customTaskExtensionCallbackConfiguration(object):
    props = {

    }


class identityGovernance_customTaskExtensionCallbackData(object):
    props = {
        'operationStatus': Collection, #extnamespace: identityGovernance_customTaskExtensionOperationStatus,
    }


class identityGovernance_customTaskExtensionCalloutData(object):
    props = {

    }


class identityGovernance_groupBasedSubjectSet(object):
    props = {

    }


class identityGovernance_membershipChangeTrigger(object):
    props = {
        'changeType': Collection, #extnamespace: identityGovernance_membershipChangeType,
    }


class identityGovernance_workflowExecutionConditions(object):
    props = {

    }


class identityGovernance_onDemandExecutionOnly(object):
    props = {

    }


class identityGovernance_parameter(object):
    props = {
        'name': Edm.String,
        'values': Collection,
        'valueType': Collection, #extnamespace: identityGovernance_valueType,
    }


class identityGovernance_ruleBasedSubjectSet(object):
    props = {
        'rule': Edm.String,
    }


class identityGovernance_runSummary(object):
    props = {
        'failedRuns': Edm.Int32,
        'failedTasks': Edm.Int32,
        'successfulRuns': Edm.Int32,
        'totalRuns': Edm.Int32,
        'totalTasks': Edm.Int32,
        'totalUsers': Edm.Int32,
    }


class identityGovernance_taskReportSummary(object):
    props = {
        'failedTasks': Edm.Int32,
        'successfulTasks': Edm.Int32,
        'totalTasks': Edm.Int32,
        'unprocessedTasks': Edm.Int32,
    }


class identityGovernance_timeBasedAttributeTrigger(object):
    props = {
        'offsetInDays': Edm.Int32,
        'timeBasedAttribute': Collection, #extnamespace: identityGovernance_workflowTriggerTimeBasedAttribute,
    }


class identityGovernance_topTasksInsightsSummary(object):
    props = {
        'failedTasks': Edm.Int32,
        'failedUsers': Edm.Int32,
        'successfulTasks': Edm.Int32,
        'successfulUsers': Edm.Int32,
        'taskDefinitionDisplayName': Edm.String,
        'taskDefinitionId': Edm.String,
        'totalTasks': Edm.Int32,
        'totalUsers': Edm.Int32,
    }


class identityGovernance_topWorkflowsInsightsSummary(object):
    props = {
        'failedRuns': Edm.Int32,
        'failedUsers': Edm.Int32,
        'successfulRuns': Edm.Int32,
        'successfulUsers': Edm.Int32,
        'totalRuns': Edm.Int32,
        'totalUsers': Edm.Int32,
        'workflowCategory': Collection, #extnamespace: identityGovernance_lifecycleWorkflowCategory,
        'workflowDisplayName': Edm.String,
        'workflowId': Edm.String,
        'workflowVersion': Edm.Int32,
    }


class identityGovernance_usersProcessingSummary(object):
    props = {
        'failedTasks': Edm.Int32,
        'failedUsers': Edm.Int32,
        'successfulUsers': Edm.Int32,
        'totalTasks': Edm.Int32,
        'totalUsers': Edm.Int32,
    }


class identityGovernance_userSummary(object):
    props = {
        'failedTasks': Edm.Int32,
        'failedUsers': Edm.Int32,
        'successfulUsers': Edm.Int32,
        'totalTasks': Edm.Int32,
        'totalUsers': Edm.Int32,
    }


class identityGovernance_workflowsInsightsByCategory(object):
    props = {
        'failedJoinerRuns': Edm.Int32,
        'failedLeaverRuns': Edm.Int32,
        'failedMoverRuns': Edm.Int32,
        'successfulJoinerRuns': Edm.Int32,
        'successfulLeaverRuns': Edm.Int32,
        'successfulMoverRuns': Edm.Int32,
        'totalJoinerRuns': Edm.Int32,
        'totalLeaverRuns': Edm.Int32,
        'totalMoverRuns': Edm.Int32,
    }


class identityGovernance_workflowsInsightsSummary(object):
    props = {
        'failedRuns': Edm.Int32,
        'failedTasks': Edm.Int32,
        'failedUsers': Edm.Int32,
        'successfulRuns': Edm.Int32,
        'successfulTasks': Edm.Int32,
        'successfulUsers': Edm.Int32,
        'totalRuns': Edm.Int32,
        'totalTasks': Edm.Int32,
        'totalUsers': Edm.Int32,
    }


class customExtensionAuthenticationConfiguration(object):
    props = {

    }


class azureAdPopTokenAuthentication(object):
    props = {

    }


class azureAdTokenAuthentication(object):
    props = {
        'resourceId': Edm.String,
    }


class customExtensionCallbackConfiguration(object):
    props = {
        'timeoutDuration': Edm.Duration,
    }


class customExtensionData(object):
    props = {

    }


class customExtensionCalloutResponse(object):
    props = {
        'data': customExtensionData,
        'source': Edm.String,
        'type': Edm.String,
    }


class customExtensionClientConfiguration(object):
    props = {
        'maximumRetries': Edm.Int32,
        'timeoutInMilliseconds': Edm.Int32,
    }


class customExtensionEndpointConfiguration(object):
    props = {

    }


class emailSettings(object):
    props = {
        'senderDomain': Edm.String,
        'useCompanyBranding': Edm.Boolean,
    }


class identity(object):
    props = {
        'displayName': Edm.String,
        'id': Edm.String,
    }


class keyValuePair(object):
    props = {
        'name': Edm.String,
        'value': Edm.String,
    }


class logicAppTriggerEndpointConfiguration(object):
    props = {
        'logicAppWorkflowName': Edm.String,
        'resourceGroupName': Edm.String,
        'subscriptionId': Edm.String,
        'url': Edm.String,
    }


class subjectSet(object):
    props = {

    }


class apiApplication(object):
    props = {
        'acceptMappedClaims': Edm.Boolean,
        'knownClientApplications': Collection,
        'oauth2PermissionScopes': Collection,
        'preAuthorizedApplications': Collection,
        'requestedAccessTokenVersion': Edm.Int32,
    }


class appRole(object):
    props = {
        'allowedMemberTypes': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'isEnabled': Edm.Boolean,
        'origin': Edm.String,
        'value': Edm.String,
    }


class authenticationBehaviors(object):
    props = {
        'blockAzureADGraphAccess': Edm.Boolean,
        'removeUnverifiedEmailClaim': Edm.Boolean,
        'requireClientServicePrincipal': Edm.Boolean,
    }


class certification(object):
    props = {
        'certificationDetailsUrl': Edm.String,
        'certificationExpirationDateTime': Edm.DateTimeOffset,
        'isCertifiedByMicrosoft': Edm.Boolean,
        'isPublisherAttested': Edm.Boolean,
        'lastCertificationDateTime': Edm.DateTimeOffset,
    }


class informationalUrl(object):
    props = {
        'logoUrl': Edm.String,
        'marketingUrl': Edm.String,
        'privacyStatementUrl': Edm.String,
        'supportUrl': Edm.String,
        'termsOfServiceUrl': Edm.String,
    }


class keyCredential(object):
    props = {
        'customKeyIdentifier': Edm.Binary,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'key': Edm.Binary,
        'keyId': Edm.Guid,
        'startDateTime': Edm.DateTimeOffset,
        'type': Edm.String,
        'usage': Edm.String,
    }


class optionalClaims(object):
    props = {
        'accessToken': Collection,
        'idToken': Collection,
        'saml2Token': Collection,
    }


class parentalControlSettings(object):
    props = {
        'countriesBlockedForMinors': Collection,
        'legalAgeGroupRule': Edm.String,
    }


class passwordCredential(object):
    props = {
        'customKeyIdentifier': Edm.Binary,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'hint': Edm.String,
        'keyId': Edm.Guid,
        'secretText': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
    }


class publicClientApplication(object):
    props = {
        'redirectUris': Collection,
    }


class requestSignatureVerification(object):
    props = {
        'allowedWeakAlgorithms': weakAlgorithms,
        'isSignedRequestRequired': Edm.Boolean,
    }


class requiredResourceAccess(object):
    props = {
        'resourceAccess': Collection,
        'resourceAppId': Edm.String,
    }


class servicePrincipalLockConfiguration(object):
    props = {
        'allProperties': Edm.Boolean,
        'credentialsWithUsageSign': Edm.Boolean,
        'credentialsWithUsageVerify': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'tokenEncryptionKeyId': Edm.Boolean,
    }


class spaApplication(object):
    props = {
        'redirectUris': Collection,
    }


class verifiedPublisher(object):
    props = {
        'addedDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'verifiedPublisherId': Edm.String,
    }


class windowsApplication(object):
    props = {
        'packageSid': Edm.String,
        'redirectUris': Collection,
    }


class assignedLabel(object):
    props = {
        'displayName': Edm.String,
        'labelId': Edm.String,
    }


class assignedLicense(object):
    props = {
        'disabledPlans': Collection,
        'skuId': Edm.Guid,
    }


class licenseProcessingState(object):
    props = {
        'state': Edm.String,
    }


class onPremisesProvisioningError(object):
    props = {
        'category': Edm.String,
        'occurredDateTime': Edm.DateTimeOffset,
        'propertyCausingError': Edm.String,
        'value': Edm.String,
    }


class serviceProvisioningError(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'isResolved': Edm.Boolean,
        'serviceInstance': Edm.String,
    }


class writebackConfiguration(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class groupWritebackConfiguration(object):
    props = {
        'onPremisesGroupType': Edm.String,
    }


class membershipRuleProcessingStatus(object):
    props = {
        'errorMessage': Edm.String,
        'lastMembershipUpdated': Edm.DateTimeOffset,
        'status': MembershipRuleProcessingStatusDetails,
    }


class signInActivity(object):
    props = {
        'lastNonInteractiveSignInDateTime': Edm.DateTimeOffset,
        'lastNonInteractiveSignInRequestId': Edm.String,
        'lastSignInDateTime': Edm.DateTimeOffset,
        'lastSignInRequestId': Edm.String,
        'lastSuccessfulSignInDateTime': Edm.DateTimeOffset,
        'lastSuccessfulSignInRequestId': Edm.String,
    }


class assignedPlan(object):
    props = {
        'assignedDateTime': Edm.DateTimeOffset,
        'capabilityStatus': Edm.String,
        'service': Edm.String,
        'servicePlanId': Edm.Guid,
    }


class authorizationInfo(object):
    props = {
        'certificateUserIds': Collection,
    }


class cloudRealtimeCommunicationInfo(object):
    props = {
        'isSipEnabled': Edm.Boolean,
    }


class customSecurityAttributeValue(object):
    props = {

    }


class deviceKey(object):
    props = {
        'deviceId': Edm.Guid,
        'keyMaterial': Edm.Binary,
        'keyType': Edm.String,
    }


class employeeOrgData(object):
    props = {
        'costCenter': Edm.String,
        'division': Edm.String,
    }


class objectIdentity(object):
    props = {
        'issuer': Edm.String,
        'issuerAssignedId': Edm.String,
        'signInType': Edm.String,
    }


class licenseAssignmentState(object):
    props = {
        'assignedByGroup': Edm.String,
        'disabledPlans': Collection,
        'error': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'skuId': Edm.Guid,
        'state': Edm.String,
    }


class onPremisesExtensionAttributes(object):
    props = {
        'extensionAttribute1': Edm.String,
        'extensionAttribute10': Edm.String,
        'extensionAttribute11': Edm.String,
        'extensionAttribute12': Edm.String,
        'extensionAttribute13': Edm.String,
        'extensionAttribute14': Edm.String,
        'extensionAttribute15': Edm.String,
        'extensionAttribute2': Edm.String,
        'extensionAttribute3': Edm.String,
        'extensionAttribute4': Edm.String,
        'extensionAttribute5': Edm.String,
        'extensionAttribute6': Edm.String,
        'extensionAttribute7': Edm.String,
        'extensionAttribute8': Edm.String,
        'extensionAttribute9': Edm.String,
    }


class onPremisesSipInfo(object):
    props = {
        'isSipEnabled': Edm.Boolean,
        'sipDeploymentLocation': Edm.String,
        'sipPrimaryAddress': Edm.String,
    }


class passwordProfile(object):
    props = {
        'forceChangePasswordNextSignIn': Edm.Boolean,
        'forceChangePasswordNextSignInWithMfa': Edm.Boolean,
        'password': Edm.String,
    }


class provisionedPlan(object):
    props = {
        'capabilityStatus': Edm.String,
        'provisioningStatus': Edm.String,
        'service': Edm.String,
    }


class userPrint(object):
    props = {

    }


class actionUrl(object):
    props = {
        'displayName': Edm.String,
        'url': Edm.String,
    }


class appIdentity(object):
    props = {
        'appId': Edm.String,
        'displayName': Edm.String,
        'servicePrincipalId': Edm.String,
        'servicePrincipalName': Edm.String,
    }


class authenticationEventHandlerResult(object):
    props = {

    }


class authenticationStrength(object):
    props = {
        'authenticationStrengthId': Edm.String,
        'authenticationStrengthResult': authenticationStrengthResult,
        'displayName': Edm.String,
    }


class conditionalAccessRuleSatisfied(object):
    props = {
        'conditionalAccessCondition': conditionalAccessConditions,
        'ruleSatisfied': conditionalAccessRule,
    }


class userIdentity(object):
    props = {
        'ipAddress': Edm.String,
        'userPrincipalName': Edm.String,
    }


class auditUserIdentity(object):
    props = {
        'homeTenantId': Edm.String,
        'homeTenantName': Edm.String,
    }


class authenticationAppDeviceDetails(object):
    props = {
        'appVersion': Edm.String,
        'clientApp': Edm.String,
        'deviceId': Edm.String,
        'operatingSystem': Edm.String,
    }


class authenticationAppPolicyDetails(object):
    props = {
        'adminConfiguration': authenticationAppAdminConfiguration,
        'authenticationEvaluation': authenticationAppEvaluation,
        'policyName': Edm.String,
        'status': authenticationAppPolicyStatus,
    }


class authenticationContext(object):
    props = {
        'detail': authenticationContextDetail,
        'id': Edm.String,
    }


class authenticationDetail(object):
    props = {
        'authenticationMethod': Edm.String,
        'authenticationMethodDetail': Edm.String,
        'authenticationStepDateTime': Edm.DateTimeOffset,
        'authenticationStepRequirement': Edm.String,
        'authenticationStepResultDetail': Edm.String,
        'succeeded': Edm.Boolean,
    }


class authenticationRequirementPolicy(object):
    props = {
        'detail': Edm.String,
        'requirementProvider': requirementProvider,
    }


class ciamUserSnapshot(object):
    props = {
        'userId': Edm.String,
    }


class conditionalAccessAudience(object):
    props = {
        'applicationId': Edm.String,
        'audienceReasons': conditionalAccessAudienceReason,
    }


class customExtensionCalloutResult(object):
    props = {
        'calloutDateTime': Edm.DateTimeOffset,
        'customExtensionId': Edm.String,
        'errorCode': Edm.Int32,
        'httpStatus': Edm.Int32,
        'numberOfAttempts': Edm.Int32,
    }


class dataProviderStoragePath(object):
    props = {
        'containerName': Edm.String,
        'dataProviderId': Edm.String,
        'path': Edm.String,
        'storageAccountName': Edm.String,
    }


class detailsInfo(object):
    props = {

    }


class deviceDetail(object):
    props = {
        'browser': Edm.String,
        'browserId': Edm.String,
        'deviceId': Edm.String,
        'displayName': Edm.String,
        'isCompliant': Edm.Boolean,
        'isManaged': Edm.Boolean,
        'operatingSystem': Edm.String,
        'trustType': Edm.String,
    }


class geoCoordinates(object):
    props = {
        'altitude': Edm.Double,
        'latitude': Edm.Double,
        'longitude': Edm.Double,
    }


class initiator(object):
    props = {
        'initiatorType': initiatorType,
    }


class keyValue(object):
    props = {
        'key': Edm.String,
        'value': Edm.String,
    }


class lastSignIn(object):
    props = {
        'interactiveDateTime': Edm.DateTimeOffset,
        'nonInteractiveDateTime': Edm.DateTimeOffset,
    }


class managedIdentity(object):
    props = {
        'associatedResourceId': Edm.String,
        'federatedTokenId': Edm.String,
        'federatedTokenIssuer': Edm.String,
        'msiType': msiType,
    }


class mfaDetail(object):
    props = {
        'authDetail': Edm.String,
        'authMethod': Edm.String,
    }


class modifiedProperty(object):
    props = {
        'displayName': Edm.String,
        'newValue': Edm.String,
        'oldValue': Edm.String,
    }


class networkLocationDetail(object):
    props = {
        'networkNames': Collection,
        'networkType': networkType,
    }


class privateLinkDetails(object):
    props = {
        'policyId': Edm.String,
        'policyName': Edm.String,
        'policyTenantId': Edm.String,
        'resourceId': Edm.String,
    }


class provisionedIdentity(object):
    props = {
        'details': detailsInfo,
        'identityType': Edm.String,
    }


class provisioningErrorInfo(object):
    props = {
        'additionalDetails': Edm.String,
        'errorCategory': provisioningStatusErrorCategory,
        'errorCode': Edm.String,
        'reason': Edm.String,
        'recommendedAction': Edm.String,
    }


class provisioningServicePrincipal(object):
    props = {

    }


class provisioningStatusInfo(object):
    props = {
        'errorInformation': provisioningErrorInfo,
        'status': provisioningResult,
    }


class provisioningStep(object):
    props = {
        'description': Edm.String,
        'details': detailsInfo,
        'name': Edm.String,
        'provisioningStepType': provisioningStepType,
        'status': provisioningResult,
    }


class provisioningSystem(object):
    props = {
        'details': detailsInfo,
    }


class reconciliationCounter(object):
    props = {
        'correlatedObjectCount': Edm.Int64,
        'sourceObjectCount': Edm.Int64,
        'targetObjectCount': Edm.Int64,
        'uncorrelatedObjectCount': Edm.Int64,
    }


class reconciliationCounters(object):
    props = {
        'user': reconciliationCounter,
    }


class serviceActivityValueMetric(object):
    props = {
        'intervalStartDateTime': Edm.DateTimeOffset,
        'value': Edm.Int64,
    }


class serviceLevelAgreementAttainment(object):
    props = {
        'endDate': Edm.Date,
        'score': Edm.Double,
        'startDate': Edm.Date,
    }


class sessionLifetimePolicy(object):
    props = {
        'detail': Edm.String,
        'expirationRequirement': expirationRequirement,
    }


class signInCounts(object):
    props = {
        'noSignIn': Edm.Int32,
        'withSignIn': Edm.Int32,
    }


class signInLocation(object):
    props = {
        'city': Edm.String,
        'countryOrRegion': Edm.String,
        'geoCoordinates': geoCoordinates,
        'state': Edm.String,
    }


class signInStatus(object):
    props = {
        'additionalDetails': Edm.String,
        'errorCode': Edm.Int32,
        'failureReason': Edm.String,
    }


class signUpIdentity(object):
    props = {
        'signUpIdentifier': Edm.String,
        'signUpIdentifierType': signUpIdentifierType,
    }


class signUpStatus(object):
    props = {
        'additionalDetails': Edm.String,
        'errorCode': Edm.Int32,
        'failureReason': Edm.String,
    }


class sourceProvisionedIdentity(object):
    props = {

    }


class statusBase(object):
    props = {
        'status': provisioningResult,
    }


class statusDetails(object):
    props = {
        'additionalDetails': Edm.String,
        'errorCategory': provisioningStatusErrorCategory,
        'errorCode': Edm.String,
        'reason': Edm.String,
        'recommendedAction': Edm.String,
    }


class storagePath(object):
    props = {
        'containerName': Edm.String,
        'path': Edm.String,
        'storageAccountName': Edm.String,
    }


class targetProvisionedIdentity(object):
    props = {

    }


class targetResource(object):
    props = {
        'displayName': Edm.String,
        'groupType': groupType,
        'id': Edm.String,
        'modifiedProperties': Collection,
        'type': Edm.String,
        'userPrincipalName': Edm.String,
    }


class tenantSecureScore(object):
    props = {
        'createDateTime': Edm.DateTimeOffset,
        'tenantMaxScore': Edm.Int64,
        'tenantScore': Edm.Int64,
    }


class tokenProtectionStatusDetails(object):
    props = {
        'signInSessionStatus': tokenProtectionStatus,
        'signInSessionStatusCode': Edm.Int32,
    }


class userRegistrationCount(object):
    props = {
        'registrationCount': Edm.Int64,
        'registrationStatus': registrationStatusType,
    }


class userRegistrationFeatureCount(object):
    props = {
        'feature': authenticationMethodFeature,
        'userCount': Edm.Int64,
    }


class userRegistrationFeatureSummary(object):
    props = {
        'totalUserCount': Edm.Int64,
        'userRegistrationFeatureCounts': Collection,
        'userRoles': includedUserRoles,
        'userTypes': includedUserTypes,
    }


class userRegistrationMethodCount(object):
    props = {
        'authenticationMethod': Edm.String,
        'userCount': Edm.Int64,
    }


class userRegistrationMethodSummary(object):
    props = {
        'totalUserCount': Edm.Int64,
        'userRegistrationMethodCounts': Collection,
        'userRoles': includedUserRoles,
        'userTypes': includedUserTypes,
    }


class Dictionary(object):
    props = {

    }


class alternativeSecurityId(object):
    props = {
        'identityProvider': Edm.String,
        'key': Edm.Binary,
        'type': Edm.Int32,
    }


class passwordSingleSignOnSettings(object):
    props = {
        'fields': Collection,
    }


class addIn(object):
    props = {
        'id': Edm.Guid,
        'properties': Collection,
        'type': Edm.String,
    }


class permissionScope(object):
    props = {
        'adminConsentDescription': Edm.String,
        'adminConsentDisplayName': Edm.String,
        'id': Edm.Guid,
        'isEnabled': Edm.Boolean,
        'origin': Edm.String,
        'type': Edm.String,
        'userConsentDescription': Edm.String,
        'userConsentDisplayName': Edm.String,
        'value': Edm.String,
    }


class samlSingleSignOnSettings(object):
    props = {
        'relayState': Edm.String,
    }


class emailAddress(object):
    props = {
        'address': Edm.String,
        'name': Edm.String,
    }


class invitedUserMessageInfo(object):
    props = {
        'ccRecipients': Collection,
        'customizedMessageBody': Edm.String,
        'messageLanguage': Edm.String,
    }


class recipient(object):
    props = {
        'emailAddress': emailAddress,
    }


class settings(object):
    props = {
        'hasGraphMailbox': Edm.Boolean,
        'hasLicense': Edm.Boolean,
        'hasOptedOut': Edm.Boolean,
    }


class applicationServicePrincipal(object):
    props = {

    }


class configurationUri(object):
    props = {
        'appliesToSingleSignOnMode': Edm.String,
        'examples': Collection,
        'isRequired': Edm.Boolean,
        'usage': uriUsageType,
        'values': Collection,
    }


class credential(object):
    props = {
        'fieldId': Edm.String,
        'type': Edm.String,
        'value': Edm.String,
    }


class informationalUrls(object):
    props = {
        'appSignUpUrl': Edm.String,
        'singleSignOnDocumentationUrl': Edm.String,
    }


class passwordSingleSignOnCredentialSet(object):
    props = {
        'credentials': Collection,
        'id': Edm.String,
    }


class passwordSingleSignOnField(object):
    props = {
        'customizedLabel': Edm.String,
        'defaultLabel': Edm.String,
        'fieldId': Edm.String,
        'type': Edm.String,
    }


class supportedClaimConfiguration(object):
    props = {
        'nameIdPolicyFormat': Edm.String,
    }


class identitySet(object):
    props = {
        'application': identity,
        'device': identity,
        'user': identity,
    }


class approvalIdentitySet(object):
    props = {
        'group': identity,
    }


class approvalItemViewPoint(object):
    props = {
        'roles': Collection,
    }


class publicErrorDetail(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
        'target': Edm.String,
    }


class publicInnerError(object):
    props = {
        'code': Edm.String,
        'details': Collection,
        'message': Edm.String,
        'target': Edm.String,
    }


class featureTarget(object):
    props = {
        'id': Edm.String,
        'targetType': featureTargetType,
    }


class authenticationMethodsRegistrationCampaign(object):
    props = {
        'enforceRegistrationAfterAllowedSnoozes': Edm.Boolean,
        'excludeTargets': Collection,
        'includeTargets': Collection,
        'snoozeDurationInDays': Edm.Int32,
        'state': advancedConfigState,
    }


class excludeTarget(object):
    props = {
        'id': Edm.String,
        'targetType': authenticationMethodTargetType,
    }


class authenticationMethodsRegistrationCampaignIncludeTarget(object):
    props = {
        'id': Edm.String,
        'targetedAuthenticationMethod': Edm.String,
        'targetType': authenticationMethodTargetType,
    }


class enforceAppPIN(object):
    props = {
        'excludeTargets': Collection,
        'includeTargets': Collection,
    }


class includeTarget(object):
    props = {
        'id': Edm.String,
        'targetType': authenticationMethodTargetType,
    }


class fido2KeyRestrictions(object):
    props = {
        'aaGuids': Collection,
        'enforcementType': fido2RestrictionEnforcementType,
        'isEnforced': Edm.Boolean,
    }


class microsoftAuthenticatorPlatformSettings(object):
    props = {
        'enforceAppPIN': enforceAppPIN,
    }


class openIdConnectSetting(object):
    props = {
        'clientId': Edm.String,
        'discoveryUrl': Edm.String,
    }


class registrationEnforcement(object):
    props = {
        'authenticationMethodsRegistrationCampaign': authenticationMethodsRegistrationCampaign,
    }


class reportSuspiciousActivitySettings(object):
    props = {
        'includeTarget': includeTarget,
        'state': advancedConfigState,
        'voiceReportingCode': Edm.Int32,
    }


class requiredVerifiableCredential(object):
    props = {
        'claimBindings': Collection,
        'trustedIssuer': Edm.String,
        'verifiableCredentialType': Edm.String,
    }


class verifiableCredentialClaimBinding(object):
    props = {
        'priority': Edm.Int32,
        'verifiableCredentialClaim': Edm.String,
    }


class systemCredentialPreferences(object):
    props = {
        'excludeTargets': Collection,
        'includeTargets': Collection,
        'state': advancedConfigState,
    }


class updateAllowedCombinationsResult(object):
    props = {
        'additionalInformation': Edm.String,
        'conditionalAccessReferences': Collection,
        'currentCombinations': Collection,
        'previousCombinations': Collection,
    }


class x509CertificateAuthenticationModeConfiguration(object):
    props = {
        'rules': Collection,
        'x509CertificateAuthenticationDefaultMode': x509CertificateAuthenticationMode,
        'x509CertificateDefaultRequiredAffinityLevel': x509CertificateAffinityLevel,
    }


class x509CertificateRule(object):
    props = {
        'identifier': Edm.String,
        'issuerSubjectIdentifier': Edm.String,
        'policyOidIdentifier': Edm.String,
        'x509CertificateAuthenticationMode': x509CertificateAuthenticationMode,
        'x509CertificateRequiredAffinityLevel': x509CertificateAffinityLevel,
        'x509CertificateRuleType': x509CertificateRuleType,
    }


class x509CertificateIssuerHintsConfiguration(object):
    props = {
        'state': x509CertificateIssuerHintsState,
    }


class x509CertificateUserBinding(object):
    props = {
        'priority': Edm.Int32,
        'trustAffinityLevel': x509CertificateAffinityLevel,
        'userProperty': Edm.String,
        'x509CertificateField': Edm.String,
    }


class phone(object):
    props = {
        'number': Edm.String,
        'type': phoneType,
    }


class searchQueryString(object):
    props = {
        'query': Edm.String,
    }


class dateTimeTimeZone(object):
    props = {
        'dateTime': Edm.String,
        'timeZone': Edm.String,
    }


class bookingCustomerInformationBase(object):
    props = {

    }


class bookingQuestionAnswer(object):
    props = {
        'answer': Edm.String,
        'answerInputType': answerInputType,
        'answerOptions': Collection,
        'isRequired': Edm.Boolean,
        'question': Edm.String,
        'questionId': Edm.String,
        'selectedOptions': Collection,
    }


class bookingPageSettings(object):
    props = {
        'accessControl': bookingPageAccessControl,
        'bookingPageColorCode': Edm.String,
        'businessTimeZone': Edm.String,
        'customerConsentMessage': Edm.String,
        'enforceOneTimePassword': Edm.Boolean,
        'isBusinessLogoDisplayEnabled': Edm.Boolean,
        'isCustomerConsentEnabled': Edm.Boolean,
        'isSearchEngineIndexabilityDisabled': Edm.Boolean,
        'isTimeSlotTimeZoneSetToBusinessTimeZone': Edm.Boolean,
        'privacyPolicyWebUrl': Edm.String,
        'termsAndConditionsWebUrl': Edm.String,
    }


class bookingQuestionAssignment(object):
    props = {
        'isRequired': Edm.Boolean,
        'questionId': Edm.String,
    }


class bookingReminder(object):
    props = {
        'message': Edm.String,
        'offset': Edm.Duration,
        'recipients': bookingReminderRecipients,
    }


class bookingsAvailability(object):
    props = {
        'availabilityType': bookingsServiceAvailabilityType,
        'businessHours': Collection,
    }


class bookingWorkHours(object):
    props = {
        'day': dayOfWeek,
        'timeSlots': Collection,
    }


class bookingsAvailabilityWindow(object):
    props = {
        'endDate': Edm.Date,
        'startDate': Edm.Date,
    }


class bookingSchedulingPolicy(object):
    props = {
        'allowStaffSelection': Edm.Boolean,
        'customAvailabilities': Collection,
        'generalAvailability': bookingsAvailability,
        'isMeetingInviteToCustomersEnabled': Edm.Boolean,
        'maximumAdvance': Edm.Duration,
        'minimumLeadTime': Edm.Duration,
        'sendConfirmationsToOwner': Edm.Boolean,
        'timeSlotInterval': Edm.Duration,
    }


class bookingWorkTimeSlot(object):
    props = {
        'end': Edm.TimeOfDay,
        'start': Edm.TimeOfDay,
    }


class physicalAddress(object):
    props = {
        'city': Edm.String,
        'countryOrRegion': Edm.String,
        'postalCode': Edm.String,
        'postOfficeBox': Edm.String,
        'state': Edm.String,
        'street': Edm.String,
        'type': physicalAddressType,
    }


class outlookGeoCoordinates(object):
    props = {
        'accuracy': Edm.Double,
        'altitude': Edm.Double,
        'altitudeAccuracy': Edm.Double,
        'latitude': Edm.Double,
        'longitude': Edm.Double,
    }


class staffAvailabilityItem(object):
    props = {
        'availabilityItems': Collection,
        'staffId': Edm.String,
    }


class timeSlot(object):
    props = {
        'end': dateTimeTimeZone,
        'start': dateTimeTimeZone,
    }


class plannerFieldRules(object):
    props = {
        'defaultRules': Collection,
        'overrides': Collection,
    }


class plannerRuleOverride(object):
    props = {
        'name': Edm.String,
        'rules': Collection,
    }


class plannerPlanConfigurationBucketDefinition(object):
    props = {
        'externalBucketId': Edm.String,
    }


class plannerPlanConfigurationBucketLocalization(object):
    props = {
        'externalBucketId': Edm.String,
        'name': Edm.String,
    }


class plannerPropertyRule(object):
    props = {
        'ruleKind': plannerRuleKind,
    }


class plannerTaskConfigurationRoleBase(object):
    props = {
        'roleKind': plannerUserRoleKind,
    }


class plannerRelationshipBasedUserType(object):
    props = {
        'role': plannerRelationshipUserRoles,
    }


class plannerTaskPolicy(object):
    props = {
        'rules': Collection,
    }


class plannerTaskPropertyRule(object):
    props = {
        'appliedCategories': plannerFieldRules,
        'approvalAttachment': plannerFieldRules,
        'assignments': plannerFieldRules,
        'checkLists': plannerFieldRules,
        'completionRequirements': Collection,
        'delete': Collection,
        'dueDate': Collection,
        'forms': plannerFieldRules,
        'move': Collection,
        'notes': Collection,
        'order': Collection,
        'percentComplete': Collection,
        'previewType': Collection,
        'priority': Collection,
        'references': plannerFieldRules,
        'startDate': Collection,
        'title': Collection,
    }


class cloudPcAuditActor(object):
    props = {
        'applicationDisplayName': Edm.String,
        'applicationId': Edm.String,
        'ipAddress': Edm.String,
        'remoteTenantId': Edm.String,
        'remoteUserId': Edm.String,
        'servicePrincipalName': Edm.String,
        'type': cloudPcAuditActorType,
        'userId': Edm.String,
        'userPermissions': Collection,
        'userPrincipalName': Edm.String,
        'userRoleScopeTags': Collection,
    }


class cloudPcUserRoleScopeTagInfo(object):
    props = {
        'displayName': Edm.String,
        'roleScopeTagId': Edm.String,
    }


class cloudPcAuditProperty(object):
    props = {
        'displayName': Edm.String,
        'newValue': Edm.String,
        'oldValue': Edm.String,
    }


class cloudPcAuditResource(object):
    props = {
        'displayName': Edm.String,
        'modifiedProperties': Collection,
        'resourceId': Edm.String,
        'resourceType': Edm.String,
    }


class cloudPcAutopilotConfiguration(object):
    props = {
        'applicationTimeoutInMinutes': Edm.Int32,
        'devicePreparationProfileId': Edm.String,
        'onFailureDeviceAccessDenied': Edm.Boolean,
    }


class cloudPcBulkActionSummary(object):
    props = {
        'failedCount': Edm.Int32,
        'inProgressCount': Edm.Int32,
        'notSupportedCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successfulCount': Edm.Int32,
    }


class cloudPcBulkRemoteActionResult(object):
    props = {
        'failedDeviceIds': Collection,
        'notFoundDeviceIds': Collection,
        'notSupportedDeviceIds': Collection,
        'successfulDeviceIds': Collection,
    }


class cloudPcConnectionSetting(object):
    props = {
        'enableSingleSignOn': Edm.Boolean,
    }


class cloudPcConnectionSettings(object):
    props = {
        'enableSingleSignOn': Edm.Boolean,
    }


class cloudPcConnectivityEvent(object):
    props = {
        'eventDateTime': Edm.DateTimeOffset,
        'eventName': Edm.String,
        'eventResult': cloudPcConnectivityEventResult,
        'eventType': cloudPcConnectivityEventType,
        'message': Edm.String,
    }


class cloudPcConnectivityResult(object):
    props = {
        'failedHealthCheckItems': Collection,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': cloudPcConnectivityStatus,
        'updatedDateTime': Edm.DateTimeOffset,
    }


class cloudPcHealthCheckItem(object):
    props = {
        'additionalDetails': Edm.String,
        'displayName': Edm.String,
        'lastHealthCheckDateTime': Edm.DateTimeOffset,
        'result': cloudPcConnectivityEventResult,
    }


class cloudPcDisasterRecoveryNetworkSetting(object):
    props = {

    }


class cloudPcDisasterRecoveryAzureConnectionSetting(object):
    props = {
        'onPremisesConnectionId': Edm.String,
    }


class cloudPcDisasterRecoveryCapability(object):
    props = {
        'capabilityType': cloudPcDisasterRecoveryCapabilityType,
        'licenseType': cloudPcDisasterRecoveryLicenseType,
        'primaryRegion': Edm.String,
        'secondaryRegion': Edm.String,
    }


class cloudPcDisasterRecoveryMicrosoftHostedNetworkSetting(object):
    props = {
        'regionGroup': cloudPcRegionGroup,
        'regionName': Edm.String,
    }


class cloudPcDomainJoinConfiguration(object):
    props = {
        'domainJoinType': cloudPcDomainJoinType,
        'onPremisesConnectionId': Edm.String,
        'regionGroup': cloudPcRegionGroup,
        'regionName': Edm.String,
        'type': cloudPcDomainJoinType,
    }


class cloudPcForensicStorageAccount(object):
    props = {
        'accessTier': cloudPcStorageAccountAccessTier,
        'immutableStorage': Edm.Boolean,
        'storageAccountId': Edm.String,
        'storageAccountName': Edm.String,
    }


class cloudPcLaunchInfo(object):
    props = {
        'cloudPcId': Edm.String,
        'cloudPcLaunchUrl': Edm.String,
        'windows365SwitchCompatible': Edm.Boolean,
        'windows365SwitchNotCompatibleReason': Edm.String,
    }


class cloudPcLoginResult(object):
    props = {
        'time': Edm.DateTimeOffset,
    }


class cloudPcManagementAssignmentTarget(object):
    props = {

    }


class cloudPcManagementGroupAssignmentTarget(object):
    props = {
        'allotmentDisplayName': Edm.String,
        'allotmentLicensesCount': Edm.Int32,
        'groupId': Edm.String,
        'servicePlanId': Edm.String,
    }


class cloudPcNotificationSetting(object):
    props = {
        'restartPromptsDisabled': Edm.Boolean,
    }


class cloudPcOnPremisesConnectionHealthCheck(object):
    props = {
        'additionalDetail': Edm.String,
        'additionalDetails': Edm.String,
        'correlationId': Edm.String,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'errorType': cloudPcOnPremisesConnectionHealthCheckErrorType,
        'recommendedAction': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'status': cloudPcOnPremisesConnectionStatus,
    }


class cloudPcOnPremisesConnectionStatusDetail(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'healthChecks': Collection,
        'startDateTime': Edm.DateTimeOffset,
    }


class cloudPcOnPremisesConnectionStatusDetails(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'healthChecks': Collection,
        'startDateTime': Edm.DateTimeOffset,
    }


class cloudPcPartnerAgentInstallResult(object):
    props = {
        'errorMessage': Edm.String,
        'installStatus': cloudPcPartnerAgentInstallStatus,
        'isThirdPartyPartner': Edm.Boolean,
        'partnerAgentName': cloudPcPartnerAgentName,
        'retriable': Edm.Boolean,
    }


class cloudPcPolicyApplyActionResult(object):
    props = {
        'finishDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'status': cloudPcPolicyApplyActionStatus,
    }


class cloudPcPolicyScheduledApplyActionDetail(object):
    props = {
        'cronScheduleExpression': Edm.String,
        'reservePercentage': Edm.Int32,
    }


class cloudPcProvisioningPolicyAutopatch(object):
    props = {
        'autopatchGroupId': Edm.String,
    }


class cloudPcRemoteActionCapability(object):
    props = {
        'actionCapability': actionCapability,
        'actionName': cloudPcRemoteActionName,
    }


class cloudPcStatusDetail(object):
    props = {
        'additionalInformation': Collection,
        'code': Edm.String,
        'message': Edm.String,
    }


class cloudPcStatusDetails(object):
    props = {
        'additionalInformation': Collection,
        'code': Edm.String,
        'message': Edm.String,
    }


class cloudPcResizeValidationResult(object):
    props = {
        'cloudPcId': Edm.String,
        'validationResult': cloudPcResizeValidationCode,
    }


class cloudPcRestorePointSetting(object):
    props = {
        'frequencyInHours': Edm.Int32,
        'frequencyType': cloudPcRestorePointFrequencyType,
        'userRestoreEnabled': Edm.Boolean,
    }


class cloudPcReviewStatus(object):
    props = {
        'accessTier': cloudPcBlobAccessTier,
        'azureStorageAccountId': Edm.String,
        'azureStorageAccountName': Edm.String,
        'azureStorageContainerName': Edm.String,
        'inReview': Edm.Boolean,
        'restorePointDateTime': Edm.DateTimeOffset,
        'reviewStartDateTime': Edm.DateTimeOffset,
        'subscriptionId': Edm.String,
        'subscriptionName': Edm.String,
        'userAccessLevel': cloudPcUserAccessLevel,
    }


class cloudPcScopedPermission(object):
    props = {
        'permission': Edm.String,
        'scopeIds': Collection,
    }


class cloudPcSourceDeviceImage(object):
    props = {
        'displayName': Edm.String,
        'id': Edm.String,
        'resourceId': Edm.String,
        'subscriptionDisplayName': Edm.String,
        'subscriptionId': Edm.String,
    }


class cloudPcSubscription(object):
    props = {
        'subscriptionId': Edm.String,
        'subscriptionName': Edm.String,
    }


class cloudPcTenantEncryptionSetting(object):
    props = {
        'lastSyncDateTime': Edm.DateTimeOffset,
        'tenantDiskEncryptionType': cloudPcDiskEncryptionType,
    }


class cloudPcWindowsSetting(object):
    props = {
        'locale': Edm.String,
    }


class cloudPcWindowsSettings(object):
    props = {
        'language': Edm.String,
    }


class microsoftManagedDesktop(object):
    props = {
        'managedType': microsoftManagedDesktopType,
        'profile': Edm.String,
        'type': microsoftManagedDesktopType,
    }


class unifiedRolePermission(object):
    props = {
        'allowedResourceActions': Collection,
        'condition': Edm.String,
        'excludedResourceActions': Collection,
    }


class deviceManagementSettings(object):
    props = {
        'androidDeviceAdministratorEnrollmentEnabled': Edm.Boolean,
        'derivedCredentialProvider': derivedCredentialProviderType,
        'derivedCredentialUrl': Edm.String,
        'deviceComplianceCheckinThresholdDays': Edm.Int32,
        'deviceInactivityBeforeRetirementInDay': Edm.Int32,
        'enableAutopilotDiagnostics': Edm.Boolean,
        'enableDeviceGroupMembershipReport': Edm.Boolean,
        'enableEnhancedTroubleshootingExperience': Edm.Boolean,
        'enableLogCollection': Edm.Boolean,
        'enhancedJailBreak': Edm.Boolean,
        'ignoreDevicesForUnsupportedSettingsEnabled': Edm.Boolean,
        'isScheduledActionEnabled': Edm.Boolean,
        'm365AppDiagnosticsEnabled': Edm.Boolean,
        'secureByDefault': Edm.Boolean,
    }


class adminConsent(object):
    props = {
        'shareAPNSData': adminConsentState,
        'shareUserExperienceAnalyticsData': adminConsentState,
    }


class dataProcessorServiceForWindowsFeaturesOnboarding(object):
    props = {
        'areDataProcessorServiceForWindowsFeaturesEnabled': Edm.Boolean,
        'hasValidWindowsLicense': Edm.Boolean,
    }


class deviceProtectionOverview(object):
    props = {
        'cleanDeviceCount': Edm.Int32,
        'criticalFailuresDeviceCount': Edm.Int32,
        'inactiveThreatAgentDeviceCount': Edm.Int32,
        'pendingFullScanDeviceCount': Edm.Int32,
        'pendingManualStepsDeviceCount': Edm.Int32,
        'pendingOfflineScanDeviceCount': Edm.Int32,
        'pendingQuickScanDeviceCount': Edm.Int32,
        'pendingRestartDeviceCount': Edm.Int32,
        'pendingSignatureUpdateDeviceCount': Edm.Int32,
        'totalReportedDeviceCount': Edm.Int32,
        'unknownStateThreatAgentDeviceCount': Edm.Int32,
    }


class managedDeviceCleanupSettings(object):
    props = {
        'deviceInactivityBeforeRetirementInDays': Edm.String,
    }


class userExperienceAnalyticsAnomalySeverityOverview(object):
    props = {
        'highSeverityAnomalyCount': Edm.Int32,
        'informationalSeverityAnomalyCount': Edm.Int32,
        'lowSeverityAnomalyCount': Edm.Int32,
        'mediumSeverityAnomalyCount': Edm.Int32,
    }


class userExperienceAnalyticsSettings(object):
    props = {
        'configurationManagerDataConnectorConfigured': Edm.Boolean,
    }


class windowsMalwareOverview(object):
    props = {
        'malwareCategorySummary': Collection,
        'malwareDetectedDeviceCount': Edm.Int32,
        'malwareExecutionStateSummary': Collection,
        'malwareNameSummary': Collection,
        'malwareSeveritySummary': Collection,
        'malwareStateSummary': Collection,
        'osVersionsSummary': Collection,
        'totalDistinctMalwareCount': Edm.Int32,
        'totalMalwareCount': Edm.Int32,
    }


class connectorStatusDetails(object):
    props = {
        'connectorInstanceId': Edm.String,
        'connectorName': connectorName,
        'eventDateTime': Edm.DateTimeOffset,
        'status': connectorHealthState,
    }


class chromeOSDeviceProperty(object):
    props = {
        'name': Edm.String,
        'updatable': Edm.Boolean,
        'value': Edm.String,
        'valueType': Edm.String,
    }


class configurationManagerClientEnabledFeatures(object):
    props = {
        'compliancePolicy': Edm.Boolean,
        'deviceConfiguration': Edm.Boolean,
        'endpointProtection': Edm.Boolean,
        'inventory': Edm.Boolean,
        'modernApps': Edm.Boolean,
        'officeApps': Edm.Boolean,
        'resourceAccess': Edm.Boolean,
        'windowsUpdateForBusiness': Edm.Boolean,
    }


class configurationManagerClientHealthState(object):
    props = {
        'errorCode': Edm.Int32,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'state': configurationManagerClientState,
    }


class configurationManagerClientInformation(object):
    props = {
        'clientIdentifier': Edm.String,
        'clientVersion': Edm.String,
        'isBlocked': Edm.Boolean,
    }


class deviceActionResult(object):
    props = {
        'actionName': Edm.String,
        'actionState': actionState,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
    }


class deviceHealthAttestationState(object):
    props = {
        'attestationIdentityKey': Edm.String,
        'bitLockerStatus': Edm.String,
        'bootAppSecurityVersion': Edm.String,
        'bootDebugging': Edm.String,
        'bootManagerSecurityVersion': Edm.String,
        'bootManagerVersion': Edm.String,
        'bootRevisionListInfo': Edm.String,
        'codeIntegrity': Edm.String,
        'codeIntegrityCheckVersion': Edm.String,
        'codeIntegrityPolicy': Edm.String,
        'contentNamespaceUrl': Edm.String,
        'contentVersion': Edm.String,
        'dataExcutionPolicy': Edm.String,
        'deviceHealthAttestationStatus': Edm.String,
        'earlyLaunchAntiMalwareDriverProtection': Edm.String,
        'firmwareProtection': firmwareProtectionType,
        'healthAttestationSupportedStatus': Edm.String,
        'healthStatusMismatchInfo': Edm.String,
        'issuedDateTime': Edm.DateTimeOffset,
        'lastUpdateDateTime': Edm.String,
        'memoryAccessProtection': azureAttestationSettingStatus,
        'memoryIntegrityProtection': azureAttestationSettingStatus,
        'operatingSystemKernelDebugging': Edm.String,
        'operatingSystemRevListInfo': Edm.String,
        'pcr0': Edm.String,
        'pcrHashAlgorithm': Edm.String,
        'resetCount': Edm.Int64,
        'restartCount': Edm.Int64,
        'safeMode': Edm.String,
        'secureBoot': Edm.String,
        'secureBootConfigurationPolicyFingerPrint': Edm.String,
        'securedCorePC': azureAttestationSettingStatus,
        'systemManagementMode': systemManagementModeLevel,
        'testSigning': Edm.String,
        'tpmVersion': Edm.String,
        'virtualizationBasedSecurity': azureAttestationSettingStatus,
        'virtualSecureMode': Edm.String,
        'windowsPE': Edm.String,
    }


class hardwareInformation(object):
    props = {
        'batteryChargeCycles': Edm.Int32,
        'batteryHealthPercentage': Edm.Int32,
        'batteryLevelPercentage': Edm.Double,
        'batterySerialNumber': Edm.String,
        'cellularTechnology': Edm.String,
        'deviceFullQualifiedDomainName': Edm.String,
        'deviceGuardLocalSystemAuthorityCredentialGuardState': deviceGuardLocalSystemAuthorityCredentialGuardState,
        'deviceGuardVirtualizationBasedSecurityHardwareRequirementState': deviceGuardVirtualizationBasedSecurityHardwareRequirementState,
        'deviceGuardVirtualizationBasedSecurityState': deviceGuardVirtualizationBasedSecurityState,
        'deviceLicensingLastErrorCode': Edm.Int32,
        'deviceLicensingLastErrorDescription': Edm.String,
        'deviceLicensingStatus': deviceLicensingStatus,
        'esimIdentifier': Edm.String,
        'freeStorageSpace': Edm.Int64,
        'imei': Edm.String,
        'ipAddressV4': Edm.String,
        'isEncrypted': Edm.Boolean,
        'isSharedDevice': Edm.Boolean,
        'isSupervised': Edm.Boolean,
        'manufacturer': Edm.String,
        'meid': Edm.String,
        'model': Edm.String,
        'operatingSystemEdition': Edm.String,
        'operatingSystemLanguage': Edm.String,
        'operatingSystemProductType': Edm.Int32,
        'osBuildNumber': Edm.String,
        'phoneNumber': Edm.String,
        'productName': Edm.String,
        'residentUsersCount': Edm.Int32,
        'serialNumber': Edm.String,
        'sharedDeviceCachedUsers': Collection,
        'subnetAddress': Edm.String,
        'subscriberCarrier': Edm.String,
        'systemManagementBIOSVersion': Edm.String,
        'totalStorageSpace': Edm.Int64,
        'tpmManufacturer': Edm.String,
        'tpmSpecificationVersion': Edm.String,
        'tpmVersion': Edm.String,
        'wifiMac': Edm.String,
        'wiredIPv4Addresses': Collection,
    }


class loggedOnUser(object):
    props = {
        'lastLogOnDateTime': Edm.DateTimeOffset,
        'userId': Edm.String,
    }


class dataSubject(object):
    props = {
        'email': Edm.String,
        'firstName': Edm.String,
        'lastName': Edm.String,
        'residency': Edm.String,
    }


class itemBody(object):
    props = {
        'content': Edm.String,
        'contentType': bodyType,
    }


class subjectRightsRequestMailboxLocation(object):
    props = {

    }


class subjectRightsRequestAllMailboxLocation(object):
    props = {

    }


class subjectRightsRequestSiteLocation(object):
    props = {

    }


class subjectRightsRequestAllSiteLocation(object):
    props = {

    }


class subjectRightsRequestDetail(object):
    props = {
        'excludedItemCount': Edm.Int64,
        'insightCounts': Collection,
        'itemCount': Edm.Int64,
        'itemNeedReview': Edm.Int64,
        'productItemCounts': Collection,
        'signedOffItemCount': Edm.Int64,
        'totalItemSize': Edm.Int64,
    }


class subjectRightsRequestEnumeratedMailboxLocation(object):
    props = {
        'upns': Collection,
        'userPrincipalNames': Collection,
    }


class subjectRightsRequestEnumeratedSiteLocation(object):
    props = {
        'urls': Collection,
    }


class subjectRightsRequestHistory(object):
    props = {
        'changedBy': identitySet,
        'eventDateTime': Edm.DateTimeOffset,
        'stage': subjectRightsRequestStage,
        'stageStatus': subjectRightsRequestStageStatus,
        'type': Edm.String,
    }


class teamDiscoverySettings(object):
    props = {
        'showInTeamsSearchAndSuggestions': Edm.Boolean,
    }


class teamFunSettings(object):
    props = {
        'allowCustomMemes': Edm.Boolean,
        'allowGiphy': Edm.Boolean,
        'allowStickersAndMemes': Edm.Boolean,
        'giphyContentRating': giphyRatingType,
    }


class teamGuestSettings(object):
    props = {
        'allowCreateUpdateChannels': Edm.Boolean,
        'allowDeleteChannels': Edm.Boolean,
    }


class teamMemberSettings(object):
    props = {
        'allowAddRemoveApps': Edm.Boolean,
        'allowCreatePrivateChannels': Edm.Boolean,
        'allowCreateUpdateChannels': Edm.Boolean,
        'allowCreateUpdateRemoveConnectors': Edm.Boolean,
        'allowCreateUpdateRemoveTabs': Edm.Boolean,
        'allowDeleteChannels': Edm.Boolean,
    }


class teamMessagingSettings(object):
    props = {
        'allowChannelMentions': Edm.Boolean,
        'allowOwnerDeleteMessages': Edm.Boolean,
        'allowTeamMentions': Edm.Boolean,
        'allowUserDeleteMessages': Edm.Boolean,
        'allowUserEditMessages': Edm.Boolean,
    }


class teamSummary(object):
    props = {
        'guestsCount': Edm.Int32,
        'membersCount': Edm.Int32,
        'ownersCount': Edm.Int32,
    }


class resultInfo(object):
    props = {
        'code': Edm.Int32,
        'message': Edm.String,
        'subcode': Edm.Int32,
    }


class deleted(object):
    props = {
        'state': Edm.String,
    }


class root(object):
    props = {

    }


class siteSettings(object):
    props = {
        'languageTag': Edm.String,
        'timeZone': Edm.String,
    }


class sharepointIds(object):
    props = {
        'listId': Edm.String,
        'listItemId': Edm.String,
        'listItemUniqueId': Edm.String,
        'siteId': Edm.String,
        'siteUrl': Edm.String,
        'tenantId': Edm.String,
        'webId': Edm.String,
    }


class resourceAccess(object):
    props = {
        'id': Edm.Guid,
        'type': Edm.String,
    }


class apiAuthenticationConfigurationBase(object):
    props = {

    }


class assignmentOrder(object):
    props = {
        'order': Collection,
    }


class authenticationAttributeCollectionInputConfiguration(object):
    props = {
        'attribute': Edm.String,
        'defaultValue': Edm.String,
        'editable': Edm.Boolean,
        'hidden': Edm.Boolean,
        'inputType': authenticationAttributeCollectionInputType,
        'label': Edm.String,
        'options': Collection,
        'required': Edm.Boolean,
        'validationRegEx': Edm.String,
        'writeToDirectory': Edm.Boolean,
    }


class authenticationAttributeCollectionOptionConfiguration(object):
    props = {
        'label': Edm.String,
        'value': Edm.String,
    }


class authenticationAttributeCollectionPage(object):
    props = {
        'customStringsFileId': Edm.String,
        'views': Collection,
    }


class authenticationAttributeCollectionPageViewConfiguration(object):
    props = {
        'description': Edm.String,
        'inputs': Collection,
        'title': Edm.String,
    }


class authenticationConditionsApplications(object):
    props = {
        'includeAllApplications': Edm.Boolean,
    }


class authenticationConfigurationValidation(object):
    props = {
        'errors': Collection,
        'warnings': Collection,
    }


class genericError(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
    }


class authenticationSourceFilter(object):
    props = {
        'includeApplications': Collection,
    }


class basicAuthentication(object):
    props = {
        'password': Edm.String,
        'username': Edm.String,
    }


class claimsMapping(object):
    props = {
        'displayName': Edm.String,
        'email': Edm.String,
        'givenName': Edm.String,
        'surname': Edm.String,
        'userId': Edm.String,
    }


class clientCertificateAuthentication(object):
    props = {
        'certificateList': Collection,
    }


class pkcs12CertificateInformation(object):
    props = {
        'isActive': Edm.Boolean,
        'notAfter': Edm.Int64,
        'notBefore': Edm.Int64,
        'thumbprint': Edm.String,
    }


class customExtensionBehaviorOnError(object):
    props = {

    }


class customExtensionOverwriteConfiguration(object):
    props = {
        'clientConfiguration': customExtensionClientConfiguration,
    }


class fallbackToMicrosoftProviderOnError(object):
    props = {

    }


class httpRequestEndpoint(object):
    props = {
        'targetUrl': Edm.String,
    }


class oidcAddressInboundClaims(object):
    props = {
        'country': Edm.String,
        'locality': Edm.String,
        'postal_code': Edm.String,
        'region': Edm.String,
        'street_address': Edm.String,
    }


class oidcClientAuthentication(object):
    props = {

    }


class oidcClientSecretAuthentication(object):
    props = {
        'clientSecret': Edm.String,
    }


class oidcInboundClaimMappingOverride(object):
    props = {
        'address': oidcAddressInboundClaims,
        'email': Edm.String,
        'email_verified': Edm.String,
        'family_name': Edm.String,
        'given_name': Edm.String,
        'name': Edm.String,
        'phone_number': Edm.String,
        'phone_number_verified': Edm.String,
        'sub': Edm.String,
    }


class oidcPrivateJwtKeyClientAuthentication(object):
    props = {

    }


class onAttributeCollectionHandler(object):
    props = {

    }


class onAttributeCollectionExternalUsersSelfServiceSignUp(object):
    props = {
        'attributeCollectionPage': authenticationAttributeCollectionPage,
    }


class onAttributeCollectionStartHandler(object):
    props = {

    }


class onAttributeCollectionStartCustomExtensionHandler(object):
    props = {
        'configuration': customExtensionOverwriteConfiguration,
    }


class onAttributeCollectionSubmitHandler(object):
    props = {

    }


class onAttributeCollectionSubmitCustomExtensionHandler(object):
    props = {
        'configuration': customExtensionOverwriteConfiguration,
    }


class onAuthenticationMethodLoadStartHandler(object):
    props = {

    }


class onAuthenticationMethodLoadStartExternalUsersSelfServiceSignUp(object):
    props = {

    }


class onInteractiveAuthFlowStartHandler(object):
    props = {

    }


class onInteractiveAuthFlowStartExternalUsersSelfServiceSignUp(object):
    props = {
        'isSignUpAllowed': Edm.Boolean,
    }


class onOtpSendHandler(object):
    props = {

    }


class onOtpSendCustomExtensionHandler(object):
    props = {
        'configuration': customExtensionOverwriteConfiguration,
    }


class onTokenIssuanceStartHandler(object):
    props = {

    }


class onTokenIssuanceStartCustomExtensionHandler(object):
    props = {
        'configuration': customExtensionOverwriteConfiguration,
    }


class onTokenIssuanceStartReturnClaim(object):
    props = {
        'claimIdInApiResponse': Edm.String,
    }


class onUserCreateStartHandler(object):
    props = {

    }


class onUserCreateStartExternalUsersSelfServiceSignUp(object):
    props = {
        'userTypeToCreate': userType,
    }


class pkcs12Certificate(object):
    props = {
        'password': Edm.String,
        'pkcs12Value': Edm.String,
    }


class selfServiceSignUpAuthenticationFlowConfiguration(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class trustFrameworkKey(object):
    props = {
        'd': Edm.String,
        'dp': Edm.String,
        'dq': Edm.String,
        'e': Edm.String,
        'exp': Edm.Int64,
        'k': Edm.String,
        'kid': Edm.String,
        'kty': Edm.String,
        'n': Edm.String,
        'nbf': Edm.Int64,
        'p': Edm.String,
        'q': Edm.String,
        'qi': Edm.String,
        'status': trustFrameworkKeyStatus,
        'use': Edm.String,
        'x5c': Collection,
        'x5t': Edm.String,
    }


class userAttributeValuesItem(object):
    props = {
        'isDefault': Edm.Boolean,
        'name': Edm.String,
        'value': Edm.String,
    }


class userFlowApiConnectorConfiguration(object):
    props = {

    }


class crossTenantMigrationCancelResponse(object):
    props = {
        'message': Edm.String,
        'status': Edm.String,
    }


class labelActionBase(object):
    props = {
        'name': Edm.String,
    }


class markContent(object):
    props = {
        'fontColor': Edm.String,
        'fontSize': Edm.Int64,
        'text': Edm.String,
    }


class addFooter(object):
    props = {
        'alignment': alignment,
        'margin': Edm.Int32,
    }


class addHeader(object):
    props = {
        'alignment': alignment,
        'margin': Edm.Int32,
    }


class addWatermark(object):
    props = {
        'orientation': pageOrientation,
    }


class autoLabeling(object):
    props = {
        'message': Edm.String,
        'sensitiveTypeIds': Collection,
    }


class dlpActionInfo(object):
    props = {

    }


class blockAccessAction(object):
    props = {

    }


class classificationInnerError(object):
    props = {
        'activityId': Edm.String,
        'clientRequestId': Edm.String,
        'code': Edm.String,
        'errorDateTime': Edm.DateTimeOffset,
    }


class classificationAttribute(object):
    props = {
        'confidence': Edm.Int32,
        'count': Edm.Int32,
    }


class classificationError(object):
    props = {
        'details': Collection,
    }


class classificationRequestContentMetaData(object):
    props = {
        'sourceId': Edm.String,
    }


class contentMetadata(object):
    props = {

    }


class contentProperties(object):
    props = {
        'extensions': Collection,
        'lastModifiedBy': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'metadata': contentMetadata,
    }


class currentLabel(object):
    props = {
        'applicationMode': applicationMode,
        'id': Edm.String,
    }


class customMetadataDictionary(object):
    props = {

    }


class detectedSensitiveContentBase(object):
    props = {
        'confidence': Edm.Int32,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'recommendedConfidence': Edm.Int32,
        'uniqueCount': Edm.Int32,
    }


class detectedSensitiveContent(object):
    props = {
        'classificationAttributes': Collection,
        'classificationMethod': classificationMethod,
        'matches': Collection,
        'scope': sensitiveTypeScope,
        'sensitiveTypeSource': sensitiveTypeSource,
    }


class sensitiveContentLocation(object):
    props = {
        'confidence': Edm.Int32,
        'evidences': Collection,
        'idMatch': Edm.String,
        'length': Edm.Int32,
        'offset': Edm.Int32,
    }


class detectedSensitiveContentWrapper(object):
    props = {
        'classification': Collection,
    }


class deviceProperties(object):
    props = {
        'deviceIdentifiers': Collection,
    }


class discoveredSensitiveType(object):
    props = {
        'classificationAttributes': Collection,
        'confidence': Edm.Int32,
        'count': Edm.Int32,
        'id': Edm.Guid,
    }


class dlpEvaluationInput(object):
    props = {
        'currentLabel': currentLabel,
        'discoveredSensitiveTypes': Collection,
    }


class dlpNotification(object):
    props = {
        'author': Edm.String,
    }


class dlpEvaluationWindowsDevicesInput(object):
    props = {
        'contentProperties': contentProperties,
        'sharedBy': Edm.String,
    }


class dlpPoliciesJobResult(object):
    props = {
        'auditCorrelationId': Edm.String,
        'evaluationDateTime': Edm.DateTimeOffset,
        'matchingRules': Collection,
    }


class matchingDlpRule(object):
    props = {
        'actions': Collection,
        'isMostRestrictive': Edm.Boolean,
        'policyId': Edm.String,
        'policyName': Edm.String,
        'priority': Edm.Int32,
        'ruleId': Edm.String,
        'ruleMode': ruleMode,
        'ruleName': Edm.String,
    }


class dlpWindowsDevicesNotification(object):
    props = {
        'contentName': Edm.String,
        'lastModfiedBy': Edm.String,
    }


class encryptContent(object):
    props = {
        'encryptWith': encryptWith,
    }


class encryptWithTemplate(object):
    props = {
        'availableForEncryption': Edm.Boolean,
        'templateId': Edm.String,
    }


class encryptWithUserDefinedRights(object):
    props = {
        'allowAdHocPermissions': Edm.Boolean,
        'allowMailForwarding': Edm.Boolean,
        'decryptionRightsManagementTemplateId': Edm.String,
    }


class responsiblePolicy(object):
    props = {
        'id': Edm.String,
        'name': Edm.String,
    }


class responsibleSensitiveType(object):
    props = {
        'description': Edm.String,
        'id': Edm.String,
        'name': Edm.String,
        'publisherName': Edm.String,
        'rulePackageId': Edm.String,
        'rulePackageType': Edm.String,
    }


class matchingLabel(object):
    props = {
        'applicationMode': applicationMode,
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
        'isEndpointProtectionEnabled': Edm.Boolean,
        'labelActions': Collection,
        'name': Edm.String,
        'policyTip': Edm.String,
        'priority': Edm.Int32,
        'toolTip': Edm.String,
    }


class evaluateSensitivityLabelsRequest(object):
    props = {
        'currentLabel': currentLabel,
        'discoveredSensitiveTypes': Collection,
    }


class justInTimeEnforcementConfiguration(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class labelPolicy(object):
    props = {
        'id': Edm.String,
        'name': Edm.String,
    }


class lobbyBypassSettings(object):
    props = {
        'isDialInBypassEnabled': Edm.Boolean,
        'scope': lobbyBypassScope,
    }


class machineLearningDetectedSensitiveContent(object):
    props = {
        'matchTolerance': mlClassificationMatchTolerance,
        'modelVersion': Edm.String,
    }


class matchedCondition(object):
    props = {
        'condition': Edm.String,
        'displayName': Edm.String,
        'values': Collection,
    }


class metadataEntry(object):
    props = {
        'key': Edm.String,
        'value': Edm.String,
    }


class notifyUserAction(object):
    props = {
        'actionLastModifiedDateTime': Edm.DateTimeOffset,
        'emailText': Edm.String,
        'policyTip': Edm.String,
        'recipients': Collection,
    }


class opticalCharacterRecognitionConfiguration(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class protectGroup(object):
    props = {
        'allowEmailFromGuestUsers': Edm.Boolean,
        'allowGuestUsers': Edm.Boolean,
        'privacy': groupPrivacy,
    }


class protectOnlineMeetingAction(object):
    props = {
        'allowedForwarders': onlineMeetingForwarders,
        'allowedPresenters': onlineMeetingPresenters,
        'isCopyToClipboardEnabled': Edm.Boolean,
        'isLobbyEnabled': Edm.Boolean,
        'lobbyBypassSettings': lobbyBypassSettings,
    }


class protectSite(object):
    props = {
        'accessType': siteAccessType,
        'conditionalAccessProtectionLevelId': Edm.String,
    }


class sensitiveContentEvidence(object):
    props = {
        'length': Edm.Int32,
        'match': Edm.String,
        'offset': Edm.Int32,
    }


class trustContainerConfiguration(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class watermarkProtectionValues(object):
    props = {
        'isEnabledForContentSharing': Edm.Boolean,
        'isEnabledForVideo': Edm.Boolean,
    }


class deviceLocalCredential(object):
    props = {
        'accountName': Edm.String,
        'accountSid': Edm.String,
        'backupDateTime': Edm.DateTimeOffset,
        'passwordBase64': Edm.String,
    }


class deviceRegistrationMembership(object):
    props = {

    }


class allDeviceRegistrationMembership(object):
    props = {

    }


class localAdminSettings(object):
    props = {
        'enableGlobalAdmins': Edm.Boolean,
        'registeringUsers': deviceRegistrationMembership,
    }


class azureADRegistrationPolicy(object):
    props = {
        'allowedToRegister': deviceRegistrationMembership,
        'isAdminConfigurable': Edm.Boolean,
    }


class enumeratedDeviceRegistrationMembership(object):
    props = {
        'groups': Collection,
        'users': Collection,
    }


class localAdminPasswordSettings(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class noDeviceRegistrationMembership(object):
    props = {

    }


class validatingDomains(object):
    props = {
        'rootDomains': rootDomains,
    }


class allDomains(object):
    props = {

    }


class preApprovedPermissions(object):
    props = {
        'permissionKind': permissionKind,
        'permissionType': permissionType,
    }


class allPreApprovedPermissions(object):
    props = {

    }


class allPreApprovedPermissionsOnResourceApp(object):
    props = {
        'resourceApplicationId': Edm.String,
    }


class scopeSensitivityLabels(object):
    props = {
        'labelKind': labelKind,
    }


class allScopeSensitivityLabels(object):
    props = {

    }


class preAuthorizedApplication(object):
    props = {
        'appId': Edm.String,
        'permissionIds': Collection,
    }


class apiServicePrincipal(object):
    props = {
        'resourceSpecificApplicationPermissions': Collection,
    }


class resourceSpecificPermission(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'isEnabled': Edm.Boolean,
        'value': Edm.String,
    }


class appManagementConfiguration(object):
    props = {
        'keyCredentials': Collection,
        'passwordCredentials': Collection,
    }


class keyCredentialConfiguration(object):
    props = {
        'certificateBasedApplicationConfigurationIds': Collection,
        'maxLifetime': Edm.Duration,
        'restrictForAppsCreatedAfterDateTime': Edm.DateTimeOffset,
        'restrictionType': appKeyCredentialRestrictionType,
        'state': appManagementRestrictionState,
    }


class passwordCredentialConfiguration(object):
    props = {
        'maxLifetime': Edm.Duration,
        'restrictForAppsCreatedAfterDateTime': Edm.DateTimeOffset,
        'restrictionType': appCredentialRestrictionType,
        'state': appManagementRestrictionState,
    }


class appManagementPolicyActorExemptions(object):
    props = {

    }


class appManagementServicePrincipalConfiguration(object):
    props = {

    }


class appMetadata(object):
    props = {
        'data': Collection,
        'version': Edm.Int32,
    }


class appMetadataEntry(object):
    props = {
        'key': Edm.String,
        'value': Edm.Binary,
    }


class certificateAuthority(object):
    props = {
        'certificate': Edm.Binary,
        'certificateRevocationListUrl': Edm.String,
        'deltaCertificateRevocationListUrl': Edm.String,
        'isRootAuthority': Edm.Boolean,
        'issuer': Edm.String,
        'issuerSki': Edm.String,
    }


class ComplexExtensionValue(object):
    props = {

    }


class contentCustomization(object):
    props = {
        'attributeCollection': Collection,
        'attributeCollectionRelativeUrl': Edm.String,
        'registrationCampaign': Collection,
        'registrationCampaignRelativeUrl': Edm.String,
    }


class conversionUserDetails(object):
    props = {
        'convertedToInternalUserDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'mail': Edm.String,
        'userPrincipalName': Edm.String,
    }


class crossTenantAccessPolicyTargetConfiguration(object):
    props = {
        'accessType': crossTenantAccessPolicyTargetConfigurationAccessType,
        'targets': Collection,
    }


class crossTenantAccessPolicyInboundTrust(object):
    props = {
        'isCompliantDeviceAccepted': Edm.Boolean,
        'isHybridAzureADJoinedDeviceAccepted': Edm.Boolean,
        'isMfaAccepted': Edm.Boolean,
    }


class crossTenantAccessPolicyTarget(object):
    props = {
        'target': Edm.String,
        'targetType': crossTenantAccessPolicyTargetType,
    }


class devicesFilter(object):
    props = {
        'mode': crossTenantAccessPolicyTargetConfigurationAccessType,
        'rule': Edm.String,
    }


class crossTenantUserSyncInbound(object):
    props = {
        'isSyncAllowed': Edm.Boolean,
    }


class customClaimBase(object):
    props = {
        'configurations': Collection,
    }


class customClaim(object):
    props = {
        'name': Edm.String,
        'namespace': Edm.String,
        'samlAttributeNameFormat': samlAttributeNameFormat,
        'tokenFormat': Collection,
    }


class customClaimAttributeBase(object):
    props = {

    }


class customClaimConditionBase(object):
    props = {

    }


class customClaimCondition(object):
    props = {
        'memberOf': Collection,
        'userType': claimConditionUserType,
    }


class invitationRedemptionIdentityProviderConfiguration(object):
    props = {
        'fallbackIdentityProvider': b2bIdentityProvidersType,
        'primaryIdentityProviderPrecedenceOrder': Collection,
    }


class defaultInvitationRedemptionIdentityProviderConfiguration(object):
    props = {

    }


class defaultUserRolePermissions(object):
    props = {
        'allowedToCreateApps': Edm.Boolean,
        'allowedToCreateSecurityGroups': Edm.Boolean,
        'allowedToCreateTenants': Edm.Boolean,
        'allowedToReadBitlockerKeysForOwnedDevice': Edm.Boolean,
        'allowedToReadOtherUsers': Edm.Boolean,
    }


class directorySizeQuota(object):
    props = {
        'total': Edm.Int32,
        'used': Edm.Int32,
    }


class domainState(object):
    props = {
        'lastActionDateTime': Edm.DateTimeOffset,
        'operation': Edm.String,
        'status': Edm.String,
    }


class enumeratedDomains(object):
    props = {
        'domainNames': Collection,
    }


class enumeratedPreApprovedPermissions(object):
    props = {
        'permissionIds': Collection,
        'resourceApplicationId': Edm.String,
    }


class enumeratedScopeSensitivityLabels(object):
    props = {
        'sensitivityLabels': Collection,
    }


class extractAlphaTransformation(object):
    props = {
        'type': transformationExtractType,
    }


class extractMailPrefixTransformation(object):
    props = {

    }


class extractNumberTransformation(object):
    props = {
        'type': transformationExtractType,
    }


class extractTransformation(object):
    props = {
        'type': Edm.String,
        'value': Edm.String,
        'value2': Edm.String,
    }


class federatedIdentityExpression(object):
    props = {
        'languageVersion': Edm.Int32,
        'value': Edm.String,
    }


class identifierUriRestriction(object):
    props = {
        'excludeActors': appManagementPolicyActorExemptions,
        'excludeAppsReceivingV2Tokens': Edm.Boolean,
        'excludeSaml': Edm.Boolean,
        'isStateSetByMicrosoft': Edm.Boolean,
        'restrictForAppsCreatedAfterDateTime': Edm.DateTimeOffset,
        'state': appManagementRestrictionState,
    }


class implicitGrantSettings(object):
    props = {
        'enableAccessTokenIssuance': Edm.Boolean,
        'enableIdTokenIssuance': Edm.Boolean,
    }


class inboundOutboundPolicyConfiguration(object):
    props = {
        'inboundAllowed': Edm.Boolean,
        'outboundAllowed': Edm.Boolean,
    }


class instanceResourceAccess(object):
    props = {
        'permissions': Collection,
        'resourceAppId': Edm.String,
    }


class resourcePermission(object):
    props = {
        'type': Edm.String,
        'value': Edm.String,
    }


class licenseUnitsDetail(object):
    props = {
        'enabled': Edm.Int32,
        'lockedOut': Edm.Int32,
        'suspended': Edm.Int32,
        'warning': Edm.Int32,
    }


class loginPageBrandingVisualElement(object):
    props = {
        'customText': Edm.String,
        'customUrl': Edm.String,
        'isHidden': Edm.Boolean,
    }


class loginPageLayoutConfiguration(object):
    props = {
        'isFooterShown': Edm.Boolean,
        'isHeaderShown': Edm.Boolean,
        'layoutTemplateType': layoutTemplateType,
    }


class loginPageTextVisibilitySettings(object):
    props = {
        'hideAccountResetCredentials': Edm.Boolean,
        'hideCannotAccessYourAccount': Edm.Boolean,
        'hideForgotMyPassword': Edm.Boolean,
        'hidePrivacyAndCookies': Edm.Boolean,
        'hideResetItNow': Edm.Boolean,
        'hideTermsOfUse': Edm.Boolean,
    }


class multiTenantOrganizationJoinRequestTransitionDetails(object):
    props = {
        'desiredMemberState': multiTenantOrganizationMemberState,
        'details': Edm.String,
        'status': multiTenantOrganizationMemberProcessingStatus,
    }


class multiTenantOrganizationMemberTransitionDetails(object):
    props = {
        'desiredRole': multiTenantOrganizationMemberRole,
        'desiredState': multiTenantOrganizationMemberState,
        'details': Edm.String,
        'status': multiTenantOrganizationMemberProcessingStatus,
    }


class oathTokenMetadata(object):
    props = {
        'enabled': Edm.Boolean,
        'manufacturer': Edm.String,
        'manufacturerProperties': Collection,
        'serialNumber': Edm.String,
        'tokenType': Edm.String,
    }


class onPremisesAccidentalDeletionPrevention(object):
    props = {
        'alertThreshold': Edm.Int32,
        'synchronizationPreventionType': onPremisesDirectorySynchronizationDeletionPreventionType,
    }


class onPremisesCurrentExportData(object):
    props = {
        'clientMachineName': Edm.String,
        'pendingObjectsAddition': Edm.Int32,
        'pendingObjectsDeletion': Edm.Int32,
        'pendingObjectsUpdate': Edm.Int32,
        'serviceAccount': Edm.String,
        'successfulLinksProvisioningCount': Edm.Int64,
        'successfulObjectsProvisioningCount': Edm.Int32,
        'totalConnectorSpaceObjects': Edm.Int32,
    }


class onPremisesWritebackConfiguration(object):
    props = {
        'unifiedGroupContainer': Edm.String,
        'userContainer': Edm.String,
    }


class onPremisesDirectorySynchronizationFeature(object):
    props = {
        'blockCloudObjectTakeoverThroughHardMatchEnabled': Edm.Boolean,
        'blockSoftMatchEnabled': Edm.Boolean,
        'bypassDirSyncOverridesEnabled': Edm.Boolean,
        'cloudPasswordPolicyForPasswordSyncedUsersEnabled': Edm.Boolean,
        'concurrentCredentialUpdateEnabled': Edm.Boolean,
        'concurrentOrgIdProvisioningEnabled': Edm.Boolean,
        'deviceWritebackEnabled': Edm.Boolean,
        'directoryExtensionsEnabled': Edm.Boolean,
        'fopeConflictResolutionEnabled': Edm.Boolean,
        'groupWriteBackEnabled': Edm.Boolean,
        'passwordSyncEnabled': Edm.Boolean,
        'passwordWritebackEnabled': Edm.Boolean,
        'quarantineUponProxyAddressesConflictEnabled': Edm.Boolean,
        'quarantineUponUpnConflictEnabled': Edm.Boolean,
        'softMatchOnUpnEnabled': Edm.Boolean,
        'synchronizeUpnForManagedUsersEnabled': Edm.Boolean,
        'unifiedGroupWritebackEnabled': Edm.Boolean,
        'userForcePasswordChangeOnLogonEnabled': Edm.Boolean,
        'userWritebackEnabled': Edm.Boolean,
    }


class optionalClaim(object):
    props = {
        'additionalProperties': Collection,
        'essential': Edm.Boolean,
        'name': Edm.String,
        'source': Edm.String,
    }


class passwordValidationInformation(object):
    props = {
        'isValid': Edm.Boolean,
        'validationResults': Collection,
    }


class validationResult(object):
    props = {
        'message': Edm.String,
        'ruleName': Edm.String,
        'validationPassed': Edm.Boolean,
    }


class physicalOfficeAddress(object):
    props = {
        'city': Edm.String,
        'countryOrRegion': Edm.String,
        'officeLocation': Edm.String,
        'postalCode': Edm.String,
        'state': Edm.String,
        'street': Edm.String,
    }


class preApprovalDetail(object):
    props = {
        'permissions': preApprovedPermissions,
        'scopeType': resourceScopeType,
        'sensitivityLabels': scopeSensitivityLabels,
    }


class privacyProfile(object):
    props = {
        'contactEmail': Edm.String,
        'statementUrl': Edm.String,
    }


class redirectUriSettings(object):
    props = {
        'index': Edm.Int32,
        'uri': Edm.String,
    }


class regexReplaceTransformation(object):
    props = {
        'additionalAttributes': Collection,
        'regex': Edm.String,
        'replacement': Edm.String,
    }


class sourcedAttribute(object):
    props = {
        'id': Edm.String,
        'isExtensionAttribute': Edm.Boolean,
        'source': Edm.String,
    }


class samlNameIdClaim(object):
    props = {
        'nameIdFormat': samlNameIDFormat,
        'serviceProviderNameQualifier': Edm.String,
    }


class selfSignedCertificate(object):
    props = {
        'customKeyIdentifier': Edm.Binary,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'key': Edm.Binary,
        'keyId': Edm.Guid,
        'startDateTime': Edm.DateTimeOffset,
        'thumbprint': Edm.String,
        'type': Edm.String,
        'usage': Edm.String,
    }


class servicePlanInfo(object):
    props = {
        'appliesTo': Edm.String,
        'provisioningStatus': Edm.String,
        'servicePlanId': Edm.Guid,
        'servicePlanName': Edm.String,
    }


class serviceProvisioningResourceErrorDetail(object):
    props = {
        'code': Edm.String,
        'details': Edm.String,
        'message': Edm.String,
    }


class serviceProvisioningLinkedResourceErrorDetail(object):
    props = {
        'propertyName': Edm.String,
        'target': Edm.String,
    }


class serviceProvisioningResourceError(object):
    props = {
        'errors': Collection,
    }


class serviceProvisioningXmlError(object):
    props = {
        'errorDetail': Edm.String,
    }


class settingTemplateValue(object):
    props = {
        'defaultValue': Edm.String,
        'description': Edm.String,
        'name': Edm.String,
        'type': Edm.String,
    }


class settingValue(object):
    props = {
        'name': Edm.String,
        'value': Edm.String,
    }


class signingCertificateUpdateStatus(object):
    props = {
        'certificateUpdateResult': Edm.String,
        'lastRunDateTime': Edm.DateTimeOffset,
    }


class substringTransformation(object):
    props = {
        'index': Edm.Int32,
        'length': Edm.Int32,
    }


class tenantInformation(object):
    props = {
        'defaultDomainName': Edm.String,
        'displayName': Edm.String,
        'federationBrandName': Edm.String,
        'tenantId': Edm.String,
    }


class toLowercaseTransformation(object):
    props = {

    }


class toUppercaseTransformation(object):
    props = {

    }


class trimTransformation(object):
    props = {
        'type': transformationTrimType,
        'value': Edm.String,
    }


class valueBasedAttribute(object):
    props = {
        'value': Edm.String,
    }


class verifiedDomain(object):
    props = {
        'capabilities': Edm.String,
        'isDefault': Edm.Boolean,
        'isInitial': Edm.Boolean,
        'name': Edm.String,
        'type': Edm.String,
    }


class certificateConnectorSetting(object):
    props = {
        'certExpiryTime': Edm.DateTimeOffset,
        'connectorVersion': Edm.String,
        'enrollmentError': Edm.String,
        'lastConnectorConnectionTime': Edm.DateTimeOffset,
        'lastUploadVersion': Edm.Int64,
        'status': Edm.Int32,
    }


class browserSharedCookieHistory(object):
    props = {
        'comment': Edm.String,
        'displayName': Edm.String,
        'hostOnly': Edm.Boolean,
        'hostOrDomain': Edm.String,
        'lastModifiedBy': identitySet,
        'path': Edm.String,
        'publishedDateTime': Edm.DateTimeOffset,
        'sourceEnvironment': browserSharedCookieSourceEnvironment,
    }


class browserSiteHistory(object):
    props = {
        'allowRedirect': Edm.Boolean,
        'comment': Edm.String,
        'compatibilityMode': browserSiteCompatibilityMode,
        'lastModifiedBy': identitySet,
        'mergeType': browserSiteMergeType,
        'publishedDateTime': Edm.DateTimeOffset,
        'targetEnvironment': browserSiteTargetEnvironment,
    }


class challengingWord(object):
    props = {
        'count': Edm.Int64,
        'word': Edm.String,
    }


class educationAssignmentRecipient(object):
    props = {

    }


class educationAssignmentClassRecipient(object):
    props = {

    }


class educationAssignmentGrade(object):
    props = {
        'gradedBy': identitySet,
        'gradedDateTime': Edm.DateTimeOffset,
    }


class educationAssignmentGradeType(object):
    props = {

    }


class educationAssignmentGroupRecipient(object):
    props = {

    }


class educationAssignmentIndividualRecipient(object):
    props = {
        'recipients': Collection,
    }


class educationAssignmentPointsGrade(object):
    props = {
        'points': Edm.Single,
    }


class educationAssignmentPointsGradeType(object):
    props = {
        'maxPoints': Edm.Single,
    }


class educationResource(object):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class educationChannelResource(object):
    props = {
        'url': Edm.String,
    }


class educationExcelResource(object):
    props = {
        'fileUrl': Edm.String,
    }


class educationExternalResource(object):
    props = {
        'webUrl': Edm.String,
    }


class educationItemBody(object):
    props = {
        'content': Edm.String,
        'contentType': bodyType,
    }


class educationFileResource(object):
    props = {
        'fileUrl': Edm.String,
    }


class educationGradingSchemeGrade(object):
    props = {
        'defaultPercentage': Edm.Single,
        'displayName': Edm.String,
        'minPercentage': Edm.Single,
    }


class educationLinkedAssignmentResource(object):
    props = {
        'url': Edm.String,
    }


class educationLinkResource(object):
    props = {
        'link': Edm.String,
    }


class educationMediaResource(object):
    props = {
        'fileUrl': Edm.String,
    }


class educationPowerPointResource(object):
    props = {
        'fileUrl': Edm.String,
    }


class educationSubmissionRecipient(object):
    props = {

    }


class educationSubmissionIndividualRecipient(object):
    props = {
        'userId': Edm.String,
    }


class educationTeamsAppResource(object):
    props = {
        'appIconWebUrl': Edm.String,
        'appId': Edm.String,
        'teamsEmbeddedContentUrl': Edm.String,
        'webUrl': Edm.String,
    }


class educationWordResource(object):
    props = {
        'fileUrl': Edm.String,
    }


class rubricCriterion(object):
    props = {
        'description': educationItemBody,
    }


class rubricLevel(object):
    props = {
        'description': educationItemBody,
        'displayName': Edm.String,
        'grading': educationAssignmentGradeType,
        'levelId': Edm.String,
    }


class rubricQuality(object):
    props = {
        'criteria': Collection,
        'description': educationItemBody,
        'displayName': Edm.String,
        'qualityId': Edm.String,
        'weight': Edm.Single,
    }


class rubricQualityFeedbackModel(object):
    props = {
        'feedback': educationItemBody,
        'qualityId': Edm.String,
    }


class rubricQualitySelectedColumnModel(object):
    props = {
        'columnId': Edm.String,
        'qualityId': Edm.String,
    }


class educationCourse(object):
    props = {
        'courseNumber': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'externalId': Edm.String,
        'subject': Edm.String,
    }


class educationTerm(object):
    props = {
        'displayName': Edm.String,
        'endDate': Edm.Date,
        'externalId': Edm.String,
        'startDate': Edm.Date,
    }


class relatedContact(object):
    props = {
        'accessConsent': Edm.Boolean,
        'displayName': Edm.String,
        'emailAddress': Edm.String,
        'id': Edm.String,
        'mobilePhone': Edm.String,
        'relationship': contactRelationship,
    }


class educationOnPremisesInfo(object):
    props = {
        'immutableId': Edm.String,
    }


class educationStudent(object):
    props = {
        'birthDate': Edm.Date,
        'externalId': Edm.String,
        'gender': educationGender,
        'grade': Edm.String,
        'graduationYear': Edm.String,
        'studentNumber': Edm.String,
    }


class educationTeacher(object):
    props = {
        'externalId': Edm.String,
        'teacherNumber': Edm.String,
    }


class artifactQuery(object):
    props = {
        'artifactType': restorableArtifact,
        'queryExpression': Edm.String,
    }


class restorePointSearchResponse(object):
    props = {
        'noResultProtectionUnitIds': Collection,
        'searchResponseId': Edm.String,
        'searchResults': Collection,
    }


class restorePointSearchResult(object):
    props = {
        'artifactHitCount': Edm.Int32,
    }


class restoreSessionArtifactCount(object):
    props = {
        'completed': Edm.Int32,
        'failed': Edm.Int32,
        'inProgress': Edm.Int32,
        'total': Edm.Int32,
    }


class retentionSetting(object):
    props = {
        'interval': Edm.String,
        'period': Edm.Duration,
    }


class serviceStatus(object):
    props = {
        'backupServiceConsumer': backupServiceConsumer,
        'disableReason': disableReason,
        'gracePeriodDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'restoreAllowedTillDateTime': Edm.DateTimeOffset,
        'status': backupServiceStatus,
    }


class timePeriod(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
    }


class contentClassification(object):
    props = {
        'confidence': Edm.Int32,
        'matches': Collection,
        'sensitiveTypeId': Edm.String,
        'uniqueCount': Edm.Int32,
    }


class matchLocation(object):
    props = {
        'length': Edm.Int32,
        'offset': Edm.Int32,
    }


class dataStoreField(object):
    props = {
        'name': Edm.String,
        'searchable': Edm.Boolean,
        'unique': Edm.Boolean,
    }


class exactDataMatchStoreColumn(object):
    props = {
        'ignoredDelimiters': Collection,
        'isCaseInsensitive': Edm.Boolean,
        'isSearchable': Edm.Boolean,
        'name': Edm.String,
    }


class exactMatchClassificationRequest(object):
    props = {
        'contentClassifications': Collection,
        'sensitiveTypeIds': Collection,
        'text': Edm.String,
        'timeoutInMs': Edm.Int32,
    }


class exactMatchClassificationResult(object):
    props = {
        'classification': Collection,
        'errors': Collection,
    }


class exactMatchDetectedSensitiveContent(object):
    props = {
        'matches': Collection,
    }


class Json(object):
    props = {

    }


class workbookDocumentTaskSchedule(object):
    props = {
        'dueDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
    }


class workbookEmailIdentity(object):
    props = {
        'displayName': Edm.String,
        'email': Edm.String,
        'id': Edm.String,
    }


class workbookIcon(object):
    props = {
        'index': Edm.Int32,
        'set': Edm.String,
    }


class workbookFilterDatetime(object):
    props = {
        'date': Edm.String,
        'specificity': Edm.String,
    }


class workbookRangeReference(object):
    props = {
        'address': Edm.String,
    }


class workbookSessionInfo(object):
    props = {
        'id': Edm.String,
        'persistChanges': Edm.Boolean,
    }


class workbookSortField(object):
    props = {
        'ascending': Edm.Boolean,
        'color': Edm.String,
        'dataOption': Edm.String,
        'icon': workbookIcon,
        'key': Edm.Int32,
        'sortOn': Edm.String,
    }


class workbookWorksheetProtectionOptions(object):
    props = {
        'allowAutoFilter': Edm.Boolean,
        'allowDeleteColumns': Edm.Boolean,
        'allowDeleteRows': Edm.Boolean,
        'allowFormatCells': Edm.Boolean,
        'allowFormatColumns': Edm.Boolean,
        'allowFormatRows': Edm.Boolean,
        'allowInsertColumns': Edm.Boolean,
        'allowInsertHyperlinks': Edm.Boolean,
        'allowInsertRows': Edm.Boolean,
        'allowPivotTables': Edm.Boolean,
        'allowSort': Edm.Boolean,
    }


class systemFacet(object):
    props = {

    }


class audio(object):
    props = {
        'album': Edm.String,
        'albumArtist': Edm.String,
        'artist': Edm.String,
        'bitrate': Edm.Int64,
        'composers': Edm.String,
        'copyright': Edm.String,
        'disc': Edm.Int16,
        'discCount': Edm.Int16,
        'duration': Edm.Int64,
        'genre': Edm.String,
        'hasDrm': Edm.Boolean,
        'isVariableBitrate': Edm.Boolean,
        'title': Edm.String,
        'track': Edm.Int32,
        'trackCount': Edm.Int32,
        'year': Edm.Int32,
    }


class fileSystemInfo(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastAccessedDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class image(object):
    props = {
        'height': Edm.Int32,
        'width': Edm.Int32,
    }


class malware(object):
    props = {
        'description': Edm.String,
    }


class package(object):
    props = {
        'type': Edm.String,
    }


class photo(object):
    props = {
        'cameraMake': Edm.String,
        'cameraModel': Edm.String,
        'exposureDenominator': Edm.Double,
        'exposureNumerator': Edm.Double,
        'fNumber': Edm.Double,
        'focalLength': Edm.Double,
        'iso': Edm.Int32,
        'orientation': Edm.Int16,
        'takenDateTime': Edm.DateTimeOffset,
    }


class publicationFacet(object):
    props = {
        'checkedOutBy': identitySet,
        'level': Edm.String,
        'versionId': Edm.String,
    }


class searchResult(object):
    props = {
        'onClickTelemetryUrl': Edm.String,
    }


class shared(object):
    props = {
        'owner': identitySet,
        'scope': Edm.String,
        'sharedBy': identitySet,
        'sharedDateTime': Edm.DateTimeOffset,
    }


class driveItemSource(object):
    props = {
        'application': driveItemSourceApplication,
        'externalId': Edm.String,
    }


class specialFolder(object):
    props = {
        'name': Edm.String,
    }


class video(object):
    props = {
        'audioBitsPerSample': Edm.Int32,
        'audioChannels': Edm.Int32,
        'audioFormat': Edm.String,
        'audioSamplesPerSecond': Edm.Int32,
        'bitrate': Edm.Int32,
        'duration': Edm.Int64,
        'fourCC': Edm.String,
        'frameRate': Edm.Double,
        'height': Edm.Int32,
        'width': Edm.Int32,
    }


class listInfo(object):
    props = {
        'contentTypesEnabled': Edm.Boolean,
        'hidden': Edm.Boolean,
        'template': Edm.String,
    }


class attendeeBase(object):
    props = {
        'type': attendeeType,
    }


class locationConstraint(object):
    props = {
        'isRequired': Edm.Boolean,
        'locations': Collection,
        'suggestLocation': Edm.Boolean,
    }


class locationConstraintItem(object):
    props = {
        'resolveAvailability': Edm.Boolean,
    }


class meetingTimeSuggestion(object):
    props = {
        'attendeeAvailability': Collection,
        'confidence': Edm.Double,
        'locations': Collection,
        'meetingTimeSlot': timeSlot,
        'order': Edm.Int32,
        'organizerAvailability': freeBusyStatus,
        'suggestionReason': Edm.String,
    }


class meetingTimeSuggestionsResult(object):
    props = {
        'emptySuggestionsReason': Edm.String,
        'meetingTimeSuggestions': Collection,
    }


class timeConstraint(object):
    props = {
        'activityDomain': activityDomain,
        'timeSlots': Collection,
    }


class workplaceSensor(object):
    props = {
        'displayName': Edm.String,
        'placeId': Edm.String,
        'sensorId': Edm.String,
        'sensorType': workplaceSensorType,
    }


class emailIdentity(object):
    props = {
        'email': Edm.String,
    }


class customAppScopeAttributesDictionary(object):
    props = {

    }


class attachmentItem(object):
    props = {
        'attachmentType': attachmentType,
        'contentId': Edm.String,
        'contentType': Edm.String,
        'isInline': Edm.Boolean,
        'name': Edm.String,
        'size': Edm.Int64,
    }


class responseStatus(object):
    props = {
        'response': responseType,
        'time': Edm.DateTimeOffset,
    }


class localeInfo(object):
    props = {
        'displayName': Edm.String,
        'locale': Edm.String,
    }


class automaticRepliesSetting(object):
    props = {
        'externalAudience': externalAudienceScope,
        'externalReplyMessage': Edm.String,
        'internalReplyMessage': Edm.String,
        'scheduledEndDateTime': dateTimeTimeZone,
        'scheduledStartDateTime': dateTimeTimeZone,
        'status': automaticRepliesStatus,
    }


class calendarSharingMessageAction(object):
    props = {
        'action': calendarSharingAction,
        'actionType': calendarSharingActionType,
        'importance': calendarSharingActionImportance,
    }


class convertIdResult(object):
    props = {
        'errorDetails': genericError,
        'sourceId': Edm.String,
        'targetId': Edm.String,
    }


class timeZoneBase(object):
    props = {
        'name': Edm.String,
    }


class standardTimeZoneOffset(object):
    props = {
        'dayOccurrence': Edm.Int32,
        'dayOfWeek': dayOfWeek,
        'month': Edm.Int32,
        'time': Edm.TimeOfDay,
        'year': Edm.Int32,
    }


class daylightTimeZoneOffset(object):
    props = {
        'daylightBias': Edm.Int32,
    }


class mailTipsError(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
    }


class followupFlag(object):
    props = {
        'completedDateTime': dateTimeTimeZone,
        'dueDateTime': dateTimeTimeZone,
        'flagStatus': followupFlagStatus,
        'startDateTime': dateTimeTimeZone,
    }


class freeBusyError(object):
    props = {
        'message': Edm.String,
        'responseCode': Edm.String,
    }


class internetMessageHeader(object):
    props = {
        'name': Edm.String,
        'value': Edm.String,
    }


class mailboxItemImportSession(object):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'importUrl': Edm.String,
    }


class workingHours(object):
    props = {
        'daysOfWeek': Collection,
        'endTime': Edm.TimeOfDay,
        'startTime': Edm.TimeOfDay,
        'timeZone': timeZoneBase,
    }


class mentionsPreview(object):
    props = {
        'isMentioned': Edm.Boolean,
    }


class messageRuleActions(object):
    props = {
        'assignCategories': Collection,
        'copyToFolder': Edm.String,
        'delete': Edm.Boolean,
        'forwardAsAttachmentTo': Collection,
        'forwardTo': Collection,
        'markAsRead': Edm.Boolean,
        'markImportance': importance,
        'moveToFolder': Edm.String,
        'permanentDelete': Edm.Boolean,
        'redirectTo': Collection,
        'stopProcessingRules': Edm.Boolean,
    }


class sizeRange(object):
    props = {
        'maximumSize': Edm.Int32,
        'minimumSize': Edm.Int32,
    }


class onlineMeetingInfo(object):
    props = {
        'conferenceId': Edm.String,
        'joinUrl': Edm.String,
        'phones': Collection,
        'quickDial': Edm.String,
        'tollFreeNumbers': Collection,
        'tollNumber': Edm.String,
    }


class recurrencePattern(object):
    props = {
        'dayOfMonth': Edm.Int32,
        'daysOfWeek': Collection,
        'firstDayOfWeek': dayOfWeek,
        'index': weekIndex,
        'interval': Edm.Int32,
        'month': Edm.Int32,
        'type': recurrencePatternType,
    }


class recurrenceRange(object):
    props = {
        'endDate': Edm.Date,
        'numberOfOccurrences': Edm.Int32,
        'recurrenceTimeZone': Edm.String,
        'startDate': Edm.Date,
        'type': recurrenceRangeType,
    }


class personDataSource(object):
    props = {
        'type': Edm.String,
    }


class rankedEmailAddress(object):
    props = {
        'address': Edm.String,
        'rank': Edm.Double,
    }


class scheduleInformation(object):
    props = {
        'availabilityView': Edm.String,
        'error': freeBusyError,
        'scheduleId': Edm.String,
        'scheduleItems': Collection,
        'workingHours': workingHours,
    }


class scheduleItem(object):
    props = {
        'end': dateTimeTimeZone,
        'isPrivate': Edm.Boolean,
        'location': Edm.String,
        'start': dateTimeTimeZone,
        'status': freeBusyStatus,
        'subject': Edm.String,
    }


class timeZoneInformation(object):
    props = {
        'alias': Edm.String,
        'displayName': Edm.String,
    }


class typedEmailAddress(object):
    props = {
        'otherLabel': Edm.String,
        'type': emailType,
    }


class uploadSession(object):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'nextExpectedRanges': Collection,
        'uploadUrl': Edm.String,
    }


class website(object):
    props = {
        'address': Edm.String,
        'displayName': Edm.String,
        'type': websiteType,
    }


class fileStorageContainerCustomPropertyDictionary(object):
    props = {

    }


class fileStorageContainerCustomPropertyValue(object):
    props = {
        'isSearchable': Edm.Boolean,
        'value': Edm.String,
    }


class fileStorageContainerSettings(object):
    props = {
        'isItemVersioningEnabled': Edm.Boolean,
        'isOcrEnabled': Edm.Boolean,
        'itemMajorVersionLimit': Edm.Int32,
    }


class fileStorageContainerViewpoint(object):
    props = {
        'effectiveRole': Edm.String,
    }


class idleSessionSignOut(object):
    props = {
        'isEnabled': Edm.Boolean,
        'signOutAfterInSeconds': Edm.Int64,
        'warnAfterInSeconds': Edm.Int64,
    }


class accessAction(object):
    props = {

    }


class album(object):
    props = {
        'coverImageItemId': Edm.String,
    }


class booleanColumn(object):
    props = {

    }


class calculatedColumn(object):
    props = {
        'format': Edm.String,
        'formula': Edm.String,
        'outputType': Edm.String,
    }


class choiceColumn(object):
    props = {
        'allowTextEntry': Edm.Boolean,
        'choices': Collection,
        'displayAs': Edm.String,
    }


class columnValidation(object):
    props = {
        'defaultLanguage': Edm.String,
        'descriptions': Collection,
        'formula': Edm.String,
    }


class displayNameLocalization(object):
    props = {
        'displayName': Edm.String,
        'languageTag': Edm.String,
    }


class commentAction(object):
    props = {
        'isReply': Edm.Boolean,
        'parentAuthor': identitySet,
        'participants': Collection,
    }


class contentApprovalStatusColumn(object):
    props = {

    }


class contentModelUsage(object):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'driveId': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'modelId': Edm.String,
        'modelVersion': Edm.String,
    }


class contentTypeInfo(object):
    props = {
        'id': Edm.String,
        'name': Edm.String,
    }


class contentTypeOrder(object):
    props = {
        'default': Edm.Boolean,
        'position': Edm.Int32,
    }


class createAction(object):
    props = {

    }


class currencyColumn(object):
    props = {
        'locale': Edm.String,
    }


class dateTimeColumn(object):
    props = {
        'displayAs': Edm.String,
        'format': Edm.String,
    }


class defaultColumnValue(object):
    props = {
        'formula': Edm.String,
        'value': Edm.String,
    }


class defaultSharingLink(object):
    props = {
        'defaultToExistingAccess': Edm.Boolean,
        'role': sharingRole,
        'scope': sharingScope,
    }


class deleteAction(object):
    props = {
        'name': Edm.String,
        'objectType': Edm.String,
    }


class sharingOperationStatus(object):
    props = {
        'disabledReason': Edm.String,
        'enabled': Edm.Boolean,
    }


class documentSet(object):
    props = {
        'allowedContentTypes': Collection,
        'defaultContents': Collection,
        'propagateWelcomePageChanges': Edm.Boolean,
        'shouldPrefixNameToFile': Edm.Boolean,
        'welcomePageUrl': Edm.String,
    }


class documentSetContent(object):
    props = {
        'contentType': contentTypeInfo,
        'fileName': Edm.String,
        'folderName': Edm.String,
    }


class documentSetVersionItem(object):
    props = {
        'itemId': Edm.String,
        'title': Edm.String,
        'versionId': Edm.String,
    }


class driveItemAccessOperationsViewpoint(object):
    props = {
        'canComment': Edm.Boolean,
        'canCreateFile': Edm.Boolean,
        'canCreateFolder': Edm.Boolean,
        'canDelete': Edm.Boolean,
        'canDownload': Edm.Boolean,
        'canRead': Edm.Boolean,
        'canUpdate': Edm.Boolean,
    }


class mediaSource(object):
    props = {
        'contentCategory': mediaSourceContentCategory,
    }


class driveRecipient(object):
    props = {
        'alias': Edm.String,
        'email': Edm.String,
        'objectId': Edm.String,
    }


class editAction(object):
    props = {

    }


class extractSensitivityLabelsResult(object):
    props = {
        'labels': Collection,
    }


class sensitivityLabelAssignment(object):
    props = {
        'assignmentMethod': sensitivityLabelAssignmentMethod,
        'sensitivityLabelId': Edm.String,
        'tenantId': Edm.String,
    }


class hashes(object):
    props = {
        'crc32Hash': Edm.String,
        'quickXorHash': Edm.String,
        'sha1Hash': Edm.String,
        'sha256Hash': Edm.String,
    }


class flexSchemaContainer(object):
    props = {

    }


class folderView(object):
    props = {
        'sortBy': Edm.String,
        'sortOrder': Edm.String,
        'viewType': Edm.String,
    }


class geolocationColumn(object):
    props = {

    }


class hyperlinkOrPictureColumn(object):
    props = {
        'isPicture': Edm.Boolean,
    }


class incompleteData(object):
    props = {
        'missingDataBeforeDateTime': Edm.DateTimeOffset,
        'wasThrottled': Edm.Boolean,
    }


class mentionAction(object):
    props = {
        'mentionees': Collection,
    }


class moveAction(object):
    props = {
        'from': Edm.String,
        'to': Edm.String,
    }


class renameAction(object):
    props = {
        'newName': Edm.String,
        'oldName': Edm.String,
    }


class restoreAction(object):
    props = {

    }


class shareAction(object):
    props = {
        'recipients': Collection,
    }


class versionAction(object):
    props = {
        'newVersion': Edm.String,
    }


class itemActionStat(object):
    props = {
        'actionCount': Edm.Int32,
        'actorCount': Edm.Int32,
    }


class itemActivityTimeSet(object):
    props = {
        'lastRecordedDateTime': Edm.DateTimeOffset,
        'observedDateTime': Edm.DateTimeOffset,
        'recordedDateTime': Edm.DateTimeOffset,
    }


class itemPreviewInfo(object):
    props = {
        'getUrl': Edm.String,
        'postParameters': Edm.String,
        'postUrl': Edm.String,
    }


class itemReference(object):
    props = {
        'driveId': Edm.String,
        'driveType': Edm.String,
        'id': Edm.String,
        'name': Edm.String,
        'path': Edm.String,
        'shareId': Edm.String,
        'sharepointIds': sharepointIds,
        'siteId': Edm.String,
    }


class sharingLinkVariants(object):
    props = {
        'addressBarLinkPermission': sharingRole,
        'allowEmbed': sharingOperationStatus,
        'passwordProtected': sharingOperationStatus,
        'requiresAuthentication': sharingOperationStatus,
    }


class sharingLinkExpirationStatus(object):
    props = {
        'defaultExpirationInDays': Edm.Int32,
        'disabledReason': Edm.String,
        'enabled': Edm.Boolean,
    }


class lookupColumn(object):
    props = {
        'allowMultipleValues': Edm.Boolean,
        'allowUnlimitedLength': Edm.Boolean,
        'columnName': Edm.String,
        'listId': Edm.String,
        'primaryLookupColumnId': Edm.String,
    }


class metaDataKeyStringPair(object):
    props = {
        'key': Edm.String,
        'value': Edm.String,
    }


class metaDataKeyValuePair(object):
    props = {
        'key': Edm.String,
        'value': Json,
    }


class numberColumn(object):
    props = {
        'decimalPlaces': Edm.String,
        'displayAs': Edm.String,
        'maximum': Edm.Double,
        'minimum': Edm.Double,
    }


class pendingContentUpdate(object):
    props = {
        'queuedDateTime': Edm.DateTimeOffset,
    }


class personOrGroupColumn(object):
    props = {
        'allowMultipleSelection': Edm.Boolean,
        'chooseFromType': Edm.String,
        'displayAs': Edm.String,
    }


class storagePlanInformation(object):
    props = {
        'upgradeAvailable': Edm.Boolean,
    }


class reactionsFacet(object):
    props = {
        'commentCount': Edm.Int32,
        'likeCount': Edm.Int32,
        'shareCount': Edm.Int32,
    }


class recycleBinSettings(object):
    props = {
        'retentionPeriodOverrideDays': Edm.Int32,
    }


class serverProcessedContent(object):
    props = {
        'componentDependencies': Collection,
        'customMetadata': Collection,
        'htmlStrings': Collection,
        'imageSources': Collection,
        'links': Collection,
        'searchablePlainTexts': Collection,
    }


class sharePointIdentity(object):
    props = {
        'loginName': Edm.String,
    }


class sharePointIdentitySet(object):
    props = {
        'group': identity,
        'siteGroup': sharePointIdentity,
        'siteUser': sharePointIdentity,
    }


class sharingInvitation(object):
    props = {
        'email': Edm.String,
        'invitedBy': identitySet,
        'redeemedBy': Edm.String,
        'signInRequired': Edm.Boolean,
    }


class sharingLink(object):
    props = {
        'application': identity,
        'configuratorUrl': Edm.String,
        'preventsDownload': Edm.Boolean,
        'scope': Edm.String,
        'type': Edm.String,
        'webHtml': Edm.String,
        'webUrl': Edm.String,
    }


class siteArchivalDetails(object):
    props = {
        'archiveStatus': siteArchiveStatus,
    }


class termColumn(object):
    props = {
        'allowMultipleValues': Edm.Boolean,
        'showFullyQualifiedName': Edm.Boolean,
    }


class textColumn(object):
    props = {
        'allowMultipleLines': Edm.Boolean,
        'appendChangesToExistingText': Edm.Boolean,
        'linesForEditing': Edm.Int32,
        'maxLength': Edm.Int32,
        'textType': Edm.String,
    }


class thumbnail(object):
    props = {
        'content': Edm.Stream,
        'height': Edm.Int32,
        'sourceItemId': Edm.String,
        'url': Edm.String,
        'width': Edm.Int32,
    }


class thumbnailColumn(object):
    props = {

    }


class titleArea(object):
    props = {
        'alternativeText': Edm.String,
        'enableGradientEffect': Edm.Boolean,
        'imageWebUrl': Edm.String,
        'layout': titleAreaLayoutType,
        'serverProcessedContent': serverProcessedContent,
        'showAuthor': Edm.Boolean,
        'showPublishedDate': Edm.Boolean,
        'showTextBlockAboveTitle': Edm.Boolean,
        'textAboveTitle': Edm.String,
        'textAlignment': titleAreaTextAlignmentType,
    }


class webPartData(object):
    props = {
        'audiences': Collection,
        'dataVersion': Edm.String,
        'description': Edm.String,
        'properties': Json,
        'serverProcessedContent': serverProcessedContent,
        'title': Edm.String,
    }


class webPartPosition(object):
    props = {
        'columnId': Edm.Double,
        'horizontalSectionId': Edm.Double,
        'isInVerticalSection': Edm.Boolean,
        'webPartIndex': Edm.Double,
    }


class attendeeNotificationInfo(object):
    props = {
        'phoneNumber': Edm.String,
        'timeZone': Edm.String,
    }


class matrixChoiceAnswer(object):
    props = {
        'displayText': Edm.String,
        'key': Edm.String,
    }


class quizInfo(object):
    props = {
        'maxPoints': Edm.Single,
    }


class matrixChoiceGroupQuizInfo(object):
    props = {

    }


class npsQuizInfo(object):
    props = {

    }


class extensionSchemaProperty(object):
    props = {
        'name': Edm.String,
        'type': Edm.String,
    }


class corsConfiguration(object):
    props = {
        'allowedHeaders': Collection,
        'allowedMethods': Collection,
        'allowedOrigins': Collection,
        'maxAgeInSeconds': Edm.Int32,
        'resource': Edm.String,
    }


class updateWindow(object):
    props = {
        'updateWindowEndTime': Edm.TimeOfDay,
        'updateWindowStartTime': Edm.TimeOfDay,
    }


class ipRange(object):
    props = {

    }


class segmentConfiguration(object):
    props = {

    }


class ipSegmentConfiguration(object):
    props = {

    }


class iPv4Range(object):
    props = {
        'lowerAddress': Edm.String,
        'upperAddress': Edm.String,
    }


class iPv6Range(object):
    props = {
        'lowerAddress': Edm.String,
        'upperAddress': Edm.String,
    }


class kerberosSignOnSettings(object):
    props = {
        'kerberosServicePrincipalName': Edm.String,
        'kerberosSignOnMappingAttributeType': kerberosSignOnMappingAttributeType,
    }


class onPremisesApplicationSegment(object):
    props = {
        'alternateUrl': Edm.String,
        'corsConfigurations': Collection,
        'externalUrl': Edm.String,
        'internalUrl': Edm.String,
    }


class onPremisesPublishingSingleSignOn(object):
    props = {
        'kerberosSignOnSettings': kerberosSignOnSettings,
        'singleSignOnMode': singleSignOnMode,
    }


class verifiedCustomDomainCertificatesMetadata(object):
    props = {
        'expiryDate': Edm.DateTimeOffset,
        'issueDate': Edm.DateTimeOffset,
        'issuerName': Edm.String,
        'subjectName': Edm.String,
        'thumbprint': Edm.String,
    }


class wafAllowedHeadersDictionary(object):
    props = {

    }


class webSegmentConfiguration(object):
    props = {

    }


class propertyToEvaluate(object):
    props = {
        'propertyName': Edm.String,
        'propertyValue': Edm.String,
    }


class attributeDefinition(object):
    props = {
        'anchor': Edm.Boolean,
        'apiExpressions': Collection,
        'caseExact': Edm.Boolean,
        'defaultValue': Edm.String,
        'flowNullValues': Edm.Boolean,
        'metadata': Collection,
        'multivalued': Edm.Boolean,
        'mutability': mutability,
        'name': Edm.String,
        'referencedObjects': Collection,
        'required': Edm.Boolean,
        'type': attributeType,
    }


class stringKeyStringValuePair(object):
    props = {
        'key': Edm.String,
        'value': Edm.String,
    }


class attributeDefinitionMetadataEntry(object):
    props = {
        'key': attributeDefinitionMetadata,
        'value': Edm.String,
    }


class referencedObject(object):
    props = {
        'referencedObjectName': Edm.String,
        'referencedProperty': Edm.String,
    }


class attributeMappingSource(object):
    props = {
        'expression': Edm.String,
        'name': Edm.String,
        'parameters': Collection,
        'type': attributeMappingSourceType,
    }


class attributeMappingParameterSchema(object):
    props = {
        'allowMultipleOccurrences': Edm.Boolean,
        'name': Edm.String,
        'required': Edm.Boolean,
        'type': attributeType,
    }


class stringKeyAttributeMappingSourceValuePair(object):
    props = {
        'key': Edm.String,
        'value': attributeMappingSource,
    }


class containerFilter(object):
    props = {
        'includedContainers': Collection,
    }


class objectDefinition(object):
    props = {
        'attributes': Collection,
        'metadata': Collection,
        'name': Edm.String,
        'supportedApis': Collection,
    }


class stringKeyObjectValuePair(object):
    props = {
        'key': Edm.String,
    }


class filter(object):
    props = {
        'categoryFilterGroups': Collection,
        'groups': Collection,
        'inputFilterGroups': Collection,
    }


class filterGroup(object):
    props = {
        'clauses': Collection,
        'name': Edm.String,
    }


class filterOperand(object):
    props = {
        'values': Collection,
    }


class groupFilter(object):
    props = {
        'includedGroups': Collection,
    }


class objectDefinitionMetadataEntry(object):
    props = {
        'key': objectDefinitionMetadata,
        'value': Edm.String,
    }


class objectMapping(object):
    props = {
        'attributeMappings': Collection,
        'enabled': Edm.Boolean,
        'flowTypes': objectFlowTypes,
        'metadata': Collection,
        'name': Edm.String,
        'scope': filter,
        'sourceObjectName': Edm.String,
        'targetObjectName': Edm.String,
    }


class objectMappingMetadataEntry(object):
    props = {
        'key': objectMappingMetadata,
        'value': Edm.String,
    }


class stringKeyLongValuePair(object):
    props = {
        'key': Edm.String,
        'value': Edm.Int64,
    }


class synchronizationError(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
        'tenantActionable': Edm.Boolean,
    }


class synchronizationJobApplicationParameters(object):
    props = {
        'ruleId': Edm.String,
        'subjects': Collection,
    }


class synchronizationJobRestartCriteria(object):
    props = {
        'resetScope': synchronizationJobRestartScope,
    }


class synchronizationMetadataEntry(object):
    props = {
        'key': synchronizationMetadata,
        'value': Edm.String,
    }


class synchronizationProgress(object):
    props = {
        'completedUnits': Edm.Int64,
        'progressObservationDateTime': Edm.DateTimeOffset,
        'totalUnits': Edm.Int64,
        'units': Edm.String,
    }


class synchronizationQuarantine(object):
    props = {
        'currentBegan': Edm.DateTimeOffset,
        'error': synchronizationError,
        'nextAttempt': Edm.DateTimeOffset,
        'reason': quarantineReason,
        'seriesBegan': Edm.DateTimeOffset,
        'seriesCount': Edm.Int64,
    }


class synchronizationRule(object):
    props = {
        'containerFilter': containerFilter,
        'editable': Edm.Boolean,
        'groupFilter': groupFilter,
        'id': Edm.String,
        'metadata': Collection,
        'name': Edm.String,
        'objectMappings': Collection,
        'priority': Edm.Int32,
        'sourceDirectoryName': Edm.String,
        'targetDirectoryName': Edm.String,
    }


class synchronizationSchedule(object):
    props = {
        'expiration': Edm.DateTimeOffset,
        'interval': Edm.Duration,
        'state': synchronizationScheduleState,
    }


class synchronizationSecretKeyStringValuePair(object):
    props = {
        'key': synchronizationSecret,
        'value': Edm.String,
    }


class synchronizationTaskExecution(object):
    props = {
        'activityIdentifier': Edm.String,
        'countEntitled': Edm.Int64,
        'countEntitledForProvisioning': Edm.Int64,
        'countEscrowed': Edm.Int64,
        'countEscrowedRaw': Edm.Int64,
        'countExported': Edm.Int64,
        'countExports': Edm.Int64,
        'countImported': Edm.Int64,
        'countImportedDeltas': Edm.Int64,
        'countImportedReferenceDeltas': Edm.Int64,
        'error': synchronizationError,
        'state': synchronizationTaskExecutionResult,
        'timeBegan': Edm.DateTimeOffset,
        'timeEnded': Edm.DateTimeOffset,
    }


class communicationsIdentitySet(object):
    props = {
        'applicationInstance': identity,
        'assertedIdentity': identity,
        'azureCommunicationServicesUser': identity,
        'encrypted': identity,
        'endpointType': endpointType,
        'guest': identity,
        'onPremises': identity,
        'phone': identity,
    }


class accessReviewApplyAction(object):
    props = {

    }


class accessReviewError(object):
    props = {

    }


class accessReviewScope(object):
    props = {

    }


class accessReviewQueryScope(object):
    props = {
        'query': Edm.String,
        'queryRoot': Edm.String,
        'queryType': Edm.String,
    }


class accessReviewInactiveUsersQueryScope(object):
    props = {
        'inactiveDuration': Edm.Duration,
    }


class accessReviewInstanceDecisionItemResource(object):
    props = {
        'displayName': Edm.String,
        'id': Edm.String,
        'type': Edm.String,
    }


class accessReviewInstanceDecisionItemAccessPackageAssignmentPolicyResource(object):
    props = {
        'accessPackageDisplayName': Edm.String,
        'accessPackageId': Edm.String,
    }


class accessReviewInstanceDecisionItemAzureRoleResource(object):
    props = {
        'scope': accessReviewInstanceDecisionItemResource,
    }


class accessReviewInstanceDecisionItemServicePrincipalResource(object):
    props = {
        'appId': Edm.String,
    }


class accessReviewInstanceDecisionItemTarget(object):
    props = {

    }


class accessReviewInstanceDecisionItemServicePrincipalTarget(object):
    props = {
        'appId': Edm.String,
        'servicePrincipalDisplayName': Edm.String,
        'servicePrincipalId': Edm.String,
    }


class accessReviewInstanceDecisionItemUserTarget(object):
    props = {
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class accessReviewNotificationRecipientScope(object):
    props = {

    }


class accessReviewNotificationRecipientQueryScope(object):
    props = {
        'query': Edm.String,
        'queryRoot': Edm.String,
        'queryType': Edm.String,
    }


class accessReviewRecommendationInsightSetting(object):
    props = {

    }


class accessReviewRecurrenceSettings(object):
    props = {
        'durationInDays': Edm.Int32,
        'recurrenceCount': Edm.Int32,
        'recurrenceEndType': Edm.String,
        'recurrenceType': Edm.String,
    }


class accessReviewReviewerScope(object):
    props = {
        'query': Edm.String,
        'queryRoot': Edm.String,
        'queryType': Edm.String,
    }


class autoReviewSettings(object):
    props = {
        'notReviewedResult': Edm.String,
    }


class accessReviewStageSettings(object):
    props = {
        'decisionsThatWillMoveToNextStage': Collection,
        'dependsOn': Collection,
        'durationInDays': Edm.Int32,
        'fallbackReviewers': Collection,
        'recommendationInsightSettings': Collection,
        'recommendationLookBackDuration': Edm.Duration,
        'recommendationsEnabled': Edm.Boolean,
        'reviewers': Collection,
        'stageId': Edm.String,
    }


class appConsentRequestScope(object):
    props = {
        'displayName': Edm.String,
    }


class businessFlowSettings(object):
    props = {
        'durationInDays': Edm.Int32,
    }


class decisionItemPrincipalResourceMembership(object):
    props = {
        'membershipType': decisionItemPrincipalResourceMembershipType,
    }


class disableAndDeleteUserApplyAction(object):
    props = {

    }


class governanceCriteria(object):
    props = {

    }


class governanceNotificationPolicy(object):
    props = {
        'enabledTemplateTypes': Collection,
        'notificationTemplates': Collection,
    }


class governanceNotificationTemplate(object):
    props = {
        'culture': Edm.String,
        'id': Edm.String,
        'source': Edm.String,
        'type': Edm.String,
        'version': Edm.String,
    }


class governancePolicy(object):
    props = {
        'decisionMakerCriteria': Collection,
        'notificationPolicy': governanceNotificationPolicy,
    }


class groupMembershipGovernanceCriteria(object):
    props = {
        'groupId': Edm.String,
    }


class groupPeerOutlierRecommendationInsightSettings(object):
    props = {

    }


class principalResourceMembershipsScope(object):
    props = {
        'principalScopes': Collection,
        'resourceScopes': Collection,
    }


class programResource(object):
    props = {
        'type': Edm.String,
    }


class removeAccessApplyAction(object):
    props = {

    }


class roleMembershipGovernanceCriteria(object):
    props = {
        'roleId': Edm.String,
        'roleTemplateId': Edm.String,
    }


class servicePrincipalIdentity(object):
    props = {
        'appId': Edm.String,
    }


class userGovernanceCriteria(object):
    props = {
        'userId': Edm.String,
    }


class userLastSignInRecommendationInsightSetting(object):
    props = {
        'recommendationLookBackDuration': Edm.Duration,
        'signInScope': userSignInRecommendationScope,
    }


class agreementFileData(object):
    props = {
        'data': Edm.Binary,
    }


class termsExpiration(object):
    props = {
        'frequency': Edm.Duration,
        'startDateTime': Edm.DateTimeOffset,
    }


class conditionalAccessSessionControl(object):
    props = {
        'isEnabled': Edm.Boolean,
    }


class applicationEnforcedRestrictionsSessionControl(object):
    props = {

    }


class authenticationFlow(object):
    props = {
        'transferMethod': conditionalAccessTransferMethods,
    }


class authenticationStrengthUsage(object):
    props = {

    }


class cloudAppSecuritySessionControl(object):
    props = {
        'cloudAppSecurityType': cloudAppSecuritySessionControlType,
    }


class conditionalAccessExternalTenants(object):
    props = {
        'membershipKind': conditionalAccessExternalTenantsMembershipKind,
    }


class conditionalAccessAllExternalTenants(object):
    props = {

    }


class conditionalAccessFilter(object):
    props = {
        'mode': filterMode,
        'rule': Edm.String,
    }


class conditionalAccessAuthenticationFlows(object):
    props = {
        'transferMethods': conditionalAccessTransferMethods,
    }


class conditionalAccessClientApplications(object):
    props = {
        'excludeServicePrincipals': Collection,
        'includeServicePrincipals': Collection,
        'servicePrincipalFilter': conditionalAccessFilter,
    }


class conditionalAccessDevices(object):
    props = {
        'deviceFilter': conditionalAccessFilter,
        'excludeDevices': Collection,
        'excludeDeviceStates': Collection,
        'includeDevices': Collection,
        'includeDeviceStates': Collection,
    }


class conditionalAccessDeviceStates(object):
    props = {
        'excludeStates': Collection,
        'includeStates': Collection,
    }


class conditionalAccessLocations(object):
    props = {
        'excludeLocations': Collection,
        'includeLocations': Collection,
    }


class conditionalAccessPlatforms(object):
    props = {
        'excludePlatforms': Collection,
        'includePlatforms': Collection,
    }


class conditionalAccessContext(object):
    props = {

    }


class conditionalAccessEnumeratedExternalTenants(object):
    props = {
        'members': Collection,
    }


class conditionalAccessGrantControls(object):
    props = {
        'builtInControls': Collection,
        'customAuthenticationFactors': Collection,
        'operator': Edm.String,
        'termsOfUse': Collection,
    }


class conditionalAccessGuestsOrExternalUsers(object):
    props = {
        'externalTenants': conditionalAccessExternalTenants,
        'guestOrExternalUserTypes': conditionalAccessGuestOrExternalUserTypes,
    }


class continuousAccessEvaluationSessionControl(object):
    props = {
        'mode': continuousAccessEvaluationMode,
    }


class persistentBrowserSessionControl(object):
    props = {
        'mode': persistentBrowserSessionMode,
    }


class secureSignInSessionControl(object):
    props = {

    }


class signInFrequencySessionControl(object):
    props = {
        'authenticationType': signInFrequencyAuthenticationType,
        'frequencyInterval': signInFrequencyInterval,
        'type': signinFrequencyType,
        'value': Edm.Int32,
    }


class deviceInfo(object):
    props = {
        'deviceId': Edm.String,
        'displayName': Edm.String,
        'enrollmentProfileName': Edm.String,
        'extensionAttribute1': Edm.String,
        'extensionAttribute10': Edm.String,
        'extensionAttribute11': Edm.String,
        'extensionAttribute12': Edm.String,
        'extensionAttribute13': Edm.String,
        'extensionAttribute14': Edm.String,
        'extensionAttribute15': Edm.String,
        'extensionAttribute2': Edm.String,
        'extensionAttribute3': Edm.String,
        'extensionAttribute4': Edm.String,
        'extensionAttribute5': Edm.String,
        'extensionAttribute6': Edm.String,
        'extensionAttribute7': Edm.String,
        'extensionAttribute8': Edm.String,
        'extensionAttribute9': Edm.String,
        'isCompliant': Edm.Boolean,
        'manufacturer': Edm.String,
        'mdmAppId': Edm.String,
        'model': Edm.String,
        'operatingSystem': Edm.String,
        'operatingSystemVersion': Edm.String,
        'ownership': Edm.String,
        'physicalIds': Collection,
        'profileType': Edm.String,
        'systemLabels': Collection,
        'trustType': Edm.String,
    }


class conditionalAccessWhatIfSubject(object):
    props = {

    }


class iPv4CidrRange(object):
    props = {
        'cidrAddress': Edm.String,
    }


class iPv6CidrRange(object):
    props = {
        'cidrAddress': Edm.String,
    }


class riskServicePrincipalActivity(object):
    props = {
        'detail': riskDetail,
        'riskEventTypes': Collection,
    }


class riskUserActivity(object):
    props = {
        'detail': riskDetail,
        'eventTypes': Collection,
        'riskEventTypes': Collection,
    }


class servicePrincipalSubject(object):
    props = {
        'servicePrincipalId': Edm.String,
    }


class userSubject(object):
    props = {
        'externalTenantId': Edm.String,
        'externalUserType': conditionalAccessGuestOrExternalUserTypes,
        'userId': Edm.String,
    }


class whatIfApplicationContext(object):
    props = {
        'includeApplications': Collection,
    }


class whatIfAuthenticationContext(object):
    props = {
        'authenticationContext': Edm.String,
    }


class whatIfUserActionContext(object):
    props = {
        'userAction': userAction,
    }


class accessPackageLocalizedContent(object):
    props = {
        'defaultText': Edm.String,
        'localizedTexts': Collection,
    }


class accessPackageAnswerString(object):
    props = {
        'value': Edm.String,
    }


class accessPackageAssignmentRequestCallbackData(object):
    props = {
        'customExtensionStageInstanceDetail': Edm.String,
        'customExtensionStageInstanceId': Edm.String,
        'stage': accessPackageCustomExtensionStage,
        'state': Edm.String,
    }


class verifiableCredentialRequirementStatus(object):
    props = {

    }


class accessPackageLocalizedText(object):
    props = {
        'languageCode': Edm.String,
        'text': Edm.String,
    }


class accessPackageMultipleChoiceQuestion(object):
    props = {
        'allowsMultipleSelection': Edm.Boolean,
        'choices': Collection,
    }


class accessPackageNotificationSettings(object):
    props = {
        'isAssignmentNotificationDisabled': Edm.Boolean,
    }


class accessPackageResourceAttributeDestination(object):
    props = {

    }


class accessPackageResourceAttributeSource(object):
    props = {

    }


class accessPackageTextInputQuestion(object):
    props = {
        'isSingleLineQuestion': Edm.Boolean,
        'regexPattern': Edm.String,
    }


class accessPackageUserDirectoryAttributeStore(object):
    props = {

    }


class approvalSettings(object):
    props = {
        'approvalMode': Edm.String,
        'approvalStages': Collection,
        'isApprovalRequired': Edm.Boolean,
        'isApprovalRequiredForExtension': Edm.Boolean,
        'isRequestorJustificationRequired': Edm.Boolean,
    }


class approvalStage(object):
    props = {
        'approvalStageTimeOutInDays': Edm.Int32,
        'escalationApprovers': Collection,
        'escalationTimeInMinutes': Edm.Int32,
        'isApproverJustificationRequired': Edm.Boolean,
        'isEscalationEnabled': Edm.Boolean,
        'primaryApprovers': Collection,
    }


class userSet(object):
    props = {
        'isBackup': Edm.Boolean,
    }


class assignmentReviewSettings(object):
    props = {
        'accessReviewTimeoutBehavior': accessReviewTimeoutBehavior,
        'durationInDays': Edm.Int32,
        'isAccessRecommendationEnabled': Edm.Boolean,
        'isApprovalJustificationRequired': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'recurrenceType': Edm.String,
        'reviewers': Collection,
        'reviewerType': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
    }


class connectedOrganizationMembers(object):
    props = {
        'description': Edm.String,
        'id': Edm.String,
    }


class connectionInfo(object):
    props = {
        'url': Edm.String,
    }


class customExtensionCalloutInstance(object):
    props = {
        'customExtensionId': Edm.String,
        'detail': Edm.String,
        'externalCorrelationId': Edm.String,
        'id': Edm.String,
        'status': customExtensionCalloutInstanceStatus,
    }


class customExtensionHandlerInstance(object):
    props = {
        'customExtensionId': Edm.String,
        'externalCorrelationId': Edm.String,
        'stage': accessPackageCustomExtensionStage,
        'status': accessPackageCustomExtensionHandlerStatus,
    }


class expirationPattern(object):
    props = {
        'duration': Edm.Duration,
        'endDateTime': Edm.DateTimeOffset,
        'type': expirationPatternType,
    }


class externalSponsors(object):
    props = {

    }


class groupMembers(object):
    props = {
        'description': Edm.String,
        'id': Edm.String,
    }


class internalSponsors(object):
    props = {

    }


class requestActivity(object):
    props = {
        'action': Edm.String,
        'actionDateTime': Edm.DateTimeOffset,
        'detail': Edm.String,
        'scheduledDateTime': Edm.DateTimeOffset,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }


class requestorManager(object):
    props = {
        'managerLevel': Edm.Int32,
    }


class requestorSettings(object):
    props = {
        'acceptRequests': Edm.Boolean,
        'allowedRequestors': Collection,
        'scopeType': Edm.String,
    }


class singleUser(object):
    props = {
        'description': Edm.String,
        'id': Edm.String,
    }


class targetUserSponsors(object):
    props = {

    }


class verifiableCredentialSettings(object):
    props = {
        'credentialTypes': Collection,
    }


class verifiableCredentialRequired(object):
    props = {
        'expiryDateTime': Edm.DateTimeOffset,
        'url': Edm.String,
    }


class verifiableCredentialRetrieved(object):
    props = {
        'expiryDateTime': Edm.DateTimeOffset,
    }


class verifiableCredentialType(object):
    props = {
        'credentialType': Edm.String,
        'issuers': Collection,
    }


class verifiableCredentialVerified(object):
    props = {

    }


class verifiedCredentialClaims(object):
    props = {

    }


class identitySource(object):
    props = {

    }


class azureActiveDirectoryTenant(object):
    props = {
        'displayName': Edm.String,
        'tenantId': Edm.String,
    }


class crossCloudAzureActiveDirectoryTenant(object):
    props = {
        'cloudInstance': Edm.String,
        'displayName': Edm.String,
        'tenantId': Edm.String,
    }


class domainIdentitySource(object):
    props = {
        'displayName': Edm.String,
        'domainName': Edm.String,
    }


class externalDomainFederation(object):
    props = {
        'displayName': Edm.String,
        'domainName': Edm.String,
        'issuerUri': Edm.String,
    }


class socialIdentitySource(object):
    props = {
        'displayName': Edm.String,
        'socialIdentitySourceType': socialIdentitySourceType,
    }


class informationProtectionAction(object):
    props = {

    }


class addContentFooterAction(object):
    props = {
        'alignment': contentAlignment,
        'fontColor': Edm.String,
        'fontName': Edm.String,
        'fontSize': Edm.Int32,
        'margin': Edm.Int32,
        'text': Edm.String,
        'uiElementName': Edm.String,
    }


class addContentHeaderAction(object):
    props = {
        'alignment': contentAlignment,
        'fontColor': Edm.String,
        'fontName': Edm.String,
        'fontSize': Edm.Int32,
        'margin': Edm.Int32,
        'text': Edm.String,
        'uiElementName': Edm.String,
    }


class addWatermarkAction(object):
    props = {
        'fontColor': Edm.String,
        'fontName': Edm.String,
        'fontSize': Edm.Int32,
        'layout': watermarkLayout,
        'text': Edm.String,
        'uiElementName': Edm.String,
    }


class labelDetails(object):
    props = {

    }


class bufferDecryptionResult(object):
    props = {
        'decryptedBuffer': Edm.Binary,
    }


class bufferEncryptionResult(object):
    props = {
        'encryptedBuffer': Edm.Binary,
        'publishingLicense': Edm.Binary,
    }


class classificationResult(object):
    props = {
        'confidenceLevel': Edm.Int32,
        'count': Edm.Int32,
        'sensitiveTypeId': Edm.String,
    }


class contentInfo(object):
    props = {
        'format': contentFormat,
        'identifier': Edm.String,
        'metadata': Collection,
        'state': contentState,
    }


class customAction(object):
    props = {
        'name': Edm.String,
        'properties': Collection,
    }


class downgradeJustification(object):
    props = {
        'isDowngradeJustified': Edm.Boolean,
        'justificationMessage': Edm.String,
    }


class informationProtectionContentLabel(object):
    props = {
        'assignmentMethod': assignmentMethod,
        'creationDateTime': Edm.DateTimeOffset,
        'label': labelDetails,
    }


class justifyAction(object):
    props = {

    }


class labelingOptions(object):
    props = {
        'assignmentMethod': assignmentMethod,
        'downgradeJustification': downgradeJustification,
        'extendedProperties': Collection,
        'labelId': Edm.String,
    }


class metadataAction(object):
    props = {
        'metadataToAdd': Collection,
        'metadataToRemove': Collection,
    }


class protectAdhocAction(object):
    props = {

    }


class protectByTemplateAction(object):
    props = {
        'templateId': Edm.String,
    }


class protectDoNotForwardAction(object):
    props = {

    }


class recommendLabelAction(object):
    props = {
        'actions': Collection,
        'actionSource': actionSource,
        'label': labelDetails,
        'responsibleSensitiveTypeIds': Collection,
    }


class removeContentFooterAction(object):
    props = {
        'uiElementNames': Collection,
    }


class removeContentHeaderAction(object):
    props = {
        'uiElementNames': Collection,
    }


class removeProtectionAction(object):
    props = {

    }


class removeWatermarkAction(object):
    props = {
        'uiElementNames': Collection,
    }


class signingResult(object):
    props = {
        'signature': Edm.Binary,
        'signingKeyId': Edm.String,
    }


class verificationResult(object):
    props = {
        'signatureValid': Edm.Boolean,
    }


class mimeContent(object):
    props = {
        'type': Edm.String,
        'value': Edm.Binary,
    }


class androidForWorkAppConfigurationSchemaItem(object):
    props = {
        'dataType': androidForWorkAppConfigurationSchemaItemDataType,
        'defaultBoolValue': Edm.Boolean,
        'defaultIntValue': Edm.Int32,
        'defaultStringArrayValue': Collection,
        'defaultStringValue': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'schemaItemKey': Edm.String,
        'selections': Collection,
    }


class androidManagedStoreAppConfigurationSchemaItem(object):
    props = {
        'dataType': androidManagedStoreAppConfigurationSchemaItemDataType,
        'defaultBoolValue': Edm.Boolean,
        'defaultIntValue': Edm.Int32,
        'defaultStringArrayValue': Collection,
        'defaultStringValue': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'index': Edm.Int32,
        'parentIndex': Edm.Int32,
        'schemaItemKey': Edm.String,
        'selections': Collection,
    }


class enrollmentTimeDeviceMembershipTarget(object):
    props = {
        'targetId': Edm.String,
        'targetType': enrollmentTimeDeviceMembershipTargetType,
    }


class enrollmentTimeDeviceMembershipTargetResult(object):
    props = {
        'enrollmentTimeDeviceMembershipTargetValidationStatuses': Collection,
        'validationSucceeded': Edm.Boolean,
    }


class enrollmentTimeDeviceMembershipTargetStatus(object):
    props = {
        'targetId': Edm.String,
        'targetValidationErrorCode': enrollmentTimeDeviceMembershipTargetValidationErrorCode,
    }


class deviceAndAppManagementAssignmentTarget(object):
    props = {
        'deviceAndAppManagementAssignmentFilterId': Edm.String,
        'deviceAndAppManagementAssignmentFilterType': deviceAndAppManagementAssignmentFilterType,
    }


class allDevicesAssignmentTarget(object):
    props = {

    }


class allLicensedUsersAssignmentTarget(object):
    props = {

    }


class androidFotaDeploymentAssignmentTarget(object):
    props = {
        'groupId': Edm.String,
    }


class groupAssignmentTarget(object):
    props = {
        'groupId': Edm.String,
    }


class exclusionGroupAssignmentTarget(object):
    props = {

    }


class zebraFotaDeploymentSettings(object):
    props = {
        'batteryRuleMinimumBatteryLevelPercentage': Edm.Int32,
        'batteryRuleRequireCharger': Edm.Boolean,
        'deviceModel': Edm.String,
        'downloadRuleNetworkType': zebraFotaNetworkType,
        'downloadRuleStartDateTime': Edm.DateTimeOffset,
        'firmwareTargetArtifactDescription': Edm.String,
        'firmwareTargetBoardSupportPackageVersion': Edm.String,
        'firmwareTargetOsVersion': Edm.String,
        'firmwareTargetPatch': Edm.String,
        'installRuleStartDateTime': Edm.DateTimeOffset,
        'installRuleWindowEndTime': Edm.TimeOfDay,
        'installRuleWindowStartTime': Edm.TimeOfDay,
        'scheduleDurationInDays': Edm.Int32,
        'scheduleMode': zebraFotaScheduleMode,
        'timeZoneOffsetInMinutes': Edm.Int32,
        'updateType': zebraFotaUpdateType,
    }


class zebraFotaDeploymentStatus(object):
    props = {
        'cancelRequested': Edm.Boolean,
        'completeOrCanceledDateTime': Edm.DateTimeOffset,
        'errorCode': zebraFotaErrorCode,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'state': zebraFotaDeploymentState,
        'totalAwaitingInstall': Edm.Int32,
        'totalCanceled': Edm.Int32,
        'totalCreated': Edm.Int32,
        'totalDevices': Edm.Int32,
        'totalDownloading': Edm.Int32,
        'totalFailedDownload': Edm.Int32,
        'totalFailedInstall': Edm.Int32,
        'totalScheduled': Edm.Int32,
        'totalSucceededInstall': Edm.Int32,
        'totalUnknown': Edm.Int32,
    }


class mobileAppAssignmentSettings(object):
    props = {

    }


class androidManagedStoreAppAssignmentSettings(object):
    props = {
        'androidManagedStoreAppTrackIds': Collection,
        'autoUpdateMode': androidManagedStoreAutoUpdateMode,
    }


class androidManagedStoreAppTrack(object):
    props = {
        'trackAlias': Edm.String,
        'trackId': Edm.String,
    }


class androidMinimumOperatingSystem(object):
    props = {
        'v10_0': Edm.Boolean,
        'v11_0': Edm.Boolean,
        'v12_0': Edm.Boolean,
        'v13_0': Edm.Boolean,
        'v14_0': Edm.Boolean,
        'v15_0': Edm.Boolean,
        'v4_0': Edm.Boolean,
        'v4_0_3': Edm.Boolean,
        'v4_1': Edm.Boolean,
        'v4_2': Edm.Boolean,
        'v4_3': Edm.Boolean,
        'v4_4': Edm.Boolean,
        'v5_0': Edm.Boolean,
        'v5_1': Edm.Boolean,
        'v6_0': Edm.Boolean,
        'v7_0': Edm.Boolean,
        'v7_1': Edm.Boolean,
        'v8_0': Edm.Boolean,
        'v8_1': Edm.Boolean,
        'v9_0': Edm.Boolean,
    }


class androidPermissionAction(object):
    props = {
        'action': androidPermissionActionType,
        'permission': Edm.String,
    }


class appConfigurationSettingItem(object):
    props = {
        'appConfigKey': Edm.String,
        'appConfigKeyType': mdmAppConfigKeyType,
        'appConfigKeyValue': Edm.String,
    }


class configurationManagerCollectionAssignmentTarget(object):
    props = {
        'collectionId': Edm.String,
    }


class excludedApps(object):
    props = {
        'access': Edm.Boolean,
        'bing': Edm.Boolean,
        'excel': Edm.Boolean,
        'groove': Edm.Boolean,
        'infoPath': Edm.Boolean,
        'lync': Edm.Boolean,
        'oneDrive': Edm.Boolean,
        'oneNote': Edm.Boolean,
        'outlook': Edm.Boolean,
        'powerPoint': Edm.Boolean,
        'publisher': Edm.Boolean,
        'sharePointDesigner': Edm.Boolean,
        'teams': Edm.Boolean,
        'visio': Edm.Boolean,
        'word': Edm.Boolean,
    }


class fileEncryptionInfo(object):
    props = {
        'encryptionKey': Edm.Binary,
        'fileDigest': Edm.Binary,
        'fileDigestAlgorithm': Edm.String,
        'initializationVector': Edm.Binary,
        'mac': Edm.Binary,
        'macKey': Edm.Binary,
        'profileIdentifier': Edm.String,
    }


class iosDeviceType(object):
    props = {
        'iPad': Edm.Boolean,
        'iPhoneAndIPod': Edm.Boolean,
    }


class iosLobAppAssignmentSettings(object):
    props = {
        'isRemovable': Edm.Boolean,
        'preventManagedAppBackup': Edm.Boolean,
        'uninstallOnDeviceRemoval': Edm.Boolean,
        'vpnConfigurationId': Edm.String,
    }


class iosMinimumOperatingSystem(object):
    props = {
        'v10_0': Edm.Boolean,
        'v11_0': Edm.Boolean,
        'v12_0': Edm.Boolean,
        'v13_0': Edm.Boolean,
        'v14_0': Edm.Boolean,
        'v15_0': Edm.Boolean,
        'v16_0': Edm.Boolean,
        'v17_0': Edm.Boolean,
        'v8_0': Edm.Boolean,
        'v9_0': Edm.Boolean,
    }


class iosStoreAppAssignmentSettings(object):
    props = {
        'isRemovable': Edm.Boolean,
        'preventManagedAppBackup': Edm.Boolean,
        'uninstallOnDeviceRemoval': Edm.Boolean,
        'vpnConfigurationId': Edm.String,
    }


class iosVppAppAssignmentSettings(object):
    props = {
        'isRemovable': Edm.Boolean,
        'preventAutoAppUpdate': Edm.Boolean,
        'preventManagedAppBackup': Edm.Boolean,
        'uninstallOnDeviceRemoval': Edm.Boolean,
        'useDeviceLicensing': Edm.Boolean,
        'vpnConfigurationId': Edm.String,
    }


class iosVppAppRevokeLicensesActionResult(object):
    props = {
        'actionFailureReason': vppTokenActionFailureReason,
        'actionName': Edm.String,
        'actionState': actionState,
        'failedLicensesCount': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'totalLicensesCount': Edm.Int32,
        'userId': Edm.String,
    }


class macOSAppScript(object):
    props = {
        'scriptContent': Edm.String,
    }


class macOSIncludedApp(object):
    props = {
        'bundleId': Edm.String,
        'bundleVersion': Edm.String,
    }


class macOsLobAppAssignmentSettings(object):
    props = {
        'uninstallOnDeviceRemoval': Edm.Boolean,
    }


class macOSLobChildApp(object):
    props = {
        'buildNumber': Edm.String,
        'bundleId': Edm.String,
        'versionNumber': Edm.String,
    }


class macOSMinimumOperatingSystem(object):
    props = {
        'v10_10': Edm.Boolean,
        'v10_11': Edm.Boolean,
        'v10_12': Edm.Boolean,
        'v10_13': Edm.Boolean,
        'v10_14': Edm.Boolean,
        'v10_15': Edm.Boolean,
        'v10_7': Edm.Boolean,
        'v10_8': Edm.Boolean,
        'v10_9': Edm.Boolean,
        'v11_0': Edm.Boolean,
        'v12_0': Edm.Boolean,
        'v13_0': Edm.Boolean,
        'v14_0': Edm.Boolean,
    }


class macOsVppAppAssignmentSettings(object):
    props = {
        'preventAutoAppUpdate': Edm.Boolean,
        'preventManagedAppBackup': Edm.Boolean,
        'uninstallOnDeviceRemoval': Edm.Boolean,
        'useDeviceLicensing': Edm.Boolean,
    }


class macOsVppAppRevokeLicensesActionResult(object):
    props = {
        'actionFailureReason': vppTokenActionFailureReason,
        'actionName': Edm.String,
        'actionState': actionState,
        'failedLicensesCount': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'totalLicensesCount': Edm.Int32,
        'userId': Edm.String,
    }


class microsoftStoreForBusinessAppAssignmentSettings(object):
    props = {
        'useDeviceContext': Edm.Boolean,
    }


class mobileAppInstallTimeSettings(object):
    props = {
        'deadlineDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'useLocalTime': Edm.Boolean,
    }


class vppLicensingType(object):
    props = {
        'supportDeviceLicensing': Edm.Boolean,
        'supportsDeviceLicensing': Edm.Boolean,
        'supportsUserLicensing': Edm.Boolean,
        'supportUserLicensing': Edm.Boolean,
    }


class win32CatalogAppAssignmentSettings(object):
    props = {

    }


class win32LobAppAutoUpdateSettings(object):
    props = {
        'autoUpdateSupersededAppsState': win32LobAutoUpdateSupersededAppsState,
    }


class win32LobAppRestartSettings(object):
    props = {
        'countdownDisplayBeforeRestartInMinutes': Edm.Int32,
        'gracePeriodInMinutes': Edm.Int32,
        'restartNotificationSnoozeDurationInMinutes': Edm.Int32,
    }


class win32LobAppDetection(object):
    props = {

    }


class win32LobAppFileSystemDetection(object):
    props = {
        'check32BitOn64System': Edm.Boolean,
        'detectionType': win32LobAppFileSystemDetectionType,
        'detectionValue': Edm.String,
        'fileOrFolderName': Edm.String,
        'operator': win32LobAppDetectionOperator,
        'path': Edm.String,
    }


class win32LobAppRequirement(object):
    props = {
        'detectionValue': Edm.String,
        'operator': win32LobAppDetectionOperator,
    }


class win32LobAppFileSystemRequirement(object):
    props = {
        'check32BitOn64System': Edm.Boolean,
        'detectionType': win32LobAppFileSystemDetectionType,
        'fileOrFolderName': Edm.String,
        'path': Edm.String,
    }


class win32LobAppRule(object):
    props = {
        'ruleType': win32LobAppRuleType,
    }


class win32LobAppFileSystemRule(object):
    props = {
        'check32BitOn64System': Edm.Boolean,
        'comparisonValue': Edm.String,
        'fileOrFolderName': Edm.String,
        'operationType': win32LobAppFileSystemOperationType,
        'operator': win32LobAppRuleOperator,
        'path': Edm.String,
    }


class win32LobAppInstallExperience(object):
    props = {
        'deviceRestartBehavior': win32LobAppRestartBehavior,
        'maxRunTimeInMinutes': Edm.Int32,
        'runAsAccount': runAsAccountType,
    }


class win32LobAppMsiInformation(object):
    props = {
        'packageType': win32LobAppMsiPackageType,
        'productCode': Edm.String,
        'productName': Edm.String,
        'productVersion': Edm.String,
        'publisher': Edm.String,
        'requiresReboot': Edm.Boolean,
        'upgradeCode': Edm.String,
    }


class win32LobAppPowerShellScriptDetection(object):
    props = {
        'enforceSignatureCheck': Edm.Boolean,
        'runAs32Bit': Edm.Boolean,
        'scriptContent': Edm.String,
    }


class win32LobAppPowerShellScriptRequirement(object):
    props = {
        'detectionType': win32LobAppPowerShellScriptDetectionType,
        'displayName': Edm.String,
        'enforceSignatureCheck': Edm.Boolean,
        'runAs32Bit': Edm.Boolean,
        'runAsAccount': runAsAccountType,
        'scriptContent': Edm.String,
    }


class win32LobAppPowerShellScriptRule(object):
    props = {
        'comparisonValue': Edm.String,
        'displayName': Edm.String,
        'enforceSignatureCheck': Edm.Boolean,
        'operationType': win32LobAppPowerShellScriptRuleOperationType,
        'operator': win32LobAppRuleOperator,
        'runAs32Bit': Edm.Boolean,
        'runAsAccount': runAsAccountType,
        'scriptContent': Edm.String,
    }


class win32LobAppProductCodeDetection(object):
    props = {
        'productCode': Edm.String,
        'productVersion': Edm.String,
        'productVersionOperator': win32LobAppDetectionOperator,
    }


class win32LobAppProductCodeRule(object):
    props = {
        'productCode': Edm.String,
        'productVersion': Edm.String,
        'productVersionOperator': win32LobAppRuleOperator,
    }


class win32LobAppRegistryDetection(object):
    props = {
        'check32BitOn64System': Edm.Boolean,
        'detectionType': win32LobAppRegistryDetectionType,
        'detectionValue': Edm.String,
        'keyPath': Edm.String,
        'operator': win32LobAppDetectionOperator,
        'valueName': Edm.String,
    }


class win32LobAppRegistryRequirement(object):
    props = {
        'check32BitOn64System': Edm.Boolean,
        'detectionType': win32LobAppRegistryDetectionType,
        'keyPath': Edm.String,
        'valueName': Edm.String,
    }


class win32LobAppRegistryRule(object):
    props = {
        'check32BitOn64System': Edm.Boolean,
        'comparisonValue': Edm.String,
        'keyPath': Edm.String,
        'operationType': win32LobAppRegistryRuleOperationType,
        'operator': win32LobAppRuleOperator,
        'valueName': Edm.String,
    }


class win32LobAppReturnCode(object):
    props = {
        'returnCode': Edm.Int32,
        'type': win32LobAppReturnCodeType,
    }


class windowsAppXAppAssignmentSettings(object):
    props = {
        'useDeviceContext': Edm.Boolean,
    }


class windowsMinimumOperatingSystem(object):
    props = {
        'v10_0': Edm.Boolean,
        'v10_1607': Edm.Boolean,
        'v10_1703': Edm.Boolean,
        'v10_1709': Edm.Boolean,
        'v10_1803': Edm.Boolean,
        'v10_1809': Edm.Boolean,
        'v10_1903': Edm.Boolean,
        'v10_1909': Edm.Boolean,
        'v10_2004': Edm.Boolean,
        'v10_21H1': Edm.Boolean,
        'v10_2H20': Edm.Boolean,
        'v8_0': Edm.Boolean,
        'v8_1': Edm.Boolean,
    }


class windowsPackageInformation(object):
    props = {
        'applicableArchitecture': windowsArchitecture,
        'displayName': Edm.String,
        'identityName': Edm.String,
        'identityPublisher': Edm.String,
        'identityResourceIdentifier': Edm.String,
        'identityVersion': Edm.String,
        'minimumSupportedOperatingSystem': windowsMinimumOperatingSystem,
    }


class windowsUniversalAppXAppAssignmentSettings(object):
    props = {
        'useDeviceContext': Edm.Boolean,
    }


class winGetAppInstallTimeSettings(object):
    props = {
        'deadlineDateTime': Edm.DateTimeOffset,
        'useLocalTime': Edm.Boolean,
    }


class winGetAppRestartSettings(object):
    props = {
        'countdownDisplayBeforeRestartInMinutes': Edm.Int32,
        'gracePeriodInMinutes': Edm.Int32,
        'restartNotificationSnoozeDurationInMinutes': Edm.Int32,
    }


class winGetAppInstallExperience(object):
    props = {
        'runAsAccount': runAsAccountType,
    }


class auditActor(object):
    props = {
        'applicationDisplayName': Edm.String,
        'applicationId': Edm.String,
        'auditActorType': Edm.String,
        'ipAddress': Edm.String,
        'remoteTenantId': Edm.String,
        'remoteUserId': Edm.String,
        'servicePrincipalName': Edm.String,
        'type': Edm.String,
        'userId': Edm.String,
        'userPermissions': Collection,
        'userPrincipalName': Edm.String,
        'userRoleScopeTags': Collection,
    }


class roleScopeTagInfo(object):
    props = {
        'displayName': Edm.String,
        'roleScopeTagId': Edm.String,
    }


class auditProperty(object):
    props = {
        'displayName': Edm.String,
        'newValue': Edm.String,
        'oldValue': Edm.String,
    }


class auditResource(object):
    props = {
        'auditResourceType': Edm.String,
        'displayName': Edm.String,
        'modifiedProperties': Collection,
        'resourceId': Edm.String,
        'type': Edm.String,
    }


class assignmentFilterEvaluateRequest(object):
    props = {
        'orderBy': Collection,
        'platform': devicePlatformType,
        'rule': Edm.String,
        'search': Edm.String,
        'skip': Edm.Int32,
        'top': Edm.Int32,
    }


class assignmentFilterEvaluationSummary(object):
    props = {
        'assignmentFilterDisplayName': Edm.String,
        'assignmentFilterId': Edm.String,
        'assignmentFilterLastModifiedDateTime': Edm.DateTimeOffset,
        'assignmentFilterPlatform': devicePlatformType,
        'assignmentFilterType': deviceAndAppManagementAssignmentFilterType,
        'assignmentFilterTypeAndEvaluationResults': Collection,
        'evaluationDateTime': Edm.DateTimeOffset,
        'evaluationResult': assignmentFilterEvaluationResult,
    }


class assignmentFilterTypeAndEvaluationResult(object):
    props = {
        'assignmentFilterType': deviceAndAppManagementAssignmentFilterType,
        'evaluationResult': assignmentFilterEvaluationResult,
    }


class assignmentFilterState(object):
    props = {
        'enabled': Edm.Boolean,
    }


class assignmentFilterStatusDetails(object):
    props = {
        'deviceProperties': Collection,
        'evalutionSummaries': Collection,
        'managedDeviceId': Edm.String,
        'payloadId': Edm.String,
        'userId': Edm.String,
    }


class assignmentFilterSupportedProperty(object):
    props = {
        'dataType': Edm.String,
        'isCollection': Edm.Boolean,
        'name': Edm.String,
        'propertyRegexConstraint': Edm.String,
        'supportedOperators': Collection,
        'supportedValues': Collection,
    }


class assignmentFilterValidationResult(object):
    props = {
        'isValidRule': Edm.Boolean,
    }


class hasPayloadLinkResultItem(object):
    props = {
        'error': Edm.String,
        'hasLink': Edm.Boolean,
        'payloadId': Edm.String,
        'sources': Collection,
    }


class payloadByFilter(object):
    props = {
        'assignmentFilterType': deviceAndAppManagementAssignmentFilterType,
        'groupId': Edm.String,
        'payloadId': Edm.String,
        'payloadType': associatedAssignmentPayloadType,
    }


class deviceManagementApplicabilityRuleDeviceMode(object):
    props = {
        'deviceMode': windows10DeviceModeType,
        'name': Edm.String,
        'ruleType': deviceManagementApplicabilityRuleType,
    }


class deviceManagementApplicabilityRuleOsEdition(object):
    props = {
        'name': Edm.String,
        'osEditionTypes': Collection,
        'ruleType': deviceManagementApplicabilityRuleType,
    }


class deviceManagementApplicabilityRuleOsVersion(object):
    props = {
        'maxOSVersion': Edm.String,
        'minOSVersion': Edm.String,
        'name': Edm.String,
        'ruleType': deviceManagementApplicabilityRuleType,
    }


class windowsEnrollmentStatusScreenSettings(object):
    props = {
        'allowDeviceUseBeforeProfileAndAppInstallComplete': Edm.Boolean,
        'allowDeviceUseOnInstallFailure': Edm.Boolean,
        'allowLogCollectionOnInstallFailure': Edm.Boolean,
        'blockDeviceSetupRetryByUser': Edm.Boolean,
        'customErrorMessage': Edm.String,
        'hideInstallationProgress': Edm.Boolean,
        'installProgressTimeoutInMinutes': Edm.Int32,
    }


class outOfBoxExperienceSetting(object):
    props = {
        'deviceUsageType': windowsDeviceUsageType,
        'escapeLinkHidden': Edm.Boolean,
        'eulaHidden': Edm.Boolean,
        'keyboardSelectionPageSkipped': Edm.Boolean,
        'privacySettingsHidden': Edm.Boolean,
        'userType': windowsUserType,
    }


class outOfBoxExperienceSettings(object):
    props = {
        'deviceUsageType': windowsDeviceUsageType,
        'hideEscapeLink': Edm.Boolean,
        'hideEULA': Edm.Boolean,
        'hidePrivacySettings': Edm.Boolean,
        'skipKeyboardSelectionPage': Edm.Boolean,
        'userType': windowsUserType,
    }


class extendedKeyUsage(object):
    props = {
        'name': Edm.String,
        'objectIdentifier': Edm.String,
    }


class trustChainCertificate(object):
    props = {
        'certificate': Edm.String,
        'displayName': Edm.String,
    }


class airPrintDestination(object):
    props = {
        'forceTls': Edm.Boolean,
        'ipAddress': Edm.String,
        'port': Edm.Int32,
        'resourcePath': Edm.String,
    }


class appListItem(object):
    props = {
        'appId': Edm.String,
        'appStoreUrl': Edm.String,
        'name': Edm.String,
        'publisher': Edm.String,
    }


class androidDeviceOwnerGlobalProxy(object):
    props = {

    }


class androidDeviceOwnerGlobalProxyAutoConfig(object):
    props = {
        'proxyAutoConfigURL': Edm.String,
    }


class androidDeviceOwnerGlobalProxyDirect(object):
    props = {
        'excludedHosts': Collection,
        'host': Edm.String,
        'port': Edm.Int32,
    }


class androidDeviceOwnerKioskModeHomeScreenItem(object):
    props = {

    }


class androidDeviceOwnerKioskModeFolderItem(object):
    props = {

    }


class androidDeviceOwnerKioskModeApp(object):
    props = {
        'className': Edm.String,
        'package': Edm.String,
    }


class androidDeviceOwnerKioskModeAppPositionItem(object):
    props = {
        'item': androidDeviceOwnerKioskModeHomeScreenItem,
        'position': Edm.Int32,
    }


class androidDeviceOwnerKioskModeManagedFolder(object):
    props = {
        'folderIdentifier': Edm.String,
        'folderName': Edm.String,
        'items': Collection,
    }


class androidDeviceOwnerKioskModeManagedFolderReference(object):
    props = {
        'folderIdentifier': Edm.String,
        'folderName': Edm.String,
    }


class androidDeviceOwnerKioskModeWeblink(object):
    props = {
        'label': Edm.String,
        'link': Edm.String,
    }


class androidDeviceOwnerSilentCertificateAccess(object):
    props = {
        'packageId': Edm.String,
    }


class androidDeviceOwnerSystemUpdateFreezePeriod(object):
    props = {
        'endDay': Edm.Int32,
        'endMonth': Edm.Int32,
        'startDay': Edm.Int32,
        'startMonth': Edm.Int32,
    }


class androidDeviceOwnerUserFacingMessage(object):
    props = {
        'defaultMessage': Edm.String,
        'localizedMessages': Collection,
    }


class appleAppListItem(object):
    props = {

    }


class specifiedCaptiveNetworkPlugins(object):
    props = {
        'allowedBundleIdentifiers': Collection,
    }


class bitLockerRecoveryOptions(object):
    props = {
        'blockDataRecoveryAgent': Edm.Boolean,
        'enableBitLockerAfterRecoveryInformationToStore': Edm.Boolean,
        'enableRecoveryInformationSaveToStore': Edm.Boolean,
        'hideRecoveryOptions': Edm.Boolean,
        'recoveryInformationToStore': bitLockerRecoveryInformationType,
        'recoveryKeyUsage': configurationUsage,
        'recoveryPasswordUsage': configurationUsage,
    }


class bitLockerRemovableDrivePolicy(object):
    props = {
        'blockCrossOrganizationWriteAccess': Edm.Boolean,
        'encryptionMethod': bitLockerEncryptionMethod,
        'requireEncryptionForWriteAccess': Edm.Boolean,
    }


class bitLockerSystemDrivePolicy(object):
    props = {
        'encryptionMethod': bitLockerEncryptionMethod,
        'minimumPinLength': Edm.Int32,
        'prebootRecoveryEnableMessageAndUrl': Edm.Boolean,
        'prebootRecoveryMessage': Edm.String,
        'prebootRecoveryUrl': Edm.String,
        'recoveryOptions': bitLockerRecoveryOptions,
        'startupAuthenticationBlockWithoutTpmChip': Edm.Boolean,
        'startupAuthenticationRequired': Edm.Boolean,
        'startupAuthenticationTpmKeyUsage': configurationUsage,
        'startupAuthenticationTpmPinAndKeyUsage': configurationUsage,
        'startupAuthenticationTpmPinUsage': configurationUsage,
        'startupAuthenticationTpmUsage': configurationUsage,
    }


class singleSignOnExtension(object):
    props = {

    }


class credentialSingleSignOnExtension(object):
    props = {
        'configurations': Collection,
        'domains': Collection,
        'extensionIdentifier': Edm.String,
        'realm': Edm.String,
        'teamIdentifier': Edm.String,
    }


class keyTypedValuePair(object):
    props = {
        'key': Edm.String,
    }


class cryptographySuite(object):
    props = {
        'authenticationTransformConstants': authenticationTransformConstant,
        'cipherTransformConstants': vpnEncryptionAlgorithmType,
        'dhGroup': diffieHellmanGroup,
        'encryptionMethod': vpnEncryptionAlgorithmType,
        'integrityCheckMethod': vpnIntegrityAlgorithmType,
        'pfsGroup': perfectForwardSecrecyGroup,
    }


class customSubjectAlternativeName(object):
    props = {
        'name': Edm.String,
        'sanType': subjectAlternativeNameType,
    }


class customUpdateTimeWindow(object):
    props = {
        'endDay': dayOfWeek,
        'endTime': Edm.TimeOfDay,
        'startDay': dayOfWeek,
        'startTime': Edm.TimeOfDay,
    }


class defenderDetectedMalwareActions(object):
    props = {
        'highSeverity': defenderThreatAction,
        'lowSeverity': defenderThreatAction,
        'moderateSeverity': defenderThreatAction,
        'severeSeverity': defenderThreatAction,
    }


class deliveryOptimizationBandwidth(object):
    props = {

    }


class deliveryOptimizationBandwidthAbsolute(object):
    props = {
        'maximumDownloadBandwidthInKilobytesPerSecond': Edm.Int64,
        'maximumUploadBandwidthInKilobytesPerSecond': Edm.Int64,
    }


class deliveryOptimizationBandwidthBusinessHoursLimit(object):
    props = {
        'bandwidthBeginBusinessHours': Edm.Int32,
        'bandwidthEndBusinessHours': Edm.Int32,
        'bandwidthPercentageDuringBusinessHours': Edm.Int32,
        'bandwidthPercentageOutsideBusinessHours': Edm.Int32,
    }


class deliveryOptimizationBandwidthHoursWithPercentage(object):
    props = {
        'bandwidthBackgroundPercentageHours': deliveryOptimizationBandwidthBusinessHoursLimit,
        'bandwidthForegroundPercentageHours': deliveryOptimizationBandwidthBusinessHoursLimit,
    }


class deliveryOptimizationBandwidthPercentage(object):
    props = {
        'maximumBackgroundBandwidthPercentage': Edm.Int32,
        'maximumForegroundBandwidthPercentage': Edm.Int32,
    }


class deliveryOptimizationGroupIdSource(object):
    props = {

    }


class deliveryOptimizationGroupIdCustom(object):
    props = {
        'groupIdCustom': Edm.String,
    }


class deliveryOptimizationGroupIdSourceOptions(object):
    props = {
        'groupIdSourceOption': deliveryOptimizationGroupIdOptionsType,
    }


class deliveryOptimizationMaxCacheSize(object):
    props = {

    }


class deliveryOptimizationMaxCacheSizeAbsolute(object):
    props = {
        'maximumCacheSizeInGigabytes': Edm.Int64,
    }


class deliveryOptimizationMaxCacheSizePercentage(object):
    props = {
        'maximumCacheSizePercentage': Edm.Int32,
    }


class deviceCompliancePolicyScript(object):
    props = {
        'deviceComplianceScriptId': Edm.String,
        'rulesContent': Edm.Binary,
    }


class deviceCompliancePolicySettingState(object):
    props = {
        'currentValue': Edm.String,
        'errorCode': Edm.Int64,
        'errorDescription': Edm.String,
        'instanceDisplayName': Edm.String,
        'setting': Edm.String,
        'settingInstanceId': Edm.String,
        'settingName': Edm.String,
        'sources': Collection,
        'state': complianceStatus,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }


class settingSource(object):
    props = {
        'displayName': Edm.String,
        'id': Edm.String,
        'sourceType': settingSourceType,
    }


class deviceComplianceScriptError(object):
    props = {
        'code': code,
        'deviceComplianceScriptRulesValidationError': deviceComplianceScriptRulesValidationError,
        'message': Edm.String,
    }


class deviceComplianceScriptRule(object):
    props = {
        'dataType': dataType,
        'deviceComplianceScriptRuleDataType': deviceComplianceScriptRuleDataType,
        'deviceComplianceScriptRulOperator': deviceComplianceScriptRulOperator,
        'operand': Edm.String,
        'operator': operator,
        'settingName': Edm.String,
    }


class deviceComplianceScriptRuleError(object):
    props = {
        'settingName': Edm.String,
    }


class deviceComplianceScriptValidationResult(object):
    props = {
        'ruleErrors': Collection,
        'rules': Collection,
        'scriptErrors': Collection,
    }


class deviceConfigurationSettingState(object):
    props = {
        'currentValue': Edm.String,
        'errorCode': Edm.Int64,
        'errorDescription': Edm.String,
        'instanceDisplayName': Edm.String,
        'setting': Edm.String,
        'settingInstanceId': Edm.String,
        'settingName': Edm.String,
        'sources': Collection,
        'state': complianceStatus,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }


class deviceConfigurationTargetedUserAndDevice(object):
    props = {
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'lastCheckinDateTime': Edm.DateTimeOffset,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class deviceManagementUserRightsLocalUserOrGroup(object):
    props = {
        'description': Edm.String,
        'name': Edm.String,
        'securityIdentifier': Edm.String,
    }


class deviceManagementUserRightsSetting(object):
    props = {
        'localUsersOrGroups': Collection,
        'state': stateManagementSetting,
    }


class edgeHomeButtonConfiguration(object):
    props = {

    }


class edgeHomeButtonHidden(object):
    props = {

    }


class edgeHomeButtonLoadsStartPage(object):
    props = {

    }


class edgeHomeButtonOpensCustomURL(object):
    props = {
        'homeButtonCustomURL': Edm.String,
    }


class edgeHomeButtonOpensNewTab(object):
    props = {

    }


class edgeSearchEngineBase(object):
    props = {

    }


class edgeSearchEngine(object):
    props = {
        'edgeSearchEngineType': edgeSearchEngineType,
    }


class edgeSearchEngineCustom(object):
    props = {
        'edgeSearchEngineOpenSearchXmlUrl': Edm.String,
    }


class encryptionReportPolicyDetails(object):
    props = {
        'policyId': Edm.String,
        'policyName': Edm.String,
    }


class iosSingleSignOnExtension(object):
    props = {

    }


class iosAzureAdSingleSignOnExtension(object):
    props = {
        'bundleIdAccessControlList': Collection,
        'configurations': Collection,
        'enableSharedDeviceMode': Edm.Boolean,
    }


class iosBookmark(object):
    props = {
        'bookmarkFolder': Edm.String,
        'displayName': Edm.String,
        'url': Edm.String,
    }


class iosCredentialSingleSignOnExtension(object):
    props = {
        'configurations': Collection,
        'domains': Collection,
        'extensionIdentifier': Edm.String,
        'realm': Edm.String,
        'teamIdentifier': Edm.String,
    }


class iosEduCertificateSettings(object):
    props = {
        'certFileName': Edm.String,
        'certificateTemplateName': Edm.String,
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'renewalThresholdPercentage': Edm.Int32,
        'trustedRootCertificate': Edm.Binary,
    }


class iosHomeScreenItem(object):
    props = {
        'displayName': Edm.String,
    }


class iosHomeScreenApp(object):
    props = {
        'bundleID': Edm.String,
        'isWebClip': Edm.Boolean,
    }


class iosHomeScreenFolder(object):
    props = {
        'pages': Collection,
    }


class iosHomeScreenFolderPage(object):
    props = {
        'apps': Collection,
        'displayName': Edm.String,
    }


class iosHomeScreenPage(object):
    props = {
        'displayName': Edm.String,
        'icons': Collection,
    }


class iosKerberosSingleSignOnExtension(object):
    props = {
        'activeDirectorySiteCode': Edm.String,
        'blockActiveDirectorySiteAutoDiscovery': Edm.Boolean,
        'blockAutomaticLogin': Edm.Boolean,
        'cacheName': Edm.String,
        'credentialBundleIdAccessControlList': Collection,
        'domainRealms': Collection,
        'domains': Collection,
        'isDefaultRealm': Edm.Boolean,
        'managedAppsInBundleIdACLIncluded': Edm.Boolean,
        'passwordBlockModification': Edm.Boolean,
        'passwordChangeUrl': Edm.String,
        'passwordEnableLocalSync': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordExpirationNotificationDays': Edm.Int32,
        'passwordMinimumAgeDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequireActiveDirectoryComplexity': Edm.Boolean,
        'passwordRequirementsDescription': Edm.String,
        'realm': Edm.String,
        'requireUserPresence': Edm.Boolean,
        'signInHelpText': Edm.String,
        'userPrincipalName': Edm.String,
    }


class iosNetworkUsageRule(object):
    props = {
        'cellularDataBlocked': Edm.Boolean,
        'cellularDataBlockWhenRoaming': Edm.Boolean,
        'managedApps': Collection,
    }


class iosNotificationSettings(object):
    props = {
        'alertType': iosNotificationAlertType,
        'appName': Edm.String,
        'badgesEnabled': Edm.Boolean,
        'bundleID': Edm.String,
        'enabled': Edm.Boolean,
        'previewVisibility': iosNotificationPreviewVisibility,
        'publisher': Edm.String,
        'showInNotificationCenter': Edm.Boolean,
        'showOnLockScreen': Edm.Boolean,
        'soundsEnabled': Edm.Boolean,
    }


class iosRedirectSingleSignOnExtension(object):
    props = {
        'configurations': Collection,
        'extensionIdentifier': Edm.String,
        'teamIdentifier': Edm.String,
        'urlPrefixes': Collection,
    }


class iosSingleSignOnSettings(object):
    props = {
        'allowedAppsList': Collection,
        'allowedUrls': Collection,
        'displayName': Edm.String,
        'kerberosPrincipalName': Edm.String,
        'kerberosRealm': Edm.String,
    }


class iosVpnSecurityAssociationParameters(object):
    props = {
        'lifetimeInMinutes': Edm.Int32,
        'securityDiffieHellmanGroup': Edm.Int32,
        'securityEncryptionAlgorithm': vpnEncryptionAlgorithmType,
        'securityIntegrityAlgorithm': vpnIntegrityAlgorithmType,
    }


class iosWebContentFilterBase(object):
    props = {

    }


class iosWebContentFilterAutoFilter(object):
    props = {
        'allowedUrls': Collection,
        'blockedUrls': Collection,
    }


class iosWebContentFilterSpecificWebsitesAccess(object):
    props = {
        'specificWebsitesOnly': Collection,
        'websiteList': Collection,
    }


class kerberosSingleSignOnExtension(object):
    props = {
        'activeDirectorySiteCode': Edm.String,
        'blockActiveDirectorySiteAutoDiscovery': Edm.Boolean,
        'blockAutomaticLogin': Edm.Boolean,
        'cacheName': Edm.String,
        'credentialBundleIdAccessControlList': Collection,
        'domainRealms': Collection,
        'domains': Collection,
        'isDefaultRealm': Edm.Boolean,
        'passwordBlockModification': Edm.Boolean,
        'passwordChangeUrl': Edm.String,
        'passwordEnableLocalSync': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordExpirationNotificationDays': Edm.Int32,
        'passwordMinimumAgeDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequireActiveDirectoryComplexity': Edm.Boolean,
        'passwordRequirementsDescription': Edm.String,
        'realm': Edm.String,
        'requireUserPresence': Edm.Boolean,
        'userPrincipalName': Edm.String,
    }


class keyBooleanValuePair(object):
    props = {
        'value': Edm.Boolean,
    }


class keyIntegerValuePair(object):
    props = {
        'value': Edm.Int32,
    }


class keyRealValuePair(object):
    props = {
        'value': Edm.Double,
    }


class keyStringValuePair(object):
    props = {
        'value': Edm.String,
    }


class macOSAppleEventReceiver(object):
    props = {
        'allowed': Edm.Boolean,
        'codeRequirement': Edm.String,
        'identifier': Edm.String,
        'identifierType': macOSProcessIdentifierType,
    }


class macOSAssociatedDomainsItem(object):
    props = {
        'applicationIdentifier': Edm.String,
        'directDownloadsEnabled': Edm.Boolean,
        'domains': Collection,
    }


class macOSSingleSignOnExtension(object):
    props = {

    }


class macOSAzureAdSingleSignOnExtension(object):
    props = {
        'bundleIdAccessControlList': Collection,
        'configurations': Collection,
        'enableSharedDeviceMode': Edm.Boolean,
    }


class macOSCredentialSingleSignOnExtension(object):
    props = {
        'configurations': Collection,
        'domains': Collection,
        'extensionIdentifier': Edm.String,
        'realm': Edm.String,
        'teamIdentifier': Edm.String,
    }


class macOSFirewallApplication(object):
    props = {
        'allowsIncomingConnections': Edm.Boolean,
        'bundleId': Edm.String,
    }


class macOSKerberosSingleSignOnExtension(object):
    props = {
        'activeDirectorySiteCode': Edm.String,
        'blockActiveDirectorySiteAutoDiscovery': Edm.Boolean,
        'blockAutomaticLogin': Edm.Boolean,
        'cacheName': Edm.String,
        'credentialBundleIdAccessControlList': Collection,
        'credentialsCacheMonitored': Edm.Boolean,
        'domainRealms': Collection,
        'domains': Collection,
        'isDefaultRealm': Edm.Boolean,
        'kerberosAppsInBundleIdACLIncluded': Edm.Boolean,
        'managedAppsInBundleIdACLIncluded': Edm.Boolean,
        'modeCredentialUsed': Edm.String,
        'passwordBlockModification': Edm.Boolean,
        'passwordChangeUrl': Edm.String,
        'passwordEnableLocalSync': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordExpirationNotificationDays': Edm.Int32,
        'passwordMinimumAgeDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequireActiveDirectoryComplexity': Edm.Boolean,
        'passwordRequirementsDescription': Edm.String,
        'preferredKDCs': Collection,
        'realm': Edm.String,
        'requireUserPresence': Edm.Boolean,
        'signInHelpText': Edm.String,
        'tlsForLDAPRequired': Edm.Boolean,
        'usernameLabelCustom': Edm.String,
        'userPrincipalName': Edm.String,
        'userSetupDelayed': Edm.Boolean,
    }


class macOSKernelExtension(object):
    props = {
        'bundleId': Edm.String,
        'teamIdentifier': Edm.String,
    }


class macOSLaunchItem(object):
    props = {
        'hide': Edm.Boolean,
        'path': Edm.String,
    }


class macOSPrivacyAccessControlItem(object):
    props = {
        'accessibility': enablement,
        'addressBook': enablement,
        'appleEventsAllowedReceivers': Collection,
        'blockCamera': Edm.Boolean,
        'blockListenEvent': Edm.Boolean,
        'blockMicrophone': Edm.Boolean,
        'blockScreenCapture': Edm.Boolean,
        'calendar': enablement,
        'codeRequirement': Edm.String,
        'displayName': Edm.String,
        'fileProviderPresence': enablement,
        'identifier': Edm.String,
        'identifierType': macOSProcessIdentifierType,
        'mediaLibrary': enablement,
        'photos': enablement,
        'postEvent': enablement,
        'reminders': enablement,
        'speechRecognition': enablement,
        'staticCodeValidation': Edm.Boolean,
        'systemPolicyAllFiles': enablement,
        'systemPolicyDesktopFolder': enablement,
        'systemPolicyDocumentsFolder': enablement,
        'systemPolicyDownloadsFolder': enablement,
        'systemPolicyNetworkVolumes': enablement,
        'systemPolicyRemovableVolumes': enablement,
        'systemPolicySystemAdminFiles': enablement,
    }


class macOSRedirectSingleSignOnExtension(object):
    props = {
        'configurations': Collection,
        'extensionIdentifier': Edm.String,
        'teamIdentifier': Edm.String,
        'urlPrefixes': Collection,
    }


class macOSSystemExtension(object):
    props = {
        'bundleId': Edm.String,
        'teamIdentifier': Edm.String,
    }


class macOSSystemExtensionTypeMapping(object):
    props = {
        'allowedTypes': macOSSystemExtensionType,
        'teamIdentifier': Edm.String,
    }


class managedDeviceMobileAppConfigurationSettingState(object):
    props = {
        'currentValue': Edm.String,
        'errorCode': Edm.Int64,
        'errorDescription': Edm.String,
        'instanceDisplayName': Edm.String,
        'setting': Edm.String,
        'settingInstanceId': Edm.String,
        'settingName': Edm.String,
        'sources': Collection,
        'state': complianceStatus,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }


class managedDeviceReportedApp(object):
    props = {
        'appId': Edm.String,
    }


class mediaContentRatingAustralia(object):
    props = {
        'movieRating': ratingAustraliaMoviesType,
        'tvRating': ratingAustraliaTelevisionType,
    }


class mediaContentRatingCanada(object):
    props = {
        'movieRating': ratingCanadaMoviesType,
        'tvRating': ratingCanadaTelevisionType,
    }


class mediaContentRatingFrance(object):
    props = {
        'movieRating': ratingFranceMoviesType,
        'tvRating': ratingFranceTelevisionType,
    }


class mediaContentRatingGermany(object):
    props = {
        'movieRating': ratingGermanyMoviesType,
        'tvRating': ratingGermanyTelevisionType,
    }


class mediaContentRatingIreland(object):
    props = {
        'movieRating': ratingIrelandMoviesType,
        'tvRating': ratingIrelandTelevisionType,
    }


class mediaContentRatingJapan(object):
    props = {
        'movieRating': ratingJapanMoviesType,
        'tvRating': ratingJapanTelevisionType,
    }


class mediaContentRatingNewZealand(object):
    props = {
        'movieRating': ratingNewZealandMoviesType,
        'tvRating': ratingNewZealandTelevisionType,
    }


class mediaContentRatingUnitedKingdom(object):
    props = {
        'movieRating': ratingUnitedKingdomMoviesType,
        'tvRating': ratingUnitedKingdomTelevisionType,
    }


class mediaContentRatingUnitedStates(object):
    props = {
        'movieRating': ratingUnitedStatesMoviesType,
        'tvRating': ratingUnitedStatesTelevisionType,
    }


class numberRange(object):
    props = {
        'lowerNumber': Edm.Int32,
        'upperNumber': Edm.Int32,
    }


class omaSetting(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isEncrypted': Edm.Boolean,
        'omaUri': Edm.String,
        'secretReferenceValueId': Edm.String,
    }


class omaSettingBase64(object):
    props = {
        'fileName': Edm.String,
        'value': Edm.String,
    }


class omaSettingBoolean(object):
    props = {
        'value': Edm.Boolean,
    }


class omaSettingDateTime(object):
    props = {
        'value': Edm.DateTimeOffset,
    }


class omaSettingFloatingPoint(object):
    props = {
        'value': Edm.Single,
    }


class omaSettingInteger(object):
    props = {
        'isReadOnly': Edm.Boolean,
        'value': Edm.Int32,
    }


class omaSettingString(object):
    props = {
        'value': Edm.String,
    }


class omaSettingStringXml(object):
    props = {
        'fileName': Edm.String,
        'value': Edm.Binary,
    }


class operatingSystemVersionRange(object):
    props = {
        'description': Edm.String,
        'highestVersion': Edm.String,
        'lowestVersion': Edm.String,
    }


class proxiedDomain(object):
    props = {
        'ipAddressOrFQDN': Edm.String,
        'proxy': Edm.String,
    }


class redirectSingleSignOnExtension(object):
    props = {
        'configurations': Collection,
        'extensionIdentifier': Edm.String,
        'teamIdentifier': Edm.String,
        'urlPrefixes': Collection,
    }


class report(object):
    props = {
        'content': Edm.Stream,
    }


class retireScheduledManagedDevice(object):
    props = {
        'complianceState': complianceStatus,
        'deviceCompliancePolicyId': Edm.String,
        'deviceCompliancePolicyName': Edm.String,
        'deviceType': deviceType,
        'id': Edm.String,
        'managedDeviceId': Edm.String,
        'managedDeviceName': Edm.String,
        'managementAgent': managementAgentType,
        'ownerType': managedDeviceOwnerType,
        'retireAfterDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
    }


class sharedPCAccountManagerPolicy(object):
    props = {
        'accountDeletionPolicy': sharedPCAccountDeletionPolicyType,
        'cacheAccountsAboveDiskFreePercentage': Edm.Int32,
        'inactiveThresholdDays': Edm.Int32,
        'removeAccountsBelowDiskFreePercentage': Edm.Int32,
    }


class unsupportedDeviceConfigurationDetail(object):
    props = {
        'message': Edm.String,
        'propertyName': Edm.String,
    }


class vpnDnsRule(object):
    props = {
        'autoTrigger': Edm.Boolean,
        'name': Edm.String,
        'persistent': Edm.Boolean,
        'proxyServerUri': Edm.String,
        'servers': Collection,
    }


class vpnOnDemandRule(object):
    props = {
        'action': vpnOnDemandRuleConnectionAction,
        'dnsSearchDomains': Collection,
        'dnsServerAddressMatch': Collection,
        'domainAction': vpnOnDemandRuleConnectionDomainAction,
        'domains': Collection,
        'interfaceTypeMatch': vpnOnDemandRuleInterfaceTypeMatch,
        'probeRequiredUrl': Edm.String,
        'probeUrl': Edm.String,
        'ssids': Collection,
    }


class vpnProxyServer(object):
    props = {
        'address': Edm.String,
        'automaticConfigurationScriptUrl': Edm.String,
        'port': Edm.Int32,
    }


class vpnRoute(object):
    props = {
        'destinationPrefix': Edm.String,
        'prefixSize': Edm.Int32,
    }


class vpnServer(object):
    props = {
        'address': Edm.String,
        'description': Edm.String,
        'isDefaultServer': Edm.Boolean,
    }


class vpnTrafficRule(object):
    props = {
        'appId': Edm.String,
        'appType': vpnTrafficRuleAppType,
        'claims': Edm.String,
        'localAddressRanges': Collection,
        'localPortRanges': Collection,
        'name': Edm.String,
        'protocols': Edm.Int32,
        'remoteAddressRanges': Collection,
        'remotePortRanges': Collection,
        'routingPolicyType': vpnTrafficRuleRoutingPolicyType,
        'vpnTrafficDirection': vpnTrafficDirection,
    }


class windows10AppsForceUpdateSchedule(object):
    props = {
        'recurrence': windows10AppsUpdateRecurrence,
        'runImmediatelyIfAfterStartDateTime': Edm.Boolean,
        'startDateTime': Edm.DateTimeOffset,
    }


class windows10AssociatedApps(object):
    props = {
        'appType': windows10AppType,
        'identifier': Edm.String,
    }


class windows10NetworkProxyServer(object):
    props = {
        'address': Edm.String,
        'exceptions': Collection,
        'useForLocalAddresses': Edm.Boolean,
    }


class windows10VpnProxyServer(object):
    props = {
        'bypassProxyServerForLocalAddress': Edm.Boolean,
    }


class windows81VpnProxyServer(object):
    props = {
        'automaticallyDetectProxySettings': Edm.Boolean,
        'bypassProxyServerForLocalAddress': Edm.Boolean,
    }


class windowsFirewallNetworkProfile(object):
    props = {
        'authorizedApplicationRulesFromGroupPolicyMerged': Edm.Boolean,
        'authorizedApplicationRulesFromGroupPolicyNotMerged': Edm.Boolean,
        'connectionSecurityRulesFromGroupPolicyMerged': Edm.Boolean,
        'connectionSecurityRulesFromGroupPolicyNotMerged': Edm.Boolean,
        'firewallEnabled': stateManagementSetting,
        'globalPortRulesFromGroupPolicyMerged': Edm.Boolean,
        'globalPortRulesFromGroupPolicyNotMerged': Edm.Boolean,
        'inboundConnectionsBlocked': Edm.Boolean,
        'inboundConnectionsRequired': Edm.Boolean,
        'inboundNotificationsBlocked': Edm.Boolean,
        'inboundNotificationsRequired': Edm.Boolean,
        'incomingTrafficBlocked': Edm.Boolean,
        'incomingTrafficRequired': Edm.Boolean,
        'outboundConnectionsBlocked': Edm.Boolean,
        'outboundConnectionsRequired': Edm.Boolean,
        'policyRulesFromGroupPolicyMerged': Edm.Boolean,
        'policyRulesFromGroupPolicyNotMerged': Edm.Boolean,
        'securedPacketExemptionAllowed': Edm.Boolean,
        'securedPacketExemptionBlocked': Edm.Boolean,
        'stealthModeBlocked': Edm.Boolean,
        'stealthModeRequired': Edm.Boolean,
        'unicastResponsesToMulticastBroadcastsBlocked': Edm.Boolean,
        'unicastResponsesToMulticastBroadcastsRequired': Edm.Boolean,
    }


class windowsFirewallRule(object):
    props = {
        'action': stateManagementSetting,
        'description': Edm.String,
        'displayName': Edm.String,
        'edgeTraversal': stateManagementSetting,
        'filePath': Edm.String,
        'interfaceTypes': windowsFirewallRuleInterfaceTypes,
        'localAddressRanges': Collection,
        'localPortRanges': Collection,
        'localUserAuthorizations': Edm.String,
        'packageFamilyName': Edm.String,
        'profileTypes': windowsFirewallRuleNetworkProfileTypes,
        'protocol': Edm.Int32,
        'remoteAddressRanges': Collection,
        'remotePortRanges': Collection,
        'serviceName': Edm.String,
        'trafficDirection': windowsFirewallRuleTrafficDirectionType,
    }


class windowsKioskUser(object):
    props = {

    }


class windowsKioskActiveDirectoryGroup(object):
    props = {
        'groupName': Edm.String,
    }


class windowsKioskAppBase(object):
    props = {
        'appType': windowsKioskAppType,
        'autoLaunch': Edm.Boolean,
        'name': Edm.String,
        'startLayoutTileSize': windowsAppStartLayoutTileSize,
    }


class windowsKioskAppConfiguration(object):
    props = {

    }


class windowsKioskAutologon(object):
    props = {

    }


class windowsKioskAzureADGroup(object):
    props = {
        'displayName': Edm.String,
        'groupId': Edm.String,
    }


class windowsKioskAzureADUser(object):
    props = {
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class windowsKioskDesktopApp(object):
    props = {
        'desktopApplicationId': Edm.String,
        'desktopApplicationLinkPath': Edm.String,
        'path': Edm.String,
    }


class windowsKioskForceUpdateSchedule(object):
    props = {
        'dayofMonth': Edm.Int32,
        'dayofWeek': dayOfWeek,
        'recurrence': windows10AppsUpdateRecurrence,
        'runImmediatelyIfAfterStartDateTime': Edm.Boolean,
        'startDateTime': Edm.DateTimeOffset,
    }


class windowsKioskLocalGroup(object):
    props = {
        'groupName': Edm.String,
    }


class windowsKioskLocalUser(object):
    props = {
        'userName': Edm.String,
    }


class windowsKioskMultipleApps(object):
    props = {
        'allowAccessToDownloadsFolder': Edm.Boolean,
        'apps': Collection,
        'disallowDesktopApps': Edm.Boolean,
        'showTaskBar': Edm.Boolean,
        'startMenuLayoutXml': Edm.Binary,
    }


class windowsKioskProfile(object):
    props = {
        'appConfiguration': windowsKioskAppConfiguration,
        'profileId': Edm.String,
        'profileName': Edm.String,
        'userAccountsConfiguration': Collection,
    }


class windowsKioskUWPApp(object):
    props = {
        'appId': Edm.String,
        'appUserModelId': Edm.String,
        'containedAppId': Edm.String,
    }


class windowsKioskWin32App(object):
    props = {
        'classicAppPath': Edm.String,
        'edgeKiosk': Edm.String,
        'edgeKioskIdleTimeoutMinutes': Edm.Int32,
        'edgeKioskType': windowsEdgeKioskType,
        'edgeNoFirstRun': Edm.Boolean,
    }


class windowsKioskVisitor(object):
    props = {

    }


class windowsNetworkIsolationPolicy(object):
    props = {
        'enterpriseCloudResources': Collection,
        'enterpriseInternalProxyServers': Collection,
        'enterpriseIPRanges': Collection,
        'enterpriseIPRangesAreAuthoritative': Edm.Boolean,
        'enterpriseNetworkDomainNames': Collection,
        'enterpriseProxyServers': Collection,
        'enterpriseProxyServersAreAuthoritative': Edm.Boolean,
        'neutralDomainResources': Collection,
    }


class windowsUpdateInstallScheduleType(object):
    props = {

    }


class windowsUpdateActiveHoursInstall(object):
    props = {
        'activeHoursEnd': Edm.TimeOfDay,
        'activeHoursStart': Edm.TimeOfDay,
    }


class windowsUpdateScheduledInstall(object):
    props = {
        'scheduledInstallDay': weeklySchedule,
        'scheduledInstallTime': Edm.TimeOfDay,
    }


class wslDistributionConfiguration(object):
    props = {
        'distribution': Edm.String,
        'maximumOSVersion': Edm.String,
        'minimumOSVersion': Edm.String,
    }


class deviceManagementConfigurationSettingApplicability(object):
    props = {
        'description': Edm.String,
        'deviceMode': deviceManagementConfigurationDeviceMode,
        'platform': deviceManagementConfigurationPlatforms,
        'technologies': deviceManagementConfigurationTechnologies,
    }


class deviceManagementConfigurationApplicationSettingApplicability(object):
    props = {

    }


class deviceManagementConfigurationChoiceSettingCollectionInstance(object):
    props = {
        'choiceSettingCollectionValue': Collection,
    }


class deviceManagementConfigurationChoiceSettingValue(object):
    props = {
        'children': Collection,
        'value': Edm.String,
    }


class deviceManagementConfigurationSettingInstanceTemplate(object):
    props = {
        'isRequired': Edm.Boolean,
        'settingDefinitionId': Edm.String,
        'settingInstanceTemplateId': Edm.String,
    }


class deviceManagementConfigurationChoiceSettingCollectionInstanceTemplate(object):
    props = {
        'allowUnmanagedValues': Edm.Boolean,
        'choiceSettingCollectionValueTemplate': Collection,
    }


class deviceManagementConfigurationChoiceSettingInstance(object):
    props = {
        'choiceSettingValue': deviceManagementConfigurationChoiceSettingValue,
    }


class deviceManagementConfigurationChoiceSettingValueDefaultTemplate(object):
    props = {

    }


class deviceManagementConfigurationChoiceSettingValueConstantDefaultTemplate(object):
    props = {
        'children': Collection,
        'settingDefinitionOptionId': Edm.String,
    }


class deviceManagementConfigurationChoiceSettingValueDefinitionTemplate(object):
    props = {
        'allowedOptions': Collection,
    }


class deviceManagementConfigurationOptionDefinitionTemplate(object):
    props = {
        'children': Collection,
        'itemId': Edm.String,
    }


class deviceManagementConfigurationDependentOn(object):
    props = {
        'dependentOn': Edm.String,
        'parentSettingId': Edm.String,
    }


class deviceManagementConfigurationExchangeOnlineSettingApplicability(object):
    props = {

    }


class deviceManagementConfigurationGroupSettingCollectionInstance(object):
    props = {
        'groupSettingCollectionValue': Collection,
    }


class deviceManagementConfigurationGroupSettingValue(object):
    props = {
        'children': Collection,
    }


class deviceManagementConfigurationGroupSettingCollectionInstanceTemplate(object):
    props = {
        'allowUnmanagedValues': Edm.Boolean,
        'groupSettingCollectionValueTemplate': Collection,
    }


class deviceManagementConfigurationGroupSettingValueTemplate(object):
    props = {
        'children': Collection,
        'settingValueTemplateId': Edm.String,
    }


class deviceManagementConfigurationGroupSettingInstance(object):
    props = {
        'groupSettingValue': deviceManagementConfigurationGroupSettingValue,
    }


class deviceManagementConfigurationGroupSettingInstanceTemplate(object):
    props = {
        'groupSettingValueTemplate': deviceManagementConfigurationGroupSettingValueTemplate,
    }


class deviceManagementConfigurationSimpleSettingValue(object):
    props = {

    }


class deviceManagementConfigurationIntegerSettingValue(object):
    props = {
        'value': Edm.Int32,
    }


class deviceManagementConfigurationIntegerSettingValueDefaultTemplate(object):
    props = {

    }


class deviceManagementConfigurationIntegerSettingValueConstantDefaultTemplate(object):
    props = {
        'constantValue': Edm.Int32,
    }


class deviceManagementConfigurationSettingValueDefinition(object):
    props = {

    }


class deviceManagementConfigurationIntegerSettingValueDefinition(object):
    props = {
        'maximumValue': Edm.Int64,
        'minimumValue': Edm.Int64,
    }


class deviceManagementConfigurationIntegerSettingValueDefinitionTemplate(object):
    props = {
        'maxValue': Edm.Int32,
        'minValue': Edm.Int32,
    }


class deviceManagementConfigurationSimpleSettingValueTemplate(object):
    props = {
        'settingValueTemplateId': Edm.String,
    }


class deviceManagementConfigurationIntegerSettingValueTemplate(object):
    props = {
        'defaultValue': deviceManagementConfigurationIntegerSettingValueDefaultTemplate,
        'recommendedValueDefinition': deviceManagementConfigurationIntegerSettingValueDefinitionTemplate,
        'requiredValueDefinition': deviceManagementConfigurationIntegerSettingValueDefinitionTemplate,
    }


class deviceManagementConfigurationSettingDependedOnBy(object):
    props = {
        'dependedOnBy': Edm.String,
        'required': Edm.Boolean,
    }


class deviceManagementConfigurationPolicyTemplateReference(object):
    props = {
        'templateDisplayName': Edm.String,
        'templateDisplayVersion': Edm.String,
        'templateFamily': deviceManagementConfigurationTemplateFamily,
        'templateId': Edm.String,
    }


class deviceManagementConfigurationStringSettingValue(object):
    props = {
        'value': Edm.String,
    }


class deviceManagementConfigurationReferenceSettingValue(object):
    props = {
        'note': Edm.String,
    }


class deviceManagementConfigurationReferredSettingInformation(object):
    props = {
        'settingDefinitionId': Edm.String,
    }


class deviceManagementConfigurationSecretSettingValue(object):
    props = {
        'value': Edm.String,
        'valueState': deviceManagementConfigurationSecretSettingValueState,
    }


class deviceManagementConfigurationSettingGroupCollectionInstance(object):
    props = {

    }


class deviceManagementConfigurationSettingGroupInstance(object):
    props = {

    }


class deviceManagementConfigurationSettingInstanceTemplateReference(object):
    props = {
        'settingInstanceTemplateId': Edm.String,
    }


class deviceManagementConfigurationSettingOccurrence(object):
    props = {
        'maxDeviceOccurrence': Edm.Int32,
        'minDeviceOccurrence': Edm.Int32,
    }


class deviceManagementConfigurationSettingValueTemplateReference(object):
    props = {
        'settingValueTemplateId': Edm.String,
        'useTemplateDefault': Edm.Boolean,
    }


class deviceManagementConfigurationSimpleSettingCollectionInstance(object):
    props = {
        'simpleSettingCollectionValue': Collection,
    }


class deviceManagementConfigurationSimpleSettingCollectionInstanceTemplate(object):
    props = {
        'allowUnmanagedValues': Edm.Boolean,
        'simpleSettingCollectionValueTemplate': Collection,
    }


class deviceManagementConfigurationSimpleSettingInstance(object):
    props = {
        'simpleSettingValue': deviceManagementConfigurationSimpleSettingValue,
    }


class deviceManagementConfigurationSimpleSettingInstanceTemplate(object):
    props = {
        'simpleSettingValueTemplate': deviceManagementConfigurationSimpleSettingValueTemplate,
    }


class deviceManagementConfigurationStringSettingValueDefaultTemplate(object):
    props = {

    }


class deviceManagementConfigurationStringSettingValueConstantDefaultTemplate(object):
    props = {
        'constantValue': Edm.String,
    }


class deviceManagementConfigurationStringSettingValueDefinition(object):
    props = {
        'fileTypes': Collection,
        'format': deviceManagementConfigurationStringFormat,
        'inputValidationSchema': Edm.String,
        'isSecret': Edm.Boolean,
        'maximumLength': Edm.Int64,
        'minimumLength': Edm.Int64,
    }


class deviceManagementConfigurationStringSettingValueTemplate(object):
    props = {
        'defaultValue': deviceManagementConfigurationStringSettingValueDefaultTemplate,
    }


class deviceManagementConfigurationWindowsSettingApplicability(object):
    props = {
        'configurationServiceProviderVersion': Edm.String,
        'maximumSupportedVersion': Edm.String,
        'minimumSupportedVersion': Edm.String,
        'requiredAzureAdTrustType': deviceManagementConfigurationAzureAdTrustType,
        'requiresAzureAd': Edm.Boolean,
        'windowsSkus': Collection,
    }


class deviceManagementPriorityMetaData(object):
    props = {
        'priority': Edm.Int32,
    }


class companyPortalBlockedAction(object):
    props = {
        'action': companyPortalAction,
        'ownerType': ownerType,
        'platform': devicePlatformType,
    }


class complianceManagementPartnerAssignment(object):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }


class deviceAndAppManagementData(object):
    props = {
        'content': Edm.Stream,
    }


class deviceEnrollmentPlatformRestriction(object):
    props = {
        'blockedManufacturers': Collection,
        'blockedSkus': Collection,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'personalDeviceEnrollmentBlocked': Edm.Boolean,
        'platformBlocked': Edm.Boolean,
    }


class deviceManagementExchangeDeviceClass(object):
    props = {
        'name': Edm.String,
        'type': deviceManagementExchangeAccessRuleType,
    }


class deviceManagementPartnerAssignment(object):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }


class rgbColor(object):
    props = {
        'b': Edm.Byte,
        'g': Edm.Byte,
        'r': Edm.Byte,
    }


class vppTokenActionResult(object):
    props = {
        'actionName': Edm.String,
        'actionState': actionState,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
    }


class vppTokenLicenseSummary(object):
    props = {
        'appleId': Edm.String,
        'availableLicenseCount': Edm.Int32,
        'organizationName': Edm.String,
        'usedLicenseCount': Edm.Int32,
        'vppTokenId': Edm.String,
    }


class vppTokenRevokeLicensesActionResult(object):
    props = {
        'actionFailureReason': vppTokenActionFailureReason,
        'failedLicensesCount': Edm.Int32,
        'totalLicensesCount': Edm.Int32,
    }


class deviceManagementConstraint(object):
    props = {

    }


class deviceManagementEnumConstraint(object):
    props = {
        'values': Collection,
    }


class deviceManagementEnumValue(object):
    props = {
        'displayName': Edm.String,
        'value': Edm.String,
    }


class deviceManagementIntentCustomizedSetting(object):
    props = {
        'customizedJson': Edm.String,
        'defaultJson': Edm.String,
        'definitionId': Edm.String,
    }


class deviceManagementIntentSettingSecretConstraint(object):
    props = {

    }


class deviceManagementSettingAbstractImplementationConstraint(object):
    props = {
        'allowedAbstractImplementationDefinitionIds': Collection,
    }


class deviceManagementSettingAppConstraint(object):
    props = {
        'supportedTypes': Collection,
    }


class deviceManagementSettingBooleanConstraint(object):
    props = {
        'value': Edm.Boolean,
    }


class deviceManagementSettingCollectionConstraint(object):
    props = {
        'maximumLength': Edm.Int32,
        'minimumLength': Edm.Int32,
    }


class deviceManagementSettingComparison(object):
    props = {
        'comparisonResult': deviceManagementComparisonResult,
        'currentValueJson': Edm.String,
        'definitionId': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
        'newValueJson': Edm.String,
    }


class deviceManagementSettingDependency(object):
    props = {
        'constraints': Collection,
        'definitionId': Edm.String,
    }


class deviceManagementSettingEnrollmentTypeConstraint(object):
    props = {
        'enrollmentTypes': Collection,
    }


class deviceManagementSettingFileConstraint(object):
    props = {
        'supportedExtensions': Collection,
    }


class deviceManagementSettingIntegerConstraint(object):
    props = {
        'maximumValue': Edm.Int32,
        'minimumValue': Edm.Int32,
    }


class deviceManagementSettingProfileConstraint(object):
    props = {
        'source': Edm.String,
        'types': Collection,
    }


class deviceManagementSettingRegexConstraint(object):
    props = {
        'regex': Edm.String,
    }


class deviceManagementSettingRequiredConstraint(object):
    props = {
        'notConfiguredValue': Edm.String,
    }


class deviceManagementSettingSddlConstraint(object):
    props = {

    }


class deviceManagementSettingStringLengthConstraint(object):
    props = {
        'maximumLength': Edm.Int32,
        'minimumLength': Edm.Int32,
    }


class deviceManagementSettingXmlConstraint(object):
    props = {

    }


class securityBaselineContributingPolicy(object):
    props = {
        'displayName': Edm.String,
        'sourceId': Edm.String,
        'sourceType': securityBaselinePolicySourceType,
    }


class activateDeviceEsimActionResult(object):
    props = {
        'carrierUrl': Edm.String,
    }


class appLogCollectionDownloadDetails(object):
    props = {
        'appLogDecryptionAlgorithm': appLogDecryptionAlgorithm,
        'decryptionKey': Edm.String,
        'downloadUrl': Edm.String,
    }


class bulkManagedDeviceActionResult(object):
    props = {
        'failedDeviceIds': Collection,
        'notFoundDeviceIds': Collection,
        'notSupportedDeviceIds': Collection,
        'successfulDeviceIds': Collection,
    }


class changeAssignmentsActionResult(object):
    props = {
        'deviceAssignmentItems': Collection,
    }


class deviceAssignmentItem(object):
    props = {
        'assignmentItemActionIntent': deviceAssignmentItemIntent,
        'assignmentItemActionStatus': deviceAssignmentItemStatus,
        'errorCode': Edm.Int64,
        'intentActionMessage': Edm.String,
        'itemDisplayName': Edm.String,
        'itemId': Edm.String,
        'itemSubTypeDisplayName': Edm.String,
        'itemType': deviceAssignmentItemType,
        'lastActionDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class comanagedDevicesSummary(object):
    props = {
        'compliancePolicyCount': Edm.Int32,
        'configurationSettingsCount': Edm.Int32,
        'endpointProtectionCount': Edm.Int32,
        'inventoryCount': Edm.Int32,
        'modernAppsCount': Edm.Int32,
        'officeAppsCount': Edm.Int32,
        'resourceAccessCount': Edm.Int32,
        'totalComanagedCount': Edm.Int32,
        'windowsUpdateForBusinessCount': Edm.Int32,
    }


class comanagementEligibleDevicesSummary(object):
    props = {
        'comanagedCount': Edm.Int32,
        'eligibleButNotAzureAdJoinedCount': Edm.Int32,
        'eligibleCount': Edm.Int32,
        'ineligibleCount': Edm.Int32,
        'needsOsUpdateCount': Edm.Int32,
        'scheduledForEnrollmentCount': Edm.Int32,
    }


class configurationManagerAction(object):
    props = {
        'action': configurationManagerActionType,
    }


class configurationManagerActionResult(object):
    props = {
        'actionDeliveryStatus': configurationManagerActionDeliveryStatus,
        'errorCode': Edm.Int32,
    }


class deleteUserFromSharedAppleDeviceActionResult(object):
    props = {
        'userPrincipalName': Edm.String,
    }


class deviceExchangeAccessStateSummary(object):
    props = {
        'allowedDeviceCount': Edm.Int32,
        'blockedDeviceCount': Edm.Int32,
        'quarantinedDeviceCount': Edm.Int32,
        'unavailableDeviceCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
    }


class deviceGeoLocation(object):
    props = {
        'altitude': Edm.Double,
        'heading': Edm.Double,
        'horizontalAccuracy': Edm.Double,
        'lastCollectedDateTime': Edm.DateTimeOffset,
        'latitude': Edm.Double,
        'longitude': Edm.Double,
        'speed': Edm.Double,
        'verticalAccuracy': Edm.Double,
    }


class deviceHealthScriptParameter(object):
    props = {
        'applyDefaultValueWhenNotAssigned': Edm.Boolean,
        'description': Edm.String,
        'isRequired': Edm.Boolean,
        'name': Edm.String,
    }


class deviceHealthScriptBooleanParameter(object):
    props = {
        'defaultValue': Edm.Boolean,
    }


class deviceHealthScriptRunSchedule(object):
    props = {
        'interval': Edm.Int32,
    }


class deviceHealthScriptTimeSchedule(object):
    props = {
        'time': Edm.TimeOfDay,
        'useUtc': Edm.Boolean,
    }


class deviceHealthScriptDailySchedule(object):
    props = {

    }


class deviceHealthScriptHourlySchedule(object):
    props = {

    }


class deviceHealthScriptIntegerParameter(object):
    props = {
        'defaultValue': Edm.Int32,
    }


class deviceHealthScriptRemediationHistory(object):
    props = {
        'historyData': Collection,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class deviceHealthScriptRemediationHistoryData(object):
    props = {
        'date': Edm.Date,
        'detectFailedDeviceCount': Edm.Int32,
        'noIssueDeviceCount': Edm.Int32,
        'remediatedDeviceCount': Edm.Int32,
    }


class deviceHealthScriptRemediationSummary(object):
    props = {
        'remediatedDeviceCount': Edm.Int32,
        'scriptCount': Edm.Int32,
    }


class deviceHealthScriptRunOnceSchedule(object):
    props = {
        'date': Edm.Date,
    }


class deviceHealthScriptStringParameter(object):
    props = {
        'defaultValue': Edm.String,
    }


class deviceIdentityAttestationDetail(object):
    props = {

    }


class deviceLogCollectionRequest(object):
    props = {
        'id': Edm.String,
        'templateType': deviceLogCollectionTemplateType,
    }


class deviceOperatingSystemSummary(object):
    props = {
        'androidCorporateWorkProfileCount': Edm.Int32,
        'androidCount': Edm.Int32,
        'androidDedicatedCount': Edm.Int32,
        'androidDeviceAdminCount': Edm.Int32,
        'androidFullyManagedCount': Edm.Int32,
        'androidWorkProfileCount': Edm.Int32,
        'aospUserAssociatedCount': Edm.Int32,
        'aospUserlessCount': Edm.Int32,
        'chromeOSCount': Edm.Int32,
        'configMgrDeviceCount': Edm.Int32,
        'iosCount': Edm.Int32,
        'linuxCount': Edm.Int32,
        'macOSCount': Edm.Int32,
        'unknownCount': Edm.Int32,
        'windowsCount': Edm.Int32,
        'windowsMobileCount': Edm.Int32,
    }


class deviceScopeActionResult(object):
    props = {
        'deviceScopeAction': deviceScopeAction,
        'deviceScopeId': Edm.String,
        'failedMessage': Edm.String,
        'status': deviceScopeActionStatus,
    }


class sharedAppleDeviceUser(object):
    props = {
        'dataQuota': Edm.Int64,
        'dataToSync': Edm.Boolean,
        'dataUsed': Edm.Int64,
        'userPrincipalName': Edm.String,
    }


class userExperienceAnalyticsInsightValue(object):
    props = {

    }


class insightValueDouble(object):
    props = {
        'value': Edm.Double,
    }


class insightValueInt(object):
    props = {
        'value': Edm.Int32,
    }


class locateDeviceActionResult(object):
    props = {
        'deviceLocation': deviceGeoLocation,
    }


class managedDeviceModelsAndManufacturers(object):
    props = {
        'deviceManufacturers': Collection,
        'deviceModels': Collection,
    }


class osVersionCount(object):
    props = {
        'deviceCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'osVersion': Edm.String,
    }


class powerliftAppDiagnosticDownloadRequest(object):
    props = {
        'files': Collection,
        'powerliftId': Edm.String,
    }


class powerliftDownloadRequest(object):
    props = {
        'files': Collection,
        'powerliftId': Edm.Guid,
    }


class powerliftIncidentDetail(object):
    props = {
        'applicationName': Edm.String,
        'clientApplicationVersion': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'easyId': Edm.String,
        'fileNames': Collection,
        'locale': Edm.String,
        'platformDisplayName': Edm.String,
        'powerliftId': Edm.String,
    }


class powerliftIncidentMetadata(object):
    props = {
        'application': Edm.String,
        'clientVersion': Edm.String,
        'createdAtDateTime': Edm.DateTimeOffset,
        'easyId': Edm.String,
        'fileNames': Collection,
        'locale': Edm.String,
        'platform': Edm.String,
        'powerliftId': Edm.Guid,
    }


class remoteLockActionResult(object):
    props = {
        'unlockPin': Edm.String,
    }


class resetPasscodeActionResult(object):
    props = {
        'errorCode': Edm.Int32,
        'passcode': Edm.String,
    }


class revokeAppleVppLicensesActionResult(object):
    props = {
        'failedLicensesCount': Edm.Int32,
        'totalLicensesCount': Edm.Int32,
    }


class rotateBitLockerKeysDeviceActionResult(object):
    props = {
        'errorCode': Edm.Int32,
    }


class tenantAttachRBACState(object):
    props = {
        'enabled': Edm.Boolean,
    }


class windowsDeviceAccount(object):
    props = {
        'password': Edm.String,
    }


class userExperienceAnalyticsAnomalyCorrelationGroupFeature(object):
    props = {
        'deviceFeatureType': userExperienceAnalyticsAnomalyDeviceFeatureType,
        'values': Collection,
    }


class userExperienceAnalyticsAutopilotDevicesSummary(object):
    props = {
        'devicesNotAutopilotRegistered': Edm.Int32,
        'devicesWithoutAutopilotProfileAssigned': Edm.Int32,
        'totalWindows10DevicesWithoutTenantAttached': Edm.Int32,
    }


class userExperienceAnalyticsCloudIdentityDevicesSummary(object):
    props = {
        'deviceWithoutCloudIdentityCount': Edm.Int32,
    }


class userExperienceAnalyticsCloudManagementDevicesSummary(object):
    props = {
        'coManagedDeviceCount': Edm.Int32,
        'intuneDeviceCount': Edm.Int32,
        'tenantAttachDeviceCount': Edm.Int32,
    }


class userExperienceAnalyticsDeviceBatteryDetail(object):
    props = {
        'batteryId': Edm.String,
        'fullBatteryDrainCount': Edm.Int32,
        'maxCapacityPercentage': Edm.Int32,
    }


class userExperienceAnalyticsDeviceScopeSummary(object):
    props = {
        'completedDeviceScopeIds': Collection,
        'insufficientDataDeviceScopeIds': Collection,
        'totalDeviceScopes': Edm.Int32,
        'totalDeviceScopesEnabled': Edm.Int32,
    }


class userExperienceAnalyticsInsight(object):
    props = {
        'insightId': Edm.String,
        'severity': userExperienceAnalyticsInsightSeverity,
        'userExperienceAnalyticsMetricId': Edm.String,
        'values': Collection,
    }


class userExperienceAnalyticsWindows10DevicesSummary(object):
    props = {
        'unsupportedOSversionDeviceCount': Edm.Int32,
    }


class userExperienceAnalyticsWorkFromAnywhereDevicesSummary(object):
    props = {
        'autopilotDevicesSummary': userExperienceAnalyticsAutopilotDevicesSummary,
        'cloudIdentityDevicesSummary': userExperienceAnalyticsCloudIdentityDevicesSummary,
        'cloudManagementDevicesSummary': userExperienceAnalyticsCloudManagementDevicesSummary,
        'coManagedDevices': Edm.Int32,
        'devicesNotAutopilotRegistered': Edm.Int32,
        'devicesWithoutAutopilotProfileAssigned': Edm.Int32,
        'devicesWithoutCloudIdentity': Edm.Int32,
        'intuneDevices': Edm.Int32,
        'tenantAttachDevices': Edm.Int32,
        'totalDevices': Edm.Int32,
        'unsupportedOSversionDevices': Edm.Int32,
        'windows10Devices': Edm.Int32,
        'windows10DevicesSummary': userExperienceAnalyticsWindows10DevicesSummary,
        'windows10DevicesWithoutTenantAttach': Edm.Int32,
    }


class windowsDefenderScanActionResult(object):
    props = {
        'scanType': Edm.String,
    }


class windowsDeviceADAccount(object):
    props = {
        'domainName': Edm.String,
        'userName': Edm.String,
    }


class windowsDeviceAzureADAccount(object):
    props = {
        'userPrincipalName': Edm.String,
    }


class windowsMalwareCategoryCount(object):
    props = {
        'activeMalwareDetectionCount': Edm.Int32,
        'category': windowsMalwareCategory,
        'deviceCount': Edm.Int32,
        'distinctActiveMalwareCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
    }


class windowsMalwareExecutionStateCount(object):
    props = {
        'deviceCount': Edm.Int32,
        'executionState': windowsMalwareExecutionState,
        'lastUpdateDateTime': Edm.DateTimeOffset,
    }


class windowsMalwareNameCount(object):
    props = {
        'deviceCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'malwareIdentifier': Edm.String,
        'name': Edm.String,
    }


class windowsMalwareSeverityCount(object):
    props = {
        'distinctMalwareCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'malwareDetectionCount': Edm.Int32,
        'severity': windowsMalwareSeverity,
    }


class windowsMalwareStateCount(object):
    props = {
        'deviceCount': Edm.Int32,
        'distinctMalwareCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'malwareDetectionCount': Edm.Int32,
        'state': windowsMalwareThreatState,
    }


class windows10XCustomSubjectAlternativeName(object):
    props = {
        'name': Edm.String,
        'sanType': subjectAlternativeNameType,
    }


class appleOwnerTypeEnrollmentType(object):
    props = {
        'enrollmentType': appleUserInitiatedEnrollmentType,
        'ownerType': managedDeviceOwnerType,
    }


class importedWindowsAutopilotDeviceIdentityState(object):
    props = {
        'deviceErrorCode': Edm.Int32,
        'deviceErrorName': Edm.String,
        'deviceImportStatus': importedWindowsAutopilotDeviceIdentityImportStatus,
        'deviceRegistrationId': Edm.String,
    }


class managementCertificateWithThumbprint(object):
    props = {
        'certificate': Edm.String,
        'thumbprint': Edm.String,
    }


class suggestedEnrollmentLimit(object):
    props = {
        'suggestedDailyLimit': Edm.Int32,
    }


class elevationRequestApplicationDetail(object):
    props = {
        'fileDescription': Edm.String,
        'fileHash': Edm.String,
        'fileName': Edm.String,
        'filePath': Edm.String,
        'productInternalName': Edm.String,
        'productName': Edm.String,
        'productVersion': Edm.String,
        'publisherCert': Edm.String,
        'publisherName': Edm.String,
    }


class groupPolicyPresentationDropdownListItem(object):
    props = {
        'displayName': Edm.String,
        'value': Edm.String,
    }


class groupPolicyUploadedLanguageFile(object):
    props = {
        'content': Edm.Binary,
        'fileName': Edm.String,
        'id': Edm.String,
        'languageCode': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class serviceNowAuthenticationMethod(object):
    props = {

    }


class serviceNowOauthSecretAuthentication(object):
    props = {
        'appId': Edm.String,
    }


class mobileAppIdentifier(object):
    props = {

    }


class androidMobileAppIdentifier(object):
    props = {
        'packageId': Edm.String,
    }


class iosMobileAppIdentifier(object):
    props = {
        'bundleId': Edm.String,
    }


class macAppIdentifier(object):
    props = {
        'bundleId': Edm.String,
    }


class managedAppDiagnosticStatus(object):
    props = {
        'mitigationInstruction': Edm.String,
        'state': Edm.String,
        'validationName': Edm.String,
    }


class managedAppLogUpload(object):
    props = {
        'managedAppComponent': Edm.String,
        'managedAppComponentDescription': Edm.String,
        'referenceId': Edm.String,
        'status': managedAppLogUploadState,
    }


class managedAppPolicyDeploymentSummaryPerApp(object):
    props = {
        'configurationAppliedUserCount': Edm.Int32,
        'mobileAppIdentifier': mobileAppIdentifier,
    }


class windowsAppIdentifier(object):
    props = {
        'windowsAppId': Edm.String,
    }


class windowsInformationProtectionApp(object):
    props = {
        'denied': Edm.Boolean,
        'description': Edm.String,
        'displayName': Edm.String,
        'productName': Edm.String,
        'publisherName': Edm.String,
    }


class windowsInformationProtectionDataRecoveryCertificate(object):
    props = {
        'certificate': Edm.Binary,
        'description': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'subjectName': Edm.String,
    }


class windowsInformationProtectionDesktopApp(object):
    props = {
        'binaryName': Edm.String,
        'binaryVersionHigh': Edm.String,
        'binaryVersionLow': Edm.String,
    }


class windowsInformationProtectionIPRangeCollection(object):
    props = {
        'displayName': Edm.String,
        'ranges': Collection,
    }


class windowsInformationProtectionProxiedDomainCollection(object):
    props = {
        'displayName': Edm.String,
        'proxiedDomains': Collection,
    }


class windowsInformationProtectionResourceCollection(object):
    props = {
        'displayName': Edm.String,
        'resources': Collection,
    }


class windowsInformationProtectionStoreApp(object):
    props = {

    }


class keyLongValuePair(object):
    props = {
        'name': Edm.String,
        'value': Edm.Int64,
    }


class metricTimeSeriesDataPoint(object):
    props = {
        'dateTime': Edm.DateTimeOffset,
        'value': Edm.Int64,
    }


class managedDeviceWindowsOperatingSystemEdition(object):
    props = {
        'editionType': managedDeviceWindowsOperatingSystemEditionType,
        'supportEndDate': Edm.Date,
    }


class managedDeviceWindowsOperatingSystemUpdate(object):
    props = {
        'buildVersion': Edm.String,
        'releaseMonth': Edm.Int32,
        'releaseYear': Edm.Int32,
    }


class configManagerPolicySummary(object):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'enforcedDeviceCount': Edm.Int32,
        'failedDeviceCount': Edm.Int32,
        'nonCompliantDeviceCount': Edm.Int32,
        'pendingDeviceCount': Edm.Int32,
        'targetedDeviceCount': Edm.Int32,
    }


class unmanagedDevice(object):
    props = {
        'deviceName': Edm.String,
        'domain': Edm.String,
        'ipAddress': Edm.String,
        'lastLoggedOnUser': Edm.String,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'location': Edm.String,
        'macAddress': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'os': Edm.String,
        'osVersion': Edm.String,
    }


class deviceAndAppManagementAssignedRoleDefinition(object):
    props = {
        'permissions': Collection,
        'roleDefinitionDisplayName': Edm.String,
    }


class deviceAndAppManagementAssignedRoleDetail(object):
    props = {
        'permissions': Collection,
        'roleDefinitions': Collection,
    }


class deviceAndAppManagementAssignedRoleDetails(object):
    props = {
        'roleAssignmentIds': Collection,
        'roleDefinitionIds': Collection,
    }


class operationApprovalPolicySet(object):
    props = {
        'policyPlatform': operationApprovalPolicyPlatform,
        'policyType': operationApprovalPolicyType,
    }


class operationApprovalRequestEntityStatus(object):
    props = {
        'entityLocked': Edm.Boolean,
        'requestExpirationDateTime': Edm.DateTimeOffset,
        'requestId': Edm.String,
        'requestStatus': operationApprovalRequestStatus,
    }


class resourceAction(object):
    props = {
        'allowedResourceActions': Collection,
        'notAllowedResourceActions': Collection,
    }


class rolePermission(object):
    props = {
        'actions': Collection,
        'resourceActions': Collection,
    }


class createRemoteHelpSessionResponse(object):
    props = {
        'sessionKey': Edm.String,
    }


class extendRemoteHelpSessionResponse(object):
    props = {
        'acsHelperUserToken': Edm.String,
        'pubSubHelperAccessUri': Edm.String,
        'sessionExpirationDateTime': Edm.DateTimeOffset,
        'sessionKey': Edm.String,
    }


class requestRemoteHelpSessionAccessResponse(object):
    props = {
        'pubSubEncryption': Edm.String,
        'pubSubEncryptionKey': Edm.String,
        'sessionKey': Edm.String,
    }


class retrieveRemoteHelpSessionResponse(object):
    props = {
        'acsGroupId': Edm.String,
        'acsHelperUserId': Edm.String,
        'acsHelperUserToken': Edm.String,
        'acsSharerUserId': Edm.String,
        'deviceName': Edm.String,
        'pubSubGroupId': Edm.String,
        'pubSubHelperAccessUri': Edm.String,
        'sessionExpirationDateTime': Edm.DateTimeOffset,
        'sessionKey': Edm.String,
    }


class embeddedSIMActivationCode(object):
    props = {
        'integratedCircuitCardIdentifier': Edm.String,
        'matchingIdentifier': Edm.String,
        'smdpPlusServerAddress': Edm.String,
    }


class deviceManagementTroubleshootingErrorDetails(object):
    props = {
        'context': Edm.String,
        'failure': Edm.String,
        'failureDetails': Edm.String,
        'remediation': Edm.String,
        'resources': Collection,
    }


class deviceManagementTroubleshootingErrorResource(object):
    props = {
        'link': Edm.String,
        'text': Edm.String,
    }


class managedDeviceSummarizedAppState(object):
    props = {
        'deviceId': Edm.String,
        'summarizedAppState': deviceManagementScriptRunState,
    }


class mobileAppIntentAndStateDetail(object):
    props = {
        'applicationId': Edm.String,
        'displayName': Edm.String,
        'displayVersion': Edm.String,
        'installState': resultantAppState,
        'mobileAppIntent': mobileAppIntent,
        'supportedDeviceTypes': Collection,
    }


class mobileAppSupportedDeviceType(object):
    props = {
        'maximumOperatingSystemVersion': Edm.String,
        'minimumOperatingSystemVersion': Edm.String,
        'type': deviceType,
    }


class mobileAppTroubleshootingAppPolicyCreationHistory(object):
    props = {
        'errorCode': Edm.String,
        'runState': runState,
    }


class mobileAppTroubleshootingAppStateHistory(object):
    props = {
        'actionType': mobileAppActionType,
        'errorCode': Edm.String,
        'runState': runState,
    }


class mobileAppTroubleshootingAppTargetHistory(object):
    props = {
        'errorCode': Edm.String,
        'runState': runState,
        'securityGroupId': Edm.String,
    }


class mobileAppTroubleshootingAppUpdateHistory(object):
    props = {

    }


class mobileAppTroubleshootingDeviceCheckinHistory(object):
    props = {

    }


class bulkDriverActionResult(object):
    props = {
        'failedDriverIds': Collection,
        'notFoundDriverIds': Collection,
        'successfulDriverIds': Collection,
    }


class expeditedWindowsQualityUpdateSettings(object):
    props = {
        'daysUntilForcedReboot': Edm.Int32,
        'qualityUpdateRelease': Edm.String,
    }


class iosAvailableUpdateVersion(object):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'postingDateTime': Edm.DateTimeOffset,
        'productVersion': Edm.String,
        'supportedDevices': Collection,
    }


class windowsDriverUpdateProfileInventorySyncStatus(object):
    props = {
        'driverInventorySyncState': windowsDriverUpdateProfileInventorySyncState,
        'lastSuccessfulSyncDateTime': Edm.DateTimeOffset,
    }


class windowsQualityUpdateProductKnowledgeBaseArticle(object):
    props = {
        'articleId': Edm.String,
        'articleUrl': Edm.String,
    }


class windowsQualityUpdateProductBuildVersionDetail(object):
    props = {
        'buildNumber': Edm.Int32,
        'majorVersionNumber': Edm.Int32,
        'minorVersionNumber': Edm.Int32,
        'updateBuildRevision': Edm.Int32,
    }


class windowsUpdateRolloutSettings(object):
    props = {
        'offerEndDateTimeInUTC': Edm.DateTimeOffset,
        'offerIntervalInDays': Edm.Int32,
        'offerStartDateTimeInUTC': Edm.DateTimeOffset,
    }


class certificateConnectorHealthMetricValue(object):
    props = {
        'dateTime': Edm.DateTimeOffset,
        'failureCount': Edm.Int64,
        'successCount': Edm.Int64,
    }


class timeSeriesParameter(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'metricName': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
    }


class serviceActivityPerformanceMetric(object):
    props = {
        'intervalStartDateTime': Edm.DateTimeOffset,
        'percentage': Edm.Double,
    }


class appsInstallationOptionsForMac(object):
    props = {
        'isMicrosoft365AppsEnabled': Edm.Boolean,
        'isSkypeForBusinessEnabled': Edm.Boolean,
    }


class appsInstallationOptionsForWindows(object):
    props = {
        'isMicrosoft365AppsEnabled': Edm.Boolean,
        'isProjectEnabled': Edm.Boolean,
        'isSkypeForBusinessEnabled': Edm.Boolean,
        'isVisioEnabled': Edm.Boolean,
    }


class serviceHealthIssuePost(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': itemBody,
        'postType': postType,
    }


class serviceUpdateMessageViewpoint(object):
    props = {
        'isArchived': Edm.Boolean,
        'isFavorited': Edm.Boolean,
        'isRead': Edm.Boolean,
    }


class stringDictionary(object):
    props = {

    }


class entitlementsDataCollectionInfo(object):
    props = {

    }


class entitlementsDataCollection(object):
    props = {
        'lastCollectionDateTime': Edm.DateTimeOffset,
        'permissionsModificationCapability': permissionsModificationCapability,
        'status': dataCollectionStatus,
    }


class noEntitlementsDataCollection(object):
    props = {

    }


class awsAssociatedIdentities(object):
    props = {

    }


class azureAssociatedIdentities(object):
    props = {

    }


class gcpAssociatedIdentities(object):
    props = {

    }


class authorizationSystemIdentitySource(object):
    props = {
        'identityProviderType': Edm.String,
    }


class aadSource(object):
    props = {
        'domain': Edm.String,
    }


class awsSource(object):
    props = {
        'accountId': Edm.String,
    }


class azureSource(object):
    props = {
        'subscriptionId': Edm.String,
    }


class gcpScope(object):
    props = {
        'resourceType': Edm.String,
    }


class gsuiteSource(object):
    props = {
        'domain': Edm.String,
    }


class unknownSource(object):
    props = {

    }


class accountsWithAccess(object):
    props = {

    }


class actionSummary(object):
    props = {
        'assigned': Edm.Int32,
        'available': Edm.Int32,
        'exercised': Edm.Int32,
    }


class allAccountsWithAccess(object):
    props = {

    }


class inboundPorts(object):
    props = {

    }


class allInboundPorts(object):
    props = {

    }


class authorizationSystemInfo(object):
    props = {
        'authorizationSystemType': authorizationSystemType,
        'displayName': Edm.String,
        'id': Edm.String,
    }


class awsAccessKeyDetails(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastUsedDateTime': Edm.DateTimeOffset,
    }


class enumeratedAccountsWithAccess(object):
    props = {

    }


class enumeratedInboundPorts(object):
    props = {
        'ports': Collection,
    }


class identityDetails(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastActiveDateTime': Edm.DateTimeOffset,
    }


class permissionsAnalyticsAggregatedIamKeySummary(object):
    props = {
        'findingsCountOverLimit': Edm.Int32,
        'totalCount': Edm.Int32,
    }


class permissionsAnalyticsAggregatedIdentitySummary(object):
    props = {
        'findingsCount': Edm.Int32,
        'totalCount': Edm.Int32,
    }


class permissionsAnalyticsAggregatedResourceSummary(object):
    props = {
        'findingsCount': Edm.Int32,
        'totalCount': Edm.Int32,
    }


class permissionsCreepIndex(object):
    props = {
        'score': Edm.Int32,
    }


class riskProfile(object):
    props = {
        'humanCount': Edm.Int32,
        'nonHumanCount': Edm.Int32,
    }


class permissionsDefinitionAction(object):
    props = {

    }


class awsPermissionsDefinitionAction(object):
    props = {

    }


class awsActionsPermissionsDefinitionAction(object):
    props = {
        'assignToRoleId': Edm.String,
    }


class awsCondition(object):
    props = {

    }


class permissionsDefinitionIdentitySource(object):
    props = {

    }


class permissionsDefinitionAuthorizationSystem(object):
    props = {
        'authorizationSystemId': Edm.String,
        'authorizationSystemType': Edm.String,
    }


class permissionsDefinition(object):
    props = {
        'authorizationSystemInfo': permissionsDefinitionAuthorizationSystem,
    }


class awsPermissionsDefinition(object):
    props = {
        'actionInfo': awsPermissionsDefinitionAction,
    }


class awsPolicyPermissionsDefinitionAction(object):
    props = {
        'assignToRoleId': Edm.String,
    }


class azurePermissionsDefinitionAction(object):
    props = {

    }


class azureActionPermissionsDefinitionAction(object):
    props = {
        'actions': Collection,
    }


class azureRolePermissionsDefinitionAction(object):
    props = {

    }


class edIdentitySource(object):
    props = {

    }


class gcpPermissionsDefinitionAction(object):
    props = {

    }


class gcpActionPermissionsDefinitionAction(object):
    props = {
        'actions': Collection,
    }


class gcpRolePermissionsDefinitionAction(object):
    props = {

    }


class localIdentitySource(object):
    props = {

    }


class samlIdentitySource(object):
    props = {

    }


class singleResourceAzurePermissionsDefinition(object):
    props = {
        'actionInfo': azurePermissionsDefinitionAction,
        'resourceId': Edm.String,
    }


class singleResourceGcpPermissionsDefinition(object):
    props = {
        'actionInfo': gcpPermissionsDefinitionAction,
        'resourceId': Edm.String,
    }


class ticketInfo(object):
    props = {
        'ticketApproverIdentityId': Edm.String,
        'ticketNumber': Edm.String,
        'ticketSubmitterIdentityId': Edm.String,
        'ticketSystem': Edm.String,
    }


class dictionaries(object):
    props = {

    }


class bucketAggregationDefinition(object):
    props = {
        'isDescending': Edm.Boolean,
        'minimumCount': Edm.Int32,
        'prefixFilter': Edm.String,
        'ranges': Collection,
        'sortBy': bucketAggregationSortProperty,
    }


class searchAlteration(object):
    props = {
        'alteredHighlightedQueryString': Edm.String,
        'alteredQueryString': Edm.String,
        'alteredQueryTokens': Collection,
    }


class alteredQueryToken(object):
    props = {
        'length': Edm.Int32,
        'offset': Edm.Int32,
        'suggestion': Edm.String,
    }


class bucketAggregationRange(object):
    props = {
        'from': Edm.String,
        'to': Edm.String,
    }


class collapseProperty(object):
    props = {
        'fields': Collection,
        'limit': Edm.Int16,
    }


class searchResourceMetadataDictionary(object):
    props = {

    }


class searchSensitivityLabelInfo(object):
    props = {
        'color': Edm.String,
        'displayName': Edm.String,
        'priority': Edm.Int32,
        'sensitivityLabelId': Edm.String,
        'tooltip': Edm.String,
    }


class resultTemplate(object):
    props = {
        'body': Json,
        'displayName': Edm.String,
    }


class resultTemplateDictionary(object):
    props = {

    }


class resultTemplateOption(object):
    props = {
        'enableResultTemplate': Edm.Boolean,
    }


class retrievalResponse(object):
    props = {
        'extract': Edm.String,
        'resourceMetadata': searchResourceMetadataDictionary,
        'resourceType': groundingEntityType,
        'webUrl': Edm.String,
    }


class searchAggregation(object):
    props = {
        'buckets': Collection,
        'field': Edm.String,
    }


class searchBucket(object):
    props = {
        'aggregationFilterToken': Edm.String,
        'count': Edm.Int32,
        'key': Edm.String,
    }


class searchAlterationOptions(object):
    props = {
        'enableModification': Edm.Boolean,
        'enableSuggestion': Edm.Boolean,
    }


class searchHit(object):
    props = {
        'contentSource': Edm.String,
        'hitId': Edm.String,
        'isCollapsed': Edm.Boolean,
        'rank': Edm.Int32,
        'resultTemplateId': Edm.String,
        'summary': Edm.String,
        '_id': Edm.String,
        '_score': Edm.Int32,
        '_summary': Edm.String,
    }


class searchHitsContainer(object):
    props = {
        'aggregations': Collection,
        'hits': Collection,
        'moreResultsAvailable': Edm.Boolean,
        'total': Edm.Int32,
    }


class sharePointOneDriveOptions(object):
    props = {
        'includeContent': searchContent,
    }


class sortProperty(object):
    props = {
        'isDescending': Edm.Boolean,
        'name': Edm.String,
    }


class dateTimeTimeZoneType(object):
    props = {
        'dateTime': Edm.String,
    }


class postalAddressType(object):
    props = {
        'city': Edm.String,
        'countryLetterCode': Edm.String,
        'postalCode': Edm.String,
        'state': Edm.String,
        'street': Edm.String,
    }


class visualProperties(object):
    props = {
        'body': Edm.String,
        'title': Edm.String,
    }


class targetPolicyEndpoints(object):
    props = {
        'platformTypes': Collection,
    }


class plannerAppliedCategories(object):
    props = {

    }


class plannerApprovalRequirement(object):
    props = {
        'isApprovalRequired': Edm.Boolean,
    }


class plannerArchivalInfo(object):
    props = {
        'justification': Edm.String,
        'statusChangedBy': identitySet,
        'statusChangedDateTime': Edm.DateTimeOffset,
    }


class plannerAssignment(object):
    props = {
        'assignedBy': identitySet,
        'assignedDateTime': Edm.DateTimeOffset,
        'orderHint': Edm.String,
    }


class plannerAssignments(object):
    props = {

    }


class plannerBaseApprovalAttachment(object):
    props = {
        'status': plannerApprovalStatus,
    }


class plannerBasicApprovalAttachment(object):
    props = {
        'approvalId': Edm.String,
    }


class plannerBucketCreation(object):
    props = {
        'creationSourceKind': plannerCreationSourceKind,
    }


class plannerBucketPropertyRule(object):
    props = {
        'order': Collection,
        'title': Collection,
    }


class plannerCategoryDescriptions(object):
    props = {
        'category1': Edm.String,
        'category10': Edm.String,
        'category11': Edm.String,
        'category12': Edm.String,
        'category13': Edm.String,
        'category14': Edm.String,
        'category15': Edm.String,
        'category16': Edm.String,
        'category17': Edm.String,
        'category18': Edm.String,
        'category19': Edm.String,
        'category2': Edm.String,
        'category20': Edm.String,
        'category21': Edm.String,
        'category22': Edm.String,
        'category23': Edm.String,
        'category24': Edm.String,
        'category25': Edm.String,
        'category3': Edm.String,
        'category4': Edm.String,
        'category5': Edm.String,
        'category6': Edm.String,
        'category7': Edm.String,
        'category8': Edm.String,
        'category9': Edm.String,
    }


class plannerChecklistItem(object):
    props = {
        'isChecked': Edm.Boolean,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'orderHint': Edm.String,
        'title': Edm.String,
    }


class plannerChecklistItems(object):
    props = {

    }


class plannerChecklistRequirement(object):
    props = {
        'requiredChecklistItemIds': Collection,
    }


class plannerExternalBucketSource(object):
    props = {
        'contextScenarioId': Edm.String,
        'externalContextId': Edm.String,
        'externalObjectId': Edm.String,
    }


class plannerPlanCreation(object):
    props = {
        'creationSourceKind': plannerCreationSourceKind,
    }


class plannerExternalPlanSource(object):
    props = {
        'contextScenarioId': Edm.String,
        'externalContextId': Edm.String,
        'externalObjectId': Edm.String,
    }


class plannerExternalReference(object):
    props = {
        'alias': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'previewPriority': Edm.String,
        'type': Edm.String,
    }


class plannerExternalReferences(object):
    props = {

    }


class plannerExternalTaskSource(object):
    props = {
        'contextScenarioId': Edm.String,
        'displayLinkType': plannerExternalTaskSourceDisplayType,
        'displayNameSegments': Collection,
        'externalContextId': Edm.String,
        'externalObjectId': Edm.String,
        'externalObjectVersion': Edm.String,
        'webUrl': Edm.String,
    }


class plannerFavoritePlanReference(object):
    props = {
        'orderHint': Edm.String,
        'planTitle': Edm.String,
    }


class plannerFavoritePlanReferenceCollection(object):
    props = {

    }


class plannerFormReference(object):
    props = {
        'displayName': Edm.String,
        'formResponse': Edm.String,
        'formWebUrl': Edm.String,
    }


class plannerFormsDictionary(object):
    props = {

    }


class plannerFormsRequirement(object):
    props = {
        'requiredForms': Collection,
    }


class plannerOrderHintsByAssignee(object):
    props = {

    }


class plannerPlanContainer(object):
    props = {
        'containerId': Edm.String,
        'type': plannerContainerType,
        'url': Edm.String,
    }


class plannerPlanContext(object):
    props = {
        'associationType': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayNameSegments': Collection,
        'isCreationContext': Edm.Boolean,
        'ownerAppId': Edm.String,
    }


class plannerPlanContextCollection(object):
    props = {

    }


class plannerPlanContextDetails(object):
    props = {
        'customLinkText': Edm.String,
        'displayLinkType': plannerPlanContextType,
        'state': plannerContextState,
        'url': Edm.String,
    }


class plannerPlanContextDetailsCollection(object):
    props = {

    }


class plannerPlanPropertyRule(object):
    props = {
        'buckets': Collection,
        'categoryDescriptions': plannerFieldRules,
        'tasks': Collection,
        'title': plannerFieldRules,
    }


class plannerRecentPlanReference(object):
    props = {
        'lastAccessedDateTime': Edm.DateTimeOffset,
        'planTitle': Edm.String,
    }


class plannerRecentPlanReferenceCollection(object):
    props = {

    }


class plannerRecurrenceSchedule(object):
    props = {
        'nextOccurrenceDateTime': Edm.DateTimeOffset,
        'pattern': recurrencePattern,
        'patternStartDateTime': Edm.DateTimeOffset,
    }


class plannerSharedWithContainer(object):
    props = {
        'accessLevel': plannerPlanAccessLevel,
    }


class plannerTaskCompletionRequirementDetails(object):
    props = {
        'approvalRequirement': plannerApprovalRequirement,
        'checklistRequirement': plannerChecklistRequirement,
        'formsRequirement': plannerFormsRequirement,
    }


class plannerTeamsPublicationInfo(object):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'publicationId': Edm.String,
        'publishedToPlanId': Edm.String,
        'publishingTeamId': Edm.String,
        'publishingTeamName': Edm.String,
    }


class plannerTaskRecurrence(object):
    props = {
        'nextInSeriesTaskId': Edm.String,
        'occurrenceId': Edm.Int32,
        'previousInSeriesTaskId': Edm.String,
        'recurrenceStartDateTime': Edm.DateTimeOffset,
        'schedule': plannerRecurrenceSchedule,
        'seriesId': Edm.String,
    }


class plannerUserIds(object):
    props = {

    }


class channelModerationSettings(object):
    props = {
        'allowNewMessageFromBots': Edm.Boolean,
        'allowNewMessageFromConnectors': Edm.Boolean,
        'replyRestriction': replyRestriction,
        'userNewMessageRestriction': userNewMessageRestriction,
    }


class channelSummary(object):
    props = {
        'guestsCount': Edm.Int32,
        'hasMembersFromOtherTenants': Edm.Boolean,
        'membersCount': Edm.Int32,
        'ownersCount': Edm.Int32,
    }


class businessScenarioTaskTargetBase(object):
    props = {
        'taskTargetKind': plannerTaskTargetKind,
    }


class businessScenarioGroupTarget(object):
    props = {
        'groupId': Edm.String,
    }


class businessScenarioProperties(object):
    props = {
        'externalBucketId': Edm.String,
        'externalContextId': Edm.String,
        'externalObjectId': Edm.String,
        'externalObjectVersion': Edm.String,
        'webUrl': Edm.String,
    }


class insightIdentity(object):
    props = {
        'address': Edm.String,
        'displayName': Edm.String,
        'id': Edm.String,
    }


class resourceReference(object):
    props = {
        'id': Edm.String,
        'type': Edm.String,
        'webUrl': Edm.String,
    }


class resourceVisualization(object):
    props = {
        'containerDisplayName': Edm.String,
        'containerType': Edm.String,
        'containerWebUrl': Edm.String,
        'mediaType': Edm.String,
        'previewImageUrl': Edm.String,
        'previewText': Edm.String,
        'title': Edm.String,
        'type': Edm.String,
    }


class sharingDetail(object):
    props = {
        'sharedBy': insightIdentity,
        'sharedDateTime': Edm.DateTimeOffset,
        'sharingReference': resourceReference,
        'sharingSubject': Edm.String,
        'sharingType': Edm.String,
    }


class usageDetails(object):
    props = {
        'lastAccessedDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class diagnostic(object):
    props = {
        'message': Edm.String,
        'url': Edm.String,
    }


class externalLink(object):
    props = {
        'href': Edm.String,
    }


class onenoteOperationError(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
    }


class onenotePagePreviewLinks(object):
    props = {
        'previewImageUrl': externalLink,
    }


class onenotePatchContentCommand(object):
    props = {
        'action': onenotePatchActionType,
        'content': Edm.String,
        'position': onenotePatchInsertPosition,
        'target': Edm.String,
    }


class pageLinks(object):
    props = {
        'oneNoteClientUrl': externalLink,
        'oneNoteWebUrl': externalLink,
    }


class recentNotebookLinks(object):
    props = {
        'oneNoteClientUrl': externalLink,
        'oneNoteWebUrl': externalLink,
    }


class sectionLinks(object):
    props = {
        'oneNoteClientUrl': externalLink,
        'oneNoteWebUrl': externalLink,
    }


class appsAndServicesSettings(object):
    props = {
        'isAppAndServicesTrialEnabled': Edm.Boolean,
        'isOfficeStoreEnabled': Edm.Boolean,
    }


class customerVoiceSettings(object):
    props = {
        'isInOrgFormsPhishingScanEnabled': Edm.Boolean,
        'isRecordIdentityByDefaultEnabled': Edm.Boolean,
        'isRestrictedSurveyAccessEnabled': Edm.Boolean,
    }


class formsSettings(object):
    props = {
        'isBingImageSearchEnabled': Edm.Boolean,
        'isExternalSendFormEnabled': Edm.Boolean,
        'isExternalShareCollaborationEnabled': Edm.Boolean,
        'isExternalShareResultEnabled': Edm.Boolean,
        'isExternalShareTemplateEnabled': Edm.Boolean,
        'isInOrgFormsPhishingScanEnabled': Edm.Boolean,
        'isRecordIdentityByDefaultEnabled': Edm.Boolean,
    }


class todoSettings(object):
    props = {
        'isExternalJoinEnabled': Edm.Boolean,
        'isExternalShareEnabled': Edm.Boolean,
        'isPushNotificationEnabled': Edm.Boolean,
    }


class delegatedAdminAccessContainer(object):
    props = {
        'accessContainerId': Edm.String,
        'accessContainerType': delegatedAdminAccessContainerType,
    }


class delegatedAdminAccessDetails(object):
    props = {
        'unifiedRoles': Collection,
    }


class unifiedRole(object):
    props = {
        'roleDefinitionId': Edm.String,
    }


class delegatedAdminRelationshipCustomerParticipant(object):
    props = {
        'displayName': Edm.String,
        'tenantId': Edm.String,
    }


class cloudClipboardItemPayload(object):
    props = {
        'content': Edm.String,
        'formatName': Edm.String,
    }


class microsoftPersonalizationSettings(object):
    props = {
        'isBingRewardsFeatureEnabled': Edm.Boolean,
    }


class profileCardAnnotation(object):
    props = {
        'displayName': Edm.String,
        'localizations': Collection,
    }


class companyDetail(object):
    props = {
        'address': physicalAddress,
        'companyCode': Edm.String,
        'department': Edm.String,
        'displayName': Edm.String,
        'officeLocation': Edm.String,
        'pronunciation': Edm.String,
        'secondaryDepartment': Edm.String,
        'webUrl': Edm.String,
    }


class educationalActivityDetail(object):
    props = {
        'abbreviation': Edm.String,
        'activities': Collection,
        'awards': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'fieldsOfStudy': Collection,
        'grade': Edm.String,
        'notes': Edm.String,
        'webUrl': Edm.String,
    }


class inferenceData(object):
    props = {
        'confidenceScore': Edm.Double,
        'userHasVerifiedAccuracy': Edm.Boolean,
    }


class institutionData(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'location': physicalAddress,
        'webUrl': Edm.String,
    }


class personDataSources(object):
    props = {
        'type': Collection,
    }


class personNamePronounciation(object):
    props = {
        'displayName': Edm.String,
        'first': Edm.String,
        'last': Edm.String,
        'maiden': Edm.String,
        'middle': Edm.String,
    }


class photoAllowedOperations(object):
    props = {

    }


class positionDetail(object):
    props = {
        'company': companyDetail,
        'description': Edm.String,
        'endMonthYear': Edm.Date,
        'jobTitle': Edm.String,
        'layer': Edm.Int32,
        'level': Edm.String,
        'role': Edm.String,
        'secondaryJobTitle': Edm.String,
        'secondaryRole': Edm.String,
        'startMonthYear': Edm.Date,
        'summary': Edm.String,
    }


class profileSourceAnnotation(object):
    props = {
        'isDefaultSource': Edm.Boolean,
        'properties': Collection,
        'sourceId': Edm.String,
    }


class regionalFormatOverrides(object):
    props = {
        'calendar': Edm.String,
        'firstDayOfWeek': Edm.String,
        'longDateFormat': Edm.String,
        'longTimeFormat': Edm.String,
        'shortDateFormat': Edm.String,
        'shortTimeFormat': Edm.String,
        'timeZone': Edm.String,
    }


class relatedPerson(object):
    props = {
        'displayName': Edm.String,
        'relationship': personRelationship,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class serviceInformation(object):
    props = {
        'name': Edm.String,
        'webUrl': Edm.String,
    }


class translationLanguageOverride(object):
    props = {
        'languageTag': Edm.String,
        'translationBehavior': translationBehavior,
    }


class translationPreferences(object):
    props = {
        'languageOverrides': Collection,
        'translationBehavior': translationBehavior,
        'untranslatedLanguages': Collection,
    }


class governancePermission(object):
    props = {
        'accessLevel': Edm.String,
        'isActive': Edm.Boolean,
        'isEligible': Edm.Boolean,
    }


class governanceRoleAssignmentRequestStatus(object):
    props = {
        'status': Edm.String,
        'statusDetails': Collection,
        'subStatus': Edm.String,
    }


class governanceRuleSetting(object):
    props = {
        'ruleIdentifier': Edm.String,
        'setting': Edm.String,
    }


class governanceSchedule(object):
    props = {
        'duration': Edm.Duration,
        'endDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'type': Edm.String,
    }


class unifiedRoleManagementPolicyRuleTarget(object):
    props = {
        'caller': Edm.String,
        'enforcedSettings': Collection,
        'inheritableSettings': Collection,
        'level': Edm.String,
        'operations': Collection,
    }


class roleSuccessStatistics(object):
    props = {
        'permanentFail': Edm.Int64,
        'permanentSuccess': Edm.Int64,
        'removeFail': Edm.Int64,
        'removeSuccess': Edm.Int64,
        'roleId': Edm.String,
        'roleName': Edm.String,
        'temporaryFail': Edm.Int64,
        'temporarySuccess': Edm.Int64,
        'unknownFail': Edm.Int64,
    }


class airPrintSettings(object):
    props = {
        'incompatiblePrinters': incompatiblePrinterSettings,
    }


class archivedPrintJob(object):
    props = {
        'acquiredByPrinter': Edm.Boolean,
        'acquiredDateTime': Edm.DateTimeOffset,
        'blackAndWhitePageCount': Edm.Int32,
        'colorPageCount': Edm.Int32,
        'completionDateTime': Edm.DateTimeOffset,
        'copiesPrinted': Edm.Int32,
        'createdBy': userIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'duplexPageCount': Edm.Int32,
        'id': Edm.String,
        'pageCount': Edm.Int32,
        'printerId': Edm.String,
        'printerName': Edm.String,
        'processingState': printJobProcessingState,
        'simplexPageCount': Edm.Int32,
    }


class deviceHealth(object):
    props = {
        'lastConnectionTime': Edm.DateTimeOffset,
    }


class integerRange(object):
    props = {
        'end': Edm.Int64,
        'maximum': Edm.Int64,
        'minimum': Edm.Int64,
        'start': Edm.Int64,
    }


class printCertificateSigningRequest(object):
    props = {
        'content': Edm.String,
        'transportKey': Edm.String,
    }


class printDocumentUploadProperties(object):
    props = {
        'contentType': Edm.String,
        'documentName': Edm.String,
        'size': Edm.Int64,
    }


class printerCapabilities(object):
    props = {
        'bottomMargins': Collection,
        'collation': Edm.Boolean,
        'colorModes': Collection,
        'contentTypes': Collection,
        'copiesPerJob': integerRange,
        'dpis': Collection,
        'duplexModes': Collection,
        'feedDirections': Collection,
        'feedOrientations': Collection,
        'finishings': Collection,
        'inputBins': Collection,
        'isColorPrintingSupported': Edm.Boolean,
        'isPageRangeSupported': Edm.Boolean,
        'leftMargins': Collection,
        'mediaColors': Collection,
        'mediaSizes': Collection,
        'mediaTypes': Collection,
        'multipageLayouts': Collection,
        'orientations': Collection,
        'outputBins': Collection,
        'pagesPerSheet': Collection,
        'qualities': Collection,
        'rightMargins': Collection,
        'scalings': Collection,
        'supportedColorConfigurations': Collection,
        'supportedCopiesPerJob': integerRange,
        'supportedDocumentMimeTypes': Collection,
        'supportedDuplexConfigurations': Collection,
        'supportedFinishings': Collection,
        'supportedMediaColors': Collection,
        'supportedMediaSizes': Collection,
        'supportedMediaTypes': Collection,
        'supportedOrientations': Collection,
        'supportedOutputBins': Collection,
        'supportedPagesPerSheet': integerRange,
        'supportedPresentationDirections': Collection,
        'supportedPrintQualities': Collection,
        'supportsFitPdfToPage': Edm.Boolean,
        'topMargins': Collection,
    }


class printerDefaults(object):
    props = {
        'colorMode': printColorMode,
        'contentType': Edm.String,
        'copiesPerJob': Edm.Int32,
        'documentMimeType': Edm.String,
        'dpi': Edm.Int32,
        'duplexConfiguration': printDuplexConfiguration,
        'duplexMode': printDuplexMode,
        'finishings': Collection,
        'fitPdfToPage': Edm.Boolean,
        'inputBin': Edm.String,
        'mediaColor': Edm.String,
        'mediaSize': Edm.String,
        'mediaType': Edm.String,
        'multipageLayout': printMultipageLayout,
        'orientation': printOrientation,
        'outputBin': Edm.String,
        'pagesPerSheet': Edm.Int32,
        'pdfFitToPage': Edm.Boolean,
        'presentationDirection': printPresentationDirection,
        'printColorConfiguration': printColorConfiguration,
        'printQuality': printQuality,
        'quality': printQuality,
        'scaling': printScaling,
    }


class printerDiscoverySettings(object):
    props = {
        'airPrint': airPrintSettings,
    }


class printMargin(object):
    props = {
        'bottom': Edm.Int32,
        'left': Edm.Int32,
        'right': Edm.Int32,
        'top': Edm.Int32,
    }


class printerLocation(object):
    props = {
        'altitudeInMeters': Edm.Int32,
        'building': Edm.String,
        'city': Edm.String,
        'countryOrRegion': Edm.String,
        'floor': Edm.String,
        'floorDescription': Edm.String,
        'floorNumber': Edm.Int32,
        'latitude': Edm.Double,
        'longitude': Edm.Double,
        'organization': Collection,
        'postalCode': Edm.String,
        'roomDescription': Edm.String,
        'roomName': Edm.String,
        'roomNumber': Edm.Int32,
        'site': Edm.String,
        'stateOrProvince': Edm.String,
        'streetAddress': Edm.String,
        'subdivision': Collection,
        'subunit': Collection,
    }


class printerShareViewpoint(object):
    props = {
        'lastUsedDateTime': Edm.DateTimeOffset,
    }


class printerStatus(object):
    props = {
        'description': Edm.String,
        'details': Collection,
        'processingState': printerProcessingState,
        'processingStateDescription': Edm.String,
        'processingStateReasons': Collection,
        'state': printerProcessingState,
    }


class printJobConfiguration(object):
    props = {
        'collate': Edm.Boolean,
        'colorMode': printColorMode,
        'copies': Edm.Int32,
        'dpi': Edm.Int32,
        'duplexMode': printDuplexMode,
        'feedOrientation': printerFeedOrientation,
        'finishings': Collection,
        'fitPdfToPage': Edm.Boolean,
        'inputBin': Edm.String,
        'margin': printMargin,
        'mediaSize': Edm.String,
        'mediaType': Edm.String,
        'multipageLayout': printMultipageLayout,
        'orientation': printOrientation,
        'outputBin': Edm.String,
        'pageRanges': Collection,
        'pagesPerSheet': Edm.Int32,
        'quality': printQuality,
        'scaling': printScaling,
    }


class printJobStatus(object):
    props = {
        'acquiredByPrinter': Edm.Boolean,
        'description': Edm.String,
        'details': Collection,
        'isAcquiredByPrinter': Edm.Boolean,
        'processingState': printJobProcessingState,
        'processingStateDescription': Edm.String,
        'state': printJobProcessingState,
    }


class printOperationStatus(object):
    props = {
        'description': Edm.String,
        'state': printOperationProcessingState,
    }


class printSettings(object):
    props = {
        'documentConversionEnabled': Edm.Boolean,
        'printerDiscoverySettings': printerDiscoverySettings,
    }


class printTaskStatus(object):
    props = {
        'description': Edm.String,
        'state': printTaskProcessingState,
    }


class imageInfo(object):
    props = {
        'addImageQuery': Edm.Boolean,
        'alternateText': Edm.String,
        'alternativeText': Edm.String,
        'iconUrl': Edm.String,
    }


class visualInfo(object):
    props = {
        'attribution': imageInfo,
        'backgroundColor': Edm.String,
        'content': Json,
        'description': Edm.String,
        'displayText': Edm.String,
    }


class payloadRequest(object):
    props = {

    }


class accountTargetContent(object):
    props = {
        'type': accountTargetContentType,
    }


class addressBookAccountTargetContent(object):
    props = {
        'accountTargetEmails': Collection,
    }


class assignedTrainingInfo(object):
    props = {
        'assignedUserCount': Edm.Int32,
        'completedUserCount': Edm.Int32,
        'displayName': Edm.String,
    }


class attackSimulationUser(object):
    props = {
        'displayName': Edm.String,
        'email': Edm.String,
        'outOfOfficeDays': Edm.Int32,
        'userId': Edm.String,
    }


class attackSimulationSimulationUserCoverage(object):
    props = {
        'attackSimulationUser': attackSimulationUser,
        'clickCount': Edm.Int32,
        'compromisedCount': Edm.Int32,
        'latestSimulationDateTime': Edm.DateTimeOffset,
        'simulationCount': Edm.Int32,
    }


class attackSimulationTrainingUserCoverage(object):
    props = {
        'attackSimulationUser': attackSimulationUser,
        'userTrainings': Collection,
    }


class userTrainingStatusInfo(object):
    props = {
        'assignedDateTime': Edm.DateTimeOffset,
        'completionDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'trainingStatus': trainingStatus,
    }


class baseEndUserNotification(object):
    props = {
        'defaultLanguage': Edm.String,
    }


class campaignSchedule(object):
    props = {
        'completionDateTime': Edm.DateTimeOffset,
        'launchDateTime': Edm.DateTimeOffset,
        'status': campaignStatus,
    }


class coachmarkLocation(object):
    props = {
        'length': Edm.Int32,
        'offset': Edm.Int32,
        'type': coachmarkLocationType,
    }


class trainingSetting(object):
    props = {
        'settingType': trainingSettingType,
    }


class customTrainingSetting(object):
    props = {
        'assignedTo': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'durationInMinutes': Edm.Int32,
        'url': Edm.String,
    }


class payloadDetail(object):
    props = {
        'coachmarks': Collection,
        'content': Edm.String,
        'phishingUrl': Edm.String,
    }


class emailPayloadDetail(object):
    props = {
        'fromEmail': Edm.String,
        'fromName': Edm.String,
        'isExternalSender': Edm.Boolean,
        'subject': Edm.String,
    }


class positiveReinforcementNotification(object):
    props = {
        'deliveryPreference': notificationDeliveryPreference,
    }


class includeAllAccountTargetContent(object):
    props = {

    }


class microsoftCustomTrainingSetting(object):
    props = {
        'completionDateTime': Edm.DateTimeOffset,
        'trainingAssignmentMappings': Collection,
        'trainingCompletionDuration': trainingCompletionDuration,
    }


class microsoftTrainingAssignmentMapping(object):
    props = {
        'assignedTo': Collection,
    }


class microsoftManagedTrainingSetting(object):
    props = {
        'completionDateTime': Edm.DateTimeOffset,
        'trainingCompletionDuration': trainingCompletionDuration,
    }


class simulationNotification(object):
    props = {
        'targettedUserType': targettedUserType,
    }


class noTrainingSetting(object):
    props = {

    }


class oAuthConsentAppDetail(object):
    props = {
        'appScope': oAuthAppScope,
        'displayLogo': Edm.String,
        'displayName': Edm.String,
    }


class payloadCoachmark(object):
    props = {
        'coachmarkLocation': coachmarkLocation,
        'description': Edm.String,
        'indicator': Edm.String,
        'isValid': Edm.Boolean,
        'language': Edm.String,
        'order': Edm.String,
    }


class recommendedAction(object):
    props = {
        'actionWebUrl': Edm.String,
        'potentialScoreImpact': Edm.Double,
        'title': Edm.String,
    }


class simulationEvent(object):
    props = {
        'count': Edm.Int32,
        'eventName': Edm.String,
    }


class simulationEventsContent(object):
    props = {
        'compromisedRate': Edm.Double,
        'events': Collection,
    }


class userSimulationDetails(object):
    props = {
        'assignedTrainingsCount': Edm.Int32,
        'completedTrainingsCount': Edm.Int32,
        'compromisedDateTime': Edm.DateTimeOffset,
        'inProgressTrainingsCount': Edm.Int32,
        'isCompromised': Edm.Boolean,
        'latestSimulationActivity': Edm.String,
        'reportedPhishDateTime': Edm.DateTimeOffset,
        'simulationEvents': Collection,
        'simulationUser': attackSimulationUser,
        'trainingEvents': Collection,
    }


class trainingEventsContent(object):
    props = {
        'assignedTrainingsInfos': Collection,
        'trainingsAssignedUserCount': Edm.Int32,
    }


class trainingNotificationDelivery(object):
    props = {
        'failedMessageDeliveryCount': Edm.Int32,
        'resolvedTargetsCount': Edm.Int32,
        'successfulMessageDeliveryCount': Edm.Int32,
    }


class userTrainingCompletionSummary(object):
    props = {
        'completedUsersCount': Edm.Int32,
        'inProgressUsersCount': Edm.Int32,
        'notCompletedUsersCount': Edm.Int32,
        'notStartedUsersCount': Edm.Int32,
        'previouslyAssignedUsersCount': Edm.Int32,
    }


class trainingReminderNotification(object):
    props = {
        'deliveryFrequency': notificationDeliveryFrequency,
    }


class userSimulationEventInfo(object):
    props = {
        'browser': Edm.String,
        'clickSource': clickSource,
        'eventDateTime': Edm.DateTimeOffset,
        'eventName': Edm.String,
        'ipAddress': Edm.String,
        'osPlatformDeviceDetails': Edm.String,
    }


class userTrainingContentEventInfo(object):
    props = {
        'browser': Edm.String,
        'contentDateTime': Edm.DateTimeOffset,
        'ipAddress': Edm.String,
        'osPlatformDeviceDetails': Edm.String,
        'potentialScoreImpact': Edm.Double,
    }


class accountAlias(object):
    props = {
        'id': Edm.String,
        'idType': Edm.String,
    }


class alertDetection(object):
    props = {
        'detectionType': Edm.String,
        'method': Edm.String,
        'name': Edm.String,
    }


class alertHistoryState(object):
    props = {
        'appId': Edm.String,
        'assignedTo': Edm.String,
        'comments': Collection,
        'feedback': alertFeedback,
        'status': alertStatus,
        'updatedDateTime': Edm.DateTimeOffset,
        'user': Edm.String,
    }


class alertTrigger(object):
    props = {
        'name': Edm.String,
        'type': Edm.String,
        'value': Edm.String,
    }


class averageComparativeScore(object):
    props = {
        'averageScore': Edm.Double,
        'basis': Edm.String,
    }


class certificationControl(object):
    props = {
        'name': Edm.String,
        'url': Edm.String,
    }


class cloudAppSecurityState(object):
    props = {
        'destinationServiceIp': Edm.String,
        'destinationServiceName': Edm.String,
        'riskScore': Edm.String,
    }


class complianceInformation(object):
    props = {
        'certificationControls': Collection,
        'certificationName': Edm.String,
    }


class controlScore(object):
    props = {
        'controlCategory': Edm.String,
        'controlName': Edm.String,
        'description': Edm.String,
        'score': Edm.Double,
    }


class domainRegistrant(object):
    props = {
        'countryOrRegionCode': Edm.String,
        'organization': Edm.String,
        'url': Edm.String,
        'vendor': Edm.String,
    }


class entitySetNames(object):
    props = {

    }


class fileHash(object):
    props = {
        'hashType': fileHashType,
        'hashValue': Edm.String,
    }


class fileSecurityState(object):
    props = {
        'fileHash': fileHash,
        'name': Edm.String,
        'path': Edm.String,
        'riskScore': Edm.String,
    }


class hostSecurityState(object):
    props = {
        'fqdn': Edm.String,
        'isAzureAdJoined': Edm.Boolean,
        'isAzureAdRegistered': Edm.Boolean,
        'isHybridAzureDomainJoined': Edm.Boolean,
        'netBiosName': Edm.String,
        'os': Edm.String,
        'privateIpAddress': Edm.String,
        'publicIpAddress': Edm.String,
        'riskScore': Edm.String,
    }


class investigationSecurityState(object):
    props = {
        'name': Edm.String,
        'status': Edm.String,
    }


class ipCategory(object):
    props = {
        'description': Edm.String,
        'name': Edm.String,
        'vendor': Edm.String,
    }


class ipReferenceData(object):
    props = {
        'asn': Edm.Int64,
        'city': Edm.String,
        'countryOrRegionCode': Edm.String,
        'organization': Edm.String,
        'state': Edm.String,
        'vendor': Edm.String,
    }


class logonUser(object):
    props = {
        'accountDomain': Edm.String,
        'accountName': Edm.String,
        'accountType': userAccountSecurityType,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'logonId': Edm.String,
        'logonTypes': Collection,
    }


class malwareState(object):
    props = {
        'category': Edm.String,
        'family': Edm.String,
        'name': Edm.String,
        'severity': Edm.String,
        'wasRunning': Edm.Boolean,
    }


class messageSecurityState(object):
    props = {
        'connectingIP': Edm.String,
        'deliveryAction': Edm.String,
        'deliveryLocation': Edm.String,
        'directionality': Edm.String,
        'internetMessageId': Edm.String,
        'messageFingerprint': Edm.String,
        'messageReceivedDateTime': Edm.DateTimeOffset,
        'messageSubject': Edm.String,
        'networkMessageId': Edm.String,
    }


class networkConnection(object):
    props = {
        'applicationName': Edm.String,
        'destinationAddress': Edm.String,
        'destinationDomain': Edm.String,
        'destinationLocation': Edm.String,
        'destinationPort': Edm.String,
        'destinationUrl': Edm.String,
        'direction': connectionDirection,
        'domainRegisteredDateTime': Edm.DateTimeOffset,
        'localDnsName': Edm.String,
        'natDestinationAddress': Edm.String,
        'natDestinationPort': Edm.String,
        'natSourceAddress': Edm.String,
        'natSourcePort': Edm.String,
        'protocol': securityNetworkProtocol,
        'riskScore': Edm.String,
        'sourceAddress': Edm.String,
        'sourceLocation': Edm.String,
        'sourcePort': Edm.String,
        'status': connectionStatus,
        'urlParameters': Edm.String,
    }


class networkInterface(object):
    props = {
        'description': Edm.String,
        'ipV4Address': Edm.String,
        'ipV6Address': Edm.String,
        'localIpV6Address': Edm.String,
        'macAddress': Edm.String,
    }


class process(object):
    props = {
        'accountName': Edm.String,
        'commandLine': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'fileHash': fileHash,
        'integrityLevel': processIntegrityLevel,
        'isElevated': Edm.Boolean,
        'name': Edm.String,
        'parentProcessCreatedDateTime': Edm.DateTimeOffset,
        'parentProcessId': Edm.Int32,
        'parentProcessName': Edm.String,
        'path': Edm.String,
        'processId': Edm.Int32,
    }


class registryKeyState(object):
    props = {
        'hive': registryHive,
        'key': Edm.String,
        'oldKey': Edm.String,
        'oldValueData': Edm.String,
        'oldValueName': Edm.String,
        'operation': registryOperation,
        'processId': Edm.Int32,
        'valueData': Edm.String,
        'valueName': Edm.String,
        'valueType': registryValueType,
    }


class reputationCategory(object):
    props = {
        'description': Edm.String,
        'name': Edm.String,
        'vendor': Edm.String,
    }


class secureScoreControlStateUpdate(object):
    props = {
        'assignedTo': Edm.String,
        'comment': Edm.String,
        'state': Edm.String,
        'updatedBy': Edm.String,
        'updatedDateTime': Edm.DateTimeOffset,
    }


class securityActionState(object):
    props = {
        'appId': Edm.String,
        'status': operationStatus,
        'updatedDateTime': Edm.DateTimeOffset,
        'user': Edm.String,
    }


class securityProviderStatus(object):
    props = {
        'enabled': Edm.Boolean,
        'endpoint': Edm.String,
        'provider': Edm.String,
        'region': Edm.String,
        'vendor': Edm.String,
    }


class securityResource(object):
    props = {
        'resource': Edm.String,
        'resourceType': securityResourceType,
    }


class securityVendorInformation(object):
    props = {
        'provider': Edm.String,
        'providerVersion': Edm.String,
        'subProvider': Edm.String,
        'vendor': Edm.String,
    }


class uriClickSecurityState(object):
    props = {
        'clickAction': Edm.String,
        'clickDateTime': Edm.DateTimeOffset,
        'id': Edm.String,
        'sourceId': Edm.String,
        'uriDomain': Edm.String,
        'verdict': Edm.String,
    }


class userAccount(object):
    props = {
        'displayName': Edm.String,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'riskScore': Edm.String,
        'service': Edm.String,
        'signinName': Edm.String,
        'status': accountStatus,
    }


class userSecurityState(object):
    props = {
        'aadUserId': Edm.String,
        'accountName': Edm.String,
        'domainName': Edm.String,
        'emailRole': emailRole,
        'isVpn': Edm.Boolean,
        'logonDateTime': Edm.DateTimeOffset,
        'logonId': Edm.String,
        'logonIp': Edm.String,
        'logonLocation': Edm.String,
        'logonType': logonType,
        'onPremisesSecurityIdentifier': Edm.String,
        'riskScore': Edm.String,
        'userAccountType': userAccountSecurityType,
        'userPrincipalName': Edm.String,
    }


class vulnerabilityState(object):
    props = {
        'cve': Edm.String,
        'severity': Edm.String,
        'wasRunning': Edm.Boolean,
    }


class participantJoiningResponse(object):
    props = {

    }


class acceptJoinResponse(object):
    props = {

    }


class mediaConfig(object):
    props = {
        'removeFromDefaultAudioGroup': Edm.Boolean,
    }


class appHostedMediaConfig(object):
    props = {
        'blob': Edm.String,
    }


class attendanceInterval(object):
    props = {
        'durationInSeconds': Edm.Int32,
        'joinDateTime': Edm.DateTimeOffset,
        'leaveDateTime': Edm.DateTimeOffset,
    }


class audioConferencing(object):
    props = {
        'conferenceId': Edm.String,
        'dialinUrl': Edm.String,
        'tollFreeNumber': Edm.String,
        'tollFreeNumbers': Collection,
        'tollNumber': Edm.String,
        'tollNumbers': Collection,
    }


class azureCommunicationServicesUserIdentity(object):
    props = {
        'azureCommunicationServicesResourceId': Edm.String,
    }


class broadcastMeetingCaptionSettings(object):
    props = {
        'isCaptionEnabled': Edm.Boolean,
        'spokenLanguage': Edm.String,
        'translationLanguages': Collection,
    }


class callMediaState(object):
    props = {
        'audio': mediaState,
    }


class callOptions(object):
    props = {
        'hideBotAfterEscalation': Edm.Boolean,
        'isContentSharingNotificationEnabled': Edm.Boolean,
        'isDeltaRosterEnabled': Edm.Boolean,
    }


class callRoute(object):
    props = {
        'final': identitySet,
        'original': identitySet,
        'routingType': routingType,
    }


class callTranscriptionInfo(object):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'state': callTranscriptionState,
    }


class chatInfo(object):
    props = {
        'messageId': Edm.String,
        'replyChainMessageId': Edm.String,
        'threadId': Edm.String,
    }


class chatRestrictions(object):
    props = {
        'allowTextOnly': Edm.Boolean,
    }


class commsNotification(object):
    props = {
        'changeType': changeType,
        'resourceUrl': Edm.String,
    }


class commsNotifications(object):
    props = {
        'value': Collection,
    }


class communicationsApplicationIdentity(object):
    props = {
        'applicationType': Edm.String,
        'hidden': Edm.Boolean,
    }


class communicationsApplicationInstanceIdentity(object):
    props = {
        'hidden': Edm.Boolean,
        'tenantId': Edm.String,
    }


class communicationsEncryptedIdentity(object):
    props = {

    }


class communicationsGuestIdentity(object):
    props = {
        'email': Edm.String,
    }


class communicationsPhoneIdentity(object):
    props = {

    }


class communicationsUserIdentity(object):
    props = {
        'tenantId': Edm.String,
    }


class customQuestionAnswer(object):
    props = {
        'displayName': Edm.String,
        'questionId': Edm.String,
        'value': Edm.String,
    }


class delegateAllowedActions(object):
    props = {
        'joinActiveCalls': Edm.Boolean,
        'makeCalls': Edm.Boolean,
        'manageCallAndDelegateSettings': Edm.Boolean,
        'pickUpHeldCalls': Edm.Boolean,
        'receiveCalls': Edm.Boolean,
    }


class incomingCallOptions(object):
    props = {

    }


class incomingContext(object):
    props = {
        'observedParticipantId': Edm.String,
        'onBehalfOf': identitySet,
        'sourceParticipantId': Edm.String,
        'transferor': identitySet,
    }


class invitationParticipantInfo(object):
    props = {
        'endpointType': endpointType,
        'hidden': Edm.Boolean,
        'identity': identitySet,
        'participantId': Edm.String,
        'removeFromDefaultAudioRoutingGroup': Edm.Boolean,
        'replacesCallId': Edm.String,
    }


class inviteNewBotResponse(object):
    props = {
        'inviteUri': Edm.String,
    }


class meetingInfo(object):
    props = {
        'allowConversationWithoutHost': Edm.Boolean,
    }


class joinMeetingIdMeetingInfo(object):
    props = {
        'joinMeetingId': Edm.String,
        'passcode': Edm.String,
    }


class joinMeetingIdSettings(object):
    props = {
        'isPasscodeRequired': Edm.Boolean,
        'joinMeetingId': Edm.String,
        'passcode': Edm.String,
    }


class liveCaptionOptions(object):
    props = {
        'streamUrl': Edm.String,
    }


class mediaInfo(object):
    props = {
        'resourceId': Edm.String,
        'uri': Edm.String,
    }


class prompt(object):
    props = {

    }


class mediaPrompt(object):
    props = {
        'loop': Edm.Int32,
        'mediaInfo': mediaInfo,
    }


class mediaStream(object):
    props = {
        'direction': mediaDirection,
        'label': Edm.String,
        'mediaType': modality,
        'serverMuted': Edm.Boolean,
        'sourceId': Edm.String,
    }


class meetingCapability(object):
    props = {
        'allowAnonymousUsersToDialOut': Edm.Boolean,
        'allowAnonymousUsersToStartMeeting': Edm.Boolean,
        'autoAdmittedUsers': autoAdmittedUsersType,
    }


class meetingParticipantInfo(object):
    props = {
        'identity': identitySet,
        'role': onlineMeetingRole,
        'upn': Edm.String,
    }


class meetingSpeaker(object):
    props = {
        'bio': Edm.String,
        'displayName': Edm.String,
    }


class onlineMeetingRestricted(object):
    props = {
        'contentSharingDisabled': onlineMeetingContentSharingDisabledReason,
        'videoDisabled': onlineMeetingVideoDisabledReason,
    }


class organizerMeetingInfo(object):
    props = {
        'organizer': identitySet,
    }


class outgoingCallOptions(object):
    props = {

    }


class outOfOfficeSettings(object):
    props = {
        'isOutOfOffice': Edm.Boolean,
        'message': Edm.String,
    }


class participantInfo(object):
    props = {
        'countryCode': Edm.String,
        'endpointType': endpointType,
        'identity': identitySet,
        'languageId': Edm.String,
        'nonAnonymizedIdentity': identitySet,
        'participantId': Edm.String,
        'platformId': Edm.String,
        'region': Edm.String,
    }


class presenceStatusMessage(object):
    props = {
        'expiryDateTime': dateTimeTimeZone,
        'message': itemBody,
        'publishedDateTime': Edm.DateTimeOffset,
    }


class recordingInfo(object):
    props = {
        'initiatedBy': participantInfo,
        'initiator': identitySet,
        'recordingStatus': recordingStatus,
    }


class rejectJoinResponse(object):
    props = {
        'reason': rejectReason,
    }


class removedState(object):
    props = {
        'reason': Edm.String,
    }


class serviceHostedMediaConfig(object):
    props = {
        'liveCaptionOptions': liveCaptionOptions,
        'preFetchMedia': Collection,
    }


class teleconferenceDeviceMediaQuality(object):
    props = {
        'averageInboundJitter': Edm.Duration,
        'averageInboundPacketLossRateInPercentage': Edm.Double,
        'averageInboundRoundTripDelay': Edm.Duration,
        'averageOutboundJitter': Edm.Duration,
        'averageOutboundPacketLossRateInPercentage': Edm.Double,
        'averageOutboundRoundTripDelay': Edm.Duration,
        'channelIndex': Edm.Int32,
        'inboundPackets': Edm.Int64,
        'localIPAddress': Edm.String,
        'localPort': Edm.Int32,
        'maximumInboundJitter': Edm.Duration,
        'maximumInboundPacketLossRateInPercentage': Edm.Double,
        'maximumInboundRoundTripDelay': Edm.Duration,
        'maximumOutboundJitter': Edm.Duration,
        'maximumOutboundPacketLossRateInPercentage': Edm.Double,
        'maximumOutboundRoundTripDelay': Edm.Duration,
        'mediaDuration': Edm.Duration,
        'networkLinkSpeedInBytes': Edm.Int64,
        'outboundPackets': Edm.Int64,
        'remoteIPAddress': Edm.String,
        'remotePort': Edm.Int32,
    }


class teleconferenceDeviceAudioQuality(object):
    props = {

    }


class teleconferenceDeviceQuality(object):
    props = {
        'callChainId': Edm.Guid,
        'cloudServiceDeploymentEnvironment': Edm.String,
        'cloudServiceDeploymentId': Edm.String,
        'cloudServiceInstanceName': Edm.String,
        'cloudServiceName': Edm.String,
        'deviceDescription': Edm.String,
        'deviceName': Edm.String,
        'mediaLegId': Edm.Guid,
        'mediaQualityList': Collection,
        'participantId': Edm.Guid,
    }


class teleconferenceDeviceVideoQuality(object):
    props = {
        'averageInboundBitRate': Edm.Double,
        'averageInboundFrameRate': Edm.Double,
        'averageOutboundBitRate': Edm.Double,
        'averageOutboundFrameRate': Edm.Double,
    }


class teleconferenceDeviceScreenSharingQuality(object):
    props = {

    }


class tokenMeetingInfo(object):
    props = {
        'token': Edm.String,
    }


class toneInfo(object):
    props = {
        'sequenceId': Edm.Int64,
        'tone': tone,
    }


class virtualEventExternalInformation(object):
    props = {
        'applicationId': Edm.String,
        'externalEventId': Edm.String,
    }


class virtualEventExternalRegistrationInformation(object):
    props = {
        'referrer': Edm.String,
        'registrationId': Edm.String,
    }


class virtualEventPresenterDetails(object):
    props = {
        'bio': itemBody,
        'company': Edm.String,
        'jobTitle': Edm.String,
        'linkedInProfileWebUrl': Edm.String,
        'personalSiteWebUrl': Edm.String,
        'photo': Edm.Stream,
        'twitterProfileWebUrl': Edm.String,
    }


class virtualEventPresenterInfo(object):
    props = {
        'presenterDetails': virtualEventPresenterDetails,
    }


class virtualEventRegistrationQuestionAnswer(object):
    props = {
        'booleanValue': Edm.Boolean,
        'displayName': Edm.String,
        'multiChoiceValues': Collection,
        'questionId': Edm.String,
        'value': Edm.String,
    }


class virtualEventSettings(object):
    props = {
        'isAttendeeEmailNotificationEnabled': Edm.Boolean,
    }


class passwordResetResponse(object):
    props = {
        'newPassword': Edm.String,
    }


class signInPreferences(object):
    props = {
        'isSystemPreferredAuthenticationMethodEnabled': Edm.Boolean,
        'userPreferredMethodForSecondaryAuthentication': userDefaultAuthenticationMethodType,
    }


class strongAuthenticationRequirements(object):
    props = {
        'perUserMfaState': perUserMfaState,
    }


class webauthnAuthenticationExtensionsClientInputs(object):
    props = {

    }


class webauthnAuthenticationExtensionsClientOutputs(object):
    props = {

    }


class webauthnAuthenticatorAttestationResponse(object):
    props = {
        'attestationObject': Edm.String,
        'clientDataJSON': Edm.String,
    }


class webauthnAuthenticatorSelectionCriteria(object):
    props = {
        'authenticatorAttachment': Edm.String,
        'requireResidentKey': Edm.Boolean,
        'userVerification': Edm.String,
    }


class webauthnPublicKeyCredential(object):
    props = {
        'clientExtensionResults': webauthnAuthenticationExtensionsClientOutputs,
        'id': Edm.String,
        'response': webauthnAuthenticatorAttestationResponse,
    }


class webauthnPublicKeyCredentialDescriptor(object):
    props = {
        'id': Edm.String,
        'transports': Collection,
        'type': Edm.String,
    }


class webauthnPublicKeyCredentialParameters(object):
    props = {
        'alg': Edm.Int32,
        'type': Edm.String,
    }


class webauthnPublicKeyCredentialRpEntity(object):
    props = {
        'id': Edm.String,
        'name': Edm.String,
    }


class webauthnPublicKeyCredentialUserEntity(object):
    props = {
        'displayName': Edm.String,
        'id': Edm.String,
        'name': Edm.String,
    }


class changeNotificationEncryptedContent(object):
    props = {
        'data': Edm.String,
        'dataKey': Edm.String,
        'dataSignature': Edm.String,
        'encryptionCertificateId': Edm.String,
        'encryptionCertificateThumbprint': Edm.String,
    }


class resourceData(object):
    props = {

    }


class changeNotificationCollection(object):
    props = {
        'validationTokens': Collection,
        'value': Collection,
    }


class acl(object):
    props = {
        'accessType': accessType,
        'identitySource': identitySourceType,
        'type': aclType,
        'value': Edm.String,
    }


class configuration(object):
    props = {
        'authorizedAppIds': Collection,
        'authorizedApps': Collection,
    }


class externalItemContent(object):
    props = {
        'type': externalItemContentType,
        'value': Edm.String,
    }


class properties(object):
    props = {

    }


class property(object):
    props = {
        'aliases': Collection,
        'isQueryable': Edm.Boolean,
        'isRefinable': Edm.Boolean,
        'isRetrievable': Edm.Boolean,
        'isSearchable': Edm.Boolean,
        'labels': Collection,
        'name': Edm.String,
        'type': propertyType,
    }


class aadUserConversationMemberResult(object):
    props = {
        'userId': Edm.String,
    }


class teamworkNotificationRecipient(object):
    props = {

    }


class aadUserNotificationRecipient(object):
    props = {
        'userId': Edm.String,
    }


class actionItem(object):
    props = {
        'ownerDisplayName': Edm.String,
        'text': Edm.String,
        'title': Edm.String,
    }


class aiInteractionAttachment(object):
    props = {
        'attachmentId': Edm.String,
        'content': Edm.String,
        'contentType': Edm.String,
        'contentUrl': Edm.String,
        'name': Edm.String,
    }


class aiInteractionContext(object):
    props = {
        'contextReference': Edm.String,
        'contextType': Edm.String,
        'displayName': Edm.String,
    }


class aiInteractionLink(object):
    props = {
        'displayName': Edm.String,
        'linkType': Edm.String,
        'linkUrl': Edm.String,
    }


class teamworkConversationIdentity(object):
    props = {
        'conversationIdentityType': teamworkConversationIdentityType,
    }


class teamworkTagIdentity(object):
    props = {

    }


class callAiInsightViewPoint(object):
    props = {
        'mentionEvents': Collection,
    }


class mentionEvent(object):
    props = {
        'eventDateTime': Edm.DateTimeOffset,
        'speaker': identitySet,
        'transcriptUtterance': Edm.String,
    }


class eventMessageDetail(object):
    props = {

    }


class callEndedEventMessageDetail(object):
    props = {
        'callDuration': Edm.Duration,
        'callEventType': teamworkCallEventType,
        'callId': Edm.String,
        'callParticipants': Collection,
        'initiator': identitySet,
    }


class callParticipantInfo(object):
    props = {
        'participant': identitySet,
    }


class callRecordingEventMessageDetail(object):
    props = {
        'callId': Edm.String,
        'callRecordingDisplayName': Edm.String,
        'callRecordingDuration': Edm.Duration,
        'callRecordingStatus': callRecordingStatus,
        'callRecordingUrl': Edm.String,
        'initiator': identitySet,
        'meetingOrganizer': identitySet,
    }


class callStartedEventMessageDetail(object):
    props = {
        'callEventType': teamworkCallEventType,
        'callId': Edm.String,
        'initiator': identitySet,
    }


class callTranscriptEventMessageDetail(object):
    props = {
        'callId': Edm.String,
        'callTranscriptICalUid': Edm.String,
        'meetingOrganizer': identitySet,
    }


class channelAddedEventMessageDetail(object):
    props = {
        'channelDisplayName': Edm.String,
        'channelId': Edm.String,
        'initiator': identitySet,
    }


class channelDeletedEventMessageDetail(object):
    props = {
        'channelDisplayName': Edm.String,
        'channelId': Edm.String,
        'initiator': identitySet,
    }


class channelDescriptionUpdatedEventMessageDetail(object):
    props = {
        'channelDescription': Edm.String,
        'channelId': Edm.String,
        'initiator': identitySet,
    }


class channelIdentity(object):
    props = {
        'channelId': Edm.String,
        'teamId': Edm.String,
    }


class channelMembersNotificationRecipient(object):
    props = {
        'channelId': Edm.String,
        'teamId': Edm.String,
    }


class channelRenamedEventMessageDetail(object):
    props = {
        'channelDisplayName': Edm.String,
        'channelId': Edm.String,
        'initiator': identitySet,
    }


class channelSetAsFavoriteByDefaultEventMessageDetail(object):
    props = {
        'channelId': Edm.String,
        'initiator': identitySet,
    }


class channelSharingUpdatedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'ownerTeamId': Edm.String,
        'ownerTenantId': Edm.String,
        'sharedChannelId': Edm.String,
    }


class channelUnsetAsFavoriteByDefaultEventMessageDetail(object):
    props = {
        'channelId': Edm.String,
        'initiator': identitySet,
    }


class chatMembersNotificationRecipient(object):
    props = {
        'chatId': Edm.String,
    }


class chatMessageAttachment(object):
    props = {
        'content': Edm.String,
        'contentType': Edm.String,
        'contentUrl': Edm.String,
        'id': Edm.String,
        'name': Edm.String,
        'teamsAppId': Edm.String,
        'thumbnailUrl': Edm.String,
    }


class chatMessageFromIdentitySet(object):
    props = {

    }


class chatMessageMentionedIdentitySet(object):
    props = {
        'conversation': teamworkConversationIdentity,
        'tag': teamworkTagIdentity,
    }


class chatMessagePolicyViolationPolicyTip(object):
    props = {
        'complianceUrl': Edm.String,
        'generalText': Edm.String,
        'matchedConditionDescriptions': Collection,
    }


class chatMessageReactionIdentitySet(object):
    props = {

    }


class chatRenamedEventMessageDetail(object):
    props = {
        'chatDisplayName': Edm.String,
        'chatId': Edm.String,
        'initiator': identitySet,
    }


class chatViewpoint(object):
    props = {
        'isHidden': Edm.Boolean,
        'lastMessageReadDateTime': Edm.DateTimeOffset,
    }


class teamworkUserIdentity(object):
    props = {
        'userIdentityType': teamworkUserIdentityType,
    }


class customAppSettings(object):
    props = {
        'developerToolsForShowingAppUsageMetrics': appDevelopmentPlatforms,
    }


class teamsAppInstallationScopeInfo(object):
    props = {
        'scope': teamsAppInstallationScopes,
    }


class groupChatTeamsAppInstallationScopeInfo(object):
    props = {
        'chatId': Edm.String,
    }


class meetingNote(object):
    props = {
        'subpoints': Collection,
        'text': Edm.String,
        'title': Edm.String,
    }


class meetingNoteSubpoint(object):
    props = {
        'text': Edm.String,
        'title': Edm.String,
    }


class meetingPolicyUpdatedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'meetingChatEnabled': Edm.Boolean,
        'meetingChatId': Edm.String,
    }


class membersAddedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'members': Collection,
        'visibleHistoryStartDateTime': Edm.DateTimeOffset,
    }


class membersDeletedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'members': Collection,
    }


class membersJoinedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'members': Collection,
    }


class membersLeftEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'members': Collection,
    }


class messagePinnedEventMessageDetail(object):
    props = {
        'eventDateTime': Edm.DateTimeOffset,
        'initiator': identitySet,
    }


class messageUnpinnedEventMessageDetail(object):
    props = {
        'eventDateTime': Edm.DateTimeOffset,
        'initiator': identitySet,
    }


class operationError(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
    }


class personalTeamsAppInstallationScopeInfo(object):
    props = {
        'userId': Edm.String,
    }


class provisionChannelEmailResult(object):
    props = {
        'email': Edm.String,
    }


class tabUpdatedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'tabId': Edm.String,
    }


class teamArchivedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamId': Edm.String,
    }


class teamClassSettings(object):
    props = {
        'notifyGuardiansAboutAssignments': Edm.Boolean,
    }


class teamCreatedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamDescription': Edm.String,
        'teamDisplayName': Edm.String,
        'teamId': Edm.String,
    }


class teamDescriptionUpdatedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamDescription': Edm.String,
        'teamId': Edm.String,
    }


class teamJoiningDisabledEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamId': Edm.String,
    }


class teamJoiningEnabledEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamId': Edm.String,
    }


class teamMembersNotificationRecipient(object):
    props = {
        'teamId': Edm.String,
    }


class teamRenamedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamDisplayName': Edm.String,
        'teamId': Edm.String,
    }


class teamsAppPermissionSet(object):
    props = {
        'resourceSpecificPermissions': Collection,
    }


class teamsAppDashboardCardBotConfiguration(object):
    props = {
        'botId': Edm.String,
    }


class teamsAppDashboardCardContentSource(object):
    props = {
        'botConfiguration': teamsAppDashboardCardBotConfiguration,
        'sourceType': teamsAppDashboardCardSourceType,
    }


class teamsAppDashboardCardIcon(object):
    props = {
        'iconUrl': Edm.String,
        'officeUIFabricIconName': Edm.String,
    }


class teamsAppInstalledEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamsAppDisplayName': Edm.String,
        'teamsAppId': Edm.String,
    }


class teamsAppResourceSpecificPermission(object):
    props = {
        'permissionType': teamsAppResourceSpecificPermissionType,
        'permissionValue': Edm.String,
    }


class teamsAppRemovedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamsAppDisplayName': Edm.String,
        'teamsAppId': Edm.String,
    }


class teamsAppUpgradedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamsAppDisplayName': Edm.String,
        'teamsAppId': Edm.String,
    }


class teamsLicensingDetails(object):
    props = {
        'hasTeamsLicense': Edm.Boolean,
    }


class teamsTabConfiguration(object):
    props = {
        'contentUrl': Edm.String,
        'entityId': Edm.String,
        'removeUrl': Edm.String,
        'websiteUrl': Edm.String,
    }


class teamTeamsAppInstallationScopeInfo(object):
    props = {
        'teamId': Edm.String,
    }


class teamUnarchivedEventMessageDetail(object):
    props = {
        'initiator': identitySet,
        'teamId': Edm.String,
    }


class teamworkOnPremisesCalendarSyncConfiguration(object):
    props = {
        'domain': Edm.String,
        'domainUserName': Edm.String,
        'smtpAddress': Edm.String,
    }


class teamworkActivePeripherals(object):
    props = {

    }


class teamworkActivityTopic(object):
    props = {
        'source': teamworkActivityTopicSource,
        'value': Edm.String,
        'webUrl': Edm.String,
    }


class teamworkApplicationIdentity(object):
    props = {
        'applicationIdentityType': teamworkApplicationIdentityType,
    }


class teamworkContentCameraConfiguration(object):
    props = {
        'isContentCameraInverted': Edm.Boolean,
        'isContentCameraOptional': Edm.Boolean,
        'isContentEnhancementEnabled': Edm.Boolean,
    }


class teamworkConfiguredPeripheral(object):
    props = {
        'isOptional': Edm.Boolean,
    }


class teamworkConnection(object):
    props = {
        'connectionStatus': teamworkConnectionStatus,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class teamworkDateTimeConfiguration(object):
    props = {
        'dateFormat': Edm.String,
        'officeHoursEndTime': Edm.TimeOfDay,
        'officeHoursStartTime': Edm.TimeOfDay,
        'timeFormat': Edm.String,
        'timeZone': Edm.String,
    }


class teamworkDeviceSoftwareVersions(object):
    props = {
        'adminAgentSoftwareVersion': Edm.String,
        'firmwareSoftwareVersion': Edm.String,
        'operatingSystemSoftwareVersion': Edm.String,
        'partnerAgentSoftwareVersion': Edm.String,
        'teamsClientSoftwareVersion': Edm.String,
    }


class teamworkDisplayScreenConfiguration(object):
    props = {
        'backlightBrightness': Edm.Int32,
        'backlightTimeout': Edm.Duration,
        'isHighContrastEnabled': Edm.Boolean,
        'isScreensaverEnabled': Edm.Boolean,
        'screensaverTimeout': Edm.Duration,
    }


class teamworkFeaturesConfiguration(object):
    props = {
        'emailToSendLogsAndFeedback': Edm.String,
        'isAutoScreenShareEnabled': Edm.Boolean,
        'isBluetoothBeaconingEnabled': Edm.Boolean,
        'isHideMeetingNamesEnabled': Edm.Boolean,
        'isSendLogsAndFeedbackEnabled': Edm.Boolean,
    }


class teamworkHardwareConfiguration(object):
    props = {
        'processorModel': Edm.String,
    }


class teamworkHardwareDetail(object):
    props = {
        'macAddresses': Collection,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'serialNumber': Edm.String,
        'uniqueId': Edm.String,
    }


class teamworkPeripheralHealth(object):
    props = {
        'connection': teamworkConnection,
        'isOptional': Edm.Boolean,
    }


class teamworkLoginStatus(object):
    props = {
        'exchangeConnection': teamworkConnection,
        'skypeConnection': teamworkConnection,
        'teamsConnection': teamworkConnection,
    }


class teamworkMicrophoneConfiguration(object):
    props = {
        'isMicrophoneOptional': Edm.Boolean,
    }


class teamworkNetworkConfiguration(object):
    props = {
        'defaultGateway': Edm.String,
        'domainName': Edm.String,
        'hostName': Edm.String,
        'ipAddress': Edm.String,
        'isDhcpEnabled': Edm.Boolean,
        'isPCPortEnabled': Edm.Boolean,
        'primaryDns': Edm.String,
        'secondaryDns': Edm.String,
        'subnetMask': Edm.String,
    }


class teamworkOnlineMeetingInfo(object):
    props = {
        'calendarEventId': Edm.String,
        'joinWebUrl': Edm.String,
        'organizer': teamworkUserIdentity,
    }


class teamworkPeripheralsHealth(object):
    props = {
        'communicationSpeakerHealth': teamworkPeripheralHealth,
        'contentCameraHealth': teamworkPeripheralHealth,
        'displayHealthCollection': Collection,
        'microphoneHealth': teamworkPeripheralHealth,
        'roomCameraHealth': teamworkPeripheralHealth,
        'speakerHealth': teamworkPeripheralHealth,
    }


class teamworkSoftwareUpdateStatus(object):
    props = {
        'availableVersion': Edm.String,
        'currentVersion': Edm.String,
        'softwareFreshness': teamworkSoftwareFreshness,
    }


class teamworkSpeakerConfiguration(object):
    props = {
        'isCommunicationSpeakerOptional': Edm.Boolean,
        'isSpeakerOptional': Edm.Boolean,
    }


class teamworkSystemConfiguration(object):
    props = {
        'dateTimeConfiguration': teamworkDateTimeConfiguration,
        'defaultPassword': Edm.String,
        'deviceLockTimeout': Edm.Duration,
        'isDeviceLockEnabled': Edm.Boolean,
        'isLoggingEnabled': Edm.Boolean,
        'isPowerSavingEnabled': Edm.Boolean,
        'isScreenCaptureEnabled': Edm.Boolean,
        'isSilentModeEnabled': Edm.Boolean,
        'language': Edm.String,
        'lockPin': Edm.String,
        'loggingLevel': Edm.String,
        'networkConfiguration': teamworkNetworkConfiguration,
    }


class scheduleEntity(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'theme': scheduleEntityTheme,
    }


class shiftItem(object):
    props = {
        'activities': Collection,
        'displayName': Edm.String,
        'notes': Edm.String,
    }


class openShiftItem(object):
    props = {
        'openSlotCount': Edm.Int32,
    }


class schedulingGroupInfo(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'schedulingGroupId': Edm.String,
    }


class shiftActivity(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'isPaid': Edm.Boolean,
        'startDateTime': Edm.DateTimeOffset,
        'theme': scheduleEntityTheme,
    }


class timeRange(object):
    props = {
        'endTime': Edm.TimeOfDay,
        'startTime': Edm.TimeOfDay,
    }


class shiftsRolePermission(object):
    props = {
        'allowedResourceActions': Collection,
    }


class shiftsTeamInfo(object):
    props = {
        'displayName': Edm.String,
        'teamId': Edm.String,
    }


class shiftsUserInfo(object):
    props = {
        'displayName': Edm.String,
        'userId': Edm.String,
    }


class timeCardEvent(object):
    props = {
        'atApprovedLocation': Edm.Boolean,
        'dateTime': Edm.DateTimeOffset,
        'isAtApprovedLocation': Edm.Boolean,
        'notes': itemBody,
    }


class timeCardEntry(object):
    props = {
        'breaks': Collection,
        'clockInEvent': timeCardEvent,
        'clockOutEvent': timeCardEvent,
    }


class timeClockSettings(object):
    props = {
        'approvedLocation': geoCoordinates,
    }


class timeOffItem(object):
    props = {
        'timeOffReasonId': Edm.String,
    }


class workforceIntegrationEncryption(object):
    props = {
        'protocol': workforceIntegrationEncryptionProtocol,
        'secret': Edm.String,
    }


class threatAssessmentRequestsCount(object):
    props = {
        'count': Edm.Int64,
        'createdDateTime': Edm.DateTimeOffset,
        'pivotValue': Edm.String,
    }


class attachmentInfo(object):
    props = {
        'attachmentType': attachmentType,
        'contentType': Edm.String,
        'name': Edm.String,
        'size': Edm.Int64,
    }


class engagementUploadSession(object):
    props = {
        'id': Edm.String,
    }


class agentReference(object):
    props = {
        'path': Edm.String,
    }


class healthMonitoring_resourceImpactSummary(object):
    props = {
        'impactedCount': Edm.String,
        'impactedCountLimitExceeded': Edm.Boolean,
        'resourceType': Edm.String,
    }


class healthMonitoring_directoryObjectImpactSummary(object):
    props = {

    }


class healthMonitoring_applicationImpactSummary(object):
    props = {

    }


class healthMonitoring_deviceImpactSummary(object):
    props = {

    }


class healthMonitoring_Dictionary(object):
    props = {

    }


class healthMonitoring_healthMonitoringDictionary(object):
    props = {

    }


class healthMonitoring_documentation(object):
    props = {

    }


class healthMonitoring_emailNotificationConfiguration(object):
    props = {
        'groupId': Edm.String,
        'isEnabled': Edm.Boolean,
    }


class healthMonitoring_enrichment(object):
    props = {
        'impacts': Collection,
        'state': Collection, #extnamespace: healthMonitoring_enrichmentState,
        'supportingData': Collection, #extnamespace: healthMonitoring_supportingData,
    }


class healthMonitoring_supportingData(object):
    props = {

    }


class healthMonitoring_groupImpactSummary(object):
    props = {

    }


class healthMonitoring_servicePrincipalImpactSummary(object):
    props = {

    }


class healthMonitoring_signals(object):
    props = {

    }


class healthMonitoring_userImpactSummary(object):
    props = {

    }


class networkaccess_alertAction(object):
    props = {
        'actionLink': Edm.String,
        'actionText': Edm.String,
    }


class networkaccess_alertFrequencyPoint(object):
    props = {
        'highSeverityCount': Edm.Int64,
        'informationalSeverityCount': Edm.Int64,
        'lowSeverityCount': Edm.Int64,
        'mediumSeverityCount': Edm.Int64,
        'timeStampDateTime': Edm.DateTimeOffset,
    }


class networkaccess_alertSeveritySummary(object):
    props = {
        'count': Edm.Int64,
        'severity': Collection, #extnamespace: networkaccess_alertSeverity,
    }


class networkaccess_alertSummary(object):
    props = {
        'alertType': Collection, #extnamespace: networkaccess_alertType,
        'count': Edm.Int64,
        'severity': Collection, #extnamespace: networkaccess_alertSeverity,
    }


class networkaccess_applicationSnapshot(object):
    props = {
        'appId': Edm.String,
    }


class networkaccess_crossTenantAccess(object):
    props = {
        'deviceCount': Edm.Int64,
        'lastAccessDateTime': Edm.DateTimeOffset,
        'resourceTenantId': Edm.String,
        'resourceTenantName': Edm.String,
        'resourceTenantPrimaryDomain': Edm.String,
        'usageStatus': Collection, #extnamespace: networkaccess_usageStatus,
        'userCount': Edm.Int64,
    }


class networkaccess_crossTenantSummary(object):
    props = {
        'authTransactionCount': Edm.Int32,
        'deviceCount': Edm.Int32,
        'newTenantCount': Edm.Int32,
        'rarelyUsedTenantCount': Edm.Int32,
        'tenantCount': Edm.Int32,
        'userCount': Edm.Int32,
    }


class networkaccess_destination(object):
    props = {
        'deviceCount': Edm.Int32,
        'firstAccessDateTime': Edm.DateTimeOffset,
        'fqdn': Edm.String,
        'ip': Edm.String,
        'lastAccessDateTime': Edm.DateTimeOffset,
        'networkingProtocol': Collection, #extnamespace: networkaccess_networkingProtocol,
        'port': Edm.Int32,
        'threatCount': Edm.Int32,
        'totalBytesReceived': Edm.Int64,
        'totalBytesSent': Edm.Int64,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
        'transactionCount': Edm.Int32,
        'userCount': Edm.Int32,
    }


class networkaccess_destinationSummary(object):
    props = {
        'count': Edm.Int64,
        'destination': Edm.String,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
    }


class networkaccess_device(object):
    props = {
        'deviceId': Edm.String,
        'displayName': Edm.String,
        'isCompliant': Edm.Boolean,
        'lastAccessDateTime': Edm.DateTimeOffset,
        'operatingSystem': Edm.String,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
    }


class networkaccess_deviceUsageSummary(object):
    props = {
        'activeDeviceCount': Edm.Int32,
        'inactiveDeviceCount': Edm.Int32,
        'totalDeviceCount': Edm.Int32,
    }


class networkaccess_discoveredApplicationSegmentReport(object):
    props = {
        'accessType': Collection, #extnamespace: networkaccess_accessType,
        'deviceCount': Edm.Int32,
        'discoveredApplicationSegmentId': Edm.String,
        'firstAccessDateTime': Edm.DateTimeOffset,
        'fqdn': Edm.String,
        'ip': Edm.String,
        'lastAccessDateTime': Edm.DateTimeOffset,
        'port': Edm.Int32,
        'totalBytesReceived': Edm.Int64,
        'totalBytesSent': Edm.Int64,
        'transactionCount': Edm.Int32,
        'transportProtocol': Collection, #extnamespace: networkaccess_networkingProtocol,
        'userCount': Edm.Int32,
    }


class networkaccess_entitiesSummary(object):
    props = {
        'deviceCount': Edm.Int64,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
        'userCount': Edm.Int64,
        'workloadCount': Edm.Int64,
    }


class networkaccess_extendedProperties(object):
    props = {

    }


class networkaccess_headers(object):
    props = {
        'origin': Edm.String,
        'referrer': Edm.String,
        'xForwardedFor': Edm.String,
    }


class networkaccess_privateAccessDetails(object):
    props = {
        'accessType': Collection, #extnamespace: networkaccess_accessType,
        'appSegmentId': Edm.String,
        'connectionStatus': Collection, #extnamespace: networkaccess_connectionStatus,
        'connectorId': Edm.String,
        'connectorIp': Edm.String,
        'connectorName': Edm.String,
        'processingRegion': Edm.String,
        'thirdPartyTokenDetails': Collection, #extnamespace: networkaccess_thirdPartyTokenDetails,
    }


class networkaccess_thirdPartyTokenDetails(object):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'issuedAtDateTime': Edm.DateTimeOffset,
        'uniqueTokenIdentifier': Edm.String,
        'validFromDateTime': Edm.DateTimeOffset,
    }


class networkaccess_relatedResource(object):
    props = {

    }


class networkaccess_relatedDestination(object):
    props = {
        'fqdn': Edm.String,
        'ip': Edm.String,
        'networkingProtocol': Collection, #extnamespace: networkaccess_networkingProtocol,
        'port': Edm.Int32,
    }


class networkaccess_relatedDevice(object):
    props = {
        'deviceId': Edm.String,
    }


class networkaccess_relatedFile(object):
    props = {
        'directory': Edm.String,
        'name': Edm.String,
        'sizeInBytes': Edm.Int64,
    }


class networkaccess_relatedFileHash(object):
    props = {
        'algorithm': Collection, #extnamespace: networkaccess_algorithm,
        'value': Edm.String,
    }


class networkaccess_relatedMalware(object):
    props = {
        'category': Collection, #extnamespace: networkaccess_malwareCategory,
        'name': Edm.String,
        'severity': Collection, #extnamespace: networkaccess_threatSeverity,
    }


class networkaccess_relatedRemoteNetwork(object):
    props = {
        'remoteNetworkId': Edm.String,
    }


class networkaccess_relatedTenant(object):
    props = {
        'tenantId': Edm.String,
    }


class networkaccess_relatedThreatIntelligence(object):
    props = {
        'threatCount': Edm.Int64,
    }


class networkaccess_relatedToken(object):
    props = {
        'uniqueTokenIdentifier': Edm.String,
    }


class networkaccess_relatedTransaction(object):
    props = {
        'transactionId': Edm.String,
    }


class networkaccess_relatedUrl(object):
    props = {
        'url': Edm.String,
    }


class networkaccess_relatedUser(object):
    props = {
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class networkaccess_relatedWebCategory(object):
    props = {
        'webCategoryName': Edm.String,
    }


class networkaccess_ruleDestination(object):
    props = {

    }


class networkaccess_tlsDetails(object):
    props = {
        'action': Collection, #extnamespace: networkaccess_tlsAction,
        'policyId': Edm.String,
        'policyName': Edm.String,
        'status': Collection, #extnamespace: networkaccess_tlsStatus,
    }


class networkaccess_transactionSummary(object):
    props = {
        'blockedCount': Edm.Int32,
        'totalCount': Edm.Int32,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
    }


class networkaccess_usageProfilingPoint(object):
    props = {
        'internetAccessTrafficCount': Edm.Int64,
        'microsoft365AccessTrafficCount': Edm.Int64,
        'privateAccessTrafficCount': Edm.Int64,
        'timeStampDateTime': Edm.DateTimeOffset,
        'totalTrafficCount': Edm.Int64,
    }


class networkaccess_user(object):
    props = {
        'displayName': Edm.String,
        'firstAccessDateTime': Edm.DateTimeOffset,
        'lastAccessDateTime': Edm.DateTimeOffset,
        'totalBytesReceived': Edm.Int64,
        'totalBytesSent': Edm.Int64,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
        'transactionCount': Edm.Int64,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'userType': Collection, #extnamespace: networkaccess_userType,
    }


class networkaccess_webCategoriesSummary(object):
    props = {
        'action': Collection, #extnamespace: networkaccess_filteringPolicyAction,
        'deviceCount': Edm.Int64,
        'transactionCount': Edm.Int64,
        'userCount': Edm.Int64,
        'webCategory': Collection, #extnamespace: networkaccess_webCategory,
    }


class networkaccess_webCategory(object):
    props = {
        'displayName': Edm.String,
        'group': Edm.String,
        'name': Edm.String,
    }


class networkaccess_association(object):
    props = {

    }


class networkaccess_associatedBranch(object):
    props = {
        'branchId': Edm.String,
    }


class networkaccess_bgpConfiguration(object):
    props = {
        'asn': Edm.Int32,
        'ipAddress': Edm.String,
        'localIpAddress': Edm.String,
        'peerIpAddress': Edm.String,
    }


class networkaccess_enrichedAuditLogsSettings(object):
    props = {
        'status': Collection, #extnamespace: networkaccess_status,
    }


class networkaccess_fqdn(object):
    props = {
        'value': Edm.String,
    }


class networkaccess_ipAddress(object):
    props = {
        'value': Edm.String,
    }


class networkaccess_ipRange(object):
    props = {
        'beginAddress': Edm.String,
        'endAddress': Edm.String,
    }


class networkaccess_ipSubnet(object):
    props = {
        'value': Edm.String,
    }


class networkaccess_localConnectivityConfiguration(object):
    props = {
        'asn': Edm.Int32,
        'bgpAddress': Edm.String,
        'endpoint': Edm.String,
        'region': Collection, #extnamespace: networkaccess_region,
    }


class networkaccess_peerConnectivityConfiguration(object):
    props = {
        'asn': Edm.Int32,
        'bgpAddress': Edm.String,
        'endpoint': Edm.String,
    }


class networkaccess_policyRuleDelta(object):
    props = {
        'action': Collection, #extnamespace: networkaccess_forwardingRuleAction,
        'ruleId': Edm.String,
    }


class networkaccess_redundancyConfiguration(object):
    props = {
        'redundancyTier': Collection, #extnamespace: networkaccess_redundancyTier,
        'zoneLocalIpAddress': Edm.String,
    }


class networkaccess_tunnelConfiguration(object):
    props = {
        'preSharedKey': Edm.String,
        'zoneRedundancyPreSharedKey': Edm.String,
    }


class networkaccess_tunnelConfigurationIKEv2Custom(object):
    props = {
        'dhGroup': Collection, #extnamespace: networkaccess_dhGroup,
        'ikeEncryption': Collection, #extnamespace: networkaccess_ikeEncryption,
        'ikeIntegrity': Collection, #extnamespace: networkaccess_ikeIntegrity,
        'ipSecEncryption': Collection, #extnamespace: networkaccess_ipSecEncryption,
        'ipSecIntegrity': Collection, #extnamespace: networkaccess_ipSecIntegrity,
        'pfsGroup': Collection, #extnamespace: networkaccess_pfsGroup,
        'saLifeTimeSeconds': Edm.Int64,
    }


class networkaccess_tunnelConfigurationIKEv2Default(object):
    props = {

    }


class networkaccess_url(object):
    props = {
        'value': Edm.String,
    }


class cloudLicensing_groupCloudLicensing(object):
    props = {

    }


class cloudLicensing_userCloudLicensing(object):
    props = {

    }


class cloudLicensing_service(object):
    props = {
        'assignableTo': Collection, #extnamespace: cloudLicensing_assigneeTypes,
        'planId': Edm.Guid,
        'planName': Edm.String,
    }


class ediscovery_ocrSettings(object):
    props = {
        'isEnabled': Edm.Boolean,
        'maxImageSize': Edm.Int32,
        'timeout': Edm.Duration,
    }


class ediscovery_redundancyDetectionSettings(object):
    props = {
        'isEnabled': Edm.Boolean,
        'maxWords': Edm.Int32,
        'minWords': Edm.Int32,
        'similarityThreshold': Edm.Int32,
    }


class ediscovery_topicModelingSettings(object):
    props = {
        'dynamicallyAdjustTopicCount': Edm.Boolean,
        'ignoreNumbers': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'topicCount': Edm.Int32,
    }


class security_exportFileMetadata(object):
    props = {
        'downloadUrl': Edm.String,
        'fileName': Edm.String,
        'size': Edm.Int64,
    }


class security_ocrSettings(object):
    props = {
        'isEnabled': Edm.Boolean,
        'maxImageSize': Edm.Int32,
        'timeout': Edm.Duration,
    }


class security_redundancyDetectionSettings(object):
    props = {
        'isEnabled': Edm.Boolean,
        'maxWords': Edm.Int32,
        'minWords': Edm.Int32,
        'similarityThreshold': Edm.Int32,
    }


class security_stringValueDictionary(object):
    props = {

    }


class security_topicModelingSettings(object):
    props = {
        'dynamicallyAdjustTopicCount': Edm.Boolean,
        'ignoreNumbers': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'topicCount': Edm.Int32,
    }


class security_deploymentAccessKeyType(object):
    props = {
        'deploymentAccessKey': Edm.String,
    }


class security_sensorDeploymentPackage(object):
    props = {
        'downloadUrl': Edm.String,
        'version': Edm.String,
    }


class security_sensorSettings(object):
    props = {
        'description': Edm.String,
        'domainControllerDnsNames': Collection,
        'isDelayedDeploymentEnabled': Edm.Boolean,
    }


class security_informationProtectionAction(object):
    props = {

    }


class security_addContentFooterAction(object):
    props = {
        'alignment': contentAlignment,
        'fontColor': Edm.String,
        'fontName': Edm.String,
        'fontSize': Edm.Int32,
        'margin': Edm.Int32,
        'text': Edm.String,
        'uiElementName': Edm.String,
    }


class security_addContentHeaderAction(object):
    props = {
        'alignment': contentAlignment,
        'fontColor': Edm.String,
        'fontName': Edm.String,
        'fontSize': Edm.Int32,
        'margin': Edm.Int32,
        'text': Edm.String,
        'uiElementName': Edm.String,
    }


class security_addWatermarkAction(object):
    props = {
        'fontColor': Edm.String,
        'fontName': Edm.String,
        'fontSize': Edm.Int32,
        'layout': watermarkLayout,
        'text': Edm.String,
        'uiElementName': Edm.String,
    }


class security_applyLabelAction(object):
    props = {
        'actions': Collection,
        'actionSource': actionSource,
        'responsibleSensitiveTypeIds': Collection,
        'sensitivityLabelId': Edm.String,
    }


class security_bufferDecryptionResult(object):
    props = {
        'decryptedBuffer': Edm.Binary,
    }


class security_bufferEncryptionResult(object):
    props = {
        'encryptedBuffer': Edm.Binary,
        'publishingLicense': Edm.Binary,
    }


class security_classificationResult(object):
    props = {
        'confidenceLevel': Edm.Int32,
        'count': Edm.Int32,
        'sensitiveTypeId': Edm.String,
    }


class security_contentInfo(object):
    props = {
        'contentFormat': Edm.String,
        'identifier': Edm.String,
        'metadata': Collection,
        'state': contentState,
    }


class security_keyValuePair(object):
    props = {
        'name': Edm.String,
        'value': Edm.String,
    }


class security_contentLabel(object):
    props = {
        'assignmentMethod': assignmentMethod,
        'createdDateTime': Edm.DateTimeOffset,
        'sensitivityLabelId': Edm.String,
    }


class security_customAction(object):
    props = {
        'name': Edm.String,
        'properties': Collection,
    }


class security_downgradeJustification(object):
    props = {
        'isDowngradeJustified': Edm.Boolean,
        'justificationMessage': Edm.String,
    }


class security_justifyAction(object):
    props = {

    }


class security_labelingOptions(object):
    props = {
        'assignmentMethod': assignmentMethod,
        'downgradeJustification': downgradeJustification,
        'extendedProperties': Collection,
        'labelId': Edm.String,
    }


class security_metadataAction(object):
    props = {
        'metadataToAdd': Collection,
        'metadataToRemove': Collection,
    }


class security_protectAdhocAction(object):
    props = {

    }


class security_protectByTemplateAction(object):
    props = {
        'templateId': Edm.String,
    }


class security_protectDoNotForwardAction(object):
    props = {

    }


class security_recommendLabelAction(object):
    props = {
        'actions': Collection,
        'actionSource': actionSource,
        'responsibleSensitiveTypeIds': Collection,
        'sensitivityLabelId': Edm.String,
    }


class security_removeContentFooterAction(object):
    props = {
        'uiElementNames': Collection,
    }


class security_removeContentHeaderAction(object):
    props = {
        'uiElementNames': Collection,
    }


class security_removeProtectionAction(object):
    props = {

    }


class security_removeWatermarkAction(object):
    props = {
        'uiElementNames': Collection,
    }


class security_signingResult(object):
    props = {
        'signature': Edm.Binary,
        'signingKeyId': Edm.String,
    }


class security_verificationResult(object):
    props = {
        'signatureValid': Edm.Boolean,
    }


class security_auditData(object):
    props = {

    }


class security_aadRiskDetectionAuditRecord(object):
    props = {

    }


class security_aedAuditRecord(object):
    props = {

    }


class security_aiAppInteractionAuditRecord(object):
    props = {

    }


class security_aipFileDeleted(object):
    props = {

    }


class security_aipHeartBeat(object):
    props = {

    }


class security_aipProtectionActionLogRequest(object):
    props = {

    }


class security_aipScannerDiscoverEvent(object):
    props = {

    }


class security_aipSensitivityLabelActionLogRequest(object):
    props = {

    }


class security_airAdminActionInvestigationData(object):
    props = {

    }


class security_airInvestigationData(object):
    props = {

    }


class security_airManualInvestigationData(object):
    props = {

    }


class security_attackSimAdminAuditRecord(object):
    props = {

    }


class security_auditSearchAuditRecord(object):
    props = {

    }


class security_azureActiveDirectoryAccountLogonAuditRecord(object):
    props = {

    }


class security_azureActiveDirectoryAuditRecord(object):
    props = {

    }


class security_azureActiveDirectoryBaseAuditRecord(object):
    props = {

    }


class security_azureActiveDirectoryStsLogonAuditRecord(object):
    props = {

    }


class security_campaignAuditRecord(object):
    props = {

    }


class security_caseAuditRecord(object):
    props = {

    }


class security_caseInvestigation(object):
    props = {

    }


class security_cdpColdCrawlStatusRecord(object):
    props = {

    }


class security_cdpContentExplorerAggregateRecord(object):
    props = {

    }


class security_cdpDlpSensitiveAuditRecord(object):
    props = {

    }


class security_cdpDlpSensitiveEndpointAuditRecord(object):
    props = {

    }


class security_cdpLogRecord(object):
    props = {

    }


class security_cdpOcrBillingRecord(object):
    props = {

    }


class security_cdpResourceScopeChangeEventRecord(object):
    props = {

    }


class security_cernerSMSLinkRecord(object):
    props = {

    }


class security_cernerSMSSettingsUpdateRecord(object):
    props = {

    }


class security_cernerSMSUnlinkRecord(object):
    props = {

    }


class security_complianceConnectorAuditRecord(object):
    props = {

    }


class security_complianceDLMExchangeAuditRecord(object):
    props = {

    }


class security_complianceDLMSharePointAuditRecord(object):
    props = {

    }


class security_complianceDlpApplicationsAuditRecord(object):
    props = {

    }


class security_complianceDlpApplicationsClassificationAuditRecord(object):
    props = {

    }


class security_complianceDlpBaseAuditRecord(object):
    props = {

    }


class security_complianceDlpClassificationBaseAuditRecord(object):
    props = {

    }


class security_complianceDlpClassificationBaseCdpRecord(object):
    props = {

    }


class security_complianceDlpEndpointAuditRecord(object):
    props = {

    }


class security_complianceDlpEndpointDiscoveryAuditRecord(object):
    props = {

    }


class security_complianceDlpExchangeAuditRecord(object):
    props = {

    }


class security_complianceDlpExchangeClassificationAuditRecord(object):
    props = {

    }


class security_complianceDlpExchangeClassificationCdpRecord(object):
    props = {

    }


class security_complianceDlpExchangeDiscoveryAuditRecord(object):
    props = {

    }


class security_complianceDlpSharePointAuditRecord(object):
    props = {

    }


class security_complianceDlpSharePointClassificationAuditRecord(object):
    props = {

    }


class security_complianceDlpSharePointClassificationExtendedAuditRecord(object):
    props = {

    }


class security_complianceManagerActionRecord(object):
    props = {

    }


class security_complianceSupervisionBaseAuditRecord(object):
    props = {

    }


class security_complianceSupervisionExchangeAuditRecord(object):
    props = {

    }


class security_consumptionResourceAuditRecord(object):
    props = {

    }


class security_copilotInteractionAuditRecord(object):
    props = {

    }


class security_coreReportingSettingsAuditRecord(object):
    props = {

    }


class security_cortanaBriefingAuditRecord(object):
    props = {

    }


class security_cpsCommonPolicyAuditRecord(object):
    props = {

    }


class security_cpsPolicyConfigAuditRecord(object):
    props = {

    }


class security_crmBaseAuditRecord(object):
    props = {

    }


class security_crmEntityOperationAuditRecord(object):
    props = {

    }


class security_customerKeyServiceEncryptionAuditRecord(object):
    props = {

    }


class security_dataCenterSecurityBaseAuditRecord(object):
    props = {

    }


class security_dataCenterSecurityCmdletAuditRecord(object):
    props = {

    }


class security_dataGovernanceAuditRecord(object):
    props = {

    }


class security_dataInsightsRestApiAuditRecord(object):
    props = {

    }


class security_dataLakeExportOperationAuditRecord(object):
    props = {

    }


class security_dataShareOperationAuditRecord(object):
    props = {

    }


class security_defaultAuditData(object):
    props = {

    }


class security_defenderSecurityAlertBaseRecord(object):
    props = {

    }


class security_deleteCertificateRecord(object):
    props = {

    }


class security_disableConsentRecord(object):
    props = {

    }


class security_discoveryAuditRecord(object):
    props = {

    }


class security_dlpEndpointAuditRecord(object):
    props = {

    }


class security_dlpSensitiveInformationTypeCmdletRecord(object):
    props = {

    }


class security_dlpSensitiveInformationTypeRulePackageCmdletRecord(object):
    props = {

    }


class security_downloadCertificateRecord(object):
    props = {

    }


class security_dynamics365BusinessCentralAuditRecord(object):
    props = {

    }


class security_enableConsentRecord(object):
    props = {

    }


class security_epicSMSLinkRecord(object):
    props = {

    }


class security_epicSMSSettingsUpdateRecord(object):
    props = {

    }


class security_epicSMSUnlinkRecord(object):
    props = {

    }


class security_exchangeAdminAuditRecord(object):
    props = {

    }


class security_exchangeAggregatedMailboxAuditRecord(object):
    props = {

    }


class security_exchangeAggregatedOperationRecord(object):
    props = {

    }


class security_exchangeMailboxAuditBaseRecord(object):
    props = {

    }


class security_exchangeMailboxAuditGroupRecord(object):
    props = {

    }


class security_exchangeMailboxAuditRecord(object):
    props = {

    }


class security_fhirBaseUrlAddRecord(object):
    props = {

    }


class security_fhirBaseUrlApproveRecord(object):
    props = {

    }


class security_fhirBaseUrlDeleteRecord(object):
    props = {

    }


class security_fhirBaseUrlUpdateRecord(object):
    props = {

    }


class security_healthcareSignalRecord(object):
    props = {

    }


class security_hostedRpaAuditRecord(object):
    props = {

    }


class security_hrSignalAuditRecord(object):
    props = {

    }


class security_hygieneEventRecord(object):
    props = {

    }


class security_informationBarrierPolicyApplicationAuditRecord(object):
    props = {

    }


class security_informationWorkerProtectionAuditRecord(object):
    props = {

    }


class security_insiderRiskScopedUserInsightsRecord(object):
    props = {

    }


class security_insiderRiskScopedUsersRecord(object):
    props = {

    }


class security_irmSecurityAlertRecord(object):
    props = {

    }


class security_irmUserDefinedDetectionRecord(object):
    props = {

    }


class security_kaizalaAuditRecord(object):
    props = {

    }


class security_labelAnalyticsAggregateAuditRecord(object):
    props = {

    }


class security_labelContentExplorerAuditRecord(object):
    props = {

    }


class security_largeContentMetadataAuditRecord(object):
    props = {

    }


class security_m365ComplianceConnectorAuditRecord(object):
    props = {

    }


class security_m365DAADAuditRecord(object):
    props = {

    }


class security_mailSubmissionData(object):
    props = {

    }


class security_managedServicesAuditRecord(object):
    props = {

    }


class security_managedTenantsAuditRecord(object):
    props = {

    }


class security_mapgAlertsAuditRecord(object):
    props = {

    }


class security_mapgOnboardAuditRecord(object):
    props = {

    }


class security_mapgPolicyAuditRecord(object):
    props = {

    }


class security_mcasAlertsAuditRecord(object):
    props = {

    }


class security_mdaDataSecuritySignalRecord(object):
    props = {

    }


class security_mdatpAuditRecord(object):
    props = {

    }


class security_mdcEventsRecord(object):
    props = {

    }


class security_mdiAuditRecord(object):
    props = {

    }


class security_meshWorldsAuditRecord(object):
    props = {

    }


class security_microsoft365BackupBackupItemAuditRecord(object):
    props = {

    }


class security_microsoft365BackupBackupPolicyAuditRecord(object):
    props = {

    }


class security_microsoft365BackupRestoreItemAuditRecord(object):
    props = {

    }


class security_microsoft365BackupRestoreTaskAuditRecord(object):
    props = {

    }


class security_microsoftDefenderExpertsBaseAuditRecord(object):
    props = {

    }


class security_microsoftDefenderExpertsXDRAuditRecord(object):
    props = {

    }


class security_microsoftFlowAuditRecord(object):
    props = {

    }


class security_microsoftFormsAuditRecord(object):
    props = {

    }


class security_microsoftGraphDataConnectConsent(object):
    props = {

    }


class security_microsoftGraphDataConnectOperation(object):
    props = {

    }


class security_microsoftPurviewDataMapOperationRecord(object):
    props = {

    }


class security_microsoftPurviewMetadataPolicyOperationRecord(object):
    props = {

    }


class security_microsoftPurviewPolicyOperationRecord(object):
    props = {

    }


class security_microsoftPurviewPrivacyAuditEvent(object):
    props = {

    }


class security_microsoftStreamAuditRecord(object):
    props = {

    }


class security_microsoftTeamsAdminAuditRecord(object):
    props = {

    }


class security_microsoftTeamsAnalyticsAuditRecord(object):
    props = {

    }


class security_microsoftTeamsAuditRecord(object):
    props = {

    }


class security_microsoftTeamsDeviceAuditRecord(object):
    props = {

    }


class security_microsoftTeamsRetentionLabelActionAuditRecord(object):
    props = {

    }


class security_microsoftTeamsSensitivityLabelActionAuditRecord(object):
    props = {

    }


class security_microsoftTeamsShiftsAuditRecord(object):
    props = {

    }


class security_mipAutoLabelExchangeItemAuditRecord(object):
    props = {

    }


class security_mipAutoLabelItemAuditRecord(object):
    props = {

    }


class security_mipAutoLabelPolicyAuditRecord(object):
    props = {

    }


class security_mipAutoLabelProgressFeedbackAuditRecord(object):
    props = {

    }


class security_mipAutoLabelSharePointItemAuditRecord(object):
    props = {

    }


class security_mipAutoLabelSharePointPolicyLocationAuditRecord(object):
    props = {

    }


class security_mipAutoLabelSimulationSharePointCompletionRecord(object):
    props = {

    }


class security_mipAutoLabelSimulationSharePointProgressRecord(object):
    props = {

    }


class security_mipAutoLabelSimulationStatisticsRecord(object):
    props = {

    }


class security_mipAutoLabelSimulationStatusRecord(object):
    props = {

    }


class security_mipExactDataMatchAuditRecord(object):
    props = {

    }


class security_mipLabelAnalyticsAuditRecord(object):
    props = {

    }


class security_mipLabelAuditRecord(object):
    props = {

    }


class security_mS365DCustomDetectionAuditRecord(object):
    props = {

    }


class security_mS365DIncidentAuditRecord(object):
    props = {

    }


class security_mS365DSuppressionRuleAuditRecord(object):
    props = {

    }


class security_msdeGeneralSettingsAuditRecord(object):
    props = {

    }


class security_msdeIndicatorsSettingsAuditRecord(object):
    props = {

    }


class security_msdeResponseActionsAuditRecord(object):
    props = {

    }


class security_msdeRolesSettingsAuditRecord(object):
    props = {

    }


class security_msticNationStateNotificationRecord(object):
    props = {

    }


class security_multiStageDispositionAuditRecord(object):
    props = {

    }


class security_myAnalyticsSettingsAuditRecord(object):
    props = {

    }


class security_officeNativeAuditRecord(object):
    props = {

    }


class security_omePortalAuditRecord(object):
    props = {

    }


class security_oneDriveAuditRecord(object):
    props = {

    }


class security_onPremisesFileShareScannerDlpAuditRecord(object):
    props = {

    }


class security_onPremisesScannerDlpAuditRecord(object):
    props = {

    }


class security_onPremisesSharePointScannerDlpAuditRecord(object):
    props = {

    }


class security_owaGetAccessTokenForResourceAuditRecord(object):
    props = {

    }


class security_peopleAdminSettingsAuditRecord(object):
    props = {

    }


class security_physicalBadgingSignalAuditRecord(object):
    props = {

    }


class security_plannerCopyPlanAuditRecord(object):
    props = {

    }


class security_plannerPlanAuditRecord(object):
    props = {

    }


class security_plannerPlanListAuditRecord(object):
    props = {

    }


class security_plannerRosterAuditRecord(object):
    props = {

    }


class security_plannerRosterSensitivityLabelAuditRecord(object):
    props = {

    }


class security_plannerTaskAuditRecord(object):
    props = {

    }


class security_plannerTaskListAuditRecord(object):
    props = {

    }


class security_plannerTenantSettingsAuditRecord(object):
    props = {

    }


class security_powerAppsAuditAppRecord(object):
    props = {

    }


class security_powerAppsAuditPlanRecord(object):
    props = {

    }


class security_powerAppsAuditResourceRecord(object):
    props = {

    }


class security_powerBiAuditRecord(object):
    props = {

    }


class security_powerBiDlpAuditRecord(object):
    props = {

    }


class security_powerPagesSiteAuditRecord(object):
    props = {

    }


class security_powerPlatformAdminDlpAuditRecord(object):
    props = {

    }


class security_powerPlatformAdminEnvironmentAuditRecord(object):
    props = {

    }


class security_powerPlatformAdministratorActivityRecord(object):
    props = {

    }


class security_powerPlatformLockboxResourceAccessRequestAuditRecord(object):
    props = {

    }


class security_powerPlatformLockboxResourceCommandAuditRecord(object):
    props = {

    }


class security_powerPlatformServiceActivityAuditRecord(object):
    props = {

    }


class security_privacyDataMatchAuditRecord(object):
    props = {

    }


class security_privacyDataMinimizationRecord(object):
    props = {

    }


class security_privacyDigestEmailRecord(object):
    props = {

    }


class security_privacyOpenAccessAuditRecord(object):
    props = {

    }


class security_privacyPortalAuditRecord(object):
    props = {

    }


class security_privacyRemediationActionRecord(object):
    props = {

    }


class security_privacyRemediationRecord(object):
    props = {

    }


class security_privacyTenantAuditHistoryRecord(object):
    props = {

    }


class security_projectAuditRecord(object):
    props = {

    }


class security_projectForTheWebAssignedToMeSettingsAuditRecord(object):
    props = {

    }


class security_projectForTheWebProjectAuditRecord(object):
    props = {

    }


class security_projectForTheWebProjectSettingsAuditRecord(object):
    props = {

    }


class security_projectForTheWebRoadmapAuditRecord(object):
    props = {

    }


class security_projectForTheWebRoadmapItemAuditRecord(object):
    props = {

    }


class security_projectForTheWebRoadmapSettingsAuditRecord(object):
    props = {

    }


class security_projectForTheWebTaskAuditRecord(object):
    props = {

    }


class security_publicFolderAuditRecord(object):
    props = {

    }


class security_purviewInsiderRiskAlertsRecord(object):
    props = {

    }


class security_purviewInsiderRiskCasesRecord(object):
    props = {

    }


class security_quarantineAuditRecord(object):
    props = {

    }


class security_recordsManagementAuditRecord(object):
    props = {

    }


class security_retentionPolicyAuditRecord(object):
    props = {

    }


class security_scoreEvidence(object):
    props = {

    }


class security_scorePlatformGenericAuditRecord(object):
    props = {

    }


class security_scriptRunAuditRecord(object):
    props = {

    }


class security_searchAuditRecord(object):
    props = {

    }


class security_securityComplianceAlertRecord(object):
    props = {

    }


class security_securityComplianceCenterEOPCmdletAuditRecord(object):
    props = {

    }


class security_securityComplianceInsightsAuditRecord(object):
    props = {

    }


class security_securityComplianceRBACAuditRecord(object):
    props = {

    }


class security_securityComplianceUserChangeAuditRecord(object):
    props = {

    }


class security_sharePointAppPermissionOperationAuditRecord(object):
    props = {

    }


class security_sharePointAuditRecord(object):
    props = {

    }


class security_sharePointCommentOperationAuditRecord(object):
    props = {

    }


class security_sharePointContentTypeOperationAuditRecord(object):
    props = {

    }


class security_sharePointESignatureAuditRecord(object):
    props = {

    }


class security_sharePointFieldOperationAuditRecord(object):
    props = {

    }


class security_sharePointFileOperationAuditRecord(object):
    props = {

    }


class security_sharePointListOperationAuditRecord(object):
    props = {

    }


class security_sharePointSharingOperationAuditRecord(object):
    props = {

    }


class security_skypeForBusinessBaseAuditRecord(object):
    props = {

    }


class security_skypeForBusinessCmdletsAuditRecord(object):
    props = {

    }


class security_skypeForBusinessPSTNUsageAuditRecord(object):
    props = {

    }


class security_skypeForBusinessUsersBlockedAuditRecord(object):
    props = {

    }


class security_smsCreatePhoneNumberRecord(object):
    props = {

    }


class security_smsDeletePhoneNumberRecord(object):
    props = {

    }


class security_supervisoryReviewDayXInsightsAuditRecord(object):
    props = {

    }


class security_syntheticProbeAuditRecord(object):
    props = {

    }


class security_teamsEasyApprovalsAuditRecord(object):
    props = {

    }


class security_teamsHealthcareAuditRecord(object):
    props = {

    }


class security_teamsUpdatesAuditRecord(object):
    props = {

    }


class security_tenantAllowBlockListAuditRecord(object):
    props = {

    }


class security_threatFinderAuditRecord(object):
    props = {

    }


class security_threatIntelligenceAtpContentData(object):
    props = {

    }


class security_threatIntelligenceMailData(object):
    props = {

    }


class security_threatIntelligenceUrlClickData(object):
    props = {

    }


class security_todoAuditRecord(object):
    props = {

    }


class security_uamOperationAuditRecord(object):
    props = {

    }


class security_unifiedGroupAuditRecord(object):
    props = {

    }


class security_unifiedSimulationMatchedItemAuditRecord(object):
    props = {

    }


class security_unifiedSimulationSummaryAuditRecord(object):
    props = {

    }


class security_uploadCertificateRecord(object):
    props = {

    }


class security_urbacAssignmentAuditRecord(object):
    props = {

    }


class security_urbacEnableStateAuditRecord(object):
    props = {

    }


class security_urbacRoleAuditRecord(object):
    props = {

    }


class security_userTrainingAuditRecord(object):
    props = {

    }


class security_vfamBasePolicyAuditRecord(object):
    props = {

    }


class security_vfamCreatePolicyAuditRecord(object):
    props = {

    }


class security_vfamDeletePolicyAuditRecord(object):
    props = {

    }


class security_vfamUpdatePolicyAuditRecord(object):
    props = {

    }


class security_vivaGoalsAuditRecord(object):
    props = {

    }


class security_vivaLearningAdminAuditRecord(object):
    props = {

    }


class security_vivaLearningAuditRecord(object):
    props = {

    }


class security_vivaPulseAdminAuditRecord(object):
    props = {

    }


class security_vivaPulseOrganizerAuditRecord(object):
    props = {

    }


class security_vivaPulseReportAuditRecord(object):
    props = {

    }


class security_vivaPulseResponseAuditRecord(object):
    props = {

    }


class security_wdatpAlertsAuditRecord(object):
    props = {

    }


class security_windows365CustomerLockboxAuditRecord(object):
    props = {

    }


class security_workplaceAnalyticsAuditRecord(object):
    props = {

    }


class security_yammerAuditRecord(object):
    props = {

    }


class security_alertComment(object):
    props = {
        'comment': Edm.String,
        'createdByDisplayName': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
    }


class security_alertTemplate(object):
    props = {
        'category': Edm.String,
        'description': Edm.String,
        'impactedAssets': Collection,
        'mitreTechniques': Collection,
        'recommendedActions': Edm.String,
        'severity': alertSeverity,
        'title': Edm.String,
    }


class security_impactedAsset(object):
    props = {

    }


class security_responseAction(object):
    props = {

    }


class security_amazonResourceEvidence(object):
    props = {
        'amazonAccountId': Edm.String,
        'amazonResourceId': Edm.String,
        'resourceName': Edm.String,
        'resourceType': Edm.String,
    }


class security_emailSender(object):
    props = {
        'displayName': Edm.String,
        'domainName': Edm.String,
        'emailAddress': Edm.String,
    }


class security_azureResourceEvidence(object):
    props = {
        'resourceId': Edm.String,
        'resourceName': Edm.String,
        'resourceType': Edm.String,
    }


class security_stream(object):
    props = {
        'name': Edm.String,
    }


class security_cloudLogonRequestEvidence(object):
    props = {
        'requestId': Edm.String,
    }


class security_containerRegistryEvidence(object):
    props = {
        'registry': Edm.String,
    }


class security_loggedOnUser(object):
    props = {
        'accountName': Edm.String,
        'domainName': Edm.String,
    }


class security_dictionary(object):
    props = {

    }


class security_dynamicColumnValue(object):
    props = {

    }


class security_fileDetails(object):
    props = {
        'fileName': Edm.String,
        'filePath': Edm.String,
        'filePublisher': Edm.String,
        'fileSize': Edm.Int64,
        'issuer': Edm.String,
        'sha1': Edm.String,
        'sha256': Edm.String,
        'signer': Edm.String,
    }


class security_geoLocation(object):
    props = {
        'city': Edm.String,
        'countryName': Edm.String,
        'latitude': Edm.Double,
        'longitude': Edm.Double,
        'state': Edm.String,
    }


class security_gitHubOrganizationEvidence(object):
    props = {
        'company': Edm.String,
        'displayName': Edm.String,
        'email': Edm.String,
        'login': Edm.String,
        'orgId': Edm.String,
        'webUrl': Edm.String,
    }


class security_gitHubRepoEvidence(object):
    props = {
        'baseUrl': Edm.String,
        'login': Edm.String,
        'owner': Edm.String,
        'ownerType': Edm.String,
        'repoId': Edm.String,
    }


class security_gitHubUserEvidence(object):
    props = {
        'email': Edm.String,
        'login': Edm.String,
        'name': Edm.String,
        'userId': Edm.String,
        'webUrl': Edm.String,
    }


class security_huntingQueryResults(object):
    props = {
        'results': Collection,
        'schema': Collection,
    }


class security_huntingRowResult(object):
    props = {

    }


class security_singlePropertySchema(object):
    props = {
        'name': Edm.String,
        'type': Edm.String,
    }


class security_urlEvidence(object):
    props = {
        'url': Edm.String,
    }


class security_mailboxEvidence(object):
    props = {
        'displayName': Edm.String,
        'primaryAddress': Edm.String,
        'userAccount': userAccount,
    }


class security_userAccount(object):
    props = {
        'accountName': Edm.String,
        'azureAdUserId': Edm.String,
        'displayName': Edm.String,
        'domainName': Edm.String,
        'userPrincipalName': Edm.String,
        'userSid': Edm.String,
    }


class security_mailClusterEvidence(object):
    props = {
        'clusterBy': Edm.String,
        'clusterByValue': Edm.String,
        'emailCount': Edm.Int64,
        'networkMessageIds': Collection,
        'query': Edm.String,
        'urn': Edm.String,
    }


class security_malwareEvidence(object):
    props = {
        'category': Edm.String,
        'files': Collection,
        'name': Edm.String,
        'processes': Collection,
    }


class security_oauthApplicationEvidence(object):
    props = {
        'appId': Edm.String,
        'displayName': Edm.String,
        'objectId': Edm.String,
        'publisher': Edm.String,
    }


class security_queryCondition(object):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'queryText': Edm.String,
    }


class security_recommendedHuntingQuery(object):
    props = {
        'kqlText': Edm.String,
    }


class security_registryKeyEvidence(object):
    props = {
        'registryHive': Edm.String,
        'registryKey': Edm.String,
    }


class security_registryValueEvidence(object):
    props = {
        'mdeDeviceId': Edm.String,
        'registryHive': Edm.String,
        'registryKey': Edm.String,
        'registryValue': Edm.String,
        'registryValueName': Edm.String,
        'registryValueType': Edm.String,
    }


class security_ruleSchedule(object):
    props = {
        'nextRunDateTime': Edm.DateTimeOffset,
        'period': Edm.String,
    }


class security_securityGroupEvidence(object):
    props = {
        'displayName': Edm.String,
        'securityGroupId': Edm.String,
    }


class security_submissionMailEvidence(object):
    props = {
        'networkMessageId': Edm.String,
        'recipient': Edm.String,
        'reportType': Edm.String,
        'sender': Edm.String,
        'senderIp': Edm.String,
        'subject': Edm.String,
        'submissionDateTime': Edm.DateTimeOffset,
        'submissionId': Edm.String,
        'submitter': Edm.String,
    }


class security_analyzedEmailAuthenticationDetail(object):
    props = {
        'compositeAuthentication': Edm.String,
        'dkim': Edm.String,
        'dmarc': Edm.String,
        'senderPolicyFramework': Edm.String,
    }


class security_analyzedEmailDlpRuleInfo(object):
    props = {
        'name': Edm.String,
        'ruleId': Edm.String,
    }


class security_analyzedEmailExchangeTransportRuleInfo(object):
    props = {
        'name': Edm.String,
        'ruleId': Edm.String,
    }


class security_analyzedEmailRecipientDetail(object):
    props = {
        'ccRecipients': Collection,
        'domainName': Edm.String,
    }


class security_analyzedEmailSenderDetail(object):
    props = {
        'displayName': Edm.String,
        'domainCreationDateTime': Edm.DateTimeOffset,
        'domainName': Edm.String,
        'domainOwner': Edm.String,
        'fromAddress': Edm.String,
        'ipv4': Edm.String,
        'location': Edm.String,
        'mailFromAddress': Edm.String,
        'mailFromDomainName': Edm.String,
    }


class security_detonationBehaviourDetails(object):
    props = {
        'actionStatus': Edm.String,
        'behaviourCapability': Edm.String,
        'behaviourGroup': Edm.String,
        'details': Edm.String,
        'eventDateTime': Edm.DateTimeOffset,
        'operation': Edm.String,
        'processId': Edm.String,
        'processName': Edm.String,
        'target': Edm.String,
    }


class security_detonationChain(object):
    props = {
        'childNodes': Collection,
        'value': Edm.String,
    }


class security_detonationObservables(object):
    props = {
        'contactedIps': Collection,
        'contactedUrls': Collection,
        'droppedfiles': Collection,
    }


class security_threatDetectionDetail(object):
    props = {
        'confidenceLevel': Edm.String,
        'priorityAccountProtection': Edm.String,
        'threats': Edm.String,
    }


class security_filePlanDescriptorBase(object):
    props = {
        'displayName': Edm.String,
    }


class security_filePlanSubcategory(object):
    props = {

    }


class security_filePlanAuthority(object):
    props = {

    }


class security_filePlanCitation(object):
    props = {
        'citationJurisdiction': Edm.String,
        'citationUrl': Edm.String,
    }


class security_filePlanDepartment(object):
    props = {

    }


class security_filePlanReference(object):
    props = {

    }


class security_retentionDuration(object):
    props = {

    }


class security_retentionDurationForever(object):
    props = {

    }


class security_retentionDurationInDays(object):
    props = {
        'days': Edm.Int32,
    }


class security_attackSimulationInfo(object):
    props = {
        'attackSimDateTime': Edm.DateTimeOffset,
        'attackSimDurationTime': Edm.Duration,
        'attackSimId': Edm.Guid,
        'attackSimUserId': Edm.String,
    }


class security_submissionDetectedFile(object):
    props = {
        'fileHash': Edm.String,
        'fileName': Edm.String,
    }


class security_submissionUserIdentity(object):
    props = {
        'email': Edm.String,
    }


class security_autonomousSystem(object):
    props = {
        'name': Edm.String,
        'number': Edm.Int32,
        'organization': Edm.String,
        'value': Edm.String,
    }


class security_formattedContent(object):
    props = {
        'content': Edm.String,
        'format': contentFormat,
    }


class security_hostPortBanner(object):
    props = {
        'banner': Edm.String,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'scanProtocol': Edm.String,
        'timesObserved': Edm.Int32,
    }


class security_hostPortComponent(object):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'isRecent': Edm.Boolean,
        'lastSeenDateTime': Edm.DateTimeOffset,
    }


class security_hostSslCertificatePort(object):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'port': Edm.Int32,
    }


class security_hyperlink(object):
    props = {
        'name': Edm.String,
        'url': Edm.String,
    }


class security_intelligenceProfileCountryOrRegionOfOrigin(object):
    props = {
        'code': Edm.String,
        'label': Edm.String,
    }


class security_sslCertificateEntity(object):
    props = {
        'address': physicalAddress,
        'alternateNames': Collection,
        'commonName': Edm.String,
        'email': Edm.String,
        'givenName': Edm.String,
        'organizationName': Edm.String,
        'organizationUnitName': Edm.String,
        'serialNumber': Edm.String,
        'surname': Edm.String,
    }


class security_whoisContact(object):
    props = {
        'address': physicalAddress,
        'email': Edm.String,
        'fax': Edm.String,
        'name': Edm.String,
        'organization': Edm.String,
        'telephone': Edm.String,
    }


class security_whoisNameserver(object):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
    }


class deviceManagement_alertImpact(object):
    props = {
        'aggregationType': Collection, #extnamespace: deviceManagement_aggregationType,
        'alertImpactDetails': Collection,
        'value': Edm.Int32,
    }


class deviceManagement_notificationChannel(object):
    props = {
        'notificationChannelType': Collection, #extnamespace: deviceManagement_notificationChannelType,
        'notificationReceivers': Collection,
    }


class deviceManagement_notificationReceiver(object):
    props = {
        'contactInformation': Edm.String,
        'locale': Edm.String,
    }


class deviceManagement_portalNotification(object):
    props = {
        'alertImpact': Collection, #extnamespace: deviceManagement_alertImpact,
        'alertRecordId': Edm.String,
        'alertRuleId': Edm.String,
        'alertRuleName': Edm.String,
        'alertRuleTemplate': Collection, #extnamespace: deviceManagement_alertRuleTemplate,
        'id': Edm.String,
        'isPortalNotificationSent': Edm.Boolean,
        'severity': Collection, #extnamespace: deviceManagement_ruleSeverityType,
    }


class deviceManagement_ruleCondition(object):
    props = {
        'aggregation': Collection, #extnamespace: deviceManagement_aggregationType,
        'conditionCategory': Collection, #extnamespace: deviceManagement_conditionCategory,
        'operator': Collection, #extnamespace: deviceManagement_operatorType,
        'relationshipType': Collection, #extnamespace: deviceManagement_relationshipType,
        'thresholdValue': Edm.String,
    }


class deviceManagement_ruleThreshold(object):
    props = {
        'aggregation': Collection, #extnamespace: deviceManagement_aggregationType,
        'operator': Collection, #extnamespace: deviceManagement_operatorType,
        'target': Edm.Int32,
    }


class termStore_localizedDescription(object):
    props = {
        'description': Edm.String,
        'languageTag': Edm.String,
    }


class termStore_localizedLabel(object):
    props = {
        'isDefault': Edm.Boolean,
        'languageTag': Edm.String,
        'name': Edm.String,
    }


class termStore_localizedName(object):
    props = {
        'languageTag': Edm.String,
        'name': Edm.String,
    }


class callRecords_administrativeUnitInfo(object):
    props = {
        'id': Edm.String,
    }


class callRecords_callLogRow(object):
    props = {
        'administrativeUnitInfos': Collection,
        'id': Edm.String,
        'otherPartyCountryCode': Edm.String,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class callRecords_userAgent(object):
    props = {
        'applicationVersion': Edm.String,
        'headerValue': Edm.String,
    }


class callRecords_clientUserAgent(object):
    props = {
        'azureADAppId': Edm.String,
        'communicationServiceId': Edm.String,
        'platform': Collection, #extnamespace: callRecords_clientPlatform,
        'productFamily': Collection, #extnamespace: callRecords_productFamily,
    }


class callRecords_deviceInfo(object):
    props = {
        'captureDeviceDriver': Edm.String,
        'captureDeviceName': Edm.String,
        'captureNotFunctioningEventRatio': Edm.Single,
        'cpuInsufficentEventRatio': Edm.Single,
        'deviceClippingEventRatio': Edm.Single,
        'deviceGlitchEventRatio': Edm.Single,
        'howlingEventCount': Edm.Int32,
        'initialSignalLevelRootMeanSquare': Edm.Single,
        'lowSpeechLevelEventRatio': Edm.Single,
        'lowSpeechToNoiseEventRatio': Edm.Single,
        'micGlitchRate': Edm.Single,
        'receivedNoiseLevel': Edm.Int32,
        'receivedSignalLevel': Edm.Int32,
        'renderDeviceDriver': Edm.String,
        'renderDeviceName': Edm.String,
        'renderMuteEventRatio': Edm.Single,
        'renderNotFunctioningEventRatio': Edm.Single,
        'renderZeroVolumeEventRatio': Edm.Single,
        'sentNoiseLevel': Edm.Int32,
        'sentSignalLevel': Edm.Int32,
        'speakerGlitchRate': Edm.Single,
    }


class callRecords_directRoutingLogRow(object):
    props = {
        'calleeNumber': Edm.String,
        'callEndSubReason': Edm.Int32,
        'callerNumber': Edm.String,
        'callType': Edm.String,
        'correlationId': Edm.String,
        'duration': Edm.Int32,
        'endDateTime': Edm.DateTimeOffset,
        'failureDateTime': Edm.DateTimeOffset,
        'finalSipCode': Edm.Int32,
        'finalSipCodePhrase': Edm.String,
        'inviteDateTime': Edm.DateTimeOffset,
        'mediaBypassEnabled': Edm.Boolean,
        'mediaPathLocation': Edm.String,
        'signalingLocation': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'successfulCall': Edm.Boolean,
        'transferorCorrelationId': Edm.String,
        'trunkFullyQualifiedDomainName': Edm.String,
        'userCountryCode': Edm.String,
    }


class callRecords_endpoint(object):
    props = {
        'userAgent': Collection, #extnamespace: callRecords_userAgent,
    }


class callRecords_failureInfo(object):
    props = {
        'reason': Edm.String,
        'stage': Collection, #extnamespace: callRecords_failureStage,
    }


class callRecords_feedbackTokenSet(object):
    props = {

    }


class callRecords_media(object):
    props = {
        'calleeDevice': Collection, #extnamespace: callRecords_deviceInfo,
        'calleeNetwork': Collection, #extnamespace: callRecords_networkInfo,
        'callerDevice': Collection, #extnamespace: callRecords_deviceInfo,
        'callerNetwork': Collection, #extnamespace: callRecords_networkInfo,
        'label': Edm.String,
        'streams': Collection,
    }


class callRecords_networkInfo(object):
    props = {
        'bandwidthLowEventRatio': Edm.Single,
        'basicServiceSetIdentifier': Edm.String,
        'connectionType': Collection, #extnamespace: callRecords_networkConnectionType,
        'delayEventRatio': Edm.Single,
        'dnsSuffix': Edm.String,
        'ipAddress': Edm.String,
        'linkSpeed': Edm.Int64,
        'macAddress': Edm.String,
        'networkTransportProtocol': Collection, #extnamespace: callRecords_networkTransportProtocol,
        'port': Edm.Int32,
        'receivedQualityEventRatio': Edm.Single,
        'reflexiveIPAddress': Edm.String,
        'relayIPAddress': Edm.String,
        'relayPort': Edm.Int32,
        'sentQualityEventRatio': Edm.Single,
        'subnet': Edm.String,
        'traceRouteHops': Collection,
        'wifiBand': Collection, #extnamespace: callRecords_wifiBand,
        'wifiBatteryCharge': Edm.Int32,
        'wifiChannel': Edm.Int32,
        'wifiMicrosoftDriver': Edm.String,
        'wifiMicrosoftDriverVersion': Edm.String,
        'wifiRadioType': Collection, #extnamespace: callRecords_wifiRadioType,
        'wifiSignalStrength': Edm.Int32,
        'wifiVendorDriver': Edm.String,
        'wifiVendorDriverVersion': Edm.String,
    }


class callRecords_mediaStream(object):
    props = {
        'audioCodec': Collection, #extnamespace: callRecords_audioCodec,
        'averageAudioDegradation': Edm.Single,
        'averageAudioNetworkJitter': Edm.Duration,
        'averageBandwidthEstimate': Edm.Int64,
        'averageFreezeDuration': Edm.Duration,
        'averageJitter': Edm.Duration,
        'averagePacketLossRate': Edm.Single,
        'averageRatioOfConcealedSamples': Edm.Single,
        'averageReceivedFrameRate': Edm.Single,
        'averageRoundTripTime': Edm.Duration,
        'averageVideoFrameLossPercentage': Edm.Single,
        'averageVideoFrameRate': Edm.Single,
        'averageVideoPacketLossRate': Edm.Single,
        'endDateTime': Edm.DateTimeOffset,
        'isAudioForwardErrorCorrectionUsed': Edm.Boolean,
        'lowFrameRateRatio': Edm.Single,
        'lowVideoProcessingCapabilityRatio': Edm.Single,
        'maxAudioNetworkJitter': Edm.Duration,
        'maxJitter': Edm.Duration,
        'maxPacketLossRate': Edm.Single,
        'maxRatioOfConcealedSamples': Edm.Single,
        'maxRoundTripTime': Edm.Duration,
        'packetUtilization': Edm.Int64,
        'postForwardErrorCorrectionPacketLossRate': Edm.Single,
        'rmsFreezeDuration': Edm.Duration,
        'startDateTime': Edm.DateTimeOffset,
        'streamDirection': Collection, #extnamespace: callRecords_mediaStreamDirection,
        'streamId': Edm.String,
        'videoCodec': Collection, #extnamespace: callRecords_videoCodec,
        'wasMediaBypassed': Edm.Boolean,
    }


class callRecords_traceRouteHop(object):
    props = {
        'hopCount': Edm.Int32,
        'ipAddress': Edm.String,
        'roundTripTime': Edm.Duration,
    }


class callRecords_participantEndpoint(object):
    props = {
        'associatedIdentity': identity,
        'cpuCoresCount': Edm.Int32,
        'cpuName': Edm.String,
        'cpuProcessorSpeedInMhz': Edm.Int32,
        'feedback': Collection, #extnamespace: callRecords_userFeedback,
        'identity': identitySet,
        'name': Edm.String,
    }


class callRecords_userFeedback(object):
    props = {
        'rating': Collection, #extnamespace: callRecords_userFeedbackRating,
        'text': Edm.String,
        'tokens': Collection, #extnamespace: callRecords_feedbackTokenSet,
    }


class callRecords_pstnBlockedUsersLogRow(object):
    props = {
        'blockDateTime': Edm.DateTimeOffset,
        'blockReason': Edm.String,
        'remediationId': Edm.String,
        'userBlockMode': Collection, #extnamespace: callRecords_pstnUserBlockMode,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'userTelephoneNumber': Edm.String,
    }


class callRecords_pstnCallLogRow(object):
    props = {
        'callDurationSource': Collection, #extnamespace: callRecords_pstnCallDurationSource,
        'calleeNumber': Edm.String,
        'callerNumber': Edm.String,
        'callId': Edm.String,
        'callType': Edm.String,
        'charge': Edm.Decimal,
        'clientLocalIpV4Address': Edm.String,
        'clientLocalIpV6Address': Edm.String,
        'clientPublicIpV4Address': Edm.String,
        'clientPublicIpV6Address': Edm.String,
        'conferenceId': Edm.String,
        'connectionCharge': Edm.Decimal,
        'currency': Edm.String,
        'destinationContext': Edm.String,
        'destinationName': Edm.String,
        'duration': Edm.Int32,
        'endDateTime': Edm.DateTimeOffset,
        'inventoryType': Edm.String,
        'licenseCapability': Edm.String,
        'operator': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'tenantCountryCode': Edm.String,
        'usageCountryCode': Edm.String,
    }


class callRecords_pstnOnlineMeetingDialoutReport(object):
    props = {
        'currency': Edm.String,
        'destinationContext': Edm.String,
        'totalCallCharge': Edm.Decimal,
        'totalCalls': Edm.Int32,
        'totalCallSeconds': Edm.Int32,
        'usageLocation': Edm.String,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class callRecords_serviceEndpoint(object):
    props = {

    }


class callRecords_serviceUserAgent(object):
    props = {
        'role': Collection, #extnamespace: callRecords_serviceRole,
    }


class callRecords_smsLogRow(object):
    props = {
        'callCharge': Edm.Decimal,
        'currency': Edm.String,
        'destinationContext': Edm.String,
        'destinationName': Edm.String,
        'destinationNumber': Edm.String,
        'licenseCapability': Edm.String,
        'sentDateTime': Edm.DateTimeOffset,
        'smsId': Edm.String,
        'smsType': Edm.String,
        'smsUnits': Edm.Int32,
        'sourceNumber': Edm.String,
        'tenantCountryCode': Edm.String,
        'userCountryCode': Edm.String,
    }


class callRecords_userIdentity(object):
    props = {
        'userPrincipalName': Edm.String,
    }


class teamsAdministration_allPolicyAssignment(object):
    props = {
        'policyAssignments': Collection,
        'policyType': Edm.String,
    }


class teamsAdministration_policyAssignment(object):
    props = {
        'assignmentType': Collection, #extnamespace: teamsAdministration_assignmentType,
        'displayName': Edm.String,
        'groupId': Edm.String,
        'policyId': Edm.String,
    }


class teamsAdministration_assignedTelephoneNumber(object):
    props = {
        'assignmentCategory': Collection, #extnamespace: teamsAdministration_assignmentCategory,
        'telephoneNumber': Edm.String,
    }


class teamsAdministration_effectivePolicyAssignment(object):
    props = {
        'policyAssignment': Collection, #extnamespace: teamsAdministration_policyAssignment,
        'policyType': Edm.String,
    }


class industryData_additionalClassGroupOptions(object):
    props = {
        'createTeam': Edm.Boolean,
        'writeDisplayNameOnCreateOnly': Edm.Boolean,
    }


class industryData_additionalUserOptions(object):
    props = {
        'allowStudentContactAssociation': Edm.Boolean,
        'markAllStudentsAsMinors': Edm.Boolean,
    }


class industryData_adminUnitCreationOptions(object):
    props = {
        'createBasedOnOrg': Edm.Boolean,
        'createBasedOnOrgPlusRoleGroup': Edm.Boolean,
    }


class industryData_aggregatedInboundStatistics(object):
    props = {
        'errors': Edm.Int32,
        'groups': Edm.Int32,
        'matchedPeopleByRole': Collection,
        'memberships': Edm.Int32,
        'organizations': Edm.Int32,
        'people': Edm.Int32,
        'unmatchedPeopleByRole': Collection,
        'warnings': Edm.Int32,
    }


class industryData_industryDataRunRoleCountMetric(object):
    props = {
        'count': Edm.Int32,
        'role': Edm.String,
    }


class industryData_filter(object):
    props = {

    }


class industryData_basicFilter(object):
    props = {
        'attribute': Collection, #extnamespace: industryData_filterOptions,
        'in': Collection,
    }


class industryData_classGroupConfiguration(object):
    props = {
        'additionalAttributes': Collection,
        'additionalOptions': Collection, #extnamespace: industryData_additionalClassGroupOptions,
        'enrollmentMappings': Collection, #extnamespace: industryData_enrollmentMappings,
    }


class industryData_enrollmentMappings(object):
    props = {
        'memberEnrollmentMappings': Collection,
        'ownerEnrollmentMappings': Collection,
    }


class industryData_credential(object):
    props = {
        'displayName': Edm.String,
        'isValid': Edm.Boolean,
        'lastValidDateTime': Edm.DateTimeOffset,
    }


class industryData_referenceValue(object):
    props = {
        'code': Edm.String,
    }


class industryData_sectionRoleReferenceValue(object):
    props = {

    }


class industryData_fileFormatReferenceValue(object):
    props = {

    }


class industryData_fileUploadSession(object):
    props = {
        'containerExpirationDateTime': Edm.DateTimeOffset,
        'containerId': Edm.String,
        'sessionExpirationDateTime': Edm.DateTimeOffset,
        'sessionUrl': Edm.String,
    }


class industryData_identifierTypeReferenceValue(object):
    props = {

    }


class industryData_industryDataActivityStatistics(object):
    props = {
        'activityId': Edm.String,
        'displayName': Edm.String,
        'status': Collection, #extnamespace: industryData_industryDataActivityStatus,
    }


class industryData_inboundActivityResults(object):
    props = {
        'errors': Edm.Int32,
        'groups': Collection, #extnamespace: industryData_industryDataRunEntityCountMetric,
        'matchedPeopleByRole': Collection,
        'memberships': Collection, #extnamespace: industryData_industryDataRunEntityCountMetric,
        'organizations': Collection, #extnamespace: industryData_industryDataRunEntityCountMetric,
        'people': Collection, #extnamespace: industryData_industryDataRunEntityCountMetric,
        'unmatchedPeopleByRole': Collection,
        'warnings': Edm.Int32,
    }


class industryData_industryDataRunEntityCountMetric(object):
    props = {
        'active': Edm.Int32,
        'inactive': Edm.Int32,
        'total': Edm.Int32,
    }


class industryData_industryDataRunStatistics(object):
    props = {
        'activityStatistics': Collection,
        'inboundTotals': Collection, #extnamespace: industryData_aggregatedInboundStatistics,
        'runId': Edm.String,
        'status': Collection, #extnamespace: industryData_industryDataRunStatus,
    }


class industryData_oAuthClientCredential(object):
    props = {
        'clientId': Edm.String,
        'clientSecret': Edm.String,
    }


class industryData_oAuth1ClientCredential(object):
    props = {

    }


class industryData_oAuth2ClientCredential(object):
    props = {
        'scope': Edm.String,
        'tokenUrl': Edm.String,
    }


class industryData_passwordSettings(object):
    props = {

    }


class industryData_roleReferenceValue(object):
    props = {

    }


class industryData_securityGroupCreationOptions(object):
    props = {
        'createBasedOnOrgPlusRoleGroup': Edm.Boolean,
        'createBasedOnRoleGroup': Edm.Boolean,
    }


class industryData_simplePasswordSettings(object):
    props = {
        'password': Edm.String,
    }


class industryData_userConfiguration(object):
    props = {
        'defaultPasswordSettings': Collection, #extnamespace: industryData_passwordSettings,
        'licenseSkus': Collection,
    }


class industryData_userCreationOptions(object):
    props = {
        'configurations': Collection,
    }


class industryData_userManagementOptions(object):
    props = {
        'additionalAttributes': Collection,
        'additionalOptions': Collection, #extnamespace: industryData_additionalUserOptions,
    }


class industryData_userMatchingSetting(object):
    props = {
        'matchTarget': Collection, #extnamespace: industryData_userMatchTargetReferenceValue,
        'priorityOrder': Edm.Int32,
        'sourceIdentifier': Collection, #extnamespace: industryData_identifierTypeReferenceValue,
    }


class industryData_userMatchTargetReferenceValue(object):
    props = {

    }


class industryData_yearReferenceValue(object):
    props = {

    }


class managedTenants_addLogRequest(object):
    props = {
        'logInformation': Edm.String,
    }


class managedTenants_alertData(object):
    props = {
        'displayName': Edm.String,
    }


class managedTenants_alertDataReferenceString(object):
    props = {
        'displayName': Edm.String,
    }


class managedTenants_alertLogContent(object):
    props = {
        'displayName': Edm.String,
    }


class managedTenants_alertRuleDefinitionTemplate(object):
    props = {
        'defaultSeverity': Collection, #extnamespace: managedTenants_alertSeverity,
    }


class managedTenants_delegatedRoleAssignedUser(object):
    props = {
        'displayName': Edm.String,
        'userEntityId': Edm.String,
        'userPrincipalName': Edm.String,
    }


class managedTenants_email(object):
    props = {
        'emailAddress': Edm.String,
    }


class managedTenants_graphAPIErrorDetails(object):
    props = {
        'code': Edm.String,
        'message': Edm.String,
    }


class managedTenants_managedTenantOperationError(object):
    props = {
        'error': Edm.String,
        'tenantId': Edm.String,
    }


class managedTenants_managedTenantExecutionError(object):
    props = {
        'errorDetails': Edm.String,
        'nodeId': Edm.Int32,
        'rawToken': Edm.String,
        'statementIndex': Edm.Int32,
    }


class managedTenants_managedTenantGenericError(object):
    props = {

    }


class managedTenants_managementActionDeploymentStatus(object):
    props = {
        'managementActionId': Edm.String,
        'managementTemplateId': Edm.String,
        'managementTemplateVersion': Edm.Int32,
        'status': Collection, #extnamespace: managedTenants_managementActionStatus,
        'workloadActionDeploymentStatuses': Collection,
    }


class managedTenants_workloadActionDeploymentStatus(object):
    props = {
        'actionId': Edm.String,
        'deployedPolicyId': Edm.String,
        'error': genericError,
        'excludeGroups': Collection,
        'includeAllUsers': Edm.Boolean,
        'includeGroups': Collection,
        'lastDeploymentDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: managedTenants_workloadActionStatus,
    }


class managedTenants_managementActionInfo(object):
    props = {
        'managementActionId': Edm.String,
        'managementTemplateId': Edm.String,
        'managementTemplateVersion': Edm.Int32,
    }


class managedTenants_managementIntentInfo(object):
    props = {
        'managementIntentDisplayName': Edm.String,
        'managementIntentId': Edm.String,
        'managementTemplates': Collection,
    }


class managedTenants_managementTemplateDetailedInfo(object):
    props = {
        'category': Collection, #extnamespace: managedTenants_managementCategory,
        'displayName': Edm.String,
        'managementTemplateId': Edm.String,
        'version': Edm.Int32,
    }


class managedTenants_notificationTarget(object):
    props = {
        'displayName': Edm.String,
    }


class managedTenants_phone(object):
    props = {
        'phoneNumber': Edm.String,
    }


class managedTenants_roleAssignment(object):
    props = {
        'assignmentType': Collection, #extnamespace: managedTenants_delegatedPrivilegeStatus,
        'roles': Collection,
    }


class managedTenants_roleDefinition(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'templateId': Edm.String,
    }


class managedTenants_setting(object):
    props = {
        'displayName': Edm.String,
        'jsonValue': Edm.String,
        'overwriteAllowed': Edm.Boolean,
        'settingId': Edm.String,
        'valueType': Collection, #extnamespace: managedTenants_managementParameterValueType,
    }


class managedTenants_templateAction(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'service': Edm.String,
        'settings': Collection,
        'templateActionId': Edm.String,
    }


class managedTenants_templateParameter(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'jsonAllowedValues': Edm.String,
        'jsonDefaultValue': Edm.String,
        'valueType': Collection, #extnamespace: managedTenants_managementParameterValueType,
    }


class managedTenants_tenantContactInformation(object):
    props = {
        'email': Edm.String,
        'name': Edm.String,
        'notes': Edm.String,
        'phone': Edm.String,
        'title': Edm.String,
    }


class managedTenants_tenantContract(object):
    props = {
        'contractType': Edm.Int32,
        'defaultDomainName': Edm.String,
        'displayName': Edm.String,
    }


class managedTenants_tenantInfo(object):
    props = {
        'tenantId': Edm.String,
    }


class managedTenants_tenantStatusInformation(object):
    props = {
        'delegatedPrivilegeStatus': Collection, #extnamespace: managedTenants_delegatedPrivilegeStatus,
        'lastDelegatedPrivilegeRefreshDateTime': Edm.DateTimeOffset,
        'offboardedByUserId': Edm.String,
        'offboardedDateTime': Edm.DateTimeOffset,
        'onboardedByUserId': Edm.String,
        'onboardedDateTime': Edm.DateTimeOffset,
        'onboardingStatus': Collection, #extnamespace: managedTenants_tenantOnboardingStatus,
        'tenantOnboardingEligibilityReason': Collection, #extnamespace: managedTenants_tenantOnboardingEligibilityReason,
        'workloadStatuses': Collection,
    }


class managedTenants_workloadStatus(object):
    props = {
        'displayName': Edm.String,
        'offboardedDateTime': Edm.DateTimeOffset,
        'onboardedDateTime': Edm.DateTimeOffset,
        'onboardingStatus': Collection, #extnamespace: managedTenants_workloadOnboardingStatus,
    }


class managedTenants_workloadAction(object):
    props = {
        'actionId': Edm.String,
        'category': Collection, #extnamespace: managedTenants_workloadActionCategory,
        'description': Edm.String,
        'displayName': Edm.String,
        'licenses': Collection,
        'service': Edm.String,
        'settings': Collection,
    }


class partners_billing_blob(object):
    props = {
        'name': Edm.String,
        'partitionValue': Edm.String,
    }


class partner_security_activityLog(object):
    props = {
        'statusFrom': Collection, #extnamespace: partner_security_securityAlertStatus,
        'statusTo': Collection, #extnamespace: partner_security_securityAlertStatus,
        'updatedBy': Edm.String,
        'updatedDateTime': Edm.DateTimeOffset,
    }


class partner_security_additionalDataDictionary(object):
    props = {

    }


class partner_security_affectedResource(object):
    props = {
        'resourceId': Edm.String,
        'resourceType': Edm.String,
    }


class partner_security_customerMfaInsight(object):
    props = {
        'compliantAdminsCount': Edm.Int64,
        'compliantNonAdminsCount': Edm.Int64,
        'legacyPerUserMfaStatus': Collection, #extnamespace: partner_security_policyStatus,
        'mfaConditionalAccessPolicyStatus': Collection, #extnamespace: partner_security_policyStatus,
        'securityDefaultsStatus': Collection, #extnamespace: partner_security_policyStatus,
        'totalUsersCount': Edm.Int64,
    }


class search_answerKeyword(object):
    props = {
        'keywords': Collection,
        'matchSimilarKeywords': Edm.Boolean,
        'reservedKeywords': Collection,
    }


class search_answerVariant(object):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'languageTag': Edm.String,
        'platform': devicePlatformType,
        'webUrl': Edm.String,
    }


class search_identity(object):
    props = {
        'displayName': Edm.String,
        'id': Edm.String,
    }


class search_identitySet(object):
    props = {
        'application': Collection, #extnamespace: search_identity,
        'device': Collection, #extnamespace: search_identity,
        'user': Collection, #extnamespace: search_identity,
    }


class externalConnectors_acl(object):
    props = {
        'accessType': Collection, #extnamespace: externalConnectors_accessType,
        'identitySource': Collection, #extnamespace: externalConnectors_identitySourceType,
        'type': Collection, #extnamespace: externalConnectors_aclType,
        'value': Edm.String,
    }


class externalConnectors_activitySettings(object):
    props = {
        'urlToItemResolvers': Collection,
    }


class externalConnectors_urlToItemResolverBase(object):
    props = {
        'priority': Edm.Int32,
    }


class externalConnectors_complianceSettings(object):
    props = {
        'eDiscoveryResultTemplates': Collection,
    }


class externalConnectors_displayTemplate(object):
    props = {
        'id': Edm.String,
        'layout': Json,
        'priority': Edm.Int32,
        'rules': Collection,
    }


class externalConnectors_configuration(object):
    props = {
        'authorizedAppIds': Collection,
    }


class externalConnectors_propertyRule(object):
    props = {
        'operation': Collection, #extnamespace: externalConnectors_ruleOperation,
        'property': Edm.String,
        'values': Collection,
        'valuesJoinedBy': binaryOperator,
    }


class externalConnectors_externalItemContent(object):
    props = {
        'type': Collection, #extnamespace: externalConnectors_externalItemContentType,
        'value': Edm.String,
    }


class externalConnectors_itemIdResolver(object):
    props = {
        'itemId': Edm.String,
        'urlMatchInfo': Collection, #extnamespace: externalConnectors_urlMatchInfo,
    }


class externalConnectors_urlMatchInfo(object):
    props = {
        'baseUrls': Collection,
        'urlPattern': Edm.String,
    }


class externalConnectors_properties(object):
    props = {

    }


class externalConnectors_property(object):
    props = {
        'aliases': Collection,
        'isExactMatchRequired': Edm.Boolean,
        'isQueryable': Edm.Boolean,
        'isRefinable': Edm.Boolean,
        'isRetrievable': Edm.Boolean,
        'isSearchable': Edm.Boolean,
        'labels': Collection,
        'name': Edm.String,
        'rankingHint': Collection, #extnamespace: externalConnectors_rankingHint,
        'type': Collection, #extnamespace: externalConnectors_propertyType,
    }


class externalConnectors_rankingHint(object):
    props = {
        'importanceScore': Collection, #extnamespace: externalConnectors_importanceScore,
    }


class externalConnectors_searchSettings(object):
    props = {
        'searchResultTemplates': Collection,
    }


class windowsUpdates_updatableAssetError(object):
    props = {

    }


class windowsUpdates_azureADDeviceRegistrationError(object):
    props = {
        'reason': Collection, #extnamespace: windowsUpdates_azureADDeviceRegistrationErrorReason,
    }


class windowsUpdates_buildVersionDetails(object):
    props = {
        'buildNumber': Edm.Int32,
        'majorVersion': Edm.Int32,
        'minorVersion': Edm.Int32,
        'updateBuildRevision': Edm.Int32,
    }


class windowsUpdates_deployableContent(object):
    props = {

    }


class windowsUpdates_catalogContent(object):
    props = {

    }


class windowsUpdates_complianceChangeRule(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastEvaluatedDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class windowsUpdates_contentApplicabilitySettings(object):
    props = {
        'offerWhileRecommendedBy': Collection,
        'safeguard': Collection, #extnamespace: windowsUpdates_safeguardSettings,
    }


class windowsUpdates_safeguardSettings(object):
    props = {
        'disabledSafeguardProfiles': Collection,
    }


class windowsUpdates_contentApprovalRule(object):
    props = {
        'contentFilter': Collection, #extnamespace: windowsUpdates_contentFilter,
        'durationBeforeDeploymentStart': Edm.Duration,
    }


class windowsUpdates_contentFilter(object):
    props = {

    }


class windowsUpdates_gradualRolloutSettings(object):
    props = {
        'durationBetweenOffers': Edm.Duration,
    }


class windowsUpdates_dateDrivenRolloutSettings(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
    }


class windowsUpdates_deploymentSettings(object):
    props = {
        'contentApplicability': Collection, #extnamespace: windowsUpdates_contentApplicabilitySettings,
        'expedite': Collection, #extnamespace: windowsUpdates_expediteSettings,
        'monitoring': Collection, #extnamespace: windowsUpdates_monitoringSettings,
        'schedule': Collection, #extnamespace: windowsUpdates_scheduleSettings,
        'userExperience': Collection, #extnamespace: windowsUpdates_userExperienceSettings,
    }


class windowsUpdates_expediteSettings(object):
    props = {
        'isExpedited': Edm.Boolean,
        'isReadinessTest': Edm.Boolean,
    }


class windowsUpdates_monitoringSettings(object):
    props = {
        'monitoringRules': Collection,
    }


class windowsUpdates_scheduleSettings(object):
    props = {
        'gradualRollout': Collection, #extnamespace: windowsUpdates_gradualRolloutSettings,
        'startDateTime': Edm.DateTimeOffset,
    }


class windowsUpdates_userExperienceSettings(object):
    props = {
        'daysUntilForcedReboot': Edm.Int32,
        'isHotpatchEnabled': Edm.Boolean,
        'offerAsOptional': Edm.Boolean,
    }


class windowsUpdates_deploymentState(object):
    props = {
        'effectiveValue': Collection, #extnamespace: windowsUpdates_deploymentStateValue,
        'reasons': Collection,
        'requestedValue': Collection, #extnamespace: windowsUpdates_requestedDeploymentStateValue,
    }


class windowsUpdates_deploymentStateReason(object):
    props = {
        'value': Collection, #extnamespace: windowsUpdates_deploymentStateReasonValue,
    }


class windowsUpdates_softwareUpdateFilter(object):
    props = {

    }


class windowsUpdates_windowsUpdateFilter(object):
    props = {

    }


class windowsUpdates_driverUpdateFilter(object):
    props = {

    }


class windowsUpdates_durationDrivenRolloutSettings(object):
    props = {
        'durationUntilDeploymentEnd': Edm.Duration,
    }


class windowsUpdates_itemBody(object):
    props = {
        'content': Edm.String,
        'contentType': Collection, #extnamespace: windowsUpdates_bodyType,
    }


class windowsUpdates_knownIssueHistoryItem(object):
    props = {
        'body': Collection, #extnamespace: windowsUpdates_itemBody,
        'createdDateTime': Edm.DateTimeOffset,
    }


class windowsUpdates_monitoringRule(object):
    props = {
        'action': Collection, #extnamespace: windowsUpdates_monitoringAction,
        'signal': Collection, #extnamespace: windowsUpdates_monitoringSignal,
        'threshold': Edm.Int32,
    }


class windowsUpdates_qualityUpdateCveSeverityInformation(object):
    props = {
        'maxBaseScore': Edm.Double,
        'maxSeverity': Collection, #extnamespace: windowsUpdates_cveSeverityLevel,
    }


class windowsUpdates_qualityUpdateFilter(object):
    props = {
        'cadence': Collection, #extnamespace: windowsUpdates_qualityUpdateCadence,
        'classification': Collection, #extnamespace: windowsUpdates_qualityUpdateClassification,
    }


class windowsUpdates_rateDrivenRolloutSettings(object):
    props = {
        'devicesPerOffer': Edm.Int32,
    }


class windowsUpdates_safeguardProfile(object):
    props = {
        'category': Collection, #extnamespace: windowsUpdates_safeguardCategory,
    }


class windowsUpdates_servicingPeriod(object):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
    }


class windowsUpdates_updatableAssetEnrollment(object):
    props = {

    }


class windowsUpdates_updateCategoryEnrollmentInformation(object):
    props = {
        'enrollmentState': Collection, #extnamespace: windowsUpdates_enrollmentState,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }


class windowsUpdates_updateManagementEnrollment(object):
    props = {
        'driver': Collection, #extnamespace: windowsUpdates_updateCategoryEnrollmentInformation,
        'feature': Collection, #extnamespace: windowsUpdates_updateCategoryEnrollmentInformation,
        'quality': Collection, #extnamespace: windowsUpdates_updateCategoryEnrollmentInformation,
    }


class identityGovernance_triggerAndScopeBasedConditions(object):
    props = {
        'scope': subjectSet,
        'trigger': Collection, #extnamespace: identityGovernance_workflowExecutionTrigger,
    }


class customExtensionCalloutRequest(object):
    props = {
        'data': customExtensionData,
        'source': Edm.String,
        'type': Edm.String,
    }


class webApplication(object):
    props = {
        'homePageUrl': Edm.String,
        'implicitGrantSettings': implicitGrantSettings,
        'logoutUrl': Edm.String,
        'oauth2AllowImplicitFlow': Edm.Boolean,
        'redirectUris': Collection,
        'redirectUriSettings': Collection,
    }


class onPremisesPublishing(object):
    props = {
        'alternateUrl': Edm.String,
        'applicationServerTimeout': Edm.String,
        'applicationType': Edm.String,
        'externalAuthenticationType': externalAuthenticationType,
        'externalUrl': Edm.String,
        'internalUrl': Edm.String,
        'isAccessibleViaZTNAClient': Edm.Boolean,
        'isBackendCertificateValidationEnabled': Edm.Boolean,
        'isDnsResolutionEnabled': Edm.Boolean,
        'isHttpOnlyCookieEnabled': Edm.Boolean,
        'isOnPremPublishingEnabled': Edm.Boolean,
        'isPersistentCookieEnabled': Edm.Boolean,
        'isSecureCookieEnabled': Edm.Boolean,
        'isStateSessionEnabled': Edm.Boolean,
        'isTranslateHostHeaderEnabled': Edm.Boolean,
        'isTranslateLinksInBodyEnabled': Edm.Boolean,
        'onPremisesApplicationSegments': Collection,
        'segmentsConfiguration': segmentConfiguration,
        'singleSignOnSettings': onPremisesPublishingSingleSignOn,
        'useAlternateUrlForTranslationAndRedirect': Edm.Boolean,
        'verifiedCustomDomainCertificatesMetadata': verifiedCustomDomainCertificatesMetadata,
        'verifiedCustomDomainKeyCredential': keyCredential,
        'verifiedCustomDomainPasswordCredential': passwordCredential,
        'wafAllowedHeaders': wafAllowedHeadersDictionary,
        'wafIpRanges': Collection,
        'wafProvider': Edm.String,
    }


class mailboxSettings(object):
    props = {
        'archiveFolder': Edm.String,
        'automaticRepliesSetting': automaticRepliesSetting,
        'dateFormat': Edm.String,
        'delegateMeetingMessageDeliveryOptions': delegateMeetingMessageDeliveryOptions,
        'language': localeInfo,
        'timeFormat': Edm.String,
        'timeZone': Edm.String,
        'userPurpose': userPurpose,
        'userPurposeV2': mailboxRecipientType,
        'workingHours': workingHours,
    }


class actionStep(object):
    props = {
        'actionUrl': actionUrl,
        'stepNumber': Edm.Int64,
        'text': Edm.String,
    }


class appliedAuthenticationEventListener(object):
    props = {
        'eventType': authenticationEventType,
        'executedListenerId': Edm.String,
        'handlerResult': authenticationEventHandlerResult,
    }


class appliedConditionalAccessPolicy(object):
    props = {
        'authenticationStrength': authenticationStrength,
        'conditionsNotSatisfied': conditionalAccessConditions,
        'conditionsSatisfied': conditionalAccessConditions,
        'displayName': Edm.String,
        'enforcedGrantControls': Collection,
        'enforcedSessionControls': Collection,
        'excludeRulesSatisfied': Collection,
        'id': Edm.String,
        'includeRulesSatisfied': Collection,
        'result': appliedConditionalAccessPolicyResult,
        'sessionControlsNotSatisfied': Collection,
    }


class auditActivityInitiator(object):
    props = {
        'app': appIdentity,
        'user': auditUserIdentity,
    }


class publicError(object):
    props = {
        'code': Edm.String,
        'details': Collection,
        'innerError': publicInnerError,
        'message': Edm.String,
        'target': Edm.String,
    }


class authenticationMethodFeatureConfiguration(object):
    props = {
        'excludeTarget': featureTarget,
        'includeTarget': featureTarget,
        'state': advancedConfigState,
    }


class microsoftAuthenticatorFeatureSettings(object):
    props = {
        'companionAppAllowedState': authenticationMethodFeatureConfiguration,
        'displayAppInformationRequiredState': authenticationMethodFeatureConfiguration,
        'displayLocationInformationRequiredState': authenticationMethodFeatureConfiguration,
        'numberMatchingRequiredState': authenticationMethodFeatureConfiguration,
    }


class searchQuery(object):
    props = {
        'queryString': Edm.String,
        'queryTemplate': Edm.String,
        'query_string': searchQueryString,
    }


class availabilityItem(object):
    props = {
        'endDateTime': dateTimeTimeZone,
        'serviceId': Edm.String,
        'startDateTime': dateTimeTimeZone,
        'status': bookingsAvailabilityStatus,
    }


class location(object):
    props = {
        'address': physicalAddress,
        'coordinates': outlookGeoCoordinates,
        'displayName': Edm.String,
        'locationEmailAddress': Edm.String,
        'locationType': locationType,
        'locationUri': Edm.String,
        'uniqueId': Edm.String,
        'uniqueIdType': locationUniqueIdType,
    }


class plannerTaskRoleBasedRule(object):
    props = {
        'defaultRule': Edm.String,
        'propertyRule': plannerTaskPropertyRule,
        'role': plannerTaskConfigurationRoleBase,
    }


class cloudPcCrossRegionDisasterRecoverySetting(object):
    props = {
        'crossRegionDisasterRecoveryEnabled': Edm.Boolean,
        'disasterRecoveryNetworkSetting': cloudPcDisasterRecoveryNetworkSetting,
        'disasterRecoveryType': cloudPcDisasterRecoveryType,
        'maintainCrossRegionRestorePointEnabled': Edm.Boolean,
        'userInitiatedDisasterRecoveryAllowed': Edm.Boolean,
    }


class cloudPcRemoteActionResult(object):
    props = {
        'actionName': Edm.String,
        'actionState': actionState,
        'cloudPcId': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'statusDetail': cloudPcStatusDetail,
        'statusDetails': cloudPcStatusDetails,
    }


class intuneBrand(object):
    props = {
        'companyPortalBlockedActions': Collection,
        'contactITEmailAddress': Edm.String,
        'contactITName': Edm.String,
        'contactITNotes': Edm.String,
        'contactITPhoneNumber': Edm.String,
        'customCanSeePrivacyMessage': Edm.String,
        'customCantSeePrivacyMessage': Edm.String,
        'customPrivacyMessage': Edm.String,
        'darkBackgroundLogo': mimeContent,
        'disableClientTelemetry': Edm.Boolean,
        'disableDeviceCategorySelection': Edm.Boolean,
        'displayName': Edm.String,
        'enrollmentAvailability': enrollmentAvailabilityOptions,
        'isFactoryResetDisabled': Edm.Boolean,
        'isRemoveDeviceDisabled': Edm.Boolean,
        'landingPageCustomizedImage': mimeContent,
        'lightBackgroundLogo': mimeContent,
        'onlineSupportSiteName': Edm.String,
        'onlineSupportSiteUrl': Edm.String,
        'privacyUrl': Edm.String,
        'roleScopeTagIds': Collection,
        'sendDeviceOwnershipChangePushNotification': Edm.Boolean,
        'showAzureADEnterpriseApps': Edm.Boolean,
        'showConfigurationManagerApps': Edm.Boolean,
        'showDisplayNameNextToLogo': Edm.Boolean,
        'showLogo': Edm.Boolean,
        'showNameNextToLogo': Edm.Boolean,
        'showOfficeWebApps': Edm.Boolean,
        'themeColor': rgbColor,
    }


class subjectRightsRequestStageDetail(object):
    props = {
        'error': publicError,
        'stage': subjectRightsRequestStage,
        'status': subjectRightsRequestStageStatus,
    }


class siteCollection(object):
    props = {
        'archivalDetails': siteArchivalDetails,
        'dataLocationCode': Edm.String,
        'hostname': Edm.String,
        'root': root,
    }


class authenticationConditions(object):
    props = {
        'applications': authenticationConditionsApplications,
    }


class classifcationErrorBase(object):
    props = {
        'code': Edm.String,
        'innerError': classificationInnerError,
        'message': Edm.String,
        'target': Edm.String,
    }


class dlpEvaluatePoliciesRequest(object):
    props = {
        'evaluationInput': dlpEvaluationInput,
        'notificationInfo': dlpNotification,
        'target': Edm.String,
    }


class evaluateLabelJobResult(object):
    props = {
        'responsiblePolicy': responsiblePolicy,
        'responsibleSensitiveTypes': Collection,
        'sensitivityLabel': matchingLabel,
    }


class evaluateLabelJobResultGroup(object):
    props = {
        'automatic': evaluateLabelJobResult,
        'recommended': evaluateLabelJobResult,
    }


class azureADJoinPolicy(object):
    props = {
        'allowedToJoin': deviceRegistrationMembership,
        'isAdminConfigurable': Edm.Boolean,
        'localAdmins': localAdminSettings,
    }


class identifierUriConfiguration(object):
    props = {
        'nonDefaultUriAddition': identifierUriRestriction,
    }


class transformationAttribute(object):
    props = {
        'attribute': customClaimAttributeBase,
        'treatAsMultiValue': Edm.Boolean,
    }


class crossTenantAccessPolicyB2BSetting(object):
    props = {
        'applications': crossTenantAccessPolicyTargetConfiguration,
        'usersAndGroups': crossTenantAccessPolicyTargetConfiguration,
    }


class crossTenantAccessPolicyTenantRestrictions(object):
    props = {
        'devices': devicesFilter,
    }


class customAppManagementApplicationConfiguration(object):
    props = {
        'identifierUris': identifierUriConfiguration,
    }


class customAppManagementConfiguration(object):
    props = {
        'applicationRestrictions': customAppManagementApplicationConfiguration,
    }


class customClaimConfiguration(object):
    props = {
        'attribute': customClaimAttributeBase,
        'condition': customClaimConditionBase,
        'transformations': Collection,
    }


class endsWithTransformation(object):
    props = {
        'output': transformationAttribute,
        'value': Edm.String,
    }


class ifEmptyTransformation(object):
    props = {
        'output': transformationAttribute,
    }


class ifNotEmptyTransformation(object):
    props = {
        'output': transformationAttribute,
    }


class joinTransformation(object):
    props = {
        'input2': transformationAttribute,
        'separator': Edm.String,
    }


class onPremisesDirectorySynchronizationConfiguration(object):
    props = {
        'accidentalDeletionPrevention': onPremisesAccidentalDeletionPrevention,
        'anchorAttribute': Edm.String,
        'applicationId': Edm.String,
        'currentExportData': onPremisesCurrentExportData,
        'customerRequestedSynchronizationInterval': Edm.Duration,
        'synchronizationClientVersion': Edm.String,
        'synchronizationInterval': Edm.Duration,
        'writebackConfiguration': onPremisesWritebackConfiguration,
    }


class startsWithTransformation(object):
    props = {
        'output': transformationAttribute,
        'value': Edm.String,
    }


class educationFeedback(object):
    props = {
        'feedbackBy': identitySet,
        'feedbackDateTime': Edm.DateTimeOffset,
        'text': educationItemBody,
    }


class workbookFilterCriteria(object):
    props = {
        'color': Edm.String,
        'criterion1': Edm.String,
        'criterion2': Edm.String,
        'dynamicCriteria': Edm.String,
        'filterOn': Edm.String,
        'icon': workbookIcon,
        'operator': Edm.String,
        'values': Json,
    }


class quota(object):
    props = {
        'deleted': Edm.Int64,
        'remaining': Edm.Int64,
        'state': Edm.String,
        'storagePlanInformation': storagePlanInformation,
        'total': Edm.Int64,
        'used': Edm.Int64,
    }


class bundle(object):
    props = {
        'album': album,
        'childCount': Edm.Int32,
    }


class file(object):
    props = {
        'hashes': hashes,
        'mimeType': Edm.String,
        'processingMetadata': Edm.Boolean,
    }


class folder(object):
    props = {
        'childCount': Edm.Int32,
        'view': folderView,
    }


class media(object):
    props = {
        'isTranscriptionShown': Edm.Boolean,
        'mediaSource': mediaSource,
    }


class pendingOperations(object):
    props = {
        'pendingContentUpdate': pendingContentUpdate,
    }


class remoteItem(object):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'file': file,
        'fileSystemInfo': fileSystemInfo,
        'folder': folder,
        'id': Edm.String,
        'image': image,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'package': package,
        'parentReference': itemReference,
        'shared': shared,
        'sharepointIds': sharepointIds,
        'size': Edm.Int64,
        'specialFolder': specialFolder,
        'video': video,
        'webDavUrl': Edm.String,
        'webUrl': Edm.String,
    }


class attendeeAvailability(object):
    props = {
        'attendee': attendeeBase,
        'availability': freeBusyStatus,
    }


class workplaceSensorEventValue(object):
    props = {
        'eventType': workplaceSensorEventType,
        'user': emailIdentity,
    }


class attendee(object):
    props = {
        'proposedNewTime': timeSlot,
        'status': responseStatus,
    }


class automaticRepliesMailTips(object):
    props = {
        'message': Edm.String,
        'messageLanguage': localeInfo,
        'scheduledEndTime': dateTimeTimeZone,
        'scheduledStartTime': dateTimeTimeZone,
    }


class customTimeZone(object):
    props = {
        'bias': Edm.Int32,
        'daylightOffset': daylightTimeZoneOffset,
        'standardOffset': standardTimeZoneOffset,
    }


class exportItemResponse(object):
    props = {
        'changeKey': Edm.String,
        'data': Edm.Stream,
        'error': mailTipsError,
        'itemId': Edm.String,
    }


class mailTips(object):
    props = {
        'automaticReplies': automaticRepliesMailTips,
        'customMailTip': Edm.String,
        'deliveryRestricted': Edm.Boolean,
        'emailAddress': emailAddress,
        'error': mailTipsError,
        'externalMemberCount': Edm.Int32,
        'isModerated': Edm.Boolean,
        'mailboxFull': Edm.Boolean,
        'maxMessageSize': Edm.Int32,
        'recipientScope': recipientScopeType,
        'recipientSuggestions': Collection,
        'totalMemberCount': Edm.Int32,
    }


class messageRulePredicates(object):
    props = {
        'bodyContains': Collection,
        'bodyOrSubjectContains': Collection,
        'categories': Collection,
        'fromAddresses': Collection,
        'hasAttachments': Edm.Boolean,
        'headerContains': Collection,
        'importance': importance,
        'isApprovalRequest': Edm.Boolean,
        'isAutomaticForward': Edm.Boolean,
        'isAutomaticReply': Edm.Boolean,
        'isEncrypted': Edm.Boolean,
        'isMeetingRequest': Edm.Boolean,
        'isMeetingResponse': Edm.Boolean,
        'isNonDeliveryReport': Edm.Boolean,
        'isPermissionControlled': Edm.Boolean,
        'isReadReceipt': Edm.Boolean,
        'isSigned': Edm.Boolean,
        'isVoicemail': Edm.Boolean,
        'messageActionFlag': messageActionFlag,
        'notSentToMe': Edm.Boolean,
        'recipientContains': Collection,
        'senderContains': Collection,
        'sensitivity': sensitivity,
        'sentCcMe': Edm.Boolean,
        'sentOnlyToMe': Edm.Boolean,
        'sentToAddresses': Collection,
        'sentToMe': Edm.Boolean,
        'sentToOrCcMe': Edm.Boolean,
        'subjectContains': Collection,
        'withinSizeRange': sizeRange,
    }


class patternedRecurrence(object):
    props = {
        'pattern': recurrencePattern,
        'range': recurrenceRange,
    }


class reminder(object):
    props = {
        'changeKey': Edm.String,
        'eventEndTime': dateTimeTimeZone,
        'eventId': Edm.String,
        'eventLocation': location,
        'eventStartTime': dateTimeTimeZone,
        'eventSubject': Edm.String,
        'eventWebLink': Edm.String,
        'reminderFireTime': dateTimeTimeZone,
    }


class directSharingAbilities(object):
    props = {
        'addExistingExternalUsers': sharingOperationStatus,
        'addInternalUsers': sharingOperationStatus,
        'addNewExternalUsers': sharingOperationStatus,
        'requestGrantAccess': sharingOperationStatus,
    }


class driveItemUploadableProperties(object):
    props = {
        'description': Edm.String,
        'driveItemSource': driveItemSource,
        'fileSize': Edm.Int64,
        'fileSystemInfo': fileSystemInfo,
        'mediaSource': mediaSource,
        'name': Edm.String,
    }


class itemActionSet(object):
    props = {
        'comment': commentAction,
        'create': createAction,
        'delete': deleteAction,
        'edit': editAction,
        'mention': mentionAction,
        'move': moveAction,
        'rename': renameAction,
        'restore': restoreAction,
        'share': shareAction,
        'version': versionAction,
    }


class linkRoleAbilities(object):
    props = {
        'addExistingExternalUsers': sharingOperationStatus,
        'addNewExternalUsers': sharingOperationStatus,
        'applyVariants': sharingLinkVariants,
        'createLink': sharingOperationStatus,
        'deleteLink': sharingOperationStatus,
        'linkAllowsExternalUsers': sharingOperationStatus,
        'linkExpiration': sharingLinkExpirationStatus,
        'retrieveLink': sharingOperationStatus,
        'updateLink': sharingOperationStatus,
    }


class linkScopeAbilities(object):
    props = {
        'blockDownloadLinkAbilities': linkRoleAbilities,
        'editLinkAbilities': linkRoleAbilities,
        'manageListLinkAbilities': linkRoleAbilities,
        'readLinkAbilities': linkRoleAbilities,
        'reviewLinkAbilities': linkRoleAbilities,
        'submitOnlyLinkAbilities': linkRoleAbilities,
    }


class sharePointSharingAbilities(object):
    props = {
        'anyoneLinkAbilities': linkScopeAbilities,
        'directSharingAbilities': directSharingAbilities,
        'organizationLinkAbilities': linkScopeAbilities,
        'specificPeopleLinkAbilities': linkScopeAbilities,
    }


class broadcastMeetingSettings(object):
    props = {
        'allowedAudience': broadcastMeetingAudience,
        'captions': broadcastMeetingCaptionSettings,
        'isAttendeeReportEnabled': Edm.Boolean,
        'isQuestionAndAnswerEnabled': Edm.Boolean,
        'isRecordingEnabled': Edm.Boolean,
        'isVideoOnDemandEnabled': Edm.Boolean,
    }


class meetingParticipants(object):
    props = {
        'attendees': Collection,
        'contributors': Collection,
        'organizer': meetingParticipantInfo,
        'producers': Collection,
    }


class hybridAgentUpdaterConfiguration(object):
    props = {
        'allowUpdateConfigurationOverride': Edm.Boolean,
        'deferUpdateDateTime': Edm.DateTimeOffset,
        'updateWindow': updateWindow,
    }


class expressionEvaluationDetails(object):
    props = {
        'expression': Edm.String,
        'expressionEvaluationDetails': Collection,
        'expressionResult': Edm.Boolean,
        'propertyToEvaluate': propertyToEvaluate,
    }


class membershipRuleEvaluationDetails(object):
    props = {
        'membershipRuleEvaluationDetails': expressionEvaluationDetails,
    }


class attributeMapping(object):
    props = {
        'defaultValue': Edm.String,
        'exportMissingReferences': Edm.Boolean,
        'flowBehavior': attributeFlowBehavior,
        'flowType': attributeFlowType,
        'matchingPriority': Edm.Int32,
        'source': attributeMappingSource,
        'targetAttributeName': Edm.String,
    }


class expressionInputObject(object):
    props = {
        'definition': objectDefinition,
        'properties': Collection,
    }


class filterClause(object):
    props = {
        'operatorName': Edm.String,
        'sourceOperandName': Edm.String,
        'targetOperand': filterOperand,
    }


class parseExpressionResponse(object):
    props = {
        'error': publicError,
        'evaluationResult': Collection,
        'evaluationSucceeded': Edm.Boolean,
        'parsedExpression': attributeMappingSource,
        'parsingSucceeded': Edm.Boolean,
    }


class publicErrorResponse(object):
    props = {
        'error': publicError,
    }


class synchronizationStatus(object):
    props = {
        'code': synchronizationStatusCode,
        'countSuccessiveCompleteFailures': Edm.Int64,
        'escrowsPruned': Edm.Boolean,
        'lastExecution': synchronizationTaskExecution,
        'lastSuccessfulExecution': synchronizationTaskExecution,
        'lastSuccessfulExecutionWithExports': synchronizationTaskExecution,
        'progress': Collection,
        'quarantine': synchronizationQuarantine,
        'steadyStateFirstAchievedTime': Edm.DateTimeOffset,
        'steadyStateLastAchievedTime': Edm.DateTimeOffset,
        'synchronizedEntryCountByType': Collection,
        'troubleshootingUrl': Edm.String,
    }


class accessReviewHistoryScheduleSettings(object):
    props = {
        'recurrence': patternedRecurrence,
        'reportRange': Edm.String,
    }


class accessReviewNotificationRecipientItem(object):
    props = {
        'notificationRecipientScope': accessReviewNotificationRecipientScope,
        'notificationTemplateType': Edm.String,
    }


class accessReviewScheduleSettings(object):
    props = {
        'applyActions': Collection,
        'autoApplyDecisionsEnabled': Edm.Boolean,
        'decisionHistoriesForReviewersEnabled': Edm.Boolean,
        'defaultDecision': Edm.String,
        'defaultDecisionEnabled': Edm.Boolean,
        'instanceDurationInDays': Edm.Int32,
        'justificationRequiredOnApproval': Edm.Boolean,
        'mailNotificationsEnabled': Edm.Boolean,
        'recommendationInsightSettings': Collection,
        'recommendationLookBackDuration': Edm.Duration,
        'recommendationsEnabled': Edm.Boolean,
        'recurrence': patternedRecurrence,
        'reminderNotificationsEnabled': Edm.Boolean,
    }


class accessReviewSettings(object):
    props = {
        'accessRecommendationsEnabled': Edm.Boolean,
        'activityDurationInDays': Edm.Int32,
        'autoApplyReviewResultsEnabled': Edm.Boolean,
        'autoReviewEnabled': Edm.Boolean,
        'autoReviewSettings': autoReviewSettings,
        'justificationRequiredOnApproval': Edm.Boolean,
        'mailNotificationsEnabled': Edm.Boolean,
        'recurrenceSettings': accessReviewRecurrenceSettings,
        'remindersEnabled': Edm.Boolean,
    }


class conditionalAccessApplications(object):
    props = {
        'applicationFilter': conditionalAccessFilter,
        'excludeApplications': Collection,
        'includeApplications': Collection,
        'includeAuthenticationContextClassReferences': Collection,
        'includeUserActions': Collection,
    }


class conditionalAccessUsers(object):
    props = {
        'excludeGroups': Collection,
        'excludeGuestsOrExternalUsers': conditionalAccessGuestsOrExternalUsers,
        'excludeRoles': Collection,
        'excludeUsers': Collection,
        'includeGroups': Collection,
        'includeGuestsOrExternalUsers': conditionalAccessGuestsOrExternalUsers,
        'includeRoles': Collection,
        'includeUsers': Collection,
    }


class conditionalAccessSessionControls(object):
    props = {
        'applicationEnforcedRestrictions': applicationEnforcedRestrictionsSessionControl,
        'cloudAppSecurity': cloudAppSecuritySessionControl,
        'continuousAccessEvaluation': continuousAccessEvaluationSessionControl,
        'disableResilienceDefaults': Edm.Boolean,
        'persistentBrowser': persistentBrowserSessionControl,
        'secureSignInSession': secureSignInSessionControl,
        'signInFrequency': signInFrequencySessionControl,
    }


class conditionalAccessWhatIfConditions(object):
    props = {
        'authenticationFlow': authenticationFlow,
        'clientAppType': conditionalAccessClientApp,
        'country': Edm.String,
        'deviceInfo': deviceInfo,
        'devicePlatform': conditionalAccessDevicePlatform,
        'insiderRiskLevel': insiderRiskLevel,
        'ipAddress': Edm.String,
        'servicePrincipalRiskLevel': riskLevel,
        'signInRiskLevel': riskLevel,
        'userRiskLevel': riskLevel,
    }


class accessPackageQuestion(object):
    props = {
        'id': Edm.String,
        'isAnswerEditable': Edm.Boolean,
        'isRequired': Edm.Boolean,
        'sequence': Edm.Int32,
        'text': accessPackageLocalizedContent,
    }


class accessPackageAnswerChoice(object):
    props = {
        'actualValue': Edm.String,
        'displayValue': accessPackageLocalizedContent,
    }


class requestSchedule(object):
    props = {
        'expiration': expirationPattern,
        'recurrence': patternedRecurrence,
        'startDateTime': Edm.DateTimeOffset,
    }


class accessPackageResourceAttribute(object):
    props = {
        'attributeDestination': accessPackageResourceAttributeDestination,
        'attributeName': Edm.String,
        'attributeSource': accessPackageResourceAttributeSource,
        'id': Edm.String,
        'isEditable': Edm.Boolean,
        'isPersistedOnAssignmentRemoval': Edm.Boolean,
    }


class accessPackageResourceAttributeQuestion(object):
    props = {
        'question': accessPackageQuestion,
    }


class verifiedCredentialData(object):
    props = {
        'authority': Edm.String,
        'claims': verifiedCredentialClaims,
        'type': Collection,
    }


class applyLabelAction(object):
    props = {
        'actions': Collection,
        'actionSource': actionSource,
        'label': labelDetails,
        'responsibleSensitiveTypeIds': Collection,
    }


class androidEnrollmentCompanyCode(object):
    props = {
        'enrollmentToken': Edm.String,
        'qrCodeContent': Edm.String,
        'qrCodeImage': mimeContent,
    }


class androidFotaDeploymentAssignment(object):
    props = {
        'assignmentTarget': deviceAndAppManagementAssignmentTarget,
        'displayName': Edm.String,
        'id': Edm.String,
        'target': androidFotaDeploymentAssignmentTarget,
    }


class win32LobAppAssignmentSettings(object):
    props = {
        'autoUpdateSettings': win32LobAppAutoUpdateSettings,
        'deliveryOptimizationPriority': win32LobAppDeliveryOptimizationPriority,
        'installTimeSettings': mobileAppInstallTimeSettings,
        'notifications': win32LobAppNotification,
        'restartSettings': win32LobAppRestartSettings,
    }


class winGetAppAssignmentSettings(object):
    props = {
        'installTimeSettings': winGetAppInstallTimeSettings,
        'notifications': winGetAppNotification,
        'restartSettings': winGetAppRestartSettings,
    }


class androidDeviceOwnerDelegatedScopeAppSetting(object):
    props = {
        'appDetail': appListItem,
        'appScopes': Collection,
    }


class appleVpnAlwaysOnConfiguration(object):
    props = {
        'airPrintExceptionAction': vpnServiceExceptionAction,
        'allowAllCaptiveNetworkPlugins': Edm.Boolean,
        'allowCaptiveWebSheet': Edm.Boolean,
        'allowedCaptiveNetworkPlugins': specifiedCaptiveNetworkPlugins,
        'cellularExceptionAction': vpnServiceExceptionAction,
        'natKeepAliveIntervalInSeconds': Edm.Int32,
        'natKeepAliveOffloadEnable': Edm.Boolean,
        'tunnelConfiguration': vpnTunnelConfigurationType,
        'userToggleEnabled': Edm.Boolean,
        'voicemailExceptionAction': vpnServiceExceptionAction,
    }


class bitLockerFixedDrivePolicy(object):
    props = {
        'encryptionMethod': bitLockerEncryptionMethod,
        'recoveryOptions': bitLockerRecoveryOptions,
        'requireEncryptionForWriteAccess': Edm.Boolean,
    }


class windowsKioskSingleUWPApp(object):
    props = {
        'uwpApp': windowsKioskUWPApp,
    }


class windowsKioskSingleWin32App(object):
    props = {
        'win32App': windowsKioskWin32App,
    }


class deviceManagementConfigurationSettingInstance(object):
    props = {
        'settingDefinitionId': Edm.String,
        'settingInstanceTemplateReference': deviceManagementConfigurationSettingInstanceTemplateReference,
    }


class deviceManagementConfigurationSettingValue(object):
    props = {
        'settingValueTemplateReference': deviceManagementConfigurationSettingValueTemplateReference,
    }


class deviceManagementConfigurationChoiceSettingValueTemplate(object):
    props = {
        'defaultValue': deviceManagementConfigurationChoiceSettingValueDefaultTemplate,
        'recommendedValueDefinition': deviceManagementConfigurationChoiceSettingValueDefinitionTemplate,
        'requiredValueDefinition': deviceManagementConfigurationChoiceSettingValueDefinitionTemplate,
        'settingValueTemplateId': Edm.String,
    }


class deviceManagementConfigurationChoiceSettingInstanceTemplate(object):
    props = {
        'choiceSettingValueTemplate': deviceManagementConfigurationChoiceSettingValueTemplate,
    }


class deviceManagementConfigurationOptionDefinition(object):
    props = {
        'dependedOnBy': Collection,
        'dependentOn': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'helpText': Edm.String,
        'itemId': Edm.String,
        'name': Edm.String,
        'optionValue': deviceManagementConfigurationSettingValue,
    }


class deviceManagementSettingInsightsDefinition(object):
    props = {
        'settingDefinitionId': Edm.String,
        'settingInsight': deviceManagementConfigurationSettingValue,
    }


class deviceManagementExchangeAccessRule(object):
    props = {
        'accessLevel': deviceManagementExchangeAccessLevel,
        'deviceClass': deviceManagementExchangeDeviceClass,
    }


class updateWindowsDeviceAccountActionParameter(object):
    props = {
        'calendarSyncEnabled': Edm.Boolean,
        'deviceAccount': windowsDeviceAccount,
        'deviceAccountEmail': Edm.String,
        'exchangeServer': Edm.String,
        'passwordRotationEnabled': Edm.Boolean,
        'sessionInitiationProtocalAddress': Edm.String,
    }


class mobileAppTroubleshootingHistoryItem(object):
    props = {
        'occurrenceDateTime': Edm.DateTimeOffset,
        'troubleshootingErrorDetails': deviceManagementTroubleshootingErrorDetails,
    }


class windowsQualityUpdateCatalogProductRevision(object):
    props = {
        'displayName': Edm.String,
        'knowledgeBaseArticle': windowsQualityUpdateProductKnowledgeBaseArticle,
        'osBuild': windowsQualityUpdateProductBuildVersionDetail,
        'productName': Edm.String,
        'releaseDateTime': Edm.DateTimeOffset,
        'versionName': Edm.String,
    }


class awsIdentitySource(object):
    props = {
        'authorizationSystemInfo': permissionsDefinitionAuthorizationSystem,
    }


class aggregationOption(object):
    props = {
        'bucketDefinition': bucketAggregationDefinition,
        'field': Edm.String,
        'size': Edm.Int32,
    }


class alterationResponse(object):
    props = {
        'originalQueryString': Edm.String,
        'queryAlteration': searchAlteration,
        'queryAlterationType': searchAlterationType,
    }


class groundingResponse(object):
    props = {
        'extracts': Collection,
        'resourceMetadata': searchResourceMetadataDictionary,
        'resourceType': groundingEntityType,
        'sensitivityLabel': searchSensitivityLabelInfo,
        'webUrl': Edm.String,
    }


class searchRequest(object):
    props = {
        'aggregationFilters': Collection,
        'aggregations': Collection,
        'collapseProperties': Collection,
        'contentSources': Collection,
        'enableTopResults': Edm.Boolean,
        'entityTypes': Collection,
        'fields': Collection,
        'from': Edm.Int32,
        'query': searchQuery,
        'queryAlterationOptions': searchAlterationOptions,
        'region': Edm.String,
        'resultTemplateOptions': resultTemplateOption,
        'sharePointOneDriveOptions': sharePointOneDriveOptions,
        'size': Edm.Int32,
        'sortProperties': Collection,
        'stored_fields': Collection,
        'trimDuplicates': Edm.Boolean,
    }


class searchResponse(object):
    props = {
        'hitsContainers': Collection,
        'queryAlterationResponse': alterationResponse,
        'resultTemplates': resultTemplateDictionary,
        'searchTerms': Collection,
    }


class payloadTypes(object):
    props = {
        'rawContent': Edm.String,
        'visualContent': visualProperties,
    }


class plannerTaskCreation(object):
    props = {
        'creationSourceKind': plannerCreationSourceKind,
        'teamsPublicationInfo': plannerTeamsPublicationInfo,
    }


class notebookLinks(object):
    props = {
        'oneNoteClientUrl': externalLink,
        'oneNoteWebUrl': externalLink,
    }


class onenotePagePreview(object):
    props = {
        'links': onenotePagePreviewLinks,
        'previewText': Edm.String,
    }


class recentNotebook(object):
    props = {
        'displayName': Edm.String,
        'lastAccessedTime': Edm.DateTimeOffset,
        'links': recentNotebookLinks,
        'sourceService': onenoteSourceService,
    }


class printerDocumentConfiguration(object):
    props = {
        'collate': Edm.Boolean,
        'colorMode': printColorMode,
        'copies': Edm.Int32,
        'dpi': Edm.Int32,
        'duplexMode': printDuplexMode,
        'feedDirection': printerFeedDirection,
        'feedOrientation': printerFeedOrientation,
        'finishings': Collection,
        'fitPdfToPage': Edm.Boolean,
        'inputBin': Edm.String,
        'margin': printMargin,
        'mediaSize': Edm.String,
        'mediaType': Edm.String,
        'multipageLayout': printMultipageLayout,
        'orientation': printOrientation,
        'outputBin': Edm.String,
        'pageRanges': Collection,
        'pagesPerSheet': Edm.Int32,
        'quality': printQuality,
        'scaling': printScaling,
    }


class attackSimulationRepeatOffender(object):
    props = {
        'attackSimulationUser': attackSimulationUser,
        'repeatOffenceCount': Edm.Int32,
    }


class endUserNotificationSetting(object):
    props = {
        'notificationPreference': endUserNotificationPreference,
        'positiveReinforcement': positiveReinforcementNotification,
        'settingType': endUserNotificationSettingType,
    }


class noTrainingNotificationSetting(object):
    props = {
        'simulationNotification': simulationNotification,
    }


class simulationReportOverview(object):
    props = {
        'recommendedActions': Collection,
        'resolvedTargetsCount': Edm.Int32,
        'simulationEventsContent': simulationEventsContent,
        'trainingEventsContent': trainingEventsContent,
    }


class trainingCampaignReportOverview(object):
    props = {
        'trainingModuleCompletion': trainingEventsContent,
        'trainingNotificationDeliveryStatus': trainingNotificationDelivery,
        'userCompletionStatus': userTrainingCompletionSummary,
    }


class trainingNotificationSetting(object):
    props = {
        'trainingAssignment': baseEndUserNotification,
        'trainingReminder': trainingReminderNotification,
    }


class userTrainingEventInfo(object):
    props = {
        'displayName': Edm.String,
        'latestTrainingStatus': trainingStatus,
        'trainingAssignedProperties': userTrainingContentEventInfo,
        'trainingCompletedProperties': userTrainingContentEventInfo,
        'trainingUpdatedProperties': userTrainingContentEventInfo,
    }


class emergencyCallerInfo(object):
    props = {
        'displayName': Edm.String,
        'location': location,
        'phoneNumber': Edm.String,
        'tenantId': Edm.String,
        'upn': Edm.String,
    }


class webauthnPublicKeyCredentialCreationOptions(object):
    props = {
        'attestation': Edm.String,
        'authenticatorSelection': webauthnAuthenticatorSelectionCriteria,
        'challenge': Edm.String,
        'excludeCredentials': Collection,
        'extensions': webauthnAuthenticationExtensionsClientInputs,
        'pubKeyCredParams': Collection,
        'rp': webauthnPublicKeyCredentialRpEntity,
        'timeout': Edm.Int32,
        'user': webauthnPublicKeyCredentialUserEntity,
    }


class changeNotification(object):
    props = {
        'changeType': changeType,
        'clientState': Edm.String,
        'encryptedContent': changeNotificationEncryptedContent,
        'id': Edm.String,
        'lifecycleEvent': lifecycleEventType,
        'resource': Edm.String,
        'resourceData': resourceData,
        'subscriptionExpirationDateTime': Edm.DateTimeOffset,
        'subscriptionId': Edm.Guid,
        'tenantId': Edm.Guid,
    }


class actionResultPart(object):
    props = {
        'error': publicError,
    }


class aiInteractionMentionedIdentitySet(object):
    props = {
        'conversation': teamworkConversationIdentity,
        'tag': teamworkTagIdentity,
    }


class chatMessageReaction(object):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'reactionContentUrl': Edm.String,
        'reactionType': Edm.String,
        'user': chatMessageReactionIdentitySet,
    }


class chatMessageMention(object):
    props = {
        'id': Edm.Int32,
        'mentioned': chatMessageMentionedIdentitySet,
        'mentionText': Edm.String,
    }


class chatMessagePolicyViolation(object):
    props = {
        'dlpAction': chatMessagePolicyViolationDlpActionTypes,
        'justificationText': Edm.String,
        'policyTip': chatMessagePolicyViolationPolicyTip,
        'userAction': chatMessagePolicyViolationUserActionTypes,
        'verdictDetails': chatMessagePolicyViolationVerdictDetailsTypes,
    }


class conversationMemberRoleUpdatedEventMessageDetail(object):
    props = {
        'conversationMemberRoles': Collection,
        'conversationMemberUser': teamworkUserIdentity,
        'initiator': identitySet,
    }


class teamsAppAuthorization(object):
    props = {
        'clientAppId': Edm.String,
        'requiredPermissionSet': teamsAppPermissionSet,
    }


class teamworkAccountConfiguration(object):
    props = {
        'onPremisesCalendarSyncConfiguration': teamworkOnPremisesCalendarSyncConfiguration,
        'supportedClient': teamworkSupportedClient,
    }


class teamworkCameraConfiguration(object):
    props = {
        'contentCameraConfiguration': teamworkContentCameraConfiguration,
    }


class teamworkDisplayConfiguration(object):
    props = {
        'configuredDisplays': Collection,
        'displayCount': Edm.Int32,
        'inBuiltDisplayScreenConfiguration': teamworkDisplayScreenConfiguration,
        'isContentDuplicationAllowed': Edm.Boolean,
        'isDualDisplayModeEnabled': Edm.Boolean,
    }


class teamworkHardwareHealth(object):
    props = {
        'computeHealth': teamworkPeripheralHealth,
        'hdmiIngestHealth': teamworkPeripheralHealth,
    }


class teamworkSoftwareUpdateHealth(object):
    props = {
        'adminAgentSoftwareUpdateStatus': teamworkSoftwareUpdateStatus,
        'companyPortalSoftwareUpdateStatus': teamworkSoftwareUpdateStatus,
        'firmwareSoftwareUpdateStatus': teamworkSoftwareUpdateStatus,
        'operatingSystemSoftwareUpdateStatus': teamworkSoftwareUpdateStatus,
        'partnerAgentSoftwareUpdateStatus': teamworkSoftwareUpdateStatus,
        'teamsClientSoftwareUpdateStatus': teamworkSoftwareUpdateStatus,
    }


class teamworkTeamsClientConfiguration(object):
    props = {
        'accountConfiguration': teamworkAccountConfiguration,
        'featuresConfiguration': teamworkFeaturesConfiguration,
    }


class shiftAvailability(object):
    props = {
        'recurrence': patternedRecurrence,
        'timeSlots': Collection,
        'timeZone': Edm.String,
    }


class timeCardBreak(object):
    props = {
        'breakId': Edm.String,
        'end': timeCardEvent,
        'notes': itemBody,
        'start': timeCardEvent,
    }


class bookingCustomerInformation(object):
    props = {
        'customerId': Edm.String,
        'customQuestionAnswers': Collection,
        'emailAddress': Edm.String,
        'location': location,
        'name': Edm.String,
        'notes': Edm.String,
        'phone': Edm.String,
        'smsNotificationsEnabled': Edm.Boolean,
        'timeZone': Edm.String,
    }


class appManagementApplicationConfiguration(object):
    props = {
        'identifierUris': identifierUriConfiguration,
    }


class customClaimTransformation(object):
    props = {
        'input': transformationAttribute,
    }


class containsTransformation(object):
    props = {
        'output': transformationAttribute,
        'value': Edm.String,
    }


class workplaceSensorDeviceTelemetry(object):
    props = {
        'boolValue': Edm.Boolean,
        'deviceId': Edm.String,
        'eventValue': workplaceSensorEventValue,
        'intValue': Edm.Int32,
        'locationHint': Edm.String,
        'sensorId': Edm.String,
        'sensorType': workplaceSensorType,
        'timestamp': Edm.DateTimeOffset,
    }


class sharingViewpoint(object):
    props = {
        'defaultSharingLink': defaultSharingLink,
        'sharingAbilities': sharePointSharingAbilities,
    }


class evaluateDynamicMembershipResult(object):
    props = {
        'membershipRule': Edm.String,
        'membershipRuleEvaluationDetails': expressionEvaluationDetails,
        'membershipRuleEvaluationResult': Edm.Boolean,
    }


class conditionalAccessConditionSet(object):
    props = {
        'applications': conditionalAccessApplications,
        'authenticationFlows': conditionalAccessAuthenticationFlows,
        'clientApplications': conditionalAccessClientApplications,
        'clientAppTypes': Collection,
        'devices': conditionalAccessDevices,
        'deviceStates': conditionalAccessDeviceStates,
        'insiderRiskLevels': conditionalAccessInsiderRiskLevels,
        'locations': conditionalAccessLocations,
        'platforms': conditionalAccessPlatforms,
        'servicePrincipalRiskLevels': Collection,
        'signInRiskLevels': Collection,
        'userRiskLevels': Collection,
        'users': conditionalAccessUsers,
    }


class conditionalAccessPolicyDetail(object):
    props = {
        'conditions': conditionalAccessConditionSet,
        'grantControls': conditionalAccessGrantControls,
        'sessionControls': conditionalAccessSessionControls,
    }


class accessPackageAnswer(object):
    props = {
        'answeredQuestion': accessPackageQuestion,
        'displayValue': Edm.String,
    }


class accessPackageAssignmentRequestRequirements(object):
    props = {
        'existingAnswers': Collection,
        'isApprovalRequired': Edm.Boolean,
        'isApprovalRequiredForExtension': Edm.Boolean,
        'isCustomAssignmentScheduleAllowed': Edm.Boolean,
        'isRequestorJustificationRequired': Edm.Boolean,
        'policyDescription': Edm.String,
        'policyDisplayName': Edm.String,
        'policyId': Edm.String,
        'questions': Collection,
        'schedule': requestSchedule,
        'verifiableCredentialRequirementStatus': verifiableCredentialRequirementStatus,
    }


class CopyNotebookModel(object):
    props = {
        'createdBy': Edm.String,
        'createdByIdentity': identitySet,
        'createdTime': Edm.DateTimeOffset,
        'id': Edm.String,
        'isDefault': Edm.Boolean,
        'isShared': Edm.Boolean,
        'lastModifiedBy': Edm.String,
        'lastModifiedByIdentity': identitySet,
        'lastModifiedTime': Edm.DateTimeOffset,
        'links': notebookLinks,
        'name': Edm.String,
        'sectionGroupsUrl': Edm.String,
        'sectionsUrl': Edm.String,
        'self': Edm.String,
        'userRole': onenoteUserRole,
    }


class simulationReport(object):
    props = {
        'overview': simulationReportOverview,
        'simulationUsers': Collection,
    }


class trainingCampaignReport(object):
    props = {
        'campaignUsers': Collection,
        'overview': trainingCampaignReportOverview,
    }


class webauthnCredentialCreationOptions(object):
    props = {
        'challengeTimeoutDateTime': Edm.DateTimeOffset,
        'publicKey': webauthnPublicKeyCredentialCreationOptions,
    }


class aiInteractionMention(object):
    props = {
        'mentioned': aiInteractionMentionedIdentitySet,
        'mentionId': Edm.Int32,
        'mentionText': Edm.String,
    }


class chatMessageHistoryItem(object):
    props = {
        'actions': chatMessageActions,
        'modifiedDateTime': Edm.DateTimeOffset,
        'reaction': chatMessageReaction,
    }


class driveItemViewpoint(object):
    props = {
        'accessOperations': driveItemAccessOperationsViewpoint,
        'sharing': sharingViewpoint,
    }

# Self-referential and circle reference types
class workbookOperationError(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'code': Edm.String,
            'innerError': workbookOperationError,
            'message': Edm.String,
        }


class retentionLabelSettings(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'behaviorDuringRetentionPeriod': behaviorDuringRetentionPeriod,
            'isContentUpdateAllowed': Edm.Boolean,
            'isDeleteAllowed': Edm.Boolean,
            'isLabelUpdateAllowed': Edm.Boolean,
            'isMetadataUpdateAllowed': Edm.Boolean,
            'isRecordLocked': Edm.Boolean,
        }


class synchronizationJobSubject(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'links': synchronizationLinkedObjects,
            'objectId': Edm.String,
            'objectTypeName': Edm.String,
        }


class synchronizationLinkedObjects(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'manager': synchronizationJobSubject,
            'members': Collection,
            'owners': Collection,
        }


class parentLabelDetails(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'color': Edm.String,
            'description': Edm.String,
            'id': Edm.String,
            'isActive': Edm.Boolean,
            'name': Edm.String,
            'parent': parentLabelDetails,
            'sensitivity': Edm.Int32,
            'tooltip': Edm.String,
        }


class security_alertEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'createdDateTime': Edm.DateTimeOffset,
            'detailedRoles': Collection,
            'remediationStatus': evidenceRemediationStatus,
            'remediationStatusDetails': Edm.String,
            'roles': Collection,
            'tags': Collection,
            'verdict': evidenceVerdict,
        }


class security_allowFileResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'deviceGroupNames': Collection,
            'identifier': fileEntityIdentifier,
        }


class security_analyzedMessageEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'antiSpamDirection': Edm.String,
            'attachmentsCount': Edm.Int64,
            'deliveryAction': Edm.String,
            'deliveryLocation': Edm.String,
            'internetMessageId': Edm.String,
            'language': Edm.String,
            'networkMessageId': Edm.String,
            'p1Sender': emailSender,
            'p2Sender': emailSender,
            'receivedDateTime': Edm.DateTimeOffset,
            'recipientEmailAddress': Edm.String,
            'senderIp': Edm.String,
            'subject': Edm.String,
            'threatDetectionMethods': Collection,
            'threats': Collection,
            'urlCount': Edm.Int64,
            'urls': Collection,
            'urn': Edm.String,
        }


class security_blobContainerEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'name': Edm.String,
            'storageResource': azureResourceEvidence,
            'url': Edm.String,
        }


class security_blobEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'blobContainer': blobContainerEvidence,
            'etag': Edm.String,
            'fileHashes': Collection,
            'name': Edm.String,
            'url': Edm.String,
        }


class security_fileHash(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'algorithm': fileHashAlgorithm,
            'value': Edm.String,
        }


class security_blockFileResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'deviceGroupNames': Collection,
            'identifier': fileEntityIdentifier,
        }


class security_cloudApplicationEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'appId': Edm.Int64,
            'displayName': Edm.String,
            'instanceId': Edm.Int64,
            'instanceName': Edm.String,
            'saasAppId': Edm.Int64,
            'stream': stream,
        }


class security_cloudLogonSessionEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'account': userEvidence,
            'browser': Edm.String,
            'deviceName': Edm.String,
            'operatingSystem': Edm.String,
            'previousLogonDateTime': Edm.DateTimeOffset,
            'protocol': Edm.String,
            'sessionId': Edm.String,
            'startUtcDateTime': Edm.DateTimeOffset,
            'userAgent': Edm.String,
        }


class security_userEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'stream': stream,
            'userAccount': userAccount,
        }


class security_collectInvestigationPackageResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': deviceIdEntityIdentifier,
        }


class security_containerEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'args': Collection,
            'command': Collection,
            'containerId': Edm.String,
            'image': containerImageEvidence,
            'isPrivileged': Edm.Boolean,
            'name': Edm.String,
            'pod': kubernetesPodEvidence,
        }


class security_containerImageEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'digestImage': containerImageEvidence,
            'imageId': Edm.String,
            'registry': containerRegistryEvidence,
        }


class security_kubernetesPodEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'containers': Collection,
            'controller': kubernetesControllerEvidence,
            'ephemeralContainers': Collection,
            'initContainers': Collection,
            'labels': dictionary,
            'name': Edm.String,
            'namespace': kubernetesNamespaceEvidence,
            'podIp': ipEvidence,
            'serviceAccount': kubernetesServiceAccountEvidence,
        }


class security_detectionAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'alertTemplate': alertTemplate,
            'organizationalScope': organizationalScope,
            'responseActions': Collection,
        }


class security_organizationalScope(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'scopeNames': Collection,
            'scopeType': scopeType,
        }


class security_deviceEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'azureAdDeviceId': Edm.String,
            'defenderAvStatus': defenderAvStatus,
            'deviceDnsName': Edm.String,
            'dnsDomain': Edm.String,
            'firstSeenDateTime': Edm.DateTimeOffset,
            'healthStatus': deviceHealthStatus,
            'hostName': Edm.String,
            'ipInterfaces': Collection,
            'lastExternalIpAddress': Edm.String,
            'lastIpAddress': Edm.String,
            'loggedOnUsers': Collection,
            'mdeDeviceId': Edm.String,
            'ntDomain': Edm.String,
            'onboardingStatus': onboardingStatus,
            'osBuild': Edm.Int64,
            'osPlatform': Edm.String,
            'rbacGroupId': Edm.Int32,
            'rbacGroupName': Edm.String,
            'riskScore': deviceRiskScore,
            'version': Edm.String,
            'vmMetadata': vmMetadata,
        }


class security_vmMetadata(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'cloudProvider': vmCloudProvider,
            'resourceId': Edm.String,
            'subscriptionId': Edm.String,
            'vmId': Edm.String,
        }


class security_disableUserResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': disableUserEntityIdentifier,
        }


class security_dnsEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'dnsServerIp': ipEvidence,
            'domainName': Edm.String,
            'hostIpAddress': ipEvidence,
            'ipAddresses': Collection,
        }


class security_ipEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'countryLetterCode': Edm.String,
            'ipAddress': Edm.String,
            'location': geoLocation,
            'stream': stream,
        }


class security_fileEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'detectionStatus': detectionStatus,
            'fileDetails': fileDetails,
            'mdeDeviceId': Edm.String,
        }


class security_fileHashEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'algorithm': fileHashAlgorithm,
            'value': Edm.String,
        }


class security_forceUserPasswordResetResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': forceUserPasswordResetEntityIdentifier,
        }


class security_googleCloudResourceEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'fullResourceName': Edm.String,
            'location': Edm.String,
            'locationType': googleCloudLocationType,
            'projectId': Edm.String,
            'projectNumber': Edm.Int64,
            'resourceName': Edm.String,
            'resourceType': Edm.String,
        }


class security_hardDeleteResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': emailEntityIdentifier,
        }


class security_hostLogonSessionEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'account': userEvidence,
            'endUtcDateTime': Edm.DateTimeOffset,
            'host': deviceEvidence,
            'sessionId': Edm.String,
            'startUtcDateTime': Edm.DateTimeOffset,
        }


class security_impactedDeviceAsset(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': deviceAssetIdentifier,
        }


class security_impactedMailboxAsset(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': mailboxAssetIdentifier,
        }


class security_impactedUserAsset(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': userAssetIdentifier,
        }


class security_initiateInvestigationResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': deviceIdEntityIdentifier,
        }


class security_ioTDeviceEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'deviceId': Edm.String,
            'deviceName': Edm.String,
            'devicePageLink': Edm.String,
            'deviceSubType': Edm.String,
            'deviceType': Edm.String,
            'importance': ioTDeviceImportanceType,
            'ioTHub': azureResourceEvidence,
            'ioTSecurityAgentId': Edm.String,
            'ipAddress': ipEvidence,
            'isAuthorized': Edm.Boolean,
            'isProgramming': Edm.Boolean,
            'isScanner': Edm.Boolean,
            'macAddress': Edm.String,
            'manufacturer': Edm.String,
            'model': Edm.String,
            'nics': Collection,
            'operatingSystem': Edm.String,
            'owners': Collection,
            'protocols': Collection,
            'purdueLayer': Edm.String,
            'sensor': Edm.String,
            'serialNumber': Edm.String,
            'site': Edm.String,
            'source': Edm.String,
            'sourceRef': urlEvidence,
            'zone': Edm.String,
        }


class security_nicEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'ipAddress': ipEvidence,
            'macAddress': Edm.String,
            'vlans': Collection,
        }


class security_isolateDeviceResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': deviceIdEntityIdentifier,
            'isolationType': isolationType,
        }


class security_kubernetesClusterEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'cloudResource': alertEvidence,
            'distribution': Edm.String,
            'name': Edm.String,
            'platform': kubernetesPlatform,
            'version': Edm.String,
        }


class security_kubernetesControllerEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'labels': dictionary,
            'name': Edm.String,
            'namespace': kubernetesNamespaceEvidence,
            'type': Edm.String,
        }


class security_kubernetesNamespaceEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'cluster': kubernetesClusterEvidence,
            'labels': dictionary,
            'name': Edm.String,
        }


class security_kubernetesServiceAccountEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'name': Edm.String,
            'namespace': kubernetesNamespaceEvidence,
        }


class security_kubernetesSecretEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'name': Edm.String,
            'namespace': kubernetesNamespaceEvidence,
            'secretType': Edm.String,
        }


class security_kubernetesServiceEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'clusterIP': ipEvidence,
            'externalIPs': Collection,
            'labels': dictionary,
            'name': Edm.String,
            'namespace': kubernetesNamespaceEvidence,
            'selector': dictionary,
            'servicePorts': Collection,
            'serviceType': kubernetesServiceType,
        }


class security_kubernetesServicePort(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'appProtocol': Edm.String,
            'name': Edm.String,
            'nodePort': Edm.Int32,
            'port': Edm.Int32,
            'protocol': containerPortProtocol,
            'targetPort': Edm.String,
        }


class security_mailboxConfigurationEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'configurationId': Edm.String,
            'configurationType': mailboxConfigurationType,
            'displayName': Edm.String,
            'externalDirectoryObjectId': Edm.Guid,
            'mailboxPrimaryAddress': Edm.String,
            'upn': Edm.String,
        }


class security_processEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'detectionStatus': detectionStatus,
            'imageFile': fileDetails,
            'mdeDeviceId': Edm.String,
            'parentProcessCreationDateTime': Edm.DateTimeOffset,
            'parentProcessId': Edm.Int64,
            'parentProcessImageFile': fileDetails,
            'processCommandLine': Edm.String,
            'processCreationDateTime': Edm.DateTimeOffset,
            'processId': Edm.Int64,
            'userAccount': userAccount,
        }


class security_markUserAsCompromisedResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': markUserAsCompromisedEntityIdentifier,
        }


class security_moveToDeletedItemsResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': emailEntityIdentifier,
        }


class security_moveToInboxResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': emailEntityIdentifier,
        }


class security_moveToJunkResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': emailEntityIdentifier,
        }


class security_networkConnectionEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'destinationAddress': ipEvidence,
            'destinationPort': Edm.Int32,
            'protocol': protocolType,
            'sourceAddress': ipEvidence,
            'sourcePort': Edm.Int32,
        }


class security_restrictAppExecutionResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': deviceIdEntityIdentifier,
        }


class security_runAntivirusScanResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': deviceIdEntityIdentifier,
        }


class security_runDetails(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'errorCode': huntingRuleErrorCode,
            'failureReason': Edm.String,
            'lastRunDateTime': Edm.DateTimeOffset,
            'status': huntingRuleRunStatus,
        }


class security_sasTokenEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'allowedIpAddresses': Edm.String,
            'allowedResourceTypes': Collection,
            'allowedServices': Collection,
            'expiryDateTime': Edm.DateTimeOffset,
            'permissions': Collection,
            'protocol': Edm.String,
            'signatureHash': Edm.String,
            'signedWith': Edm.String,
            'startDateTime': Edm.DateTimeOffset,
            'storageResource': azureResourceEvidence,
        }


class security_servicePrincipalEvidence(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'appId': Edm.String,
            'appOwnerTenantId': Edm.String,
            'servicePrincipalName': Edm.String,
            'servicePrincipalObjectId': Edm.String,
            'servicePrincipalType': servicePrincipalType,
            'tenantId': Edm.String,
        }


class security_softDeleteResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': emailEntityIdentifier,
        }


class security_stopAndQuarantineFileResponseAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'identifier': stopAndQuarantineFileEntityIdentifier,
        }


class security_analyzedEmailAttachment(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'detonationDetails': detonationDetails,
            'fileExtension': Edm.String,
            'fileName': Edm.String,
            'fileSize': Edm.Int32,
            'fileType': Edm.String,
            'malwareFamily': Edm.String,
            'sha256': Edm.String,
            'tenantAllowBlockListDetailInfo': Edm.String,
            'threatType': threatType,
        }


class security_detonationDetails(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'analysisDateTime': Edm.DateTimeOffset,
            'compromiseIndicators': Collection,
            'detonationBehaviourDetails': detonationBehaviourDetails,
            'detonationChain': detonationChain,
            'detonationObservables': detonationObservables,
            'detonationScreenshotUri': Edm.String,
            'detonationVerdict': Edm.String,
            'detonationVerdictReason': Edm.String,
        }


class security_analyzedEmailDeliveryDetail(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'action': deliveryAction,
            'latestThreats': Edm.String,
            'location': deliveryLocation,
            'originalThreats': Edm.String,
        }


class security_analyzedEmailUrl(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'detectionMethod': Edm.String,
            'detonationDetails': detonationDetails,
            'tenantAllowBlockListDetailInfo': Edm.String,
            'threatType': threatType,
            'url': Edm.String,
        }


class security_compromiseIndicator(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'value': Edm.String,
            'verdict': verdictCategory,
        }


class security_timelineEvent(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'eventDateTime': Edm.DateTimeOffset,
            'eventDetails': Edm.String,
            'eventResult': Edm.String,
            'eventSource': eventSource,
            'eventThreats': Collection,
            'eventType': timelineEventType,
        }


class security_eventPropagationResult(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'location': Edm.String,
            'serviceName': Edm.String,
            'status': eventPropagationStatus,
            'statusInformation': Edm.String,
        }


class security_eventQuery(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'query': Edm.String,
            'queryType': queryType,
        }


class security_filePlanAppliedCategory(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'subcategory': filePlanSubcategory,
        }


class security_retentionEventStatus(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'error': publicError,
            'status': eventStatusType,
        }


class security_submissionAdminReview(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'reviewBy': Edm.String,
            'reviewDateTime': Edm.DateTimeOffset,
            'reviewResult': submissionResultCategory,
        }


class security_submissionResult(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'category': submissionResultCategory,
            'detail': submissionResultDetail,
            'detectedFiles': Collection,
            'detectedUrls': Collection,
            'userMailboxSetting': userMailboxSetting,
        }


class security_tenantAllowBlockListEntryResult(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'entryType': tenantAllowBlockListEntryType,
            'expirationDateTime': Edm.DateTimeOffset,
            'identity': Edm.String,
            'status': longRunningOperationStatus,
            'value': Edm.String,
        }


class security_tenantAllowOrBlockListAction(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'action': tenantAllowBlockListAction,
            'expirationDateTime': Edm.DateTimeOffset,
            'note': Edm.String,
            'results': Collection,
        }


class security_cvssSummary(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'score': Edm.Double,
            'severity': vulnerabilitySeverity,
            'vectorString': Edm.String,
        }


class security_hostReputationRule(object):
    props = {}
    def __init__(self):
        self.__class__.props = {
            'description': Edm.String,
            'name': Edm.String,
            'relatedDetailsUrl': Edm.String,
            'severity': hostReputationRuleSeverity,
        }

