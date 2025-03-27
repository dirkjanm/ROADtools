from roadtools.roadlib.metadef.basetypes import Edm, Collection
from roadtools.roadlib.metadef.complextypes_msgraph import *
class entity(object):
    props = {
        'id': Edm.String,
    }
    rels = [

    ]


class directoryObject(entity):
    props = {
        'deletedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]

class identityGovernance_workflowBase(object):
    props = {
        'category': Collection, #extnamespace: identityGovernance_lifecycleWorkflowCategory,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'executionConditions': Collection, #extnamespace: identityGovernance_workflowExecutionConditions,
        'isEnabled': Edm.Boolean,
        'isSchedulingEnabled': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'createdBy',
        'lastModifiedBy',
        'tasks',
    ]


class identityGovernance_lifecycleWorkflowsContainer(entity):
    props = {

    }
    rels = [
        'customTaskExtensions',
        'deletedItems',
        'insights',
        'settings',
        'taskDefinitions',
        'workflows',
        'workflowTemplates',
    ]


class identityGovernance_task(entity):
    props = {
        'arguments': Collection,
        'category': Collection, #extnamespace: identityGovernance_lifecycleTaskCategory,
        'continueOnError': Edm.Boolean,
        'description': Edm.String,
        'displayName': Edm.String,
        'executionSequence': Edm.Int32,
        'isEnabled': Edm.Boolean,
        'taskDefinitionId': Edm.String,
    }
    rels = [
        'taskProcessingResults',
    ]


class identityGovernance_taskProcessingResult(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'failureReason': Edm.String,
        'processingStatus': Collection, #extnamespace: identityGovernance_lifecycleWorkflowProcessingStatus,
        'startedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'subject',
        'task',
    ]


class identityGovernance_insights(entity):
    props = {

    }
    rels = [

    ]


class identityGovernance_lifecycleManagementSettings(entity):
    props = {
        'emailSettings': emailSettings,
        'workflowScheduleIntervalInHours': Edm.Int32,
    }
    rels = [

    ]


class identityGovernance_taskDefinition(entity):
    props = {
        'category': Collection, #extnamespace: identityGovernance_lifecycleTaskCategory,
        'continueOnError': Edm.Boolean,
        'description': Edm.String,
        'displayName': Edm.String,
        'parameters': Collection,
        'version': Edm.Int32,
    }
    rels = [

    ]


class identityGovernance_workflowTemplate(entity):
    props = {
        'category': Collection, #extnamespace: identityGovernance_lifecycleWorkflowCategory,
        'description': Edm.String,
        'displayName': Edm.String,
        'executionConditions': Collection, #extnamespace: identityGovernance_workflowExecutionConditions,
    }
    rels = [
        'tasks',
    ]


class identityGovernance_run(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'failedTasksCount': Edm.Int32,
        'failedUsersCount': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'processingStatus': Collection, #extnamespace: identityGovernance_lifecycleWorkflowProcessingStatus,
        'scheduledDateTime': Edm.DateTimeOffset,
        'startedDateTime': Edm.DateTimeOffset,
        'successfulUsersCount': Edm.Int32,
        'totalTasksCount': Edm.Int32,
        'totalUnprocessedTasksCount': Edm.Int32,
        'totalUsersCount': Edm.Int32,
        'workflowExecutionType': Collection, #extnamespace: identityGovernance_workflowExecutionType,
    }
    rels = [
        'taskProcessingResults',
        'userProcessingResults',
    ]


class identityGovernance_userProcessingResult(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'failedTasksCount': Edm.Int32,
        'processingStatus': Collection, #extnamespace: identityGovernance_lifecycleWorkflowProcessingStatus,
        'scheduledDateTime': Edm.DateTimeOffset,
        'startedDateTime': Edm.DateTimeOffset,
        'totalTasksCount': Edm.Int32,
        'totalUnprocessedTasksCount': Edm.Int32,
        'workflowExecutionType': Collection, #extnamespace: identityGovernance_workflowExecutionType,
        'workflowVersion': Edm.Int32,
    }
    rels = [
        'subject',
        'taskProcessingResults',
    ]


class identityGovernance_taskReport(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'failedUsersCount': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'processingStatus': Collection, #extnamespace: identityGovernance_lifecycleWorkflowProcessingStatus,
        'runId': Edm.String,
        'startedDateTime': Edm.DateTimeOffset,
        'successfulUsersCount': Edm.Int32,
        'totalUsersCount': Edm.Int32,
        'unprocessedUsersCount': Edm.Int32,
    }
    rels = [
        'task',
        'taskDefinition',
        'taskProcessingResults',
    ]


class application(directoryObject):
    props = {
        'api': apiApplication,
        'appId': Edm.String,
        'appRoles': Collection,
        'authenticationBehaviors': authenticationBehaviors,
        'certification': certification,
        'createdDateTime': Edm.DateTimeOffset,
        'defaultRedirectUri': Edm.String,
        'description': Edm.String,
        'disabledByMicrosoftStatus': Edm.String,
        'displayName': Edm.String,
        'groupMembershipClaims': Edm.String,
        'identifierUris': Collection,
        'info': informationalUrl,
        'isDeviceOnlyAuthSupported': Edm.Boolean,
        'isFallbackPublicClient': Edm.Boolean,
        'keyCredentials': Collection,
        'logo': Edm.Stream,
        'nativeAuthenticationApisEnabled': nativeAuthenticationApisEnabled,
        'notes': Edm.String,
        'optionalClaims': optionalClaims,
        'parentalControlSettings': parentalControlSettings,
        'passwordCredentials': Collection,
        'publicClient': publicClientApplication,
        'publisherDomain': Edm.String,
        'requestSignatureVerification': requestSignatureVerification,
        'requiredResourceAccess': Collection,
        'samlMetadataUrl': Edm.String,
        'serviceManagementReference': Edm.String,
        'servicePrincipalLockConfiguration': servicePrincipalLockConfiguration,
        'signInAudience': Edm.String,
        'spa': spaApplication,
        'tags': Collection,
        'tokenEncryptionKeyId': Edm.Guid,
        'uniqueName': Edm.String,
        'verifiedPublisher': verifiedPublisher,
        'web': webApplication,
        'windows': windowsApplication,
        'onPremisesPublishing': onPremisesPublishing,
    }
    rels = [
        'appManagementPolicies',
        'createdOnBehalfOf',
        'extensionProperties',
        'federatedIdentityCredentials',
        'homeRealmDiscoveryPolicies',
        'owners',
        'tokenIssuancePolicies',
        'tokenLifetimePolicies',
        'connectorGroup',
        'synchronization',
    ]


class policyBase(directoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class extensionProperty(directoryObject):
    props = {
        'appDisplayName': Edm.String,
        'dataType': Edm.String,
        'isMultiValued': Edm.Boolean,
        'isSyncedFromOnPremises': Edm.Boolean,
        'name': Edm.String,
        'targetObjects': Collection,
    }
    rels = [

    ]


class federatedIdentityCredential(entity):
    props = {
        'audiences': Collection,
        'claimsMatchingExpression': federatedIdentityExpression,
        'description': Edm.String,
        'issuer': Edm.String,
        'name': Edm.String,
        'subject': Edm.String,
    }
    rels = [

    ]


class connectorGroup(entity):
    props = {
        'connectorGroupType': connectorGroupType,
        'isDefault': Edm.Boolean,
        'name': Edm.String,
        'region': connectorGroupRegion,
    }
    rels = [
        'applications',
        'members',
    ]


class synchronization(entity):
    props = {
        'secrets': Collection,
    }
    rels = [
        'jobs',
        'templates',
    ]


class customCalloutExtension(entity):
    props = {
        'authenticationConfiguration': customExtensionAuthenticationConfiguration,
        'clientConfiguration': customExtensionClientConfiguration,
        'description': Edm.String,
        'displayName': Edm.String,
        'endpointConfiguration': customExtensionEndpointConfiguration,
    }
    rels = [

    ]


class deletedItemContainer(entity):
    props = {

    }
    rels = [
        'workflows',
    ]


class group(directoryObject):
    props = {
        'cloudLicensing': Collection, #extnamespace: cloudLicensing_groupCloudLicensing,
        'assignedLabels': Collection,
        'assignedLicenses': Collection,
        'classification': Edm.String,
        'createdByAppId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'groupTypes': Collection,
        'hasMembersWithLicenseErrors': Edm.Boolean,
        'infoCatalogs': Collection,
        'isAssignableToRole': Edm.Boolean,
        'isManagementRestricted': Edm.Boolean,
        'licenseProcessingState': licenseProcessingState,
        'mail': Edm.String,
        'mailEnabled': Edm.Boolean,
        'mailNickname': Edm.String,
        'membershipRule': Edm.String,
        'membershipRuleProcessingState': Edm.String,
        'onPremisesDomainName': Edm.String,
        'onPremisesLastSyncDateTime': Edm.DateTimeOffset,
        'onPremisesNetBiosName': Edm.String,
        'onPremisesProvisioningErrors': Collection,
        'onPremisesSamAccountName': Edm.String,
        'onPremisesSecurityIdentifier': Edm.String,
        'onPremisesSyncEnabled': Edm.Boolean,
        'organizationId': Edm.String,
        'preferredDataLocation': Edm.String,
        'preferredLanguage': Edm.String,
        'proxyAddresses': Collection,
        'renewedDateTime': Edm.DateTimeOffset,
        'resourceBehaviorOptions': Collection,
        'resourceProvisioningOptions': Collection,
        'securityEnabled': Edm.Boolean,
        'securityIdentifier': Edm.String,
        'serviceProvisioningErrors': Collection,
        'theme': Edm.String,
        'uniqueName': Edm.String,
        'visibility': Edm.String,
        'writebackConfiguration': groupWritebackConfiguration,
        'accessType': groupAccessType,
        'allowExternalSenders': Edm.Boolean,
        'autoSubscribeNewMembers': Edm.Boolean,
        'hideFromAddressLists': Edm.Boolean,
        'hideFromOutlookClients': Edm.Boolean,
        'isFavorite': Edm.Boolean,
        'isSubscribedByMail': Edm.Boolean,
        'unseenConversationsCount': Edm.Int32,
        'unseenCount': Edm.Int32,
        'unseenMessagesCount': Edm.Int32,
        'membershipRuleProcessingStatus': membershipRuleProcessingStatus,
        'isArchived': Edm.Boolean,
    }
    rels = [
        'appRoleAssignments',
        'createdOnBehalfOf',
        'endpoints',
        'memberOf',
        'members',
        'membersWithLicenseErrors',
        'owners',
        'permissionGrants',
        'settings',
        'transitiveMemberOf',
        'transitiveMembers',
        'acceptedSenders',
        'calendar',
        'calendarView',
        'conversations',
        'events',
        'rejectedSenders',
        'threads',
        'drive',
        'drives',
        'sites',
        'extensions',
        'groupLifecyclePolicies',
        'planner',
        'onenote',
        'photo',
        'photos',
        'team',
    ]


class appRoleAssignment(directoryObject):
    props = {
        'appRoleId': Edm.Guid,
        'creationTimestamp': Edm.DateTimeOffset,
        'principalDisplayName': Edm.String,
        'principalId': Edm.Guid,
        'principalType': Edm.String,
        'resourceDisplayName': Edm.String,
        'resourceId': Edm.Guid,
    }
    rels = [

    ]


class endpoint(directoryObject):
    props = {
        'capability': Edm.String,
        'providerId': Edm.String,
        'providerName': Edm.String,
        'providerResourceId': Edm.String,
        'uri': Edm.String,
    }
    rels = [

    ]


class resourceSpecificPermissionGrant(directoryObject):
    props = {
        'clientAppId': Edm.String,
        'clientId': Edm.String,
        'permission': Edm.String,
        'permissionType': Edm.String,
        'resourceAppId': Edm.String,
    }
    rels = [

    ]


class directorySetting(entity):
    props = {
        'displayName': Edm.String,
        'templateId': Edm.String,
        'values': Collection,
    }
    rels = [

    ]


class calendar(entity):
    props = {
        'allowedOnlineMeetingProviders': Collection,
        'calendarGroupId': Edm.String,
        'canEdit': Edm.Boolean,
        'canShare': Edm.Boolean,
        'canViewPrivateItems': Edm.Boolean,
        'changeKey': Edm.String,
        'color': calendarColor,
        'defaultOnlineMeetingProvider': onlineMeetingProviderType,
        'hexColor': Edm.String,
        'isDefaultCalendar': Edm.Boolean,
        'isRemovable': Edm.Boolean,
        'isShared': Edm.Boolean,
        'isSharedWithMe': Edm.Boolean,
        'isTallyingResponses': Edm.Boolean,
        'name': Edm.String,
        'owner': emailAddress,
    }
    rels = [
        'calendarPermissions',
        'calendarView',
        'events',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
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


class conversation(entity):
    props = {
        'hasAttachments': Edm.Boolean,
        'lastDeliveredDateTime': Edm.DateTimeOffset,
        'preview': Edm.String,
        'topic': Edm.String,
        'uniqueSenders': Collection,
    }
    rels = [
        'threads',
    ]


class conversationThread(entity):
    props = {
        'ccRecipients': Collection,
        'hasAttachments': Edm.Boolean,
        'isLocked': Edm.Boolean,
        'lastDeliveredDateTime': Edm.DateTimeOffset,
        'preview': Edm.String,
        'topic': Edm.String,
        'toRecipients': Collection,
        'uniqueSenders': Collection,
    }
    rels = [
        'posts',
    ]


class baseItem(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'eTag': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'parentReference': itemReference,
        'webUrl': Edm.String,
    }
    rels = [
        'createdByUser',
        'lastModifiedByUser',
    ]


class extension(entity):
    props = {

    }
    rels = [

    ]


class groupLifecyclePolicy(entity):
    props = {
        'alternateNotificationEmails': Edm.String,
        'groupLifetimeInDays': Edm.Int32,
        'managedGroupTypes': Edm.String,
    }
    rels = [

    ]


class plannerGroup(entity):
    props = {

    }
    rels = [
        'plans',
    ]


class onenote(entity):
    props = {

    }
    rels = [
        'notebooks',
        'operations',
        'pages',
        'resources',
        'sectionGroups',
        'sections',
    ]


class profilePhoto(entity):
    props = {
        'height': Edm.Int32,
        'width': Edm.Int32,
    }
    rels = [

    ]


class team(entity):
    props = {
        'classification': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'discoverySettings': teamDiscoverySettings,
        'displayName': Edm.String,
        'firstChannelName': Edm.String,
        'funSettings': teamFunSettings,
        'guestSettings': teamGuestSettings,
        'internalId': Edm.String,
        'isArchived': Edm.Boolean,
        'isMembershipLimitedToOwners': Edm.Boolean,
        'memberSettings': teamMemberSettings,
        'messagingSettings': teamMessagingSettings,
        'specialization': teamSpecialization,
        'summary': teamSummary,
        'tenantId': Edm.String,
        'visibility': teamVisibilityType,
        'webUrl': Edm.String,
    }
    rels = [
        'allChannels',
        'channels',
        'group',
        'incomingChannels',
        'installedApps',
        'members',
        'operations',
        'owners',
        'permissionGrants',
        'photo',
        'primaryChannel',
        'tags',
        'template',
        'templateDefinition',
        'schedule',
    ]


class identityGovernance(object):
    props = {

    }
    rels = [
        'lifecycleWorkflows',
        'accessReviews',
        'appConsent',
        'termsOfUse',
        'entitlementManagement',
        'permissionsAnalytics',
        'permissionsManagement',
        'privilegedAccess',
        'roleManagementAlerts',
    ]


class accessReviewSet(entity):
    props = {

    }
    rels = [
        'decisions',
        'definitions',
        'historyDefinitions',
        'policy',
    ]


class appConsentApprovalRoute(entity):
    props = {

    }
    rels = [
        'appConsentRequests',
    ]


class termsOfUseContainer(entity):
    props = {

    }
    rels = [
        'agreementAcceptances',
        'agreements',
    ]


class entitlementManagement(entity):
    props = {

    }
    rels = [
        'accessPackageAssignmentApprovals',
        'accessPackageAssignmentPolicies',
        'accessPackageAssignmentRequests',
        'accessPackageAssignmentResourceRoles',
        'accessPackageAssignments',
        'accessPackageCatalogs',
        'accessPackageResourceEnvironments',
        'accessPackageResourceRequests',
        'accessPackageResourceRoleScopes',
        'accessPackageResources',
        'accessPackages',
        'assignmentRequests',
        'connectedOrganizations',
        'settings',
        'subjects',
    ]


class permissionsAnalyticsAggregation(entity):
    props = {

    }
    rels = [
        'aws',
        'azure',
        'gcp',
    ]


class permissionsManagement(entity):
    props = {

    }
    rels = [
        'scheduledPermissionsApprovals',
        'permissionsRequestChanges',
        'scheduledPermissionsRequests',
    ]


class privilegedAccessRoot(entity):
    props = {

    }
    rels = [
        'group',
    ]


class roleManagementAlert(entity):
    props = {

    }
    rels = [
        'alertConfigurations',
        'alertDefinitions',
        'alerts',
        'operations',
    ]


class user(directoryObject):
    props = {
        'signInActivity': signInActivity,
        'cloudLicensing': Collection, #extnamespace: cloudLicensing_userCloudLicensing,
        'accountEnabled': Edm.Boolean,
        'ageGroup': Edm.String,
        'assignedLicenses': Collection,
        'assignedPlans': Collection,
        'authorizationInfo': authorizationInfo,
        'businessPhones': Collection,
        'city': Edm.String,
        'cloudRealtimeCommunicationInfo': cloudRealtimeCommunicationInfo,
        'companyName': Edm.String,
        'consentProvidedForMinor': Edm.String,
        'country': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'creationType': Edm.String,
        'customSecurityAttributes': customSecurityAttributeValue,
        'department': Edm.String,
        'deviceKeys': Collection,
        'displayName': Edm.String,
        'employeeHireDate': Edm.DateTimeOffset,
        'employeeId': Edm.String,
        'employeeLeaveDateTime': Edm.DateTimeOffset,
        'employeeOrgData': employeeOrgData,
        'employeeType': Edm.String,
        'externalUserState': Edm.String,
        'externalUserStateChangeDateTime': Edm.String,
        'faxNumber': Edm.String,
        'givenName': Edm.String,
        'identities': Collection,
        'imAddresses': Collection,
        'infoCatalogs': Collection,
        'isLicenseReconciliationNeeded': Edm.Boolean,
        'isManagementRestricted': Edm.Boolean,
        'isResourceAccount': Edm.Boolean,
        'jobTitle': Edm.String,
        'lastPasswordChangeDateTime': Edm.DateTimeOffset,
        'legalAgeGroupClassification': Edm.String,
        'licenseAssignmentStates': Collection,
        'mail': Edm.String,
        'mailNickname': Edm.String,
        'mobilePhone': Edm.String,
        'officeLocation': Edm.String,
        'onPremisesDistinguishedName': Edm.String,
        'onPremisesDomainName': Edm.String,
        'onPremisesExtensionAttributes': onPremisesExtensionAttributes,
        'onPremisesImmutableId': Edm.String,
        'onPremisesLastSyncDateTime': Edm.DateTimeOffset,
        'onPremisesProvisioningErrors': Collection,
        'onPremisesSamAccountName': Edm.String,
        'onPremisesSecurityIdentifier': Edm.String,
        'onPremisesSipInfo': onPremisesSipInfo,
        'onPremisesSyncEnabled': Edm.Boolean,
        'onPremisesUserPrincipalName': Edm.String,
        'otherMails': Collection,
        'passwordPolicies': Edm.String,
        'passwordProfile': passwordProfile,
        'postalCode': Edm.String,
        'preferredDataLocation': Edm.String,
        'preferredLanguage': Edm.String,
        'provisionedPlans': Collection,
        'proxyAddresses': Collection,
        'refreshTokensValidFromDateTime': Edm.DateTimeOffset,
        'securityIdentifier': Edm.String,
        'serviceProvisioningErrors': Collection,
        'showInAddressList': Edm.Boolean,
        'signInSessionsValidFromDateTime': Edm.DateTimeOffset,
        'state': Edm.String,
        'streetAddress': Edm.String,
        'surname': Edm.String,
        'usageLocation': Edm.String,
        'userPrincipalName': Edm.String,
        'userType': Edm.String,
        'mailboxSettings': mailboxSettings,
        'deviceEnrollmentLimit': Edm.Int32,
        'print': userPrint,
        'aboutMe': Edm.String,
        'birthday': Edm.DateTimeOffset,
        'hireDate': Edm.DateTimeOffset,
        'interests': Collection,
        'mySite': Edm.String,
        'pastProjects': Collection,
        'preferredName': Edm.String,
        'responsibilities': Collection,
        'schools': Collection,
        'skills': Collection,
    }
    rels = [
        'analytics',
        'cloudPCs',
        'usageRights',
        'informationProtection',
        'appRoleAssignedResources',
        'appRoleAssignments',
        'createdObjects',
        'directReports',
        'invitedBy',
        'licenseDetails',
        'manager',
        'memberOf',
        'oauth2PermissionGrants',
        'ownedDevices',
        'ownedObjects',
        'registeredDevices',
        'scopedRoleMemberOf',
        'sponsors',
        'transitiveMemberOf',
        'transitiveReports',
        'calendar',
        'calendarGroups',
        'calendars',
        'calendarView',
        'contactFolders',
        'contacts',
        'events',
        'inferenceClassification',
        'joinedGroups',
        'mailFolders',
        'messages',
        'outlook',
        'people',
        'drive',
        'drives',
        'followedSites',
        'extensions',
        'appConsentRequestsForApproval',
        'approvals',
        'pendingAccessReviewInstances',
        'agreementAcceptances',
        'security',
        'deviceEnrollmentConfigurations',
        'managedDevices',
        'managedAppLogCollectionRequests',
        'managedAppRegistrations',
        'windowsInformationProtectionDeviceRegistrations',
        'deviceManagementTroubleshootingEvents',
        'mobileAppIntentAndStates',
        'mobileAppTroubleshootingEvents',
        'notifications',
        'planner',
        'insights',
        'settings',
        'onenote',
        'cloudClipboard',
        'photo',
        'photos',
        'profile',
        'activities',
        'devices',
        'onlineMeetings',
        'presence',
        'virtualEvents',
        'authentication',
        'chats',
        'joinedTeams',
        'permissionGrants',
        'teamwork',
        'solutions',
        'todo',
        'employeeExperience',
    ]


class userAnalytics(entity):
    props = {
        'settings': settings,
    }
    rels = [
        'activityStatistics',
    ]


class cloudPC(entity):
    props = {
        'aadDeviceId': Edm.String,
        'allotmentDisplayName': Edm.String,
        'connectionSetting': cloudPcConnectionSetting,
        'connectionSettings': cloudPcConnectionSettings,
        'connectivityResult': cloudPcConnectivityResult,
        'deviceRegionName': Edm.String,
        'disasterRecoveryCapability': cloudPcDisasterRecoveryCapability,
        'diskEncryptionState': cloudPcDiskEncryptionState,
        'displayName': Edm.String,
        'frontlineCloudPcAvailability': frontlineCloudPcAvailability,
        'gracePeriodEndDateTime': Edm.DateTimeOffset,
        'imageDisplayName': Edm.String,
        'lastLoginResult': cloudPcLoginResult,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastRemoteActionResult': cloudPcRemoteActionResult,
        'managedDeviceId': Edm.String,
        'managedDeviceName': Edm.String,
        'onPremisesConnectionName': Edm.String,
        'osVersion': cloudPcOperatingSystem,
        'partnerAgentInstallResults': Collection,
        'powerState': cloudPcPowerState,
        'productType': cloudPcProductType,
        'provisioningPolicyId': Edm.String,
        'provisioningPolicyName': Edm.String,
        'provisioningType': cloudPcProvisioningType,
        'scopeIds': Collection,
        'servicePlanId': Edm.String,
        'servicePlanName': Edm.String,
        'servicePlanType': cloudPcServicePlanType,
        'status': cloudPcStatus,
        'statusDetail': cloudPcStatusDetail,
        'statusDetails': cloudPcStatusDetails,
        'userAccountType': cloudPcUserAccountType,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class usageRight(entity):
    props = {
        'catalogId': Edm.String,
        'serviceIdentifier': Edm.String,
        'state': usageRightState,
    }
    rels = [

    ]


class informationProtection(entity):
    props = {

    }
    rels = [
        'bitlocker',
        'dataLossPreventionPolicies',
        'sensitivityLabels',
        'sensitivityPolicySettings',
        'policy',
        'threatAssessmentRequests',
    ]


class servicePrincipal(directoryObject):
    props = {
        'passwordSingleSignOnSettings': passwordSingleSignOnSettings,
        'accountEnabled': Edm.Boolean,
        'addIns': Collection,
        'alternativeNames': Collection,
        'appDescription': Edm.String,
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'applicationTemplateId': Edm.String,
        'appOwnerOrganizationId': Edm.Guid,
        'appRoleAssignmentRequired': Edm.Boolean,
        'appRoles': Collection,
        'customSecurityAttributes': customSecurityAttributeValue,
        'description': Edm.String,
        'disabledByMicrosoftStatus': Edm.String,
        'displayName': Edm.String,
        'errorUrl': Edm.String,
        'homepage': Edm.String,
        'info': informationalUrl,
        'keyCredentials': Collection,
        'loginUrl': Edm.String,
        'logoutUrl': Edm.String,
        'notes': Edm.String,
        'notificationEmailAddresses': Collection,
        'passwordCredentials': Collection,
        'preferredSingleSignOnMode': Edm.String,
        'preferredTokenSigningKeyEndDateTime': Edm.DateTimeOffset,
        'preferredTokenSigningKeyThumbprint': Edm.String,
        'publishedPermissionScopes': Collection,
        'publisherName': Edm.String,
        'replyUrls': Collection,
        'samlMetadataUrl': Edm.String,
        'samlSingleSignOnSettings': samlSingleSignOnSettings,
        'servicePrincipalNames': Collection,
        'servicePrincipalType': Edm.String,
        'signInAudience': Edm.String,
        'tags': Collection,
        'tokenEncryptionKeyId': Edm.Guid,
        'verifiedPublisher': verifiedPublisher,
    }
    rels = [
        'appManagementPolicies',
        'appRoleAssignedTo',
        'appRoleAssignments',
        'claimsMappingPolicies',
        'claimsPolicy',
        'createdObjects',
        'delegatedPermissionClassifications',
        'endpoints',
        'federatedIdentityCredentials',
        'homeRealmDiscoveryPolicies',
        'licenseDetails',
        'memberOf',
        'oauth2PermissionGrants',
        'ownedObjects',
        'owners',
        'permissionGrantPreApprovalPolicies',
        'remoteDesktopSecurityConfiguration',
        'tokenIssuancePolicies',
        'tokenLifetimePolicies',
        'transitiveMemberOf',
        'synchronization',
    ]


class licenseDetails(entity):
    props = {
        'servicePlans': Collection,
        'skuId': Edm.Guid,
        'skuPartNumber': Edm.String,
    }
    rels = [

    ]


class oAuth2PermissionGrant(entity):
    props = {
        'clientId': Edm.String,
        'consentType': Edm.String,
        'expiryTime': Edm.DateTimeOffset,
        'principalId': Edm.String,
        'resourceId': Edm.String,
        'scope': Edm.String,
        'startTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class scopedRoleMembership(entity):
    props = {
        'administrativeUnitId': Edm.String,
        'roleId': Edm.String,
        'roleMemberInfo': identity,
    }
    rels = [

    ]


class calendarGroup(entity):
    props = {
        'changeKey': Edm.String,
        'classId': Edm.Guid,
        'name': Edm.String,
    }
    rels = [
        'calendars',
    ]


class contactFolder(entity):
    props = {
        'displayName': Edm.String,
        'parentFolderId': Edm.String,
        'wellKnownName': Edm.String,
    }
    rels = [
        'childFolders',
        'contacts',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class inferenceClassification(entity):
    props = {

    }
    rels = [
        'overrides',
    ]


class mailFolder(entity):
    props = {
        'childFolderCount': Edm.Int32,
        'displayName': Edm.String,
        'isHidden': Edm.Boolean,
        'parentFolderId': Edm.String,
        'totalItemCount': Edm.Int32,
        'unreadItemCount': Edm.Int32,
        'wellKnownName': Edm.String,
    }
    rels = [
        'childFolders',
        'messageRules',
        'messages',
        'multiValueExtendedProperties',
        'operations',
        'singleValueExtendedProperties',
        'userConfigurations',
    ]


class outlookUser(entity):
    props = {

    }
    rels = [
        'masterCategories',
        'taskFolders',
        'taskGroups',
        'tasks',
    ]


class person(entity):
    props = {
        'birthday': Edm.String,
        'companyName': Edm.String,
        'department': Edm.String,
        'displayName': Edm.String,
        'emailAddresses': Collection,
        'givenName': Edm.String,
        'isFavorite': Edm.Boolean,
        'mailboxType': Edm.String,
        'officeLocation': Edm.String,
        'personNotes': Edm.String,
        'personType': Edm.String,
        'phones': Collection,
        'postalAddresses': Collection,
        'profession': Edm.String,
        'sources': Collection,
        'surname': Edm.String,
        'title': Edm.String,
        'userPrincipalName': Edm.String,
        'websites': Collection,
        'yomiCompany': Edm.String,
    }
    rels = [

    ]


class appConsentRequest(entity):
    props = {
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'consentType': Edm.String,
        'pendingScopes': Collection,
    }
    rels = [
        'userConsentRequests',
    ]


class approval(entity):
    props = {

    }
    rels = [
        'request',
        'steps',
    ]


class accessReviewInstance(entity):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'errors': Collection,
        'fallbackReviewers': Collection,
        'reviewers': Collection,
        'scope': accessReviewScope,
        'startDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
    }
    rels = [
        'contactedReviewers',
        'decisions',
        'definition',
        'stages',
    ]


class agreementAcceptance(entity):
    props = {
        'agreementFileId': Edm.String,
        'agreementId': Edm.String,
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'deviceOSType': Edm.String,
        'deviceOSVersion': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'recordedDateTime': Edm.DateTimeOffset,
        'state': agreementAcceptanceState,
        'userDisplayName': Edm.String,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceEnrollmentConfiguration(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'deviceEnrollmentConfigurationType': deviceEnrollmentConfigurationType,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'priority': Edm.Int32,
        'roleScopeTagIds': Collection,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
    ]


class managedDevice(entity):
    props = {
        'cloudPcRemoteActionResults': Collection,
        'aadRegistered': Edm.Boolean,
        'activationLockBypassCode': Edm.String,
        'androidSecurityPatchLevel': Edm.String,
        'autopilotEnrolled': Edm.Boolean,
        'azureActiveDirectoryDeviceId': Edm.String,
        'azureADDeviceId': Edm.String,
        'azureADRegistered': Edm.Boolean,
        'bootstrapTokenEscrowed': Edm.Boolean,
        'chassisType': chassisType,
        'chromeOSDeviceInfo': Collection,
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'complianceState': complianceState,
        'configurationManagerClientEnabledFeatures': configurationManagerClientEnabledFeatures,
        'configurationManagerClientHealthState': configurationManagerClientHealthState,
        'configurationManagerClientInformation': configurationManagerClientInformation,
        'deviceActionResults': Collection,
        'deviceCategoryDisplayName': Edm.String,
        'deviceEnrollmentType': deviceEnrollmentType,
        'deviceFirmwareConfigurationInterfaceManaged': Edm.Boolean,
        'deviceHealthAttestationState': deviceHealthAttestationState,
        'deviceName': Edm.String,
        'deviceRegistrationState': deviceRegistrationState,
        'deviceType': deviceType,
        'easActivated': Edm.Boolean,
        'easActivationDateTime': Edm.DateTimeOffset,
        'easDeviceId': Edm.String,
        'emailAddress': Edm.String,
        'enrolledByUserPrincipalName': Edm.String,
        'enrolledDateTime': Edm.DateTimeOffset,
        'enrollmentProfileName': Edm.String,
        'ethernetMacAddress': Edm.String,
        'exchangeAccessState': deviceManagementExchangeAccessState,
        'exchangeAccessStateReason': deviceManagementExchangeAccessStateReason,
        'exchangeLastSuccessfulSyncDateTime': Edm.DateTimeOffset,
        'freeStorageSpaceInBytes': Edm.Int64,
        'hardwareInformation': hardwareInformation,
        'iccid': Edm.String,
        'imei': Edm.String,
        'isEncrypted': Edm.Boolean,
        'isSupervised': Edm.Boolean,
        'jailBroken': Edm.String,
        'joinType': joinType,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'lostModeState': lostModeState,
        'managedDeviceName': Edm.String,
        'managedDeviceOwnerType': managedDeviceOwnerType,
        'managementAgent': managementAgentType,
        'managementCertificateExpirationDate': Edm.DateTimeOffset,
        'managementFeatures': managedDeviceManagementFeatures,
        'managementState': managementState,
        'manufacturer': Edm.String,
        'meid': Edm.String,
        'model': Edm.String,
        'notes': Edm.String,
        'operatingSystem': Edm.String,
        'osVersion': Edm.String,
        'ownerType': ownerType,
        'partnerReportedThreatState': managedDevicePartnerReportedHealthState,
        'phoneNumber': Edm.String,
        'physicalMemoryInBytes': Edm.Int64,
        'preferMdmOverGroupPolicyAppliedDateTime': Edm.DateTimeOffset,
        'processorArchitecture': managedDeviceArchitecture,
        'remoteAssistanceSessionErrorDetails': Edm.String,
        'remoteAssistanceSessionUrl': Edm.String,
        'requireUserEnrollmentApproval': Edm.Boolean,
        'retireAfterDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'securityPatchLevel': Edm.String,
        'serialNumber': Edm.String,
        'skuFamily': Edm.String,
        'skuNumber': Edm.Int32,
        'specificationVersion': Edm.String,
        'subscriberCarrier': Edm.String,
        'totalStorageSpaceInBytes': Edm.Int64,
        'udid': Edm.String,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'usersLoggedOn': Collection,
        'wiFiMacAddress': Edm.String,
        'windowsActiveMalwareCount': Edm.Int32,
        'windowsRemediatedMalwareCount': Edm.Int32,
    }
    rels = [
        'assignmentFilterEvaluationStatusDetails',
        'deviceCompliancePolicyStates',
        'deviceConfigurationStates',
        'managedDeviceMobileAppConfigurationStates',
        'securityBaselineStates',
        'detectedApps',
        'deviceCategory',
        'deviceHealthScriptStates',
        'logCollectionRequests',
        'users',
        'windowsProtectionState',
    ]


class managedAppLogCollectionRequest(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'managedAppRegistrationId': Edm.String,
        'requestedBy': Edm.String,
        'requestedByUserPrincipalName': Edm.String,
        'requestedDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
        'uploadedLogs': Collection,
        'userLogUploadConsent': managedAppLogUploadConsent,
        'version': Edm.String,
    }
    rels = [

    ]


class managedAppRegistration(entity):
    props = {
        'appIdentifier': mobileAppIdentifier,
        'applicationVersion': Edm.String,
        'azureADDeviceId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'deviceManufacturer': Edm.String,
        'deviceModel': Edm.String,
        'deviceName': Edm.String,
        'deviceTag': Edm.String,
        'deviceType': Edm.String,
        'flaggedReasons': Collection,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'managementSdkVersion': Edm.String,
        'platformVersion': Edm.String,
        'userId': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'appliedPolicies',
        'intendedPolicies',
        'managedAppLogCollectionRequests',
        'operations',
    ]


class windowsInformationProtectionDeviceRegistration(entity):
    props = {
        'deviceMacAddress': Edm.String,
        'deviceName': Edm.String,
        'deviceRegistrationId': Edm.String,
        'deviceType': Edm.String,
        'lastCheckInDateTime': Edm.DateTimeOffset,
        'userId': Edm.String,
    }
    rels = [

    ]


class deviceManagementTroubleshootingEvent(entity):
    props = {
        'additionalInformation': Collection,
        'correlationId': Edm.String,
        'eventDateTime': Edm.DateTimeOffset,
        'eventName': Edm.String,
        'troubleshootingErrorDetails': deviceManagementTroubleshootingErrorDetails,
    }
    rels = [

    ]


class mobileAppIntentAndState(entity):
    props = {
        'managedDeviceIdentifier': Edm.String,
        'mobileAppList': Collection,
        'userId': Edm.String,
    }
    rels = [

    ]


class notification(entity):
    props = {
        'displayTimeToLive': Edm.Int32,
        'expirationDateTime': Edm.DateTimeOffset,
        'groupName': Edm.String,
        'payload': payloadTypes,
        'priority': priority,
        'targetHostName': Edm.String,
        'targetPolicy': targetPolicyEndpoints,
    }
    rels = [

    ]


class plannerDelta(entity):
    props = {

    }
    rels = [

    ]


class officeGraphInsights(entity):
    props = {

    }
    rels = [
        'shared',
        'trending',
        'used',
    ]


class userSettings(entity):
    props = {
        'contributionToContentDiscoveryAsOrganizationDisabled': Edm.Boolean,
        'contributionToContentDiscoveryDisabled': Edm.Boolean,
    }
    rels = [
        'exchange',
        'itemInsights',
        'windows',
        'contactMergeSuggestions',
        'regionalAndLanguageSettings',
        'shiftPreferences',
        'storage',
    ]


class cloudClipboardRoot(entity):
    props = {

    }
    rels = [
        'items',
    ]


class profile(entity):
    props = {

    }
    rels = [
        'account',
        'addresses',
        'anniversaries',
        'awards',
        'certifications',
        'educationalActivities',
        'emails',
        'interests',
        'languages',
        'names',
        'notes',
        'patents',
        'phones',
        'positions',
        'projects',
        'publications',
        'skills',
        'webAccounts',
        'websites',
    ]


class userActivity(entity):
    props = {
        'activationUrl': Edm.String,
        'activitySourceHost': Edm.String,
        'appActivityId': Edm.String,
        'appDisplayName': Edm.String,
        'contentInfo': Json,
        'contentUrl': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
        'fallbackUrl': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': status,
        'userTimezone': Edm.String,
        'visualElements': visualInfo,
    }
    rels = [
        'historyItems',
    ]


class device(directoryObject):
    props = {
        'accountEnabled': Edm.Boolean,
        'alternativeNames': Collection,
        'alternativeSecurityIds': Collection,
        'approximateLastSignInDateTime': Edm.DateTimeOffset,
        'complianceExpirationDateTime': Edm.DateTimeOffset,
        'deviceCategory': Edm.String,
        'deviceId': Edm.String,
        'deviceMetadata': Edm.String,
        'deviceOwnership': Edm.String,
        'deviceVersion': Edm.Int32,
        'displayName': Edm.String,
        'domainName': Edm.String,
        'enrollmentProfileName': Edm.String,
        'enrollmentType': Edm.String,
        'extensionAttributes': onPremisesExtensionAttributes,
        'hostnames': Collection,
        'isCompliant': Edm.Boolean,
        'isManaged': Edm.Boolean,
        'isManagementRestricted': Edm.Boolean,
        'isRooted': Edm.Boolean,
        'managementType': Edm.String,
        'manufacturer': Edm.String,
        'mdmAppId': Edm.String,
        'model': Edm.String,
        'onPremisesLastSyncDateTime': Edm.DateTimeOffset,
        'onPremisesSecurityIdentifier': Edm.String,
        'onPremisesSyncEnabled': Edm.Boolean,
        'operatingSystem': Edm.String,
        'operatingSystemVersion': Edm.String,
        'physicalIds': Collection,
        'profileType': Edm.String,
        'registrationDateTime': Edm.DateTimeOffset,
        'systemLabels': Collection,
        'trustType': Edm.String,
        'kind': Edm.String,
        'name': Edm.String,
        'platform': Edm.String,
        'status': Edm.String,
    }
    rels = [
        'usageRights',
        'deviceTemplate',
        'memberOf',
        'registeredOwners',
        'registeredUsers',
        'transitiveMemberOf',
        'extensions',
        'commands',
    ]


class onlineMeetingBase(entity):
    props = {
        'allowAttendeeToEnableCamera': Edm.Boolean,
        'allowAttendeeToEnableMic': Edm.Boolean,
        'allowBreakoutRooms': Edm.Boolean,
        'allowedLobbyAdmitters': allowedLobbyAdmitterRoles,
        'allowedPresenters': onlineMeetingPresenters,
        'allowLiveShare': meetingLiveShareOptions,
        'allowMeetingChat': meetingChatMode,
        'allowParticipantsToChangeName': Edm.Boolean,
        'allowPowerPointSharing': Edm.Boolean,
        'allowRecording': Edm.Boolean,
        'allowTeamworkReactions': Edm.Boolean,
        'allowTranscription': Edm.Boolean,
        'allowWhiteboard': Edm.Boolean,
        'anonymizeIdentityForRoles': Collection,
        'audioConferencing': audioConferencing,
        'chatInfo': chatInfo,
        'chatRestrictions': chatRestrictions,
        'isEndToEndEncryptionEnabled': Edm.Boolean,
        'isEntryExitAnnounced': Edm.Boolean,
        'joinInformation': itemBody,
        'joinMeetingIdSettings': joinMeetingIdSettings,
        'joinWebUrl': Edm.String,
        'lobbyBypassSettings': lobbyBypassSettings,
        'recordAutomatically': Edm.Boolean,
        'shareMeetingChatHistoryDefault': meetingChatHistoryDefaultMode,
        'subject': Edm.String,
        'videoTeleconferenceId': Edm.String,
        'watermarkProtection': watermarkProtectionValues,
    }
    rels = [
        'attendanceReports',
    ]


class presence(entity):
    props = {
        'activity': Edm.String,
        'availability': Edm.String,
        'outOfOfficeSettings': outOfOfficeSettings,
        'sequenceNumber': Edm.String,
        'statusMessage': presenceStatusMessage,
    }
    rels = [

    ]


class userVirtualEventsRoot(entity):
    props = {

    }
    rels = [
        'webinars',
    ]


class authentication(entity):
    props = {
        'requirements': strongAuthenticationRequirements,
        'signInPreferences': signInPreferences,
    }
    rels = [
        'emailMethods',
        'fido2Methods',
        'hardwareOathMethods',
        'methods',
        'microsoftAuthenticatorMethods',
        'operations',
        'passwordlessMicrosoftAuthenticatorMethods',
        'passwordMethods',
        'phoneMethods',
        'platformCredentialMethods',
        'softwareOathMethods',
        'temporaryAccessPassMethods',
        'windowsHelloForBusinessMethods',
    ]


class chat(entity):
    props = {
        'chatType': chatType,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'isHiddenForAllMembers': Edm.Boolean,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'onlineMeetingInfo': teamworkOnlineMeetingInfo,
        'tenantId': Edm.String,
        'topic': Edm.String,
        'viewpoint': chatViewpoint,
        'webUrl': Edm.String,
    }
    rels = [
        'installedApps',
        'lastMessagePreview',
        'members',
        'messages',
        'operations',
        'permissionGrants',
        'pinnedMessages',
        'tabs',
    ]


class userTeamwork(entity):
    props = {
        'locale': Edm.String,
        'region': Edm.String,
    }
    rels = [
        'associatedTeams',
        'installedApps',
    ]


class userSolutionRoot(entity):
    props = {

    }
    rels = [
        'workingTimeSchedule',
    ]


class todo(entity):
    props = {

    }
    rels = [
        'lists',
    ]


class employeeExperienceUser(entity):
    props = {

    }
    rels = [
        'learningCourseActivities',
    ]


class activeUsersMetric(entity):
    props = {
        'appId': Edm.String,
        'appName': Edm.String,
        'count': Edm.Int64,
        'country': Edm.String,
        'factDate': Edm.Date,
        'language': Edm.String,
        'os': Edm.String,
    }
    rels = [

    ]


class appCredentialSignInActivity(entity):
    props = {
        'appId': Edm.String,
        'appObjectId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'credentialOrigin': applicationKeyOrigin,
        'expirationDateTime': Edm.DateTimeOffset,
        'keyId': Edm.String,
        'keyType': applicationKeyType,
        'keyUsage': applicationKeyUsage,
        'resourceId': Edm.String,
        'servicePrincipalObjectId': Edm.String,
        'signInActivity': signInActivity,
    }
    rels = [

    ]


class applicationSignInDetailedSummary(entity):
    props = {
        'aggregatedEventDateTime': Edm.DateTimeOffset,
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'signInCount': Edm.Int64,
        'status': signInStatus,
    }
    rels = [

    ]


class applicationSignInSummary(entity):
    props = {
        'appDisplayName': Edm.String,
        'failedSignInCount': Edm.Int64,
        'successfulSignInCount': Edm.Int64,
        'successPercentage': Edm.Double,
    }
    rels = [

    ]


class auditLogRoot(object):
    props = {

    }
    rels = [
        'customSecurityAttributeAudits',
        'directoryAudits',
        'directoryProvisioning',
        'provisioning',
        'signIns',
        'signUps',
    ]


class customSecurityAttributeAudit(entity):
    props = {
        'activityDateTime': Edm.DateTimeOffset,
        'activityDisplayName': Edm.String,
        'additionalDetails': Collection,
        'category': Edm.String,
        'correlationId': Edm.String,
        'initiatedBy': auditActivityInitiator,
        'loggedByService': Edm.String,
        'operationType': Edm.String,
        'result': operationResult,
        'resultReason': Edm.String,
        'targetResources': Collection,
        'userAgent': Edm.String,
    }
    rels = [

    ]


class directoryAudit(entity):
    props = {
        'activityDateTime': Edm.DateTimeOffset,
        'activityDisplayName': Edm.String,
        'additionalDetails': Collection,
        'category': Edm.String,
        'correlationId': Edm.String,
        'initiatedBy': auditActivityInitiator,
        'loggedByService': Edm.String,
        'operationType': Edm.String,
        'result': operationResult,
        'resultReason': Edm.String,
        'targetResources': Collection,
        'userAgent': Edm.String,
    }
    rels = [

    ]


class provisioningObjectSummary(entity):
    props = {
        'action': Edm.String,
        'activityDateTime': Edm.DateTimeOffset,
        'changeId': Edm.String,
        'cycleId': Edm.String,
        'durationInMilliseconds': Edm.Int32,
        'initiatedBy': initiator,
        'jobId': Edm.String,
        'modifiedProperties': Collection,
        'provisioningAction': provisioningAction,
        'provisioningStatusInfo': provisioningStatusInfo,
        'provisioningSteps': Collection,
        'servicePrincipal': provisioningServicePrincipal,
        'sourceIdentity': provisionedIdentity,
        'sourceSystem': provisioningSystem,
        'statusInfo': statusBase,
        'targetIdentity': provisionedIdentity,
        'targetSystem': provisioningSystem,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class signIn(entity):
    props = {
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'appliedConditionalAccessPolicies': Collection,
        'appliedEventListeners': Collection,
        'appOwnerTenantId': Edm.String,
        'appTokenProtectionStatus': tokenProtectionStatus,
        'authenticationAppDeviceDetails': authenticationAppDeviceDetails,
        'authenticationAppPolicyEvaluationDetails': Collection,
        'authenticationContextClassReferences': Collection,
        'authenticationDetails': Collection,
        'authenticationMethodsUsed': Collection,
        'authenticationProcessingDetails': Collection,
        'authenticationProtocol': protocolType,
        'authenticationRequirement': Edm.String,
        'authenticationRequirementPolicies': Collection,
        'autonomousSystemNumber': Edm.Int32,
        'azureResourceId': Edm.String,
        'clientAppUsed': Edm.String,
        'clientCredentialType': clientCredentialType,
        'conditionalAccessAudiences': Collection,
        'conditionalAccessStatus': conditionalAccessStatus,
        'correlationId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'crossTenantAccessType': signInAccessType,
        'deviceDetail': deviceDetail,
        'federatedCredentialId': Edm.String,
        'flaggedForReview': Edm.Boolean,
        'globalSecureAccessIpAddress': Edm.String,
        'homeTenantId': Edm.String,
        'homeTenantName': Edm.String,
        'incomingTokenType': incomingTokenType,
        'ipAddress': Edm.String,
        'ipAddressFromResourceProvider': Edm.String,
        'isInteractive': Edm.Boolean,
        'isTenantRestricted': Edm.Boolean,
        'isThroughGlobalSecureAccess': Edm.Boolean,
        'location': signInLocation,
        'managedServiceIdentity': managedIdentity,
        'mfaDetail': mfaDetail,
        'networkLocationDetails': Collection,
        'originalRequestId': Edm.String,
        'originalTransferMethod': originalTransferMethods,
        'privateLinkDetails': privateLinkDetails,
        'processingTimeInMilliseconds': Edm.Int32,
        'resourceDisplayName': Edm.String,
        'resourceId': Edm.String,
        'resourceOwnerTenantId': Edm.String,
        'resourceServicePrincipalId': Edm.String,
        'resourceTenantId': Edm.String,
        'riskDetail': riskDetail,
        'riskEventTypes_v2': Collection,
        'riskLevelAggregated': riskLevel,
        'riskLevelDuringSignIn': riskLevel,
        'riskState': riskState,
        'servicePrincipalCredentialKeyId': Edm.String,
        'servicePrincipalCredentialThumbprint': Edm.String,
        'servicePrincipalId': Edm.String,
        'servicePrincipalName': Edm.String,
        'sessionId': Edm.String,
        'sessionLifetimePolicies': Collection,
        'signInEventTypes': Collection,
        'signInIdentifier': Edm.String,
        'signInIdentifierType': signInIdentifierType,
        'signInTokenProtectionStatus': tokenProtectionStatus,
        'status': signInStatus,
        'tokenIssuerName': Edm.String,
        'tokenIssuerType': tokenIssuerType,
        'tokenProtectionStatusDetails': tokenProtectionStatusDetails,
        'uniqueTokenIdentifier': Edm.String,
        'userAgent': Edm.String,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'userType': signInUserType,
    }
    rels = [

    ]


class selfServiceSignUp(entity):
    props = {
        'appDisplayName': Edm.String,
        'appId': Edm.String,
        'appliedEventListeners': Collection,
        'correlationId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'signUpIdentity': signUpIdentity,
        'signUpIdentityProvider': Edm.String,
        'signUpStage': signUpStage,
        'status': signUpStatus,
        'userSnapshot': ciamUserSnapshot,
    }
    rels = [

    ]


class authenticationFailure(entity):
    props = {
        'count': Edm.Int64,
        'reason': Edm.String,
        'reasonCode': authenticationFailureReasonCode,
    }
    rels = [

    ]


class authenticationMethodsRoot(entity):
    props = {

    }
    rels = [
        'userRegistrationDetails',
    ]


class userRegistrationDetails(entity):
    props = {
        'defaultMfaMethod': defaultMfaMethodType,
        'isAdmin': Edm.Boolean,
        'isMfaCapable': Edm.Boolean,
        'isMfaRegistered': Edm.Boolean,
        'isPasswordlessCapable': Edm.Boolean,
        'isSsprCapable': Edm.Boolean,
        'isSsprEnabled': Edm.Boolean,
        'isSsprRegistered': Edm.Boolean,
        'isSystemPreferredAuthenticationMethodEnabled': Edm.Boolean,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'methodsRegistered': Collection,
        'systemPreferredAuthenticationMethods': Collection,
        'userDisplayName': Edm.String,
        'userPreferredMethodForSecondaryAuthentication': userDefaultAuthenticationMethod,
        'userPrincipalName': Edm.String,
        'userType': signInUserType,
    }
    rels = [

    ]


class authenticationsMetric(entity):
    props = {
        'appid': Edm.String,
        'attemptsCount': Edm.Int64,
        'authFlow': Edm.String,
        'browser': Edm.String,
        'country': Edm.String,
        'factDate': Edm.Date,
        'identityProvider': Edm.String,
        'language': Edm.String,
        'os': Edm.String,
        'successCount': Edm.Int64,
    }
    rels = [
        'failures',
    ]


class azureADAuthentication(entity):
    props = {
        'attainments': Collection,
    }
    rels = [

    ]


class credentialUsageSummary(entity):
    props = {
        'authMethod': usageAuthMethod,
        'failureActivityCount': Edm.Int64,
        'feature': featureType,
        'successfulActivityCount': Edm.Int64,
    }
    rels = [

    ]


class credentialUserRegistrationCount(entity):
    props = {
        'totalUserCount': Edm.Int64,
        'userRegistrationCounts': Collection,
    }
    rels = [

    ]


class credentialUserRegistrationDetails(entity):
    props = {
        'authMethods': Collection,
        'isCapable': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'isMfaRegistered': Edm.Boolean,
        'isRegistered': Edm.Boolean,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class inactiveUsersByApplicationMetricBase(entity):
    props = {
        'appId': Edm.String,
        'factDate': Edm.Date,
        'inactive30DayCount': Edm.Int64,
        'inactive60DayCount': Edm.Int64,
        'inactive90DayCount': Edm.Int64,
    }
    rels = [

    ]


class inactiveUsersMetricBase(entity):
    props = {
        'appId': Edm.String,
        'factDate': Edm.Date,
        'inactive30DayCount': Edm.Int64,
        'inactive60DayCount': Edm.Int64,
        'inactive90DayCount': Edm.Int64,
    }
    rels = [

    ]


class dailyUserInsightMetricsRoot(entity):
    props = {

    }
    rels = [
        'activeUsers',
        'authentications',
        'inactiveUsers',
        'inactiveUsersByApplication',
        'mfaCompletions',
        'mfaTelecomFraud',
        'signUps',
        'summary',
        'userCount',
    ]


class mfaCompletionMetric(entity):
    props = {
        'appId': Edm.String,
        'attemptsCount': Edm.Int64,
        'country': Edm.String,
        'factDate': Edm.Date,
        'identityProvider': Edm.String,
        'language': Edm.String,
        'mfaMethod': Edm.String,
        'os': Edm.String,
        'successCount': Edm.Int64,
    }
    rels = [
        'mfaFailures',
    ]


class mfaTelecomFraudMetric(entity):
    props = {
        'captchaFailureCount': Edm.Int64,
        'captchaNotTriggeredUserCount': Edm.Int64,
        'captchaShownUserCount': Edm.Int64,
        'captchaSuccessCount': Edm.Int64,
        'factDate': Edm.Date,
        'telecomBlockedUserCount': Edm.Int64,
    }
    rels = [

    ]


class userSignUpMetric(entity):
    props = {
        'appId': Edm.String,
        'browser': Edm.String,
        'count': Edm.Int64,
        'country': Edm.String,
        'factDate': Edm.Date,
        'identityProvider': Edm.String,
        'language': Edm.String,
        'os': Edm.String,
    }
    rels = [

    ]


class insightSummary(entity):
    props = {
        'activeUsers': Edm.Int64,
        'appId': Edm.String,
        'authenticationCompletions': Edm.Int64,
        'authenticationRequests': Edm.Int64,
        'factDate': Edm.Date,
        'os': Edm.String,
        'securityTextCompletions': Edm.Int64,
        'securityTextRequests': Edm.Int64,
        'securityVoiceCompletions': Edm.Int64,
        'securityVoiceRequests': Edm.Int64,
    }
    rels = [

    ]


class userCountMetric(entity):
    props = {
        'count': Edm.Int64,
        'factDate': Edm.Date,
        'language': Edm.String,
    }
    rels = [

    ]


class directory(entity):
    props = {

    }
    rels = [
        'impactedResources',
        'recommendations',
        'deviceLocalCredentials',
        'administrativeUnits',
        'attributeSets',
        'certificateAuthorities',
        'customSecurityAttributeDefinitions',
        'deletedItems',
        'externalUserProfiles',
        'federationConfigurations',
        'inboundSharedUserProfiles',
        'onPremisesSynchronization',
        'outboundSharedUserProfiles',
        'pendingExternalUserProfiles',
        'publicKeyInfrastructure',
        'sharedEmailDomains',
        'subscriptions',
        'templates',
        'featureRolloutPolicies',
        'authenticationMethodDevices',
    ]


class impactedResource(entity):
    props = {
        'addedDateTime': Edm.DateTimeOffset,
        'additionalDetails': Collection,
        'apiUrl': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': Edm.String,
        'lastModifiedDateTime': Edm.String,
        'owner': Edm.String,
        'portalUrl': Edm.String,
        'postponeUntilDateTime': Edm.DateTimeOffset,
        'rank': Edm.Int32,
        'recommendationId': Edm.String,
        'resourceType': Edm.String,
        'status': recommendationStatus,
        'subjectId': Edm.String,
    }
    rels = [

    ]


class recommendationBase(entity):
    props = {
        'actionSteps': Collection,
        'benefits': Edm.String,
        'category': recommendationCategory,
        'createdDateTime': Edm.DateTimeOffset,
        'currentScore': Edm.Double,
        'displayName': Edm.String,
        'featureAreas': Collection,
        'impactStartDateTime': Edm.DateTimeOffset,
        'impactType': Edm.String,
        'insights': Edm.String,
        'lastCheckedDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'maxScore': Edm.Double,
        'postponeUntilDateTime': Edm.DateTimeOffset,
        'priority': recommendationPriority,
        'recommendationType': recommendationType,
        'releaseType': Edm.String,
        'remediationImpact': Edm.String,
        'requiredLicenses': requiredLicenses,
        'status': recommendationStatus,
    }
    rels = [
        'impactedResources',
    ]


class deviceLocalCredentialInfo(entity):
    props = {
        'credentials': Collection,
        'deviceName': Edm.String,
        'lastBackupDateTime': Edm.DateTimeOffset,
        'refreshDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class administrativeUnit(directoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isMemberManagementRestricted': Edm.Boolean,
        'membershipRule': Edm.String,
        'membershipRuleProcessingState': Edm.String,
        'membershipType': Edm.String,
        'visibility': Edm.String,
    }
    rels = [
        'deletedMembers',
        'members',
        'scopedRoleMembers',
        'extensions',
    ]


class attributeSet(entity):
    props = {
        'description': Edm.String,
        'maxAttributesPerSet': Edm.Int32,
    }
    rels = [

    ]


class certificateAuthorityPath(entity):
    props = {

    }
    rels = [
        'certificateBasedApplicationConfigurations',
        'mutualTlsOauthConfigurations',
    ]


class customSecurityAttributeDefinition(entity):
    props = {
        'attributeSet': Edm.String,
        'description': Edm.String,
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


class externalProfile(directoryObject):
    props = {
        'address': physicalOfficeAddress,
        'companyName': Edm.String,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'department': Edm.String,
        'displayName': Edm.String,
        'isDiscoverable': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'jobTitle': Edm.String,
        'phoneNumber': Edm.String,
        'supervisorId': Edm.String,
    }
    rels = [

    ]


class identityProviderBase(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [

    ]


class inboundSharedUserProfile(object):
    props = {
        'displayName': Edm.String,
        'homeTenantId': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class onPremisesDirectorySynchronization(entity):
    props = {
        'configuration': onPremisesDirectorySynchronizationConfiguration,
        'features': onPremisesDirectorySynchronizationFeature,
    }
    rels = [

    ]


class outboundSharedUserProfile(object):
    props = {
        'userId': Edm.String,
    }
    rels = [
        'tenants',
    ]


class publicKeyInfrastructureRoot(entity):
    props = {

    }
    rels = [
        'certificateBasedAuthConfigurations',
    ]


class sharedEmailDomain(entity):
    props = {
        'provisioningStatus': Edm.String,
    }
    rels = [

    ]


class companySubscription(entity):
    props = {
        'commerceSubscriptionId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'isTrial': Edm.Boolean,
        'nextLifecycleDateTime': Edm.DateTimeOffset,
        'ocpSubscriptionId': Edm.String,
        'ownerId': Edm.String,
        'ownerTenantId': Edm.String,
        'ownerType': Edm.String,
        'serviceStatus': Collection,
        'skuId': Edm.String,
        'skuPartNumber': Edm.String,
        'status': Edm.String,
        'totalLicenses': Edm.Int32,
    }
    rels = [

    ]


class template(entity):
    props = {

    }
    rels = [
        'deviceTemplates',
    ]


class featureRolloutPolicy(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'feature': stagedFeatureName,
        'isAppliedToOrganization': Edm.Boolean,
        'isEnabled': Edm.Boolean,
    }
    rels = [
        'appliesTo',
    ]


class authenticationMethodDevice(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [
        'hardwareOathDevices',
    ]


class governanceInsight(entity):
    props = {
        'insightCreatedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class mfaFailure(entity):
    props = {
        'count': Edm.Int64,
        'reason': Edm.String,
        'reasonCode': mfaFailureReasonCode,
    }
    rels = [

    ]


class mfaUserCountMetric(entity):
    props = {
        'count': Edm.Int64,
        'factDate': Edm.Date,
        'mfaType': mfaType,
    }
    rels = [

    ]


class monthlyUserInsightMetricsRoot(entity):
    props = {

    }
    rels = [
        'activeUsers',
        'authentications',
        'inactiveUsers',
        'inactiveUsersByApplication',
        'mfaCompletions',
        'mfaRegisteredUsers',
        'requests',
        'signUps',
        'summary',
    ]


class userRequestsMetric(entity):
    props = {
        'appId': Edm.String,
        'browser': Edm.String,
        'country': Edm.String,
        'factDate': Edm.Date,
        'identityProvider': Edm.String,
        'language': Edm.String,
        'requestCount': Edm.Int64,
    }
    rels = [

    ]


class relyingPartyDetailedSummary(entity):
    props = {
        'failedSignInCount': Edm.Int64,
        'migrationStatus': migrationStatus,
        'migrationValidationDetails': Collection,
        'relyingPartyId': Edm.String,
        'relyingPartyName': Edm.String,
        'replyUrls': Collection,
        'serviceId': Edm.String,
        'signInSuccessRate': Edm.Double,
        'successfulSignInCount': Edm.Int64,
        'totalSignInCount': Edm.Int64,
        'uniqueUserCount': Edm.Int64,
    }
    rels = [

    ]


class reportRoot(object):
    props = {

    }
    rels = [
        'appCredentialSignInActivities',
        'applicationSignInDetailedSummary',
        'authenticationMethods',
        'credentialUserRegistrationDetails',
        'healthMonitoring',
        'serviceActivity',
        'servicePrincipalSignInActivities',
        'sla',
        'userCredentialUsageDetails',
        'userInsights',
        'partners',
        'dailyPrintUsage',
        'dailyPrintUsageByPrinter',
        'dailyPrintUsageByUser',
        'dailyPrintUsageSummariesByPrinter',
        'dailyPrintUsageSummariesByUser',
        'monthlyPrintUsageByPrinter',
        'monthlyPrintUsageByUser',
        'monthlyPrintUsageSummariesByPrinter',
        'monthlyPrintUsageSummariesByUser',
        'security',
    ]


class serviceActivity(entity):
    props = {

    }
    rels = [

    ]


class servicePrincipalSignInActivity(entity):
    props = {
        'appId': Edm.String,
        'applicationAuthenticationClientSignInActivity': signInActivity,
        'applicationAuthenticationResourceSignInActivity': signInActivity,
        'delegatedClientSignInActivity': signInActivity,
        'delegatedResourceSignInActivity': signInActivity,
        'lastSignInActivity': signInActivity,
    }
    rels = [

    ]


class serviceLevelAgreementRoot(entity):
    props = {

    }
    rels = [
        'azureADAuthentication',
    ]


class userCredentialUsageDetails(entity):
    props = {
        'authMethod': usageAuthMethod,
        'eventDateTime': Edm.DateTimeOffset,
        'failureReason': Edm.String,
        'feature': featureType,
        'isSuccess': Edm.Boolean,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class userInsightsRoot(entity):
    props = {

    }
    rels = [
        'daily',
        'monthly',
    ]


class partners(entity):
    props = {

    }
    rels = [
        'billing',
    ]


class printUsage(entity):
    props = {
        'blackAndWhitePageCount': Edm.Int64,
        'colorPageCount': Edm.Int64,
        'completedBlackAndWhiteJobCount': Edm.Int64,
        'completedColorJobCount': Edm.Int64,
        'completedJobCount': Edm.Int64,
        'doubleSidedSheetCount': Edm.Int64,
        'incompleteJobCount': Edm.Int64,
        'mediaSheetCount': Edm.Int64,
        'pageCount': Edm.Int64,
        'singleSidedSheetCount': Edm.Int64,
        'usageDate': Edm.Date,
    }
    rels = [

    ]


class securityReportsRoot(entity):
    props = {

    }
    rels = [

    ]


class deviceTemplate(directoryObject):
    props = {
        'deviceAuthority': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'mutualTlsOauthConfigurationId': Edm.String,
        'mutualTlsOauthConfigurationTenantId': Edm.String,
        'operatingSystem': Edm.String,
    }
    rels = [
        'deviceInstances',
        'owners',
    ]


class command(entity):
    props = {
        'appServiceName': Edm.String,
        'error': Edm.String,
        'packageFamilyName': Edm.String,
        'payload': payloadRequest,
        'permissionTicket': Edm.String,
        'postBackUri': Edm.String,
        'status': Edm.String,
        'type': Edm.String,
    }
    rels = [
        'responsepayload',
    ]


class customClaimsPolicy(entity):
    props = {
        'audienceOverride': Edm.String,
        'claims': Collection,
        'includeApplicationIdInIssuer': Edm.Boolean,
        'includeBasicClaimSet': Edm.Boolean,
    }
    rels = [

    ]


class delegatedPermissionClassification(entity):
    props = {
        'classification': permissionClassificationType,
        'permissionId': Edm.String,
        'permissionName': Edm.String,
    }
    rels = [

    ]


class permissionGrantPreApprovalPolicy(directoryObject):
    props = {
        'conditions': Collection,
    }
    rels = [

    ]


class remoteDesktopSecurityConfiguration(entity):
    props = {
        'isRemoteDesktopProtocolEnabled': Edm.Boolean,
    }
    rels = [
        'targetDeviceGroups',
    ]


class invitation(entity):
    props = {
        'invitedUserDisplayName': Edm.String,
        'invitedUserEmailAddress': Edm.String,
        'invitedUserMessageInfo': invitedUserMessageInfo,
        'invitedUserType': Edm.String,
        'inviteRedeemUrl': Edm.String,
        'inviteRedirectUrl': Edm.String,
        'resetRedemption': Edm.Boolean,
        'sendInvitationMessage': Edm.Boolean,
        'status': Edm.String,
    }
    rels = [
        'invitedUser',
        'invitedUserSponsors',
    ]


class activityStatistics(entity):
    props = {
        'activity': analyticsActivityType,
        'duration': Edm.Duration,
        'endDate': Edm.Date,
        'startDate': Edm.Date,
        'timeZoneUsed': Edm.String,
    }
    rels = [

    ]


class applicationTemplate(entity):
    props = {
        'categories': Collection,
        'configurationUris': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'homePageUrl': Edm.String,
        'informationalUrls': informationalUrls,
        'logoUrl': Edm.String,
        'publisher': Edm.String,
        'supportedClaimConfiguration': supportedClaimConfiguration,
        'supportedProvisioningTypes': Collection,
        'supportedSingleSignOnModes': Collection,
    }
    rels = [

    ]


class approvalItem(entity):
    props = {
        'allowCancel': Edm.Boolean,
        'allowEmailNotification': Edm.Boolean,
        'approvalType': approvalItemType,
        'approvers': Collection,
        'completedDateTime': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'owner': approvalIdentitySet,
        'responsePrompts': Collection,
        'result': Edm.String,
        'state': approvalItemState,
        'viewPoint': approvalItemViewPoint,
    }
    rels = [
        'requests',
        'responses',
    ]


class approvalItemRequest(entity):
    props = {
        'approver': approvalIdentitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'isReassigned': Edm.Boolean,
        'reassignedFrom': approvalIdentitySet,
    }
    rels = [

    ]


class approvalItemResponse(entity):
    props = {
        'comments': Edm.String,
        'createdBy': approvalIdentitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'owners': Collection,
        'response': Edm.String,
    }
    rels = [

    ]


class approvalOperation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'error': publicError,
        'lastActionDateTime': Edm.DateTimeOffset,
        'resourceLocation': Edm.String,
        'status': approvalOperationStatus,
    }
    rels = [

    ]


class approvalSolution(entity):
    props = {
        'provisioningStatus': provisionState,
    }
    rels = [
        'approvalItems',
        'operations',
    ]


class solutionsRoot(object):
    props = {

    }
    rels = [
        'approval',
        'bookingBusinesses',
        'bookingCurrencies',
        'businessScenarios',
        'backupRestore',
        'virtualEvents',
    ]


class bookingNamedEntity(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [

    ]


class bookingCurrency(entity):
    props = {
        'symbol': Edm.String,
    }
    rels = [

    ]


class businessScenario(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'ownerAppIds': Collection,
        'uniqueName': Edm.String,
    }
    rels = [
        'planner',
    ]


class backupRestoreRoot(entity):
    props = {
        'serviceStatus': serviceStatus,
    }
    rels = [
        'driveInclusionRules',
        'driveProtectionUnits',
        'driveProtectionUnitsBulkAdditionJobs',
        'exchangeProtectionPolicies',
        'exchangeRestoreSessions',
        'mailboxInclusionRules',
        'mailboxProtectionUnits',
        'mailboxProtectionUnitsBulkAdditionJobs',
        'oneDriveForBusinessProtectionPolicies',
        'oneDriveForBusinessRestoreSessions',
        'protectionPolicies',
        'protectionUnits',
        'restorePoints',
        'restoreSessions',
        'serviceApps',
        'sharePointProtectionPolicies',
        'sharePointRestoreSessions',
        'siteInclusionRules',
        'siteProtectionUnits',
        'siteProtectionUnitsBulkAdditionJobs',
    ]


class virtualEventsRoot(entity):
    props = {

    }
    rels = [
        'events',
        'townhalls',
        'webinars',
    ]


class authenticationCombinationConfiguration(entity):
    props = {
        'appliesToCombinations': Collection,
    }
    rels = [

    ]


class authenticationMethodConfiguration(entity):
    props = {
        'excludeTargets': Collection,
        'state': authenticationMethodState,
    }
    rels = [

    ]


class authenticationMethodModeDetail(entity):
    props = {
        'authenticationMethod': baseAuthenticationMethod,
        'displayName': Edm.String,
    }
    rels = [

    ]


class authenticationMethodsPolicy(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'microsoftAuthenticatorPlatformSettings': microsoftAuthenticatorPlatformSettings,
        'policyMigrationState': authenticationMethodsPolicyMigrationState,
        'policyVersion': Edm.String,
        'reconfirmationInDays': Edm.Int32,
        'registrationEnforcement': registrationEnforcement,
        'reportSuspiciousActivitySettings': reportSuspiciousActivitySettings,
        'systemCredentialPreferences': systemCredentialPreferences,
    }
    rels = [
        'authenticationMethodConfigurations',
    ]


class authenticationMethodTarget(entity):
    props = {
        'isRegistrationRequired': Edm.Boolean,
        'targetType': authenticationMethodTargetType,
    }
    rels = [

    ]


class authenticationStrengthPolicy(entity):
    props = {
        'allowedCombinations': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'policyType': authenticationStrengthPolicyType,
        'requirementsSatisfied': authenticationStrengthRequirements,
    }
    rels = [
        'combinationConfigurations',
    ]


class authenticationStrengthRoot(entity):
    props = {
        'authenticationCombinations': Collection,
        'combinations': Collection,
    }
    rels = [
        'authenticationMethodModes',
        'policies',
    ]


class conditionalAccessRoot(entity):
    props = {

    }
    rels = [
        'authenticationStrength',
        'authenticationStrengths',
        'authenticationContextClassReferences',
        'namedLocations',
        'policies',
        'templates',
    ]


class authenticationContextClassReference(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isAvailable': Edm.Boolean,
    }
    rels = [

    ]


class namedLocation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class conditionalAccessPolicy(entity):
    props = {
        'conditions': conditionalAccessConditionSet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'grantControls': conditionalAccessGrantControls,
        'modifiedDateTime': Edm.DateTimeOffset,
        'sessionControls': conditionalAccessSessionControls,
        'state': conditionalAccessPolicyState,
    }
    rels = [

    ]


class conditionalAccessTemplate(entity):
    props = {
        'description': Edm.String,
        'details': conditionalAccessPolicyDetail,
        'name': Edm.String,
        'scenarios': templateScenarios,
    }
    rels = [

    ]


class policyRoot(entity):
    props = {

    }
    rels = [
        'authenticationMethodsPolicy',
        'authenticationStrengthPolicies',
        'authenticationFlowsPolicy',
        'b2cAuthenticationMethodsPolicy',
        'deviceRegistrationPolicy',
        'activityBasedTimeoutPolicies',
        'appManagementPolicies',
        'authorizationPolicy',
        'claimsMappingPolicies',
        'crossTenantAccessPolicy',
        'defaultAppManagementPolicy',
        'externalIdentitiesPolicy',
        'federatedTokenValidationPolicy',
        'homeRealmDiscoveryPolicies',
        'permissionGrantPolicies',
        'permissionGrantPreApprovalPolicies',
        'servicePrincipalCreationPolicies',
        'tokenIssuancePolicies',
        'tokenLifetimePolicies',
        'featureRolloutPolicies',
        'accessReviewPolicy',
        'adminConsentRequestPolicy',
        'directoryRoleAccessReviewPolicy',
        'conditionalAccessPolicies',
        'identitySecurityDefaultsEnforcementPolicy',
        'mobileAppManagementPolicies',
        'mobileDeviceManagementPolicies',
        'roleManagementPolicies',
        'roleManagementPolicyAssignments',
    ]


class authenticationFlowsPolicy(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'selfServiceSignUp': selfServiceSignUpAuthenticationFlowConfiguration,
    }
    rels = [

    ]


class b2cAuthenticationMethodsPolicy(entity):
    props = {
        'isEmailPasswordAuthenticationEnabled': Edm.Boolean,
        'isPhoneOneTimePasswordAuthenticationEnabled': Edm.Boolean,
        'isUserNameAuthenticationEnabled': Edm.Boolean,
    }
    rels = [

    ]


class deviceRegistrationPolicy(entity):
    props = {
        'azureADJoin': azureADJoinPolicy,
        'azureADRegistration': azureADRegistrationPolicy,
        'description': Edm.String,
        'displayName': Edm.String,
        'localAdminPassword': localAdminPasswordSettings,
        'multiFactorAuthConfiguration': multiFactorAuthConfiguration,
        'userDeviceQuota': Edm.Int32,
    }
    rels = [

    ]


class federatedTokenValidationPolicy(directoryObject):
    props = {
        'validatingDomains': validatingDomains,
    }
    rels = [

    ]


class accessReviewPolicy(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isGroupOwnerManagementEnabled': Edm.Boolean,
    }
    rels = [

    ]


class adminConsentRequestPolicy(entity):
    props = {
        'isEnabled': Edm.Boolean,
        'notifyReviewers': Edm.Boolean,
        'remindersEnabled': Edm.Boolean,
        'requestDurationInDays': Edm.Int32,
        'reviewers': Collection,
        'version': Edm.Int32,
    }
    rels = [

    ]


class directoryRoleAccessReviewPolicy(entity):
    props = {
        'settings': accessReviewScheduleSettings,
    }
    rels = [

    ]


class mobilityManagementPolicy(entity):
    props = {
        'appliesTo': policyScope,
        'complianceUrl': Edm.String,
        'description': Edm.String,
        'discoveryUrl': Edm.String,
        'displayName': Edm.String,
        'isValid': Edm.Boolean,
        'termsOfUseUrl': Edm.String,
    }
    rels = [
        'includedGroups',
    ]


class unifiedRoleManagementPolicy(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isOrganizationDefault': Edm.Boolean,
        'lastModifiedBy': identity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'scopeId': Edm.String,
        'scopeType': Edm.String,
    }
    rels = [
        'effectiveRules',
        'rules',
    ]


class unifiedRoleManagementPolicyAssignment(entity):
    props = {
        'policyId': Edm.String,
        'roleDefinitionId': Edm.String,
        'scopeId': Edm.String,
        'scopeType': Edm.String,
    }
    rels = [
        'policy',
    ]


class searchEntity(entity):
    props = {

    }
    rels = [
        'acronyms',
        'bookmarks',
        'qnas',
    ]


class bitlocker(entity):
    props = {

    }
    rels = [
        'recoveryKeys',
    ]


class bitlockerRecoveryKey(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'deviceId': Edm.String,
        'key': Edm.String,
        'volumeType': volumeType,
    }
    rels = [

    ]


class dataLossPreventionPolicy(entity):
    props = {
        'name': Edm.String,
    }
    rels = [

    ]


class sensitivityLabel(entity):
    props = {
        'applicableTo': sensitivityLabelTarget,
        'applicationMode': applicationMode,
        'assignedPolicies': Collection,
        'autoLabeling': autoLabeling,
        'description': Edm.String,
        'displayName': Edm.String,
        'isDefault': Edm.Boolean,
        'isEndpointProtectionEnabled': Edm.Boolean,
        'labelActions': Collection,
        'name': Edm.String,
        'priority': Edm.Int32,
        'toolTip': Edm.String,
    }
    rels = [
        'sublabels',
    ]


class sensitivityPolicySettings(entity):
    props = {
        'applicableTo': sensitivityLabelTarget,
        'downgradeSensitivityRequiresJustification': Edm.Boolean,
        'helpWebUrl': Edm.String,
        'isMandatory': Edm.Boolean,
    }
    rels = [

    ]


class informationProtectionPolicy(entity):
    props = {

    }
    rels = [
        'labels',
    ]


class threatAssessmentRequest(entity):
    props = {
        'category': threatCategory,
        'contentType': threatAssessmentContentType,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'expectedAssessment': threatExpectedAssessment,
        'requestSource': threatAssessmentRequestSource,
        'status': threatAssessmentStatus,
    }
    rels = [
        'results',
    ]


class bookingAppointment(entity):
    props = {
        'additionalInformation': Edm.String,
        'anonymousJoinWebUrl': Edm.String,
        'appointmentLabel': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'customerEmailAddress': Edm.String,
        'customerId': Edm.String,
        'customerLocation': location,
        'customerName': Edm.String,
        'customerNotes': Edm.String,
        'customerPhone': Edm.String,
        'customers': Collection,
        'customerTimeZone': Edm.String,
        'duration': Edm.Duration,
        'end': dateTimeTimeZone,
        'filledAttendeesCount': Edm.Int32,
        'invoiceAmount': Edm.Double,
        'invoiceDate': dateTimeTimeZone,
        'invoiceId': Edm.String,
        'invoiceStatus': bookingInvoiceStatus,
        'invoiceUrl': Edm.String,
        'isCustomerAllowedToManageBooking': Edm.Boolean,
        'isLocationOnline': Edm.Boolean,
        'joinWebUrl': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'maximumAttendeesCount': Edm.Int32,
        'onlineMeetingUrl': Edm.String,
        'optOutOfCustomerEmail': Edm.Boolean,
        'postBuffer': Edm.Duration,
        'preBuffer': Edm.Duration,
        'price': Edm.Double,
        'priceType': bookingPriceType,
        'reminders': Collection,
        'selfServiceAppointmentId': Edm.String,
        'serviceId': Edm.String,
        'serviceLocation': location,
        'serviceName': Edm.String,
        'serviceNotes': Edm.String,
        'smsNotificationsEnabled': Edm.Boolean,
        'staffMemberIds': Collection,
        'start': dateTimeTimeZone,
    }
    rels = [

    ]


class bookingCustomQuestion(entity):
    props = {
        'answerInputType': answerInputType,
        'answerOptions': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class businessScenarioPlanner(entity):
    props = {

    }
    rels = [
        'planConfiguration',
        'taskConfiguration',
        'tasks',
    ]


class plannerPlanConfiguration(entity):
    props = {
        'buckets': Collection,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'defaultLanguage': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'localizations',
    ]


class plannerTaskConfiguration(entity):
    props = {
        'editPolicy': plannerTaskPolicy,
    }
    rels = [

    ]


class plannerPlanConfigurationLocalization(entity):
    props = {
        'buckets': Collection,
        'languageTag': Edm.String,
        'planTitle': Edm.String,
    }
    rels = [

    ]


class changeItemBase(entity):
    props = {
        'changeItemService': Edm.String,
        'description': Edm.String,
        'documentationUrls': Collection,
        'shortDescription': Edm.String,
        'systemTags': Collection,
        'tags': Collection,
        'title': Edm.String,
    }
    rels = [

    ]


class identityContainer(object):
    props = {

    }
    rels = [
        'productChanges',
        'apiConnectors',
        'authenticationEventListeners',
        'authenticationEventsFlows',
        'b2cUserFlows',
        'b2xUserFlows',
        'customAuthenticationExtensions',
        'identityProviders',
        'userFlowAttributes',
        'userFlows',
        'conditionalAccess',
        'continuousAccessEvaluationPolicy',
    ]


class identityApiConnector(entity):
    props = {
        'authenticationConfiguration': apiAuthenticationConfigurationBase,
        'displayName': Edm.String,
        'targetUrl': Edm.String,
    }
    rels = [

    ]


class authenticationEventListener(entity):
    props = {
        'authenticationEventsFlowId': Edm.String,
        'conditions': authenticationConditions,
        'priority': Edm.Int32,
    }
    rels = [

    ]


class authenticationEventsFlow(entity):
    props = {
        'conditions': authenticationConditions,
        'description': Edm.String,
        'displayName': Edm.String,
        'priority': Edm.Int32,
    }
    rels = [

    ]


class identityUserFlow(entity):
    props = {
        'userFlowType': userFlowType,
        'userFlowTypeVersion': Edm.Single,
    }
    rels = [

    ]


class identityUserFlowAttribute(entity):
    props = {
        'dataType': identityUserFlowAttributeDataType,
        'description': Edm.String,
        'displayName': Edm.String,
        'userFlowAttributeType': identityUserFlowAttributeType,
    }
    rels = [

    ]


class continuousAccessEvaluationPolicy(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'groups': Collection,
        'isEnabled': Edm.Boolean,
        'migrate': Edm.Boolean,
        'users': Collection,
    }
    rels = [

    ]


class admin(object):
    props = {

    }
    rels = [
        'edge',
        'exchange',
        'sharepoint',
        'microsoft365Apps',
        'serviceAnnouncement',
        'entra',
        'reportSettings',
        'appsAndServices',
        'dynamics',
        'forms',
        'todo',
        'people',
        'windows',
    ]


class edge(entity):
    props = {

    }
    rels = [
        'internetExplorerMode',
    ]


class exchangeAdmin(entity):
    props = {

    }
    rels = [
        'mailboxes',
        'messageTraces',
    ]


class sharepoint(entity):
    props = {

    }
    rels = [
        'settings',
    ]


class adminMicrosoft365Apps(entity):
    props = {

    }
    rels = [
        'installationOptions',
    ]


class serviceAnnouncement(entity):
    props = {

    }
    rels = [
        'healthOverviews',
        'issues',
        'messages',
    ]


class entra(entity):
    props = {

    }
    rels = [
        'uxSetting',
    ]


class adminReportSettings(entity):
    props = {
        'displayConcealedNames': Edm.Boolean,
    }
    rels = [

    ]


class adminAppsAndServices(entity):
    props = {
        'settings': appsAndServicesSettings,
    }
    rels = [

    ]


class adminDynamics(entity):
    props = {
        'customerVoice': customerVoiceSettings,
    }
    rels = [

    ]


class adminForms(entity):
    props = {
        'settings': formsSettings,
    }
    rels = [

    ]


class adminTodo(entity):
    props = {
        'settings': todoSettings,
    }
    rels = [

    ]


class peopleAdminSettings(entity):
    props = {

    }
    rels = [
        'profileCardProperties',
        'pronouns',
        'itemInsights',
    ]


class adminWindows(entity):
    props = {

    }
    rels = [
        'updates',
    ]


class appScope(entity):
    props = {
        'displayName': Edm.String,
        'type': Edm.String,
    }
    rels = [

    ]


class cloudPcAuditEvent(entity):
    props = {
        'activity': Edm.String,
        'activityDateTime': Edm.DateTimeOffset,
        'activityOperationType': cloudPcAuditActivityOperationType,
        'activityResult': cloudPcAuditActivityResult,
        'activityType': Edm.String,
        'actor': cloudPcAuditActor,
        'category': cloudPcAuditCategory,
        'componentName': Edm.String,
        'correlationId': Edm.String,
        'displayName': Edm.String,
        'resources': Collection,
    }
    rels = [

    ]


class cloudPcBulkAction(entity):
    props = {
        'actionSummary': cloudPcBulkActionSummary,
        'cloudPcIds': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'initiatedByUserPrincipalName': Edm.String,
        'scheduledDuringMaintenanceWindow': Edm.Boolean,
        'status': cloudPcBulkActionStatus,
    }
    rels = [

    ]


class cloudPcCrossCloudGovernmentOrganizationMapping(entity):
    props = {
        'organizationIdsInUSGovCloud': Collection,
    }
    rels = [

    ]


class cloudPcDeviceImage(entity):
    props = {
        'displayName': Edm.String,
        'errorCode': cloudPcDeviceImageErrorCode,
        'expirationDate': Edm.Date,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'operatingSystem': Edm.String,
        'osBuildNumber': Edm.String,
        'osStatus': cloudPcDeviceImageOsStatus,
        'osVersionNumber': Edm.String,
        'scopeIds': Collection,
        'sourceImageResourceId': Edm.String,
        'status': cloudPcDeviceImageStatus,
        'statusDetails': cloudPcDeviceImageStatusDetails,
        'version': Edm.String,
    }
    rels = [

    ]


class cloudPcExportJob(entity):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'exportJobStatus': cloudPcExportJobStatus,
        'exportUrl': Edm.String,
        'filter': Edm.String,
        'format': Edm.String,
        'reportName': cloudPcReportName,
        'requestDateTime': Edm.DateTimeOffset,
        'select': Collection,
    }
    rels = [

    ]


class cloudPcExternalPartnerSetting(entity):
    props = {
        'enableConnection': Edm.Boolean,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'partnerId': Edm.String,
        'status': cloudPcExternalPartnerStatus,
        'statusDetails': Edm.String,
    }
    rels = [

    ]


class cloudPcFrontLineServicePlan(entity):
    props = {
        'allotmentLicensesCount': Edm.Int32,
        'displayName': Edm.String,
        'totalCount': Edm.Int32,
        'usedCount': Edm.Int32,
    }
    rels = [

    ]


class cloudPcGalleryImage(entity):
    props = {
        'displayName': Edm.String,
        'endDate': Edm.Date,
        'expirationDate': Edm.Date,
        'offer': Edm.String,
        'offerDisplayName': Edm.String,
        'offerName': Edm.String,
        'osVersionNumber': Edm.String,
        'publisher': Edm.String,
        'publisherName': Edm.String,
        'recommendedSku': Edm.String,
        'sizeInGB': Edm.Int32,
        'sku': Edm.String,
        'skuDisplayName': Edm.String,
        'skuName': Edm.String,
        'startDate': Edm.Date,
        'status': cloudPcGalleryImageStatus,
    }
    rels = [

    ]


class cloudPcOnPremisesConnection(entity):
    props = {
        'adDomainName': Edm.String,
        'adDomainPassword': Edm.String,
        'adDomainUsername': Edm.String,
        'alternateResourceUrl': Edm.String,
        'connectionType': cloudPcOnPremisesConnectionType,
        'displayName': Edm.String,
        'healthCheckPaused': Edm.Boolean,
        'healthCheckStatus': cloudPcOnPremisesConnectionStatus,
        'healthCheckStatusDetail': cloudPcOnPremisesConnectionStatusDetail,
        'healthCheckStatusDetails': cloudPcOnPremisesConnectionStatusDetails,
        'inUse': Edm.Boolean,
        'inUseByCloudPc': Edm.Boolean,
        'managedBy': cloudPcManagementService,
        'organizationalUnit': Edm.String,
        'resourceGroupId': Edm.String,
        'scopeIds': Collection,
        'subnetId': Edm.String,
        'subscriptionId': Edm.String,
        'subscriptionName': Edm.String,
        'type': cloudPcOnPremisesConnectionType,
        'virtualNetworkId': Edm.String,
        'virtualNetworkLocation': Edm.String,
    }
    rels = [

    ]


class cloudPcOrganizationSettings(entity):
    props = {
        'enableMEMAutoEnroll': Edm.Boolean,
        'enableSingleSignOn': Edm.Boolean,
        'osVersion': cloudPcOperatingSystem,
        'userAccountType': cloudPcUserAccountType,
        'windowsSettings': cloudPcWindowsSettings,
    }
    rels = [

    ]


class cloudPcProvisioningPolicy(entity):
    props = {
        'alternateResourceUrl': Edm.String,
        'autopatch': cloudPcProvisioningPolicyAutopatch,
        'autopilotConfiguration': cloudPcAutopilotConfiguration,
        'cloudPcGroupDisplayName': Edm.String,
        'cloudPcNamingTemplate': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'domainJoinConfigurations': Collection,
        'enableSingleSignOn': Edm.Boolean,
        'gracePeriodInHours': Edm.Int32,
        'imageDisplayName': Edm.String,
        'imageId': Edm.String,
        'imageType': cloudPcProvisioningPolicyImageType,
        'localAdminEnabled': Edm.Boolean,
        'managedBy': cloudPcManagementService,
        'microsoftManagedDesktop': microsoftManagedDesktop,
        'provisioningType': cloudPcProvisioningType,
        'scopeIds': Collection,
        'windowsSetting': cloudPcWindowsSetting,
        'windowsSettings': cloudPcWindowsSettings,
    }
    rels = [
        'assignments',
    ]


class cloudPcProvisioningPolicyAssignment(entity):
    props = {
        'target': cloudPcManagementAssignmentTarget,
    }
    rels = [
        'assignedUsers',
    ]


class cloudPcReports(entity):
    props = {

    }
    rels = [
        'exportJobs',
    ]


class cloudPcServicePlan(entity):
    props = {
        'displayName': Edm.String,
        'provisioningType': cloudPcProvisioningType,
        'ramInGB': Edm.Int32,
        'storageInGB': Edm.Int32,
        'supportedSolution': cloudPcManagementService,
        'type': cloudPcServicePlanType,
        'userProfileInGB': Edm.Int32,
        'vCpuCount': Edm.Int32,
    }
    rels = [

    ]


class cloudPcSnapshot(entity):
    props = {
        'cloudPcId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastRestoredDateTime': Edm.DateTimeOffset,
        'snapshotType': cloudPcSnapshotType,
        'status': cloudPcSnapshotStatus,
    }
    rels = [

    ]


class cloudPcSupportedRegion(entity):
    props = {
        'displayName': Edm.String,
        'regionGroup': cloudPcRegionGroup,
        'regionStatus': cloudPcSupportedRegionStatus,
        'supportedSolution': cloudPcManagementService,
    }
    rels = [

    ]


class cloudPcUserSetting(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'crossRegionDisasterRecoverySetting': cloudPcCrossRegionDisasterRecoverySetting,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'localAdminEnabled': Edm.Boolean,
        'notificationSetting': cloudPcNotificationSetting,
        'resetEnabled': Edm.Boolean,
        'restorePointSetting': cloudPcRestorePointSetting,
        'selfServiceEnabled': Edm.Boolean,
    }
    rels = [
        'assignments',
    ]


class cloudPcUserSettingAssignment(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'target': cloudPcManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceManagement(entity):
    props = {
        'deviceComplianceReportSummarizationDateTime': Edm.DateTimeOffset,
        'intuneAccountId': Edm.Guid,
        'lastReportAggregationDateTime': Edm.DateTimeOffset,
        'legacyPcManangementEnabled': Edm.Boolean,
        'maximumDepTokens': Edm.Int32,
        'settings': deviceManagementSettings,
        'unlicensedAdminstratorsEnabled': Edm.Boolean,
        'intuneBrand': intuneBrand,
        'accountMoveCompletionDateTime': Edm.DateTimeOffset,
        'adminConsent': adminConsent,
        'dataProcessorServiceForWindowsFeaturesOnboarding': dataProcessorServiceForWindowsFeaturesOnboarding,
        'deviceProtectionOverview': deviceProtectionOverview,
        'managedDeviceCleanupSettings': managedDeviceCleanupSettings,
        'subscriptions': deviceManagementSubscriptions,
        'subscriptionState': deviceManagementSubscriptionState,
        'userExperienceAnalyticsAnomalySeverityOverview': userExperienceAnalyticsAnomalySeverityOverview,
        'userExperienceAnalyticsSettings': userExperienceAnalyticsSettings,
        'windowsMalwareOverview': windowsMalwareOverview,
        'connectorStatus': Collection,
    }
    rels = [
        'monitoring',
        'virtualEndpoint',
        'androidDeviceOwnerEnrollmentProfiles',
        'androidForWorkAppConfigurationSchemas',
        'androidForWorkEnrollmentProfiles',
        'androidForWorkSettings',
        'androidManagedStoreAccountEnterpriseSettings',
        'androidManagedStoreAppConfigurationSchemas',
        'zebraFotaArtifacts',
        'zebraFotaConnector',
        'zebraFotaDeployments',
        'auditEvents',
        'assignmentFilters',
        'chromeOSOnboardingSettings',
        'cloudCertificationAuthority',
        'cloudCertificationAuthorityLeafCertificate',
        'termsAndConditions',
        'advancedThreatProtectionOnboardingStateSummary',
        'cartToClassAssociations',
        'deviceCompliancePolicies',
        'deviceCompliancePolicyDeviceStateSummary',
        'deviceCompliancePolicySettingStateSummaries',
        'deviceConfigurationConflictSummary',
        'deviceConfigurationDeviceStateSummaries',
        'deviceConfigurationRestrictedAppsViolations',
        'deviceConfigurations',
        'deviceConfigurationsAllManagedDeviceCertificateStates',
        'deviceConfigurationUserStateSummaries',
        'endpointPrivilegeManagementProvisioningStatus',
        'hardwareConfigurations',
        'hardwarePasswordDetails',
        'hardwarePasswordInfo',
        'iosUpdateStatuses',
        'macOSSoftwareUpdateAccountSummaries',
        'managedDeviceEncryptionStates',
        'ndesConnectors',
        'softwareUpdateStatusSummary',
        'complianceCategories',
        'compliancePolicies',
        'complianceSettings',
        'configurationCategories',
        'configurationPolicies',
        'configurationPolicyTemplates',
        'configurationSettings',
        'reusablePolicySettings',
        'reusableSettings',
        'templateInsights',
        'templateSettings',
        'complianceManagementPartners',
        'conditionalAccessSettings',
        'deviceCategories',
        'deviceEnrollmentConfigurations',
        'deviceManagementPartners',
        'exchangeConnectors',
        'exchangeOnPremisesPolicies',
        'exchangeOnPremisesPolicy',
        'mobileThreatDefenseConnectors',
        'categories',
        'intents',
        'settingDefinitions',
        'templates',
        'applePushNotificationCertificate',
        'cloudPCConnectivityIssues',
        'comanagedDevices',
        'comanagementEligibleDevices',
        'dataSharingConsents',
        'detectedApps',
        'deviceComplianceScripts',
        'deviceCustomAttributeShellScripts',
        'deviceHealthScripts',
        'deviceManagementScripts',
        'deviceShellScripts',
        'managedDeviceCleanupRules',
        'managedDeviceOverview',
        'managedDevices',
        'mobileAppTroubleshootingEvents',
        'privilegeManagementElevations',
        'remoteActionAudits',
        'tenantAttachRBAC',
        'userExperienceAnalyticsAnomaly',
        'userExperienceAnalyticsAnomalyCorrelationGroupOverview',
        'userExperienceAnalyticsAnomalyDevice',
        'userExperienceAnalyticsAppHealthApplicationPerformance',
        'userExperienceAnalyticsAppHealthApplicationPerformanceByAppVersion',
        'userExperienceAnalyticsAppHealthApplicationPerformanceByAppVersionDetails',
        'userExperienceAnalyticsAppHealthApplicationPerformanceByAppVersionDeviceId',
        'userExperienceAnalyticsAppHealthApplicationPerformanceByOSVersion',
        'userExperienceAnalyticsAppHealthDeviceModelPerformance',
        'userExperienceAnalyticsAppHealthDevicePerformance',
        'userExperienceAnalyticsAppHealthDevicePerformanceDetails',
        'userExperienceAnalyticsAppHealthOSVersionPerformance',
        'userExperienceAnalyticsAppHealthOverview',
        'userExperienceAnalyticsBaselines',
        'userExperienceAnalyticsBatteryHealthAppImpact',
        'userExperienceAnalyticsBatteryHealthCapacityDetails',
        'userExperienceAnalyticsBatteryHealthDeviceAppImpact',
        'userExperienceAnalyticsBatteryHealthDevicePerformance',
        'userExperienceAnalyticsBatteryHealthDeviceRuntimeHistory',
        'userExperienceAnalyticsBatteryHealthModelPerformance',
        'userExperienceAnalyticsBatteryHealthOsPerformance',
        'userExperienceAnalyticsBatteryHealthRuntimeDetails',
        'userExperienceAnalyticsCategories',
        'userExperienceAnalyticsDeviceMetricHistory',
        'userExperienceAnalyticsDevicePerformance',
        'userExperienceAnalyticsDeviceScope',
        'userExperienceAnalyticsDeviceScopes',
        'userExperienceAnalyticsDeviceScores',
        'userExperienceAnalyticsDeviceStartupHistory',
        'userExperienceAnalyticsDeviceStartupProcesses',
        'userExperienceAnalyticsDeviceStartupProcessPerformance',
        'userExperienceAnalyticsDevicesWithoutCloudIdentity',
        'userExperienceAnalyticsDeviceTimelineEvent',
        'userExperienceAnalyticsImpactingProcess',
        'userExperienceAnalyticsMetricHistory',
        'userExperienceAnalyticsModelScores',
        'userExperienceAnalyticsNotAutopilotReadyDevice',
        'userExperienceAnalyticsOverview',
        'userExperienceAnalyticsRemoteConnection',
        'userExperienceAnalyticsResourcePerformance',
        'userExperienceAnalyticsScoreHistory',
        'userExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric',
        'userExperienceAnalyticsWorkFromAnywhereMetrics',
        'userExperienceAnalyticsWorkFromAnywhereModelPerformance',
        'windowsMalwareInformation',
        'derivedCredentials',
        'resourceAccessProfiles',
        'appleUserInitiatedEnrollmentProfiles',
        'depOnboardingSettings',
        'importedDeviceIdentities',
        'importedWindowsAutopilotDeviceIdentities',
        'windowsAutopilotDeploymentProfiles',
        'windowsAutopilotDeviceIdentities',
        'windowsAutopilotSettings',
        'elevationRequests',
        'groupPolicyMigrationReports',
        'groupPolicyObjectFiles',
        'groupPolicyCategories',
        'groupPolicyConfigurations',
        'groupPolicyDefinitionFiles',
        'groupPolicyDefinitions',
        'groupPolicyUploadedDefinitionFiles',
        'serviceNowConnections',
        'microsoftTunnelConfigurations',
        'microsoftTunnelHealthThresholds',
        'microsoftTunnelServerLogCollectionResponses',
        'microsoftTunnelSites',
        'notificationMessageTemplates',
        'domainJoinConnectors',
        'managedDeviceWindowsOSImages',
        'configManagerCollections',
        'operationApprovalPolicies',
        'operationApprovalRequests',
        'resourceOperations',
        'roleAssignments',
        'roleDefinitions',
        'roleScopeTags',
        'remoteAssistancePartners',
        'remoteAssistanceSettings',
        'reports',
        'embeddedSIMActivationCodePools',
        'telecomExpenseManagementPartners',
        'autopilotEvents',
        'troubleshootingEvents',
        'windowsDriverUpdateProfiles',
        'windowsFeatureUpdateProfiles',
        'windowsQualityUpdatePolicies',
        'windowsQualityUpdateProfiles',
        'windowsUpdateCatalogItems',
        'intuneBrandingProfiles',
        'windowsInformationProtectionAppLearningSummaries',
        'windowsInformationProtectionNetworkLearningSummaries',
        'certificateConnectorDetails',
        'userPfxCertificates',
    ]


class virtualEndpoint(entity):
    props = {

    }
    rels = [
        'auditEvents',
        'bulkActions',
        'cloudPCs',
        'crossCloudGovernmentOrganizationMapping',
        'deviceImages',
        'externalPartnerSettings',
        'frontLineServicePlans',
        'galleryImages',
        'onPremisesConnections',
        'organizationSettings',
        'provisioningPolicies',
        'reports',
        'servicePlans',
        'snapshots',
        'supportedRegions',
        'userSettings',
    ]


class androidDeviceOwnerEnrollmentProfile(entity):
    props = {
        'accountId': Edm.String,
        'configureWifi': Edm.Boolean,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'enrolledDeviceCount': Edm.Int32,
        'enrollmentMode': androidDeviceOwnerEnrollmentMode,
        'enrollmentTokenType': androidDeviceOwnerEnrollmentTokenType,
        'enrollmentTokenUsageCount': Edm.Int32,
        'isTeamsDeviceProfile': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'qrCodeContent': Edm.String,
        'qrCodeImage': mimeContent,
        'roleScopeTagIds': Collection,
        'tokenCreationDateTime': Edm.DateTimeOffset,
        'tokenExpirationDateTime': Edm.DateTimeOffset,
        'tokenValue': Edm.String,
        'wifiHidden': Edm.Boolean,
        'wifiPassword': Edm.String,
        'wifiSecurityType': aospWifiSecurityType,
        'wifiSsid': Edm.String,
    }
    rels = [

    ]


class androidForWorkAppConfigurationSchema(entity):
    props = {
        'exampleJson': Edm.Binary,
        'schemaItems': Collection,
    }
    rels = [

    ]


class androidForWorkEnrollmentProfile(entity):
    props = {
        'accountId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'enrolledDeviceCount': Edm.Int32,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'qrCodeContent': Edm.String,
        'qrCodeImage': mimeContent,
        'tokenExpirationDateTime': Edm.DateTimeOffset,
        'tokenValue': Edm.String,
    }
    rels = [

    ]


class androidForWorkSettings(entity):
    props = {
        'bindStatus': androidForWorkBindStatus,
        'deviceOwnerManagementEnabled': Edm.Boolean,
        'enrollmentTarget': androidForWorkEnrollmentTarget,
        'lastAppSyncDateTime': Edm.DateTimeOffset,
        'lastAppSyncStatus': androidForWorkSyncStatus,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'ownerOrganizationName': Edm.String,
        'ownerUserPrincipalName': Edm.String,
        'targetGroupIds': Collection,
    }
    rels = [

    ]


class androidManagedStoreAccountEnterpriseSettings(entity):
    props = {
        'androidDeviceOwnerFullyManagedEnrollmentEnabled': Edm.Boolean,
        'bindStatus': androidManagedStoreAccountBindStatus,
        'companyCodes': Collection,
        'deviceOwnerManagementEnabled': Edm.Boolean,
        'enrollmentTarget': androidManagedStoreAccountEnrollmentTarget,
        'lastAppSyncDateTime': Edm.DateTimeOffset,
        'lastAppSyncStatus': androidManagedStoreAccountAppSyncStatus,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'managedGooglePlayInitialScopeTagIds': Collection,
        'ownerOrganizationName': Edm.String,
        'ownerUserPrincipalName': Edm.String,
        'targetGroupIds': Collection,
    }
    rels = [

    ]


class androidManagedStoreAppConfigurationSchema(entity):
    props = {
        'exampleJson': Edm.Binary,
        'nestedSchemaItems': Collection,
        'schemaItems': Collection,
    }
    rels = [

    ]


class zebraFotaArtifact(entity):
    props = {
        'boardSupportPackageVersion': Edm.String,
        'description': Edm.String,
        'deviceModel': Edm.String,
        'osVersion': Edm.String,
        'patchVersion': Edm.String,
        'releaseNotesUrl': Edm.String,
    }
    rels = [

    ]


class zebraFotaConnector(entity):
    props = {
        'enrollmentAuthorizationUrl': Edm.String,
        'enrollmentToken': Edm.String,
        'fotaAppsApproved': Edm.Boolean,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'state': zebraFotaConnectorState,
    }
    rels = [

    ]


class zebraFotaDeployment(entity):
    props = {
        'deploymentAssignments': Collection,
        'deploymentSettings': zebraFotaDeploymentSettings,
        'deploymentStatus': zebraFotaDeploymentStatus,
        'description': Edm.String,
        'displayName': Edm.String,
        'roleScopeTagIds': Collection,
    }
    rels = [

    ]


class auditEvent(entity):
    props = {
        'activity': Edm.String,
        'activityDateTime': Edm.DateTimeOffset,
        'activityOperationType': Edm.String,
        'activityResult': Edm.String,
        'activityType': Edm.String,
        'actor': auditActor,
        'category': Edm.String,
        'componentName': Edm.String,
        'correlationId': Edm.Guid,
        'displayName': Edm.String,
        'resources': Collection,
    }
    rels = [

    ]


class deviceAndAppManagementAssignmentFilter(entity):
    props = {
        'assignmentFilterManagementType': assignmentFilterManagementType,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'payloads': Collection,
        'platform': devicePlatformType,
        'roleScopeTags': Collection,
        'rule': Edm.String,
    }
    rels = [

    ]


class chromeOSOnboardingSettings(entity):
    props = {
        'lastDirectorySyncDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'onboardingStatus': onboardingStatus,
        'ownerUserPrincipalName': Edm.String,
    }
    rels = [

    ]


class cloudCertificationAuthority(entity):
    props = {
        'certificateDownloadUrl': Edm.String,
        'certificateKeySize': cloudCertificationAuthorityCertificateKeySize,
        'certificateRevocationListUrl': Edm.String,
        'certificateSigningRequest': Edm.String,
        'certificationAuthorityIssuerId': Edm.String,
        'certificationAuthorityIssuerUri': Edm.String,
        'certificationAuthorityStatus': cloudCertificationAuthorityStatus,
        'cloudCertificationAuthorityHashingAlgorithm': cloudCertificationAuthorityHashingAlgorithm,
        'cloudCertificationAuthorityType': cloudCertificationAuthorityType,
        'commonName': Edm.String,
        'countryName': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'eTag': Edm.String,
        'extendedKeyUsages': Collection,
        'issuerCommonName': Edm.String,
        'keyPlatform': cloudCertificationAuthorityKeyPlatformType,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'localityName': Edm.String,
        'ocspResponderUri': Edm.String,
        'organizationName': Edm.String,
        'organizationUnit': Edm.String,
        'roleScopeTagIds': Collection,
        'rootCertificateCommonName': Edm.String,
        'scepServerUrl': Edm.String,
        'serialNumber': Edm.String,
        'stateName': Edm.String,
        'subjectName': Edm.String,
        'thumbprint': Edm.String,
        'validityEndDateTime': Edm.DateTimeOffset,
        'validityPeriodInYears': Edm.Int32,
        'validityStartDateTime': Edm.DateTimeOffset,
        'versionNumber': Edm.Int32,
    }
    rels = [
        'cloudCertificationAuthorityLeafCertificate',
    ]


class cloudCertificationAuthorityLeafCertificate(entity):
    props = {
        'certificateStatus': cloudCertificationAuthorityLeafCertificateStatus,
        'certificationAuthorityIssuerUri': Edm.String,
        'crlDistributionPointUrl': Edm.String,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'devicePlatform': Edm.String,
        'extendedKeyUsages': Collection,
        'issuerId': Edm.String,
        'issuerName': Edm.String,
        'keyUsages': Collection,
        'ocspResponderUri': Edm.String,
        'revocationDateTime': Edm.DateTimeOffset,
        'serialNumber': Edm.String,
        'subjectName': Edm.String,
        'thumbprint': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'validityEndDateTime': Edm.DateTimeOffset,
        'validityStartDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class termsAndConditions(entity):
    props = {
        'acceptanceStatement': Edm.String,
        'bodyText': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'modifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'title': Edm.String,
        'version': Edm.Int32,
    }
    rels = [
        'acceptanceStatuses',
        'assignments',
        'groupAssignments',
    ]


class advancedThreatProtectionOnboardingStateSummary(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'conflictDeviceCount': Edm.Int32,
        'errorDeviceCount': Edm.Int32,
        'nonCompliantDeviceCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'notAssignedDeviceCount': Edm.Int32,
        'remediatedDeviceCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [
        'advancedThreatProtectionOnboardingDeviceSettingStates',
    ]


class cartToClassAssociation(entity):
    props = {
        'classroomIds': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'deviceCartIds': Collection,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'version': Edm.Int32,
    }
    rels = [

    ]


class deviceCompliancePolicy(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
        'deviceSettingStateSummaries',
        'deviceStatuses',
        'deviceStatusOverview',
        'scheduledActionsForRule',
        'userStatuses',
        'userStatusOverview',
    ]


class deviceCompliancePolicyDeviceStateSummary(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'configManagerCount': Edm.Int32,
        'conflictDeviceCount': Edm.Int32,
        'errorDeviceCount': Edm.Int32,
        'inGracePeriodCount': Edm.Int32,
        'nonCompliantDeviceCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'remediatedDeviceCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class deviceCompliancePolicySettingStateSummary(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'conflictDeviceCount': Edm.Int32,
        'errorDeviceCount': Edm.Int32,
        'nonCompliantDeviceCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'platformType': policyPlatformType,
        'remediatedDeviceCount': Edm.Int32,
        'setting': Edm.String,
        'settingName': Edm.String,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [
        'deviceComplianceSettingStates',
    ]


class deviceConfigurationConflictSummary(entity):
    props = {
        'conflictingDeviceConfigurations': Collection,
        'contributingSettings': Collection,
        'deviceCheckinsImpacted': Edm.Int32,
    }
    rels = [

    ]


class deviceConfigurationDeviceStateSummary(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'conflictDeviceCount': Edm.Int32,
        'errorDeviceCount': Edm.Int32,
        'nonCompliantDeviceCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'remediatedDeviceCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class restrictedAppsViolation(entity):
    props = {
        'deviceConfigurationId': Edm.String,
        'deviceConfigurationName': Edm.String,
        'deviceName': Edm.String,
        'managedDeviceId': Edm.String,
        'platformType': policyPlatformType,
        'restrictedApps': Collection,
        'restrictedAppsState': restrictedAppsState,
        'userId': Edm.String,
        'userName': Edm.String,
    }
    rels = [

    ]


class deviceConfiguration(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'deviceManagementApplicabilityRuleDeviceMode': deviceManagementApplicabilityRuleDeviceMode,
        'deviceManagementApplicabilityRuleOsEdition': deviceManagementApplicabilityRuleOsEdition,
        'deviceManagementApplicabilityRuleOsVersion': deviceManagementApplicabilityRuleOsVersion,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'supportsScopeTags': Edm.Boolean,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
        'deviceSettingStateSummaries',
        'deviceStatuses',
        'deviceStatusOverview',
        'groupAssignments',
        'userStatuses',
        'userStatusOverview',
    ]


class managedAllDeviceCertificateState(entity):
    props = {
        'certificateExpirationDateTime': Edm.DateTimeOffset,
        'certificateExtendedKeyUsages': Edm.String,
        'certificateIssuanceDateTime': Edm.DateTimeOffset,
        'certificateIssuerName': Edm.String,
        'certificateKeyUsages': Edm.Int32,
        'certificateRevokeStatus': certificateRevocationStatus,
        'certificateRevokeStatusLastChangeDateTime': Edm.DateTimeOffset,
        'certificateSerialNumber': Edm.String,
        'certificateSubjectName': Edm.String,
        'certificateThumbprint': Edm.String,
        'managedDeviceDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceConfigurationUserStateSummary(entity):
    props = {
        'compliantUserCount': Edm.Int32,
        'conflictUserCount': Edm.Int32,
        'errorUserCount': Edm.Int32,
        'nonCompliantUserCount': Edm.Int32,
        'notApplicableUserCount': Edm.Int32,
        'remediatedUserCount': Edm.Int32,
        'unknownUserCount': Edm.Int32,
    }
    rels = [

    ]


class endpointPrivilegeManagementProvisioningStatus(entity):
    props = {
        'licenseType': licenseType,
        'onboardedToMicrosoftManagedPlatform': Edm.Boolean,
    }
    rels = [

    ]


class hardwareConfiguration(entity):
    props = {
        'configurationFileContent': Edm.Binary,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'fileName': Edm.String,
        'hardwareConfigurationFormat': hardwareConfigurationFormat,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'perDevicePasswordDisabled': Edm.Boolean,
        'roleScopeTagIds': Collection,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
        'deviceRunStates',
        'runSummary',
        'userRunStates',
    ]


class hardwarePasswordDetail(entity):
    props = {
        'currentPassword': Edm.String,
        'previousPasswords': Collection,
        'serialNumber': Edm.String,
    }
    rels = [

    ]


class hardwarePasswordInfo(entity):
    props = {
        'currentPassword': Edm.String,
        'previousPasswords': Collection,
        'serialNumber': Edm.String,
    }
    rels = [

    ]


class iosUpdateDeviceStatus(entity):
    props = {
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'deviceModel': Edm.String,
        'installStatus': iosUpdatesInstallStatus,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'osVersion': Edm.String,
        'platform': Edm.Int32,
        'status': complianceStatus,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class macOSSoftwareUpdateAccountSummary(entity):
    props = {
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'displayName': Edm.String,
        'failedUpdateCount': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'osVersion': Edm.String,
        'successfulUpdateCount': Edm.Int32,
        'totalUpdateCount': Edm.Int32,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'categorySummaries',
    ]


class managedDeviceEncryptionState(entity):
    props = {
        'advancedBitLockerStates': advancedBitLockerState,
        'deviceName': Edm.String,
        'deviceType': deviceTypes,
        'encryptionPolicySettingState': complianceStatus,
        'encryptionReadinessState': encryptionReadinessState,
        'encryptionState': encryptionState,
        'fileVaultStates': fileVaultState,
        'osVersion': Edm.String,
        'policyDetails': Collection,
        'tpmSpecificationVersion': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class ndesConnector(entity):
    props = {
        'connectorVersion': Edm.String,
        'displayName': Edm.String,
        'enrolledDateTime': Edm.DateTimeOffset,
        'lastConnectionDateTime': Edm.DateTimeOffset,
        'machineName': Edm.String,
        'roleScopeTagIds': Collection,
        'state': ndesConnectorState,
    }
    rels = [

    ]


class softwareUpdateStatusSummary(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'compliantUserCount': Edm.Int32,
        'conflictDeviceCount': Edm.Int32,
        'conflictUserCount': Edm.Int32,
        'displayName': Edm.String,
        'errorDeviceCount': Edm.Int32,
        'errorUserCount': Edm.Int32,
        'nonCompliantDeviceCount': Edm.Int32,
        'nonCompliantUserCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'notApplicableUserCount': Edm.Int32,
        'remediatedDeviceCount': Edm.Int32,
        'remediatedUserCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
        'unknownUserCount': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementConfigurationCategory(entity):
    props = {
        'categoryDescription': Edm.String,
        'childCategoryIds': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'helpText': Edm.String,
        'name': Edm.String,
        'parentCategoryId': Edm.String,
        'platforms': deviceManagementConfigurationPlatforms,
        'rootCategoryId': Edm.String,
        'settingUsage': deviceManagementConfigurationSettingUsage,
        'technologies': deviceManagementConfigurationTechnologies,
    }
    rels = [

    ]


class deviceManagementCompliancePolicy(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'creationSource': Edm.String,
        'description': Edm.String,
        'isAssigned': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'platforms': deviceManagementConfigurationPlatforms,
        'roleScopeTagIds': Collection,
        'settingCount': Edm.Int32,
        'technologies': deviceManagementConfigurationTechnologies,
    }
    rels = [
        'assignments',
        'scheduledActionsForRule',
        'settings',
    ]


class deviceManagementConfigurationSettingDefinition(entity):
    props = {
        'accessTypes': deviceManagementConfigurationSettingAccessTypes,
        'applicability': deviceManagementConfigurationSettingApplicability,
        'baseUri': Edm.String,
        'categoryId': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'helpText': Edm.String,
        'infoUrls': Collection,
        'keywords': Collection,
        'name': Edm.String,
        'occurrence': deviceManagementConfigurationSettingOccurrence,
        'offsetUri': Edm.String,
        'referredSettingInformationList': Collection,
        'riskLevel': deviceManagementConfigurationSettingRiskLevel,
        'rootDefinitionId': Edm.String,
        'settingUsage': deviceManagementConfigurationSettingUsage,
        'uxBehavior': deviceManagementConfigurationControlType,
        'version': Edm.String,
        'visibility': deviceManagementConfigurationSettingVisibility,
    }
    rels = [

    ]


class deviceManagementConfigurationPolicy(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'creationSource': Edm.String,
        'description': Edm.String,
        'isAssigned': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'platforms': deviceManagementConfigurationPlatforms,
        'priorityMetaData': deviceManagementPriorityMetaData,
        'roleScopeTagIds': Collection,
        'settingCount': Edm.Int32,
        'technologies': deviceManagementConfigurationTechnologies,
        'templateReference': deviceManagementConfigurationPolicyTemplateReference,
    }
    rels = [
        'assignments',
        'settings',
    ]


class deviceManagementConfigurationPolicyTemplate(entity):
    props = {
        'allowUnmanagedSettings': Edm.Boolean,
        'baseId': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'displayVersion': Edm.String,
        'lifecycleState': deviceManagementTemplateLifecycleState,
        'platforms': deviceManagementConfigurationPlatforms,
        'settingTemplateCount': Edm.Int32,
        'technologies': deviceManagementConfigurationTechnologies,
        'templateFamily': deviceManagementConfigurationTemplateFamily,
        'version': Edm.Int32,
    }
    rels = [
        'settingTemplates',
    ]


class deviceManagementReusablePolicySetting(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'referencingConfigurationPolicyCount': Edm.Int32,
        'settingDefinitionId': Edm.String,
        'settingInstance': deviceManagementConfigurationSettingInstance,
        'version': Edm.Int32,
    }
    rels = [
        'referencingConfigurationPolicies',
    ]


class deviceManagementTemplateInsightsDefinition(entity):
    props = {
        'settingInsights': Collection,
    }
    rels = [

    ]


class deviceManagementConfigurationSettingTemplate(entity):
    props = {
        'settingInstanceTemplate': deviceManagementConfigurationSettingInstanceTemplate,
    }
    rels = [
        'settingDefinitions',
    ]


class complianceManagementPartner(entity):
    props = {
        'androidEnrollmentAssignments': Collection,
        'androidOnboarded': Edm.Boolean,
        'displayName': Edm.String,
        'iosEnrollmentAssignments': Collection,
        'iosOnboarded': Edm.Boolean,
        'lastHeartbeatDateTime': Edm.DateTimeOffset,
        'macOsEnrollmentAssignments': Collection,
        'macOsOnboarded': Edm.Boolean,
        'partnerState': deviceManagementPartnerTenantState,
    }
    rels = [

    ]


class onPremisesConditionalAccessSettings(entity):
    props = {
        'enabled': Edm.Boolean,
        'excludedGroups': Collection,
        'includedGroups': Collection,
        'overrideDefaultRule': Edm.Boolean,
    }
    rels = [

    ]


class deviceCategory(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'roleScopeTagIds': Collection,
    }
    rels = [

    ]


class deviceManagementPartner(entity):
    props = {
        'displayName': Edm.String,
        'groupsRequiringPartnerEnrollment': Collection,
        'isConfigured': Edm.Boolean,
        'lastHeartbeatDateTime': Edm.DateTimeOffset,
        'partnerAppType': deviceManagementPartnerAppType,
        'partnerState': deviceManagementPartnerTenantState,
        'singleTenantAppId': Edm.String,
        'whenPartnerDevicesWillBeMarkedAsNonCompliantDateTime': Edm.DateTimeOffset,
        'whenPartnerDevicesWillBeRemovedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class deviceManagementExchangeConnector(entity):
    props = {
        'connectorServerName': Edm.String,
        'exchangeAlias': Edm.String,
        'exchangeConnectorType': deviceManagementExchangeConnectorType,
        'exchangeOrganization': Edm.String,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'primarySmtpAddress': Edm.String,
        'serverName': Edm.String,
        'status': deviceManagementExchangeConnectorStatus,
        'version': Edm.String,
    }
    rels = [

    ]


class deviceManagementExchangeOnPremisesPolicy(entity):
    props = {
        'accessRules': Collection,
        'defaultAccessLevel': deviceManagementExchangeAccessLevel,
        'knownDeviceClasses': Collection,
        'notificationContent': Edm.Binary,
    }
    rels = [
        'conditionalAccessSettings',
    ]


class mobileThreatDefenseConnector(entity):
    props = {
        'allowPartnerToCollectIOSApplicationMetadata': Edm.Boolean,
        'allowPartnerToCollectIOSPersonalApplicationMetadata': Edm.Boolean,
        'androidDeviceBlockedOnMissingPartnerData': Edm.Boolean,
        'androidEnabled': Edm.Boolean,
        'androidMobileApplicationManagementEnabled': Edm.Boolean,
        'iosDeviceBlockedOnMissingPartnerData': Edm.Boolean,
        'iosEnabled': Edm.Boolean,
        'iosMobileApplicationManagementEnabled': Edm.Boolean,
        'lastHeartbeatDateTime': Edm.DateTimeOffset,
        'macDeviceBlockedOnMissingPartnerData': Edm.Boolean,
        'macEnabled': Edm.Boolean,
        'microsoftDefenderForEndpointAttachEnabled': Edm.Boolean,
        'partnerState': mobileThreatPartnerTenantState,
        'partnerUnresponsivenessThresholdInDays': Edm.Int32,
        'partnerUnsupportedOsVersionBlocked': Edm.Boolean,
        'windowsDeviceBlockedOnMissingPartnerData': Edm.Boolean,
        'windowsEnabled': Edm.Boolean,
        'windowsMobileApplicationManagementEnabled': Edm.Boolean,
    }
    rels = [

    ]


class deviceManagementSettingCategory(entity):
    props = {
        'displayName': Edm.String,
        'hasRequiredSetting': Edm.Boolean,
    }
    rels = [
        'settingDefinitions',
    ]


class deviceManagementIntent(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isAssigned': Edm.Boolean,
        'isMigratingToConfigurationPolicy': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'templateId': Edm.String,
    }
    rels = [
        'assignments',
        'categories',
        'deviceSettingStateSummaries',
        'deviceStates',
        'deviceStateSummary',
        'settings',
        'userStates',
        'userStateSummary',
    ]


class deviceManagementSettingDefinition(entity):
    props = {
        'constraints': Collection,
        'dependencies': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'documentationUrl': Edm.String,
        'headerSubtitle': Edm.String,
        'headerTitle': Edm.String,
        'isTopLevel': Edm.Boolean,
        'keywords': Collection,
        'placeholderText': Edm.String,
        'valueType': deviceManangementIntentValueType,
    }
    rels = [

    ]


class deviceManagementTemplate(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'intentCount': Edm.Int32,
        'isDeprecated': Edm.Boolean,
        'platformType': policyPlatformType,
        'publishedDateTime': Edm.DateTimeOffset,
        'templateSubtype': deviceManagementTemplateSubtype,
        'templateType': deviceManagementTemplateType,
        'versionInfo': Edm.String,
    }
    rels = [
        'categories',
        'migratableTo',
        'settings',
    ]


class applePushNotificationCertificate(entity):
    props = {
        'appleIdentifier': Edm.String,
        'certificate': Edm.String,
        'certificateSerialNumber': Edm.String,
        'certificateUploadFailureReason': Edm.String,
        'certificateUploadStatus': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'topicIdentifier': Edm.String,
    }
    rels = [

    ]


class cloudPCConnectivityIssue(entity):
    props = {
        'deviceId': Edm.String,
        'errorCode': Edm.String,
        'errorDateTime': Edm.DateTimeOffset,
        'errorDescription': Edm.String,
        'recommendedAction': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class comanagementEligibleDevice(entity):
    props = {
        'clientRegistrationStatus': deviceRegistrationState,
        'deviceName': Edm.String,
        'deviceType': deviceType,
        'entitySource': Edm.Int32,
        'managementAgents': managementAgentType,
        'managementState': managementState,
        'manufacturer': Edm.String,
        'mdmStatus': Edm.String,
        'model': Edm.String,
        'osDescription': Edm.String,
        'osVersion': Edm.String,
        'ownerType': ownerType,
        'referenceId': Edm.String,
        'serialNumber': Edm.String,
        'status': comanagementEligibleType,
        'upn': Edm.String,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
    }
    rels = [

    ]


class dataSharingConsent(entity):
    props = {
        'grantDateTime': Edm.DateTimeOffset,
        'granted': Edm.Boolean,
        'grantedByUpn': Edm.String,
        'grantedByUserId': Edm.String,
        'serviceDisplayName': Edm.String,
        'termsUrl': Edm.String,
    }
    rels = [

    ]


class detectedApp(entity):
    props = {
        'deviceCount': Edm.Int32,
        'displayName': Edm.String,
        'platform': detectedAppPlatformType,
        'publisher': Edm.String,
        'sizeInByte': Edm.Int64,
        'version': Edm.String,
    }
    rels = [
        'managedDevices',
    ]


class deviceComplianceScript(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'detectionScriptContent': Edm.Binary,
        'displayName': Edm.String,
        'enforceSignatureCheck': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'publisher': Edm.String,
        'roleScopeTagIds': Collection,
        'runAs32Bit': Edm.Boolean,
        'runAsAccount': runAsAccountType,
        'version': Edm.String,
    }
    rels = [
        'assignments',
        'deviceRunStates',
        'runSummary',
    ]


class deviceCustomAttributeShellScript(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'customAttributeName': Edm.String,
        'customAttributeType': deviceCustomAttributeValueType,
        'description': Edm.String,
        'displayName': Edm.String,
        'fileName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'runAsAccount': runAsAccountType,
        'scriptContent': Edm.Binary,
    }
    rels = [
        'assignments',
        'deviceRunStates',
        'groupAssignments',
        'runSummary',
        'userRunStates',
    ]


class deviceHealthScript(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'detectionScriptContent': Edm.Binary,
        'detectionScriptParameters': Collection,
        'deviceHealthScriptType': deviceHealthScriptType,
        'displayName': Edm.String,
        'enforceSignatureCheck': Edm.Boolean,
        'highestAvailableVersion': Edm.String,
        'isGlobalScript': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'publisher': Edm.String,
        'remediationScriptContent': Edm.Binary,
        'remediationScriptParameters': Collection,
        'roleScopeTagIds': Collection,
        'runAs32Bit': Edm.Boolean,
        'runAsAccount': runAsAccountType,
        'version': Edm.String,
    }
    rels = [
        'assignments',
        'deviceRunStates',
        'runSummary',
    ]


class deviceManagementScript(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'enforceSignatureCheck': Edm.Boolean,
        'fileName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'runAs32Bit': Edm.Boolean,
        'runAsAccount': runAsAccountType,
        'scriptContent': Edm.Binary,
    }
    rels = [
        'assignments',
        'deviceRunStates',
        'groupAssignments',
        'runSummary',
        'userRunStates',
    ]


class deviceShellScript(entity):
    props = {
        'blockExecutionNotifications': Edm.Boolean,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'executionFrequency': Edm.Duration,
        'fileName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'retryCount': Edm.Int32,
        'roleScopeTagIds': Collection,
        'runAsAccount': runAsAccountType,
        'scriptContent': Edm.Binary,
    }
    rels = [
        'assignments',
        'deviceRunStates',
        'groupAssignments',
        'runSummary',
        'userRunStates',
    ]


class managedDeviceCleanupRule(entity):
    props = {
        'description': Edm.String,
        'deviceCleanupRulePlatformType': deviceCleanupRulePlatformType,
        'deviceInactivityBeforeRetirementInDays': Edm.Int32,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class managedDeviceOverview(entity):
    props = {
        'deviceExchangeAccessStateSummary': deviceExchangeAccessStateSummary,
        'deviceOperatingSystemSummary': deviceOperatingSystemSummary,
        'dualEnrolledDeviceCount': Edm.Int32,
        'enrolledDeviceCount': Edm.Int32,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'managedDeviceModelsAndManufacturers': managedDeviceModelsAndManufacturers,
        'mdmEnrolledCount': Edm.Int32,
    }
    rels = [

    ]


class privilegeManagementElevation(entity):
    props = {
        'certificatePayload': Edm.String,
        'companyName': Edm.String,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'elevationType': privilegeManagementElevationType,
        'eventDateTime': Edm.DateTimeOffset,
        'fileDescription': Edm.String,
        'filePath': Edm.String,
        'fileVersion': Edm.String,
        'hash': Edm.String,
        'internalName': Edm.String,
        'justification': Edm.String,
        'parentProcessName': Edm.String,
        'policyId': Edm.String,
        'policyName': Edm.String,
        'processType': privilegeManagementProcessType,
        'productName': Edm.String,
        'result': Edm.Int32,
        'ruleId': Edm.String,
        'systemInitiatedElevation': Edm.Boolean,
        'upn': Edm.String,
        'userType': privilegeManagementEndUserType,
    }
    rels = [

    ]


class remoteActionAudit(entity):
    props = {
        'action': remoteAction,
        'actionState': actionState,
        'bulkDeviceActionId': Edm.String,
        'deviceActionCategory': deviceActionCategory,
        'deviceDisplayName': Edm.String,
        'deviceIMEI': Edm.String,
        'deviceOwnerUserPrincipalName': Edm.String,
        'initiatedByUserPrincipalName': Edm.String,
        'managedDeviceId': Edm.String,
        'requestDateTime': Edm.DateTimeOffset,
        'userName': Edm.String,
    }
    rels = [

    ]


class tenantAttachRBAC(entity):
    props = {

    }
    rels = [

    ]


class userExperienceAnalyticsAnomaly(entity):
    props = {
        'anomalyFirstOccurrenceDateTime': Edm.DateTimeOffset,
        'anomalyId': Edm.String,
        'anomalyLatestOccurrenceDateTime': Edm.DateTimeOffset,
        'anomalyName': Edm.String,
        'anomalyType': userExperienceAnalyticsAnomalyType,
        'assetName': Edm.String,
        'assetPublisher': Edm.String,
        'assetVersion': Edm.String,
        'detectionModelId': Edm.String,
        'deviceImpactedCount': Edm.Int32,
        'issueId': Edm.String,
        'severity': userExperienceAnalyticsAnomalySeverity,
        'state': userExperienceAnalyticsAnomalyState,
    }
    rels = [

    ]


class userExperienceAnalyticsAnomalyCorrelationGroupOverview(entity):
    props = {
        'anomalyCorrelationGroupCount': Edm.Int32,
        'anomalyId': Edm.String,
        'correlationGroupAnomalousDeviceCount': Edm.Int32,
        'correlationGroupAtRiskDeviceCount': Edm.Int32,
        'correlationGroupDeviceCount': Edm.Int32,
        'correlationGroupFeatures': Collection,
        'correlationGroupId': Edm.String,
        'correlationGroupPrevalence': userExperienceAnalyticsAnomalyCorrelationGroupPrevalence,
        'correlationGroupPrevalencePercentage': Edm.Double,
        'totalDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class userExperienceAnalyticsAnomalyDevice(entity):
    props = {
        'anomalyId': Edm.String,
        'anomalyOnDeviceFirstOccurrenceDateTime': Edm.DateTimeOffset,
        'anomalyOnDeviceLatestOccurrenceDateTime': Edm.DateTimeOffset,
        'correlationGroupId': Edm.String,
        'deviceId': Edm.String,
        'deviceManufacturer': Edm.String,
        'deviceModel': Edm.String,
        'deviceName': Edm.String,
        'deviceStatus': userExperienceAnalyticsDeviceStatus,
        'osName': Edm.String,
        'osVersion': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthApplicationPerformance(entity):
    props = {
        'activeDeviceCount': Edm.Int32,
        'appCrashCount': Edm.Int32,
        'appDisplayName': Edm.String,
        'appHangCount': Edm.Int32,
        'appHealthScore': Edm.Double,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appUsageDuration': Edm.Int32,
        'meanTimeToFailureInMinutes': Edm.Int32,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthAppPerformanceByAppVersion(entity):
    props = {
        'appCrashCount': Edm.Int32,
        'appDisplayName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appUsageDuration': Edm.Int32,
        'appVersion': Edm.String,
        'meanTimeToFailureInMinutes': Edm.Int32,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthAppPerformanceByAppVersionDetails(entity):
    props = {
        'appCrashCount': Edm.Int32,
        'appDisplayName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appVersion': Edm.String,
        'deviceCountWithCrashes': Edm.Int32,
        'isLatestUsedVersion': Edm.Boolean,
        'isMostUsedVersion': Edm.Boolean,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthAppPerformanceByAppVersionDeviceId(entity):
    props = {
        'appCrashCount': Edm.Int32,
        'appDisplayName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appVersion': Edm.String,
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'processedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthAppPerformanceByOSVersion(entity):
    props = {
        'activeDeviceCount': Edm.Int32,
        'appCrashCount': Edm.Int32,
        'appDisplayName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appUsageDuration': Edm.Int32,
        'meanTimeToFailureInMinutes': Edm.Int32,
        'osBuildNumber': Edm.String,
        'osVersion': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthDeviceModelPerformance(entity):
    props = {
        'activeDeviceCount': Edm.Int32,
        'deviceManufacturer': Edm.String,
        'deviceModel': Edm.String,
        'healthStatus': userExperienceAnalyticsHealthState,
        'meanTimeToFailureInMinutes': Edm.Int32,
        'modelAppHealthScore': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthDevicePerformance(entity):
    props = {
        'appCrashCount': Edm.Int32,
        'appHangCount': Edm.Int32,
        'crashedAppCount': Edm.Int32,
        'deviceAppHealthScore': Edm.Double,
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'deviceManufacturer': Edm.String,
        'deviceModel': Edm.String,
        'healthStatus': userExperienceAnalyticsHealthState,
        'meanTimeToFailureInMinutes': Edm.Int32,
        'processedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthDevicePerformanceDetails(entity):
    props = {
        'appDisplayName': Edm.String,
        'appPublisher': Edm.String,
        'appVersion': Edm.String,
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'eventDateTime': Edm.DateTimeOffset,
        'eventType': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsAppHealthOSVersionPerformance(entity):
    props = {
        'activeDeviceCount': Edm.Int32,
        'meanTimeToFailureInMinutes': Edm.Int32,
        'osBuildNumber': Edm.String,
        'osVersion': Edm.String,
        'osVersionAppHealthScore': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsCategory(entity):
    props = {
        'insights': Collection,
    }
    rels = [
        'metricValues',
    ]


class userExperienceAnalyticsBaseline(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'isBuiltIn': Edm.Boolean,
    }
    rels = [
        'appHealthMetrics',
        'batteryHealthMetrics',
        'bestPracticesMetrics',
        'deviceBootPerformanceMetrics',
        'rebootAnalyticsMetrics',
        'resourcePerformanceMetrics',
        'workFromAnywhereMetrics',
    ]


class userExperienceAnalyticsBatteryHealthAppImpact(entity):
    props = {
        'activeDevices': Edm.Int32,
        'appDisplayName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'batteryUsagePercentage': Edm.Double,
        'isForegroundApp': Edm.Boolean,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthCapacityDetails(entity):
    props = {
        'activeDevices': Edm.Int32,
        'batteryCapacityFair': Edm.Int32,
        'batteryCapacityGood': Edm.Int32,
        'batteryCapacityPoor': Edm.Int32,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthDeviceAppImpact(entity):
    props = {
        'appDisplayName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'batteryUsagePercentage': Edm.Double,
        'deviceId': Edm.String,
        'isForegroundApp': Edm.Boolean,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthDevicePerformance(entity):
    props = {
        'batteryAgeInDays': Edm.Int32,
        'deviceBatteriesDetails': Collection,
        'deviceBatteryCount': Edm.Int32,
        'deviceBatteryHealthScore': Edm.Int32,
        'deviceBatteryTags': Collection,
        'deviceId': Edm.String,
        'deviceManufacturerName': Edm.String,
        'deviceModelName': Edm.String,
        'deviceName': Edm.String,
        'estimatedRuntimeInMinutes': Edm.Int32,
        'fullBatteryDrainCount': Edm.Int32,
        'healthStatus': userExperienceAnalyticsHealthState,
        'manufacturer': Edm.String,
        'maxCapacityPercentage': Edm.Int32,
        'model': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthDeviceRuntimeHistory(entity):
    props = {
        'deviceId': Edm.String,
        'estimatedRuntimeInMinutes': Edm.Int32,
        'runtimeDateTime': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthModelPerformance(entity):
    props = {
        'activeDevices': Edm.Int32,
        'averageBatteryAgeInDays': Edm.Int32,
        'averageEstimatedRuntimeInMinutes': Edm.Int32,
        'averageMaxCapacityPercentage': Edm.Int32,
        'deviceManufacturerName': Edm.String,
        'deviceModelName': Edm.String,
        'manufacturer': Edm.String,
        'meanFullBatteryDrainCount': Edm.Int32,
        'medianEstimatedRuntimeInMinutes': Edm.Int32,
        'medianFullBatteryDrainCount': Edm.Int32,
        'medianMaxCapacityPercentage': Edm.Int32,
        'model': Edm.String,
        'modelBatteryHealthScore': Edm.Int32,
        'modelHealthStatus': userExperienceAnalyticsHealthState,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthOsPerformance(entity):
    props = {
        'activeDevices': Edm.Int32,
        'averageBatteryAgeInDays': Edm.Int32,
        'averageEstimatedRuntimeInMinutes': Edm.Int32,
        'averageMaxCapacityPercentage': Edm.Int32,
        'meanFullBatteryDrainCount': Edm.Int32,
        'medianEstimatedRuntimeInMinutes': Edm.Int32,
        'medianFullBatteryDrainCount': Edm.Int32,
        'medianMaxCapacityPercentage': Edm.Int32,
        'osBatteryHealthScore': Edm.Int32,
        'osBuildNumber': Edm.String,
        'osHealthStatus': userExperienceAnalyticsHealthState,
        'osVersion': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsBatteryHealthRuntimeDetails(entity):
    props = {
        'activeDevices': Edm.Int32,
        'batteryRuntimeFair': Edm.Int32,
        'batteryRuntimeGood': Edm.Int32,
        'batteryRuntimePoor': Edm.Int32,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class userExperienceAnalyticsMetricHistory(entity):
    props = {
        'deviceId': Edm.String,
        'metricDateTime': Edm.DateTimeOffset,
        'metricType': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsDevicePerformance(entity):
    props = {
        'averageBlueScreens': Edm.Double,
        'averageRestarts': Edm.Double,
        'blueScreenCount': Edm.Int32,
        'bootScore': Edm.Int32,
        'coreBootTimeInMs': Edm.Int32,
        'coreLoginTimeInMs': Edm.Int32,
        'deviceCount': Edm.Int64,
        'deviceName': Edm.String,
        'diskType': diskType,
        'groupPolicyBootTimeInMs': Edm.Int32,
        'groupPolicyLoginTimeInMs': Edm.Int32,
        'healthStatus': userExperienceAnalyticsHealthState,
        'loginScore': Edm.Int32,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'modelStartupPerformanceScore': Edm.Double,
        'operatingSystemVersion': Edm.String,
        'responsiveDesktopTimeInMs': Edm.Int32,
        'restartCount': Edm.Int32,
        'startupPerformanceScore': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceScope(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'deviceScopeName': Edm.String,
        'enabled': Edm.Boolean,
        'isBuiltIn': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'operator': deviceScopeOperator,
        'ownerId': Edm.String,
        'parameter': deviceScopeParameter,
        'status': deviceScopeStatus,
        'value': Edm.String,
        'valueObjectId': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceScores(entity):
    props = {
        'appReliabilityScore': Edm.Double,
        'batteryHealthScore': Edm.Double,
        'deviceName': Edm.String,
        'endpointAnalyticsScore': Edm.Double,
        'healthStatus': userExperienceAnalyticsHealthState,
        'manufacturer': Edm.String,
        'meanResourceSpikeTimeScore': Edm.Double,
        'model': Edm.String,
        'startupPerformanceScore': Edm.Double,
        'workFromAnywhereScore': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceStartupHistory(entity):
    props = {
        'coreBootTimeInMs': Edm.Int32,
        'coreLoginTimeInMs': Edm.Int32,
        'deviceId': Edm.String,
        'featureUpdateBootTimeInMs': Edm.Int32,
        'groupPolicyBootTimeInMs': Edm.Int32,
        'groupPolicyLoginTimeInMs': Edm.Int32,
        'isFeatureUpdate': Edm.Boolean,
        'isFirstLogin': Edm.Boolean,
        'operatingSystemVersion': Edm.String,
        'responsiveDesktopTimeInMs': Edm.Int32,
        'restartCategory': userExperienceAnalyticsOperatingSystemRestartCategory,
        'restartFaultBucket': Edm.String,
        'restartStopCode': Edm.String,
        'startTime': Edm.DateTimeOffset,
        'totalBootTimeInMs': Edm.Int32,
        'totalLoginTimeInMs': Edm.Int32,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceStartupProcess(entity):
    props = {
        'managedDeviceId': Edm.String,
        'processName': Edm.String,
        'productName': Edm.String,
        'publisher': Edm.String,
        'startupImpactInMs': Edm.Int32,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceStartupProcessPerformance(entity):
    props = {
        'deviceCount': Edm.Int64,
        'medianImpactInMs': Edm.Int64,
        'processName': Edm.String,
        'productName': Edm.String,
        'publisher': Edm.String,
        'totalImpactInMs': Edm.Int64,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceWithoutCloudIdentity(entity):
    props = {
        'azureAdDeviceId': Edm.String,
        'deviceName': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsDeviceTimelineEvent(entity):
    props = {
        'deviceId': Edm.String,
        'eventDateTime': Edm.DateTimeOffset,
        'eventDetails': Edm.String,
        'eventLevel': deviceEventLevel,
        'eventName': Edm.String,
        'eventSource': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsImpactingProcess(entity):
    props = {
        'category': Edm.String,
        'description': Edm.String,
        'deviceId': Edm.String,
        'impactValue': Edm.Double,
        'processName': Edm.String,
        'publisher': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsModelScores(entity):
    props = {
        'appReliabilityScore': Edm.Double,
        'batteryHealthScore': Edm.Double,
        'endpointAnalyticsScore': Edm.Double,
        'healthStatus': userExperienceAnalyticsHealthState,
        'manufacturer': Edm.String,
        'meanResourceSpikeTimeScore': Edm.Double,
        'model': Edm.String,
        'modelDeviceCount': Edm.Int64,
        'startupPerformanceScore': Edm.Double,
        'workFromAnywhereScore': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsNotAutopilotReadyDevice(entity):
    props = {
        'autoPilotProfileAssigned': Edm.Boolean,
        'autoPilotRegistered': Edm.Boolean,
        'azureAdJoinType': Edm.String,
        'azureAdRegistered': Edm.Boolean,
        'deviceName': Edm.String,
        'managedBy': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'serialNumber': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsOverview(entity):
    props = {
        'insights': Collection,
    }
    rels = [

    ]


class userExperienceAnalyticsRemoteConnection(entity):
    props = {
        'cloudPcFailurePercentage': Edm.Double,
        'cloudPcRoundTripTime': Edm.Double,
        'cloudPcSignInTime': Edm.Double,
        'coreBootTime': Edm.Double,
        'coreSignInTime': Edm.Double,
        'deviceCount': Edm.Int32,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'remoteSignInTime': Edm.Double,
        'userPrincipalName': Edm.String,
        'virtualNetwork': Edm.String,
    }
    rels = [

    ]


class userExperienceAnalyticsResourcePerformance(entity):
    props = {
        'averageSpikeTimeScore': Edm.Int32,
        'cpuClockSpeedInMHz': Edm.Double,
        'cpuDisplayName': Edm.String,
        'cpuSpikeTimePercentage': Edm.Double,
        'cpuSpikeTimePercentageThreshold': Edm.Double,
        'cpuSpikeTimeScore': Edm.Int32,
        'deviceCount': Edm.Int64,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'deviceResourcePerformanceScore': Edm.Int32,
        'diskType': diskType,
        'healthStatus': userExperienceAnalyticsHealthState,
        'machineType': userExperienceAnalyticsMachineType,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'ramSpikeTimePercentage': Edm.Double,
        'ramSpikeTimePercentageThreshold': Edm.Double,
        'ramSpikeTimeScore': Edm.Int32,
        'totalProcessorCoreCount': Edm.Int32,
        'totalRamInMB': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsScoreHistory(entity):
    props = {
        'startupDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class userExperienceAnalyticsWorkFromAnywhereHardwareReadinessMetric(entity):
    props = {
        'osCheckFailedPercentage': Edm.Double,
        'processor64BitCheckFailedPercentage': Edm.Double,
        'processorCoreCountCheckFailedPercentage': Edm.Double,
        'processorFamilyCheckFailedPercentage': Edm.Double,
        'processorSpeedCheckFailedPercentage': Edm.Double,
        'ramCheckFailedPercentage': Edm.Double,
        'secureBootCheckFailedPercentage': Edm.Double,
        'storageCheckFailedPercentage': Edm.Double,
        'totalDeviceCount': Edm.Int32,
        'tpmCheckFailedPercentage': Edm.Double,
        'upgradeEligibleDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class userExperienceAnalyticsWorkFromAnywhereMetric(entity):
    props = {

    }
    rels = [
        'metricDevices',
    ]


class userExperienceAnalyticsWorkFromAnywhereModelPerformance(entity):
    props = {
        'cloudIdentityScore': Edm.Double,
        'cloudManagementScore': Edm.Double,
        'cloudProvisioningScore': Edm.Double,
        'healthStatus': userExperienceAnalyticsHealthState,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'modelDeviceCount': Edm.Int32,
        'windowsScore': Edm.Double,
        'workFromAnywhereScore': Edm.Double,
    }
    rels = [

    ]


class windowsMalwareInformation(entity):
    props = {
        'additionalInformationUrl': Edm.String,
        'category': windowsMalwareCategory,
        'displayName': Edm.String,
        'lastDetectionDateTime': Edm.DateTimeOffset,
        'severity': windowsMalwareSeverity,
    }
    rels = [
        'deviceMalwareStates',
    ]


class deviceManagementDerivedCredentialSettings(entity):
    props = {
        'displayName': Edm.String,
        'helpUrl': Edm.String,
        'issuer': deviceManagementDerivedCredentialIssuer,
        'notificationType': deviceManagementDerivedCredentialNotificationType,
        'renewalThresholdPercentage': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementResourceAccessProfileBase(entity):
    props = {
        'creationDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
    ]


class appleUserInitiatedEnrollmentProfile(entity):
    props = {
        'availableEnrollmentTypeOptions': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'defaultEnrollmentType': appleUserInitiatedEnrollmentType,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'platform': devicePlatformType,
        'priority': Edm.Int32,
    }
    rels = [
        'assignments',
    ]


class depOnboardingSetting(entity):
    props = {
        'appleIdentifier': Edm.String,
        'dataSharingConsentGranted': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastSuccessfulSyncDateTime': Edm.DateTimeOffset,
        'lastSyncErrorCode': Edm.Int32,
        'lastSyncTriggeredDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'shareTokenWithSchoolDataSyncService': Edm.Boolean,
        'syncedDeviceCount': Edm.Int32,
        'tokenExpirationDateTime': Edm.DateTimeOffset,
        'tokenName': Edm.String,
        'tokenType': depTokenType,
    }
    rels = [
        'defaultIosEnrollmentProfile',
        'defaultMacOsEnrollmentProfile',
        'defaultTvOSEnrollmentProfile',
        'defaultVisionOSEnrollmentProfile',
        'enrollmentProfiles',
        'importedAppleDeviceIdentities',
    ]


class importedDeviceIdentity(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'enrollmentState': enrollmentState,
        'importedDeviceIdentifier': Edm.String,
        'importedDeviceIdentityType': importedDeviceIdentityType,
        'lastContactedDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'platform': platform,
    }
    rels = [

    ]


class importedWindowsAutopilotDeviceIdentity(entity):
    props = {
        'assignedUserPrincipalName': Edm.String,
        'groupTag': Edm.String,
        'hardwareIdentifier': Edm.Binary,
        'importId': Edm.String,
        'productKey': Edm.String,
        'serialNumber': Edm.String,
        'state': importedWindowsAutopilotDeviceIdentityState,
    }
    rels = [

    ]


class windowsAutopilotDeploymentProfile(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'deviceNameTemplate': Edm.String,
        'deviceType': windowsAutopilotDeviceType,
        'displayName': Edm.String,
        'enableWhiteGlove': Edm.Boolean,
        'enrollmentStatusScreenSettings': windowsEnrollmentStatusScreenSettings,
        'extractHardwareHash': Edm.Boolean,
        'hardwareHashExtractionEnabled': Edm.Boolean,
        'language': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'locale': Edm.String,
        'managementServiceAppId': Edm.String,
        'outOfBoxExperienceSetting': outOfBoxExperienceSetting,
        'outOfBoxExperienceSettings': outOfBoxExperienceSettings,
        'preprovisioningAllowed': Edm.Boolean,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'assignedDevices',
        'assignments',
    ]


class windowsAutopilotDeviceIdentity(entity):
    props = {
        'addressableUserName': Edm.String,
        'azureActiveDirectoryDeviceId': Edm.String,
        'azureAdDeviceId': Edm.String,
        'deploymentProfileAssignedDateTime': Edm.DateTimeOffset,
        'deploymentProfileAssignmentDetailedStatus': windowsAutopilotProfileAssignmentDetailedStatus,
        'deploymentProfileAssignmentStatus': windowsAutopilotProfileAssignmentStatus,
        'deviceAccountPassword': Edm.String,
        'deviceAccountUpn': Edm.String,
        'deviceFriendlyName': Edm.String,
        'displayName': Edm.String,
        'enrollmentState': enrollmentState,
        'groupTag': Edm.String,
        'lastContactedDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'productKey': Edm.String,
        'purchaseOrderIdentifier': Edm.String,
        'remediationState': windowsAutopilotDeviceRemediationState,
        'remediationStateLastModifiedDateTime': Edm.DateTimeOffset,
        'resourceName': Edm.String,
        'serialNumber': Edm.String,
        'skuNumber': Edm.String,
        'systemFamily': Edm.String,
        'userlessEnrollmentStatus': windowsAutopilotUserlessEnrollmentStatus,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'deploymentProfile',
        'intendedDeploymentProfile',
    ]


class windowsAutopilotSettings(entity):
    props = {
        'lastManualSyncTriggerDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'syncStatus': windowsAutopilotSyncStatus,
    }
    rels = [

    ]


class privilegeManagementElevationRequest(entity):
    props = {
        'applicationDetail': elevationRequestApplicationDetail,
        'deviceName': Edm.String,
        'requestCreatedDateTime': Edm.DateTimeOffset,
        'requestedByUserId': Edm.String,
        'requestedByUserPrincipalName': Edm.String,
        'requestedOnDeviceId': Edm.String,
        'requestExpiryDateTime': Edm.DateTimeOffset,
        'requestJustification': Edm.String,
        'requestLastModifiedDateTime': Edm.DateTimeOffset,
        'reviewCompletedByUserId': Edm.String,
        'reviewCompletedByUserPrincipalName': Edm.String,
        'reviewCompletedDateTime': Edm.DateTimeOffset,
        'reviewerJustification': Edm.String,
        'status': elevationRequestState,
    }
    rels = [

    ]


class groupPolicyMigrationReport(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'groupPolicyCreatedDateTime': Edm.DateTimeOffset,
        'groupPolicyLastModifiedDateTime': Edm.DateTimeOffset,
        'groupPolicyObjectId': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'migrationReadiness': groupPolicyMigrationReadiness,
        'ouDistinguishedName': Edm.String,
        'roleScopeTagIds': Collection,
        'supportedSettingsCount': Edm.Int32,
        'supportedSettingsPercent': Edm.Int32,
        'targetedInActiveDirectory': Edm.Boolean,
        'totalSettingsCount': Edm.Int32,
    }
    rels = [
        'groupPolicySettingMappings',
        'unsupportedGroupPolicyExtensions',
    ]


class groupPolicyObjectFile(entity):
    props = {
        'content': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'groupPolicyObjectId': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'ouDistinguishedName': Edm.String,
        'roleScopeTagIds': Collection,
    }
    rels = [

    ]


class groupPolicyCategory(entity):
    props = {
        'displayName': Edm.String,
        'ingestionSource': ingestionSource,
        'isRoot': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'children',
        'definitionFile',
        'definitions',
        'parent',
    ]


class groupPolicyConfiguration(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'policyConfigurationIngestionType': groupPolicyConfigurationIngestionType,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'assignments',
        'definitionValues',
    ]


class groupPolicyDefinitionFile(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'fileName': Edm.String,
        'languageCodes': Collection,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'policyType': groupPolicyType,
        'revision': Edm.String,
        'targetNamespace': Edm.String,
        'targetPrefix': Edm.String,
    }
    rels = [
        'definitions',
    ]


class groupPolicyDefinition(entity):
    props = {
        'categoryPath': Edm.String,
        'classType': groupPolicyDefinitionClassType,
        'displayName': Edm.String,
        'explainText': Edm.String,
        'groupPolicyCategoryId': Edm.Guid,
        'hasRelatedDefinitions': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'minDeviceCspVersion': Edm.String,
        'minUserCspVersion': Edm.String,
        'policyType': groupPolicyType,
        'supportedOn': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'category',
        'definitionFile',
        'nextVersionDefinition',
        'presentations',
        'previousVersionDefinition',
    ]


class serviceNowConnection(entity):
    props = {
        'authenticationMethod': serviceNowAuthenticationMethod,
        'createdDateTime': Edm.DateTimeOffset,
        'incidentApiUrl': Edm.String,
        'instanceUrl': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastQueriedDateTime': Edm.DateTimeOffset,
        'serviceNowConnectionStatus': serviceNowConnectionStatus,
    }
    rels = [

    ]


class microsoftTunnelConfiguration(entity):
    props = {
        'advancedSettings': Collection,
        'defaultDomainSuffix': Edm.String,
        'description': Edm.String,
        'disableUdpConnections': Edm.Boolean,
        'displayName': Edm.String,
        'dnsServers': Collection,
        'ipv6Network': Edm.String,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'listenPort': Edm.Int32,
        'network': Edm.String,
        'roleScopeTagIds': Collection,
        'routeExcludes': Collection,
        'routeIncludes': Collection,
        'routesExclude': Collection,
        'routesInclude': Collection,
        'splitDNS': Collection,
    }
    rels = [

    ]


class microsoftTunnelHealthThreshold(entity):
    props = {
        'defaultHealthyThreshold': Edm.Int64,
        'defaultUnhealthyThreshold': Edm.Int64,
        'healthyThreshold': Edm.Int64,
        'unhealthyThreshold': Edm.Int64,
    }
    rels = [

    ]


class microsoftTunnelServerLogCollectionResponse(entity):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'expiryDateTime': Edm.DateTimeOffset,
        'requestDateTime': Edm.DateTimeOffset,
        'serverId': Edm.String,
        'sizeInBytes': Edm.Int64,
        'startDateTime': Edm.DateTimeOffset,
        'status': microsoftTunnelLogCollectionStatus,
    }
    rels = [

    ]


class microsoftTunnelSite(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'internalNetworkProbeUrl': Edm.String,
        'publicAddress': Edm.String,
        'roleScopeTagIds': Collection,
        'upgradeAutomatically': Edm.Boolean,
        'upgradeAvailable': Edm.Boolean,
        'upgradeWindowEndTime': Edm.TimeOfDay,
        'upgradeWindowStartTime': Edm.TimeOfDay,
        'upgradeWindowUtcOffsetInMinutes': Edm.Int32,
    }
    rels = [
        'microsoftTunnelConfiguration',
        'microsoftTunnelServers',
    ]


class notificationMessageTemplate(entity):
    props = {
        'brandingOptions': notificationTemplateBrandingOptions,
        'defaultLocale': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'localizedNotificationMessages',
    ]


class deviceManagementDomainJoinConnector(entity):
    props = {
        'displayName': Edm.String,
        'lastConnectionDateTime': Edm.DateTimeOffset,
        'state': deviceManagementDomainJoinConnectorState,
        'version': Edm.String,
    }
    rels = [

    ]


class managedDeviceWindowsOperatingSystemImage(entity):
    props = {
        'availableUpdates': Collection,
        'supportedArchitectures': Collection,
        'supportedEditions': Collection,
    }
    rels = [

    ]


class configManagerCollection(entity):
    props = {
        'collectionIdentifier': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'hierarchyIdentifier': Edm.String,
        'hierarchyName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class operationApprovalPolicy(entity):
    props = {
        'approverGroupIds': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'policyPlatform': operationApprovalPolicyPlatform,
        'policySet': operationApprovalPolicySet,
        'policyType': operationApprovalPolicyType,
    }
    rels = [

    ]


class operationApprovalRequest(entity):
    props = {
        'approvalJustification': Edm.String,
        'approver': identitySet,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'requestDateTime': Edm.DateTimeOffset,
        'requestJustification': Edm.String,
        'requestor': identitySet,
        'requiredOperationApprovalPolicyTypes': Collection,
        'status': operationApprovalRequestStatus,
    }
    rels = [

    ]


class resourceOperation(entity):
    props = {
        'actionName': Edm.String,
        'description': Edm.String,
        'enabledForScopeValidation': Edm.Boolean,
        'resource': Edm.String,
        'resourceName': Edm.String,
    }
    rels = [

    ]


class roleAssignment(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'resourceScopes': Collection,
        'scopeMembers': Collection,
        'scopeType': roleAssignmentScopeType,
    }
    rels = [
        'roleDefinition',
    ]


class roleDefinition(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isBuiltIn': Edm.Boolean,
        'isBuiltInRoleDefinition': Edm.Boolean,
        'permissions': Collection,
        'rolePermissions': Collection,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'roleAssignments',
    ]


class roleScopeTag(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isBuiltIn': Edm.Boolean,
        'permissions': Collection,
    }
    rels = [
        'assignments',
    ]


class remoteAssistancePartner(entity):
    props = {
        'displayName': Edm.String,
        'lastConnectionDateTime': Edm.DateTimeOffset,
        'onboardingRequestExpiryDateTime': Edm.DateTimeOffset,
        'onboardingStatus': remoteAssistanceOnboardingStatus,
        'onboardingUrl': Edm.String,
    }
    rels = [

    ]


class remoteAssistanceSettings(entity):
    props = {
        'allowSessionsToUnenrolledDevices': Edm.Boolean,
        'blockChat': Edm.Boolean,
        'remoteAssistanceState': remoteAssistanceState,
    }
    rels = [

    ]


class deviceManagementReports(entity):
    props = {

    }
    rels = [
        'cachedReportConfigurations',
        'exportJobs',
    ]


class embeddedSIMActivationCodePool(entity):
    props = {
        'activationCodeCount': Edm.Int32,
        'activationCodes': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'assignments',
        'deviceStates',
    ]


class telecomExpenseManagementPartner(entity):
    props = {
        'appAuthorized': Edm.Boolean,
        'displayName': Edm.String,
        'enabled': Edm.Boolean,
        'lastConnectionDateTime': Edm.DateTimeOffset,
        'url': Edm.String,
    }
    rels = [

    ]


class deviceManagementAutopilotEvent(entity):
    props = {
        'accountSetupDuration': Edm.Duration,
        'accountSetupStatus': windowsAutopilotDeploymentState,
        'deploymentDuration': Edm.Duration,
        'deploymentEndDateTime': Edm.DateTimeOffset,
        'deploymentStartDateTime': Edm.DateTimeOffset,
        'deploymentState': windowsAutopilotDeploymentState,
        'deploymentTotalDuration': Edm.Duration,
        'deviceId': Edm.String,
        'deviceRegisteredDateTime': Edm.DateTimeOffset,
        'deviceSerialNumber': Edm.String,
        'deviceSetupDuration': Edm.Duration,
        'deviceSetupStatus': windowsAutopilotDeploymentState,
        'enrollmentFailureDetails': Edm.String,
        'enrollmentStartDateTime': Edm.DateTimeOffset,
        'enrollmentState': enrollmentState,
        'enrollmentType': windowsAutopilotEnrollmentType,
        'eventDateTime': Edm.DateTimeOffset,
        'managedDeviceName': Edm.String,
        'osVersion': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'windows10EnrollmentCompletionPageConfigurationDisplayName': Edm.String,
        'windows10EnrollmentCompletionPageConfigurationId': Edm.String,
        'windowsAutopilotDeploymentProfileDisplayName': Edm.String,
    }
    rels = [

    ]


class windowsDriverUpdateProfile(entity):
    props = {
        'approvalType': driverUpdateProfileApprovalType,
        'createdDateTime': Edm.DateTimeOffset,
        'deploymentDeferralInDays': Edm.Int32,
        'description': Edm.String,
        'deviceReporting': Edm.Int32,
        'displayName': Edm.String,
        'inventorySyncStatus': windowsDriverUpdateProfileInventorySyncStatus,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'newUpdates': Edm.Int32,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'assignments',
        'driverInventories',
    ]


class windowsFeatureUpdateProfile(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'deployableContentDisplayName': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'endOfSupportDate': Edm.DateTimeOffset,
        'featureUpdateVersion': Edm.String,
        'installFeatureUpdatesOptional': Edm.Boolean,
        'installLatestWindows10OnWindows11IneligibleDevice': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'rolloutSettings': windowsUpdateRolloutSettings,
    }
    rels = [
        'assignments',
    ]


class windowsQualityUpdatePolicy(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'hotpatchEnabled': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'assignments',
    ]


class windowsQualityUpdateProfile(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'deployableContentDisplayName': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'expeditedUpdateSettings': expeditedWindowsQualityUpdateSettings,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'releaseDateDisplayName': Edm.String,
        'roleScopeTagIds': Collection,
    }
    rels = [
        'assignments',
    ]


class windowsUpdateCatalogItem(entity):
    props = {
        'displayName': Edm.String,
        'endOfSupportDate': Edm.DateTimeOffset,
        'releaseDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class intuneBrandingProfile(entity):
    props = {
        'companyPortalBlockedActions': Collection,
        'contactITEmailAddress': Edm.String,
        'contactITName': Edm.String,
        'contactITNotes': Edm.String,
        'contactITPhoneNumber': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'customCanSeePrivacyMessage': Edm.String,
        'customCantSeePrivacyMessage': Edm.String,
        'customPrivacyMessage': Edm.String,
        'disableClientTelemetry': Edm.Boolean,
        'disableDeviceCategorySelection': Edm.Boolean,
        'displayName': Edm.String,
        'enrollmentAvailability': enrollmentAvailabilityOptions,
        'isDefaultProfile': Edm.Boolean,
        'isFactoryResetDisabled': Edm.Boolean,
        'isRemoveDeviceDisabled': Edm.Boolean,
        'landingPageCustomizedImage': mimeContent,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lightBackgroundLogo': mimeContent,
        'onlineSupportSiteName': Edm.String,
        'onlineSupportSiteUrl': Edm.String,
        'privacyUrl': Edm.String,
        'profileDescription': Edm.String,
        'profileName': Edm.String,
        'roleScopeTagIds': Collection,
        'sendDeviceOwnershipChangePushNotification': Edm.Boolean,
        'showAzureADEnterpriseApps': Edm.Boolean,
        'showConfigurationManagerApps': Edm.Boolean,
        'showDisplayNameNextToLogo': Edm.Boolean,
        'showLogo': Edm.Boolean,
        'showOfficeWebApps': Edm.Boolean,
        'themeColor': rgbColor,
        'themeColorLogo': mimeContent,
    }
    rels = [
        'assignments',
    ]


class windowsInformationProtectionAppLearningSummary(entity):
    props = {
        'applicationName': Edm.String,
        'applicationType': applicationType,
        'deviceCount': Edm.Int32,
    }
    rels = [

    ]


class windowsInformationProtectionNetworkLearningSummary(entity):
    props = {
        'deviceCount': Edm.Int32,
        'url': Edm.String,
    }
    rels = [

    ]


class certificateConnectorDetails(entity):
    props = {
        'connectorName': Edm.String,
        'connectorVersion': Edm.String,
        'enrollmentDateTime': Edm.DateTimeOffset,
        'lastCheckinDateTime': Edm.DateTimeOffset,
        'machineName': Edm.String,
    }
    rels = [

    ]


class userPFXCertificate(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'encryptedPfxBlob': Edm.Binary,
        'encryptedPfxPassword': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'intendedPurpose': userPfxIntendedPurpose,
        'keyName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'paddingScheme': userPfxPaddingScheme,
        'providerName': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'thumbprint': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class assignmentFilterEvaluationStatusDetails(entity):
    props = {
        'payloadId': Edm.String,
    }
    rels = [

    ]


class deviceCompliancePolicyState(entity):
    props = {
        'displayName': Edm.String,
        'platformType': policyPlatformType,
        'settingCount': Edm.Int32,
        'settingStates': Collection,
        'state': complianceStatus,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'version': Edm.Int32,
    }
    rels = [

    ]


class deviceConfigurationState(entity):
    props = {
        'displayName': Edm.String,
        'platformType': policyPlatformType,
        'settingCount': Edm.Int32,
        'settingStates': Collection,
        'state': complianceStatus,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'version': Edm.Int32,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationState(entity):
    props = {
        'displayName': Edm.String,
        'platformType': policyPlatformType,
        'settingCount': Edm.Int32,
        'settingStates': Collection,
        'state': complianceStatus,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'version': Edm.Int32,
    }
    rels = [

    ]


class securityBaselineState(entity):
    props = {
        'displayName': Edm.String,
        'securityBaselineTemplateId': Edm.String,
        'state': securityBaselineComplianceState,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'settingStates',
    ]


class deviceHealthScriptPolicyState(object):
    props = {
        'assignmentFilterIds': Collection,
        'detectionState': runState,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'expectedStateUpdateDateTime': Edm.DateTimeOffset,
        'id': Edm.String,
        'lastStateUpdateDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'osVersion': Edm.String,
        'policyId': Edm.String,
        'policyName': Edm.String,
        'postRemediationDetectionScriptError': Edm.String,
        'postRemediationDetectionScriptOutput': Edm.String,
        'preRemediationDetectionScriptError': Edm.String,
        'preRemediationDetectionScriptOutput': Edm.String,
        'remediationScriptError': Edm.String,
        'remediationState': remediationState,
        'userName': Edm.String,
    }
    rels = [

    ]


class deviceLogCollectionResponse(entity):
    props = {
        'enrolledByUser': Edm.String,
        'errorCode': Edm.Int64,
        'expirationDateTimeUTC': Edm.DateTimeOffset,
        'initiatedByUserPrincipalName': Edm.String,
        'managedDeviceId': Edm.Guid,
        'receivedDateTimeUTC': Edm.DateTimeOffset,
        'requestedDateTimeUTC': Edm.DateTimeOffset,
        'size': Edm.Double,
        'sizeInKB': Edm.Double,
        'status': appLogUploadState,
    }
    rels = [

    ]


class windowsProtectionState(entity):
    props = {
        'antiMalwareVersion': Edm.String,
        'deviceState': windowsDeviceHealthState,
        'engineVersion': Edm.String,
        'fullScanOverdue': Edm.Boolean,
        'fullScanRequired': Edm.Boolean,
        'isVirtualMachine': Edm.Boolean,
        'lastFullScanDateTime': Edm.DateTimeOffset,
        'lastFullScanSignatureVersion': Edm.String,
        'lastQuickScanDateTime': Edm.DateTimeOffset,
        'lastQuickScanSignatureVersion': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'malwareProtectionEnabled': Edm.Boolean,
        'networkInspectionSystemEnabled': Edm.Boolean,
        'productStatus': windowsDefenderProductStatus,
        'quickScanOverdue': Edm.Boolean,
        'realTimeProtectionEnabled': Edm.Boolean,
        'rebootRequired': Edm.Boolean,
        'signatureUpdateOverdue': Edm.Boolean,
        'signatureVersion': Edm.String,
        'tamperProtectionEnabled': Edm.Boolean,
    }
    rels = [
        'detectedMalwareState',
    ]


class rbacApplicationMultiple(entity):
    props = {

    }
    rels = [
        'resourceNamespaces',
        'roleAssignments',
        'roleDefinitions',
    ]


class unifiedRbacResourceNamespace(entity):
    props = {
        'name': Edm.String,
    }
    rels = [
        'resourceActions',
    ]


class unifiedRoleAssignmentMultiple(entity):
    props = {
        'appScopeIds': Collection,
        'condition': Edm.String,
        'description': Edm.String,
        'directoryScopeIds': Collection,
        'displayName': Edm.String,
        'principalIds': Collection,
        'roleDefinitionId': Edm.String,
    }
    rels = [
        'appScopes',
        'directoryScopes',
        'principals',
        'roleDefinition',
    ]


class unifiedRoleDefinition(entity):
    props = {
        'allowedPrincipalTypes': allowedRolePrincipalTypes,
        'description': Edm.String,
        'displayName': Edm.String,
        'isBuiltIn': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'isPrivileged': Edm.Boolean,
        'resourceScopes': Collection,
        'rolePermissions': Collection,
        'templateId': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'inheritsPermissionsFrom',
    ]


class roleManagement(object):
    props = {

    }
    rels = [
        'directory',
        'cloudPC',
        'enterpriseApps',
        'exchange',
        'entitlementManagement',
        'deviceManagement',
        'defender',
    ]


class rbacApplication(entity):
    props = {

    }
    rels = [
        'resourceNamespaces',
        'roleAssignments',
        'roleDefinitions',
        'transitiveRoleAssignments',
        'roleAssignmentApprovals',
        'roleAssignmentScheduleInstances',
        'roleAssignmentScheduleRequests',
        'roleAssignmentSchedules',
        'roleEligibilityScheduleInstances',
        'roleEligibilityScheduleRequests',
        'roleEligibilitySchedules',
    ]


class unifiedRbacApplication(entity):
    props = {

    }
    rels = [
        'customAppScopes',
        'resourceNamespaces',
        'roleAssignments',
        'roleDefinitions',
        'transitiveRoleAssignments',
    ]


class unifiedRbacResourceAction(entity):
    props = {
        'actionVerb': Edm.String,
        'authenticationContextId': Edm.String,
        'description': Edm.String,
        'isAuthenticationContextSettable': Edm.Boolean,
        'isPrivileged': Edm.Boolean,
        'name': Edm.String,
        'resourceScopeId': Edm.String,
    }
    rels = [
        'authenticationContext',
        'resourceScope',
    ]


class unifiedRbacResourceScope(entity):
    props = {
        'displayName': Edm.String,
        'scope': Edm.String,
        'type': Edm.String,
    }
    rels = [

    ]


class authoredNote(entity):
    props = {
        'author': identity,
        'content': itemBody,
        'createdDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class privacy(object):
    props = {

    }
    rels = [
        'subjectRightsRequests',
    ]


class subjectRightsRequest(entity):
    props = {
        'assignedTo': identity,
        'closedDateTime': Edm.DateTimeOffset,
        'contentQuery': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'dataSubject': dataSubject,
        'dataSubjectType': dataSubjectType,
        'description': Edm.String,
        'displayName': Edm.String,
        'externalId': Edm.String,
        'history': Collection,
        'includeAllVersions': Edm.Boolean,
        'includeAuthoredContent': Edm.Boolean,
        'insight': subjectRightsRequestDetail,
        'internalDueDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'mailboxLocations': subjectRightsRequestMailboxLocation,
        'pauseAfterEstimate': Edm.Boolean,
        'regulations': Collection,
        'siteLocations': subjectRightsRequestSiteLocation,
        'stages': Collection,
        'status': subjectRightsRequestStatus,
        'type': subjectRightsRequestType,
    }
    rels = [
        'approvers',
        'collaborators',
        'notes',
        'team',
    ]


class security(object):
    props = {

    }
    rels = [
        'subjectRightsRequests',
        'cases',
        'dataDiscovery',
        'identities',
        'informationProtection',
        'auditLog',
        'alerts_v2',
        'incidents',
        'rules',
        'collaboration',
        'partner',
        'attackSimulation',
        'labels',
        'triggers',
        'triggerTypes',
        'threatSubmission',
        'alerts',
        'cloudAppSecurityProfiles',
        'domainSecurityProfiles',
        'fileSecurityProfiles',
        'hostSecurityProfiles',
        'ipSecurityProfiles',
        'providerTenantSettings',
        'secureScoreControlProfiles',
        'secureScores',
        'securityActions',
        'tiIndicators',
        'userSecurityProfiles',
        'threatIntelligence',
    ]


class attackSimulationRoot(entity):
    props = {

    }
    rels = [
        'endUserNotifications',
        'landingPages',
        'loginPages',
        'operations',
        'payloads',
        'simulationAutomations',
        'simulations',
        'trainingCampaigns',
        'trainings',
    ]


class alert(entity):
    props = {
        'activityGroupName': Edm.String,
        'alertDetections': Collection,
        'assignedTo': Edm.String,
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'category': Edm.String,
        'closedDateTime': Edm.DateTimeOffset,
        'cloudAppStates': Collection,
        'comments': Collection,
        'confidence': Edm.Int32,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'detectionIds': Collection,
        'eventDateTime': Edm.DateTimeOffset,
        'feedback': alertFeedback,
        'fileStates': Collection,
        'historyStates': Collection,
        'hostStates': Collection,
        'incidentIds': Collection,
        'investigationSecurityStates': Collection,
        'lastEventDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'malwareStates': Collection,
        'messageSecurityStates': Collection,
        'networkConnections': Collection,
        'processes': Collection,
        'recommendedActions': Collection,
        'registryKeyStates': Collection,
        'securityResources': Collection,
        'severity': alertSeverity,
        'sourceMaterials': Collection,
        'status': alertStatus,
        'tags': Collection,
        'title': Edm.String,
        'triggers': Collection,
        'uriClickSecurityStates': Collection,
        'userStates': Collection,
        'vendorInformation': securityVendorInformation,
        'vulnerabilityStates': Collection,
    }
    rels = [

    ]


class cloudAppSecurityProfile(entity):
    props = {
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'deploymentPackageUrl': Edm.String,
        'destinationServiceName': Edm.String,
        'isSigned': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'manifest': Edm.String,
        'name': Edm.String,
        'permissionsRequired': applicationPermissionsRequired,
        'platform': Edm.String,
        'policyName': Edm.String,
        'publisher': Edm.String,
        'riskScore': Edm.String,
        'tags': Collection,
        'type': Edm.String,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class domainSecurityProfile(entity):
    props = {
        'activityGroupNames': Collection,
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'countHits': Edm.Int32,
        'countInOrg': Edm.Int32,
        'domainCategories': Collection,
        'domainRegisteredDateTime': Edm.DateTimeOffset,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'registrant': domainRegistrant,
        'riskScore': Edm.String,
        'tags': Collection,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class fileSecurityProfile(entity):
    props = {
        'activityGroupNames': Collection,
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'certificateThumbprint': Edm.String,
        'extensions': Collection,
        'fileType': Edm.String,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'hashes': Collection,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'malwareStates': Collection,
        'names': Collection,
        'riskScore': Edm.String,
        'size': Edm.Int64,
        'tags': Collection,
        'vendorInformation': securityVendorInformation,
        'vulnerabilityStates': Collection,
    }
    rels = [

    ]


class hostSecurityProfile(entity):
    props = {
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'fqdn': Edm.String,
        'isAzureAdJoined': Edm.Boolean,
        'isAzureAdRegistered': Edm.Boolean,
        'isHybridAzureDomainJoined': Edm.Boolean,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'logonUsers': Collection,
        'netBiosName': Edm.String,
        'networkInterfaces': Collection,
        'os': Edm.String,
        'osVersion': Edm.String,
        'parentHost': Edm.String,
        'relatedHostIds': Collection,
        'riskScore': Edm.String,
        'tags': Collection,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class ipSecurityProfile(entity):
    props = {
        'activityGroupNames': Collection,
        'address': Edm.String,
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'countHits': Edm.Int32,
        'countHosts': Edm.Int32,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'ipCategories': Collection,
        'ipReferenceData': Collection,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'riskScore': Edm.String,
        'tags': Collection,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class providerTenantSetting(entity):
    props = {
        'azureTenantId': Edm.String,
        'enabled': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'provider': Edm.String,
        'vendor': Edm.String,
    }
    rels = [

    ]


class secureScoreControlProfile(entity):
    props = {
        'actionType': Edm.String,
        'actionUrl': Edm.String,
        'azureTenantId': Edm.String,
        'complianceInformation': Collection,
        'controlCategory': Edm.String,
        'controlStateUpdates': Collection,
        'deprecated': Edm.Boolean,
        'implementationCost': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'maxScore': Edm.Double,
        'rank': Edm.Int32,
        'remediation': Edm.String,
        'remediationImpact': Edm.String,
        'service': Edm.String,
        'threats': Collection,
        'tier': Edm.String,
        'title': Edm.String,
        'userImpact': Edm.String,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class secureScore(entity):
    props = {
        'activeUserCount': Edm.Int32,
        'averageComparativeScores': Collection,
        'azureTenantId': Edm.String,
        'controlScores': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'currentScore': Edm.Double,
        'enabledServices': Collection,
        'licensedUserCount': Edm.Int32,
        'maxScore': Edm.Double,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class securityAction(entity):
    props = {
        'actionReason': Edm.String,
        'appId': Edm.String,
        'azureTenantId': Edm.String,
        'clientContext': Edm.String,
        'completedDateTime': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'errorInfo': resultInfo,
        'lastActionDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'parameters': Collection,
        'states': Collection,
        'status': operationStatus,
        'user': Edm.String,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class tiIndicator(entity):
    props = {
        'action': tiAction,
        'activityGroupNames': Collection,
        'additionalInformation': Edm.String,
        'azureTenantId': Edm.String,
        'confidence': Edm.Int32,
        'description': Edm.String,
        'diamondModel': diamondModel,
        'domainName': Edm.String,
        'emailEncoding': Edm.String,
        'emailLanguage': Edm.String,
        'emailRecipient': Edm.String,
        'emailSenderAddress': Edm.String,
        'emailSenderName': Edm.String,
        'emailSourceDomain': Edm.String,
        'emailSourceIpAddress': Edm.String,
        'emailSubject': Edm.String,
        'emailXMailer': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'externalId': Edm.String,
        'fileCompileDateTime': Edm.DateTimeOffset,
        'fileCreatedDateTime': Edm.DateTimeOffset,
        'fileHashType': fileHashType,
        'fileHashValue': Edm.String,
        'fileMutexName': Edm.String,
        'fileName': Edm.String,
        'filePacker': Edm.String,
        'filePath': Edm.String,
        'fileSize': Edm.Int64,
        'fileType': Edm.String,
        'ingestedDateTime': Edm.DateTimeOffset,
        'isActive': Edm.Boolean,
        'killChain': Collection,
        'knownFalsePositives': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'malwareFamilyNames': Collection,
        'networkCidrBlock': Edm.String,
        'networkDestinationAsn': Edm.Int64,
        'networkDestinationCidrBlock': Edm.String,
        'networkDestinationIPv4': Edm.String,
        'networkDestinationIPv6': Edm.String,
        'networkDestinationPort': Edm.Int32,
        'networkIPv4': Edm.String,
        'networkIPv6': Edm.String,
        'networkPort': Edm.Int32,
        'networkProtocol': Edm.Int32,
        'networkSourceAsn': Edm.Int64,
        'networkSourceCidrBlock': Edm.String,
        'networkSourceIPv4': Edm.String,
        'networkSourceIPv6': Edm.String,
        'networkSourcePort': Edm.Int32,
        'passiveOnly': Edm.Boolean,
        'severity': Edm.Int32,
        'tags': Collection,
        'targetProduct': Edm.String,
        'threatType': Edm.String,
        'tlpLevel': tlpLevel,
        'url': Edm.String,
        'userAgent': Edm.String,
    }
    rels = [

    ]


class userSecurityProfile(entity):
    props = {
        'accounts': Collection,
        'azureSubscriptionId': Edm.String,
        'azureTenantId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'riskScore': Edm.String,
        'tags': Collection,
        'userPrincipalName': Edm.String,
        'vendorInformation': securityVendorInformation,
    }
    rels = [

    ]


class channel(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'email': Edm.String,
        'isArchived': Edm.Boolean,
        'isFavoriteByDefault': Edm.Boolean,
        'layoutType': channelLayoutType,
        'membershipType': channelMembershipType,
        'moderationSettings': channelModerationSettings,
        'summary': channelSummary,
        'tenantId': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [
        'planner',
        'allMembers',
        'filesFolder',
        'members',
        'messages',
        'sharedWithTeams',
        'tabs',
    ]


class teamsAppInstallation(entity):
    props = {
        'consentedPermissionSet': teamsAppPermissionSet,
        'scopeInfo': teamsAppInstallationScopeInfo,
    }
    rels = [
        'teamsApp',
        'teamsAppDefinition',
    ]


class conversationMember(entity):
    props = {
        'displayName': Edm.String,
        'roles': Collection,
        'visibleHistoryStartDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class teamsAsyncOperation(entity):
    props = {
        'attemptsCount': Edm.Int32,
        'createdDateTime': Edm.DateTimeOffset,
        'error': operationError,
        'lastActionDateTime': Edm.DateTimeOffset,
        'operationType': teamsAsyncOperationType,
        'status': teamsAsyncOperationStatus,
        'targetResourceId': Edm.String,
        'targetResourceLocation': Edm.String,
    }
    rels = [

    ]


class teamworkTag(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'memberCount': Edm.Int32,
        'tagType': teamworkTagType,
        'teamId': Edm.String,
    }
    rels = [
        'members',
    ]


class teamsTemplate(entity):
    props = {

    }
    rels = [

    ]


class teamTemplateDefinition(entity):
    props = {
        'audience': teamTemplateAudience,
        'categories': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'iconUrl': Edm.String,
        'languageTag': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'parentTemplateId': Edm.String,
        'publisherName': Edm.String,
        'shortDescription': Edm.String,
    }
    rels = [
        'teamDefinition',
    ]


class schedule(entity):
    props = {
        'activitiesIncludedWhenCopyingShiftsEnabled': Edm.Boolean,
        'enabled': Edm.Boolean,
        'isActivitiesIncludedWhenCopyingShiftsEnabled': Edm.Boolean,
        'isCrossLocationShiftRequestApprovalRequired': Edm.Boolean,
        'isCrossLocationShiftsEnabled': Edm.Boolean,
        'offerShiftRequestsEnabled': Edm.Boolean,
        'openShiftsEnabled': Edm.Boolean,
        'provisionStatus': operationStatus,
        'provisionStatusCode': Edm.String,
        'startDayOfWeek': dayOfWeek,
        'swapShiftsRequestsEnabled': Edm.Boolean,
        'timeClockEnabled': Edm.Boolean,
        'timeClockSettings': timeClockSettings,
        'timeOffRequestsEnabled': Edm.Boolean,
        'timeZone': Edm.String,
        'workforceIntegrationIds': Collection,
    }
    rels = [
        'dayNotes',
        'offerShiftRequests',
        'openShiftChangeRequests',
        'openShifts',
        'schedulingGroups',
        'shifts',
        'shiftsRoleDefinitions',
        'swapShiftsChangeRequests',
        'timeCards',
        'timeOffReasons',
        'timeOffRequests',
        'timesOff',
    ]


class compliance(object):
    props = {

    }
    rels = [
        'ediscovery',
    ]


class itemAnalytics(entity):
    props = {

    }
    rels = [
        'allTime',
        'itemActivityStats',
        'lastSevenDays',
    ]


class columnDefinition(entity):
    props = {
        'boolean': booleanColumn,
        'calculated': calculatedColumn,
        'choice': choiceColumn,
        'columnGroup': Edm.String,
        'contentApprovalStatus': contentApprovalStatusColumn,
        'currency': currencyColumn,
        'dateTime': dateTimeColumn,
        'defaultValue': defaultColumnValue,
        'description': Edm.String,
        'displayName': Edm.String,
        'enforceUniqueValues': Edm.Boolean,
        'geolocation': geolocationColumn,
        'hidden': Edm.Boolean,
        'hyperlinkOrPicture': hyperlinkOrPictureColumn,
        'indexed': Edm.Boolean,
        'isDeletable': Edm.Boolean,
        'isReorderable': Edm.Boolean,
        'isSealed': Edm.Boolean,
        'lookup': lookupColumn,
        'name': Edm.String,
        'number': numberColumn,
        'personOrGroup': personOrGroupColumn,
        'propagateChanges': Edm.Boolean,
        'readOnly': Edm.Boolean,
        'required': Edm.Boolean,
        'sourceContentType': contentTypeInfo,
        'term': termColumn,
        'text': textColumn,
        'thumbnail': thumbnailColumn,
        'type': columnTypes,
        'validation': columnValidation,
    }
    rels = [
        'sourceColumn',
    ]


class contentModel(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'modelType': contentModelType,
        'name': Edm.String,
    }
    rels = [

    ]


class contentType(entity):
    props = {
        'associatedHubsUrls': Collection,
        'description': Edm.String,
        'documentSet': documentSet,
        'documentTemplate': documentSetContent,
        'group': Edm.String,
        'hidden': Edm.Boolean,
        'inheritedFrom': itemReference,
        'isBuiltIn': Edm.Boolean,
        'name': Edm.String,
        'order': contentTypeOrder,
        'parentId': Edm.String,
        'propagateChanges': Edm.Boolean,
        'readOnly': Edm.Boolean,
        'sealed': Edm.Boolean,
    }
    rels = [
        'base',
        'baseTypes',
        'columnLinks',
        'columnPositions',
        'columns',
    ]


class documentProcessingJob(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'jobType': documentProcessingJobType,
        'listItemUniqueId': Edm.String,
        'status': documentProcessingJobStatus,
    }
    rels = [

    ]


class longRunningOperation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastActionDateTime': Edm.DateTimeOffset,
        'resourceLocation': Edm.String,
        'status': longRunningOperationStatus,
        'statusDetail': Edm.String,
    }
    rels = [

    ]


class permission(entity):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'grantedTo': identitySet,
        'grantedToIdentities': Collection,
        'grantedToIdentitiesV2': Collection,
        'grantedToV2': sharePointIdentitySet,
        'hasPassword': Edm.Boolean,
        'inheritedFrom': itemReference,
        'invitation': sharingInvitation,
        'link': sharingLink,
        'roles': Collection,
        'shareId': Edm.String,
    }
    rels = [

    ]


class copilotAdmin(entity):
    props = {

    }
    rels = [
        'settings',
    ]


class copilotAdminSetting(entity):
    props = {

    }
    rels = [
        'limitedMode',
    ]


class copilotAdminLimitedMode(entity):
    props = {
        'groupId': Edm.String,
        'isEnabledForGroup': Edm.Boolean,
    }
    rels = [

    ]


class copilotRoot(object):
    props = {

    }
    rels = [
        'admin',
        'interactionHistory',
        'users',
    ]


class aiInteractionHistory(entity):
    props = {

    }
    rels = [

    ]


class aiUser(entity):
    props = {

    }
    rels = [
        'interactionHistory',
    ]


class authenticationConditionApplication(object):
    props = {
        'appId': Edm.String,
    }
    rels = [

    ]


class authenticationEventsPolicy(entity):
    props = {

    }
    rels = [
        'onSignupStart',
    ]


class authenticationListener(entity):
    props = {
        'priority': Edm.Int32,
        'sourceFilter': authenticationSourceFilter,
    }
    rels = [

    ]


class identityProvider(entity):
    props = {
        'clientId': Edm.String,
        'clientSecret': Edm.String,
        'name': Edm.String,
        'type': Edm.String,
    }
    rels = [

    ]


class userFlowLanguageConfiguration(entity):
    props = {
        'displayName': Edm.String,
        'isEnabled': Edm.Boolean,
    }
    rels = [
        'defaultPages',
        'overridesPages',
    ]


class identityUserFlowAttributeAssignment(entity):
    props = {
        'displayName': Edm.String,
        'isOptional': Edm.Boolean,
        'requiresVerification': Edm.Boolean,
        'userAttributeValues': Collection,
        'userInputType': identityUserFlowAttributeInputType,
    }
    rels = [
        'userAttribute',
    ]


class trustFramework(object):
    props = {

    }
    rels = [
        'keySets',
        'policies',
    ]


class trustFrameworkKeySet(entity):
    props = {
        'keys': Collection,
    }
    rels = [
        'keys_v2',
    ]


class trustFrameworkPolicy(entity):
    props = {

    }
    rels = [

    ]


class trustFrameworkKey_v2(object):
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
    rels = [

    ]


class userFlowLanguagePage(entity):
    props = {

    }
    rels = [

    ]


class jobResponseBase(entity):
    props = {
        'creationDateTime': Edm.DateTimeOffset,
        'endDateTime': Edm.DateTimeOffset,
        'error': classificationError,
        'startDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
        'tenantId': Edm.String,
        'type': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class dataClassificationService(entity):
    props = {

    }
    rels = [
        'exactMatchDataStores',
        'classifyFileJobs',
        'classifyTextJobs',
        'evaluateDlpPoliciesJobs',
        'evaluateLabelJobs',
        'jobs',
        'sensitiveTypes',
        'sensitivityLabels',
        'exactMatchUploadAgents',
    ]


class exactMatchDataStoreBase(entity):
    props = {
        'columns': Collection,
        'dataLastUpdatedDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class sensitiveType(entity):
    props = {
        'classificationMethod': classificationMethod,
        'description': Edm.String,
        'name': Edm.String,
        'publisherName': Edm.String,
        'rulePackageId': Edm.String,
        'rulePackageType': Edm.String,
        'scope': sensitiveTypeScope,
        'sensitiveTypeSource': sensitiveTypeSource,
        'state': Edm.String,
    }
    rels = [

    ]


class exactMatchUploadAgent(entity):
    props = {
        'creationDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
    }
    rels = [

    ]


class fileClassificationRequest(entity):
    props = {
        'file': Edm.Stream,
        'sensitiveTypeIds': Collection,
    }
    rels = [

    ]


class textClassificationRequest(entity):
    props = {
        'contentMetaData': classificationRequestContentMetaData,
        'fileExtension': Edm.String,
        'matchTolerancesToInclude': mlClassificationMatchTolerance,
        'scopesToRun': sensitiveTypeScope,
        'sensitiveTypeIds': Collection,
        'text': Edm.String,
    }
    rels = [

    ]


class customSecurityAttributeExemption(entity):
    props = {
        'operator': customSecurityAttributeComparisonOperator,
    }
    rels = [

    ]


class allowedDataLocation(entity):
    props = {
        'appId': Edm.String,
        'domain': Edm.String,
        'isDefault': Edm.Boolean,
        'location': Edm.String,
    }
    rels = [

    ]


class allowedValue(entity):
    props = {
        'isActive': Edm.Boolean,
    }
    rels = [

    ]


class defaultUserRoleOverride(entity):
    props = {
        'isDefault': Edm.Boolean,
        'rolePermissions': Collection,
    }
    rels = [

    ]


class certificateAuthorityAsEntity(entity):
    props = {
        'certificate': Edm.Binary,
        'isRootAuthority': Edm.Boolean,
        'issuer': Edm.String,
        'issuerSubjectKeyIdentifier': Edm.String,
    }
    rels = [

    ]


class certificateAuthorityDetail(directoryObject):
    props = {
        'certificate': Edm.Binary,
        'certificateAuthorityType': certificateAuthorityType,
        'certificateRevocationListUrl': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'deltaCertificateRevocationListUrl': Edm.String,
        'displayName': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'isIssuerHintEnabled': Edm.Boolean,
        'issuer': Edm.String,
        'issuerSubjectKeyIdentifier': Edm.String,
        'thumbprint': Edm.String,
    }
    rels = [

    ]


class trustedCertificateAuthorityAsEntityBase(directoryObject):
    props = {

    }
    rels = [
        'trustedCertificateAuthorities',
    ]


class trustedCertificateAuthorityBase(directoryObject):
    props = {
        'certificateAuthorities': Collection,
    }
    rels = [

    ]


class certificateBasedAuthConfiguration(entity):
    props = {
        'certificateAuthorities': Collection,
    }
    rels = [

    ]


class certificateBasedAuthPki(directoryObject):
    props = {
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
        'statusDetails': Edm.String,
    }
    rels = [
        'certificateAuthorities',
    ]


class contract(directoryObject):
    props = {
        'contractType': Edm.String,
        'customerId': Edm.Guid,
        'defaultDomainName': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class crossTenantAccessPolicyConfigurationDefault(entity):
    props = {
        'automaticUserConsentSettings': inboundOutboundPolicyConfiguration,
        'b2bCollaborationInbound': crossTenantAccessPolicyB2BSetting,
        'b2bCollaborationOutbound': crossTenantAccessPolicyB2BSetting,
        'b2bDirectConnectInbound': crossTenantAccessPolicyB2BSetting,
        'b2bDirectConnectOutbound': crossTenantAccessPolicyB2BSetting,
        'inboundTrust': crossTenantAccessPolicyInboundTrust,
        'invitationRedemptionIdentityProviderConfiguration': defaultInvitationRedemptionIdentityProviderConfiguration,
        'isServiceDefault': Edm.Boolean,
        'tenantRestrictions': crossTenantAccessPolicyTenantRestrictions,
    }
    rels = [

    ]


class crossTenantAccessPolicyConfigurationPartner(object):
    props = {
        'automaticUserConsentSettings': inboundOutboundPolicyConfiguration,
        'b2bCollaborationInbound': crossTenantAccessPolicyB2BSetting,
        'b2bCollaborationOutbound': crossTenantAccessPolicyB2BSetting,
        'b2bDirectConnectInbound': crossTenantAccessPolicyB2BSetting,
        'b2bDirectConnectOutbound': crossTenantAccessPolicyB2BSetting,
        'inboundTrust': crossTenantAccessPolicyInboundTrust,
        'isInMultiTenantOrganization': Edm.Boolean,
        'isServiceProvider': Edm.Boolean,
        'tenantId': Edm.String,
        'tenantRestrictions': crossTenantAccessPolicyTenantRestrictions,
    }
    rels = [
        'identitySynchronization',
    ]


class policyTemplate(entity):
    props = {

    }
    rels = [
        'multiTenantOrganizationIdentitySynchronization',
        'multiTenantOrganizationPartnerConfiguration',
    ]


class crossTenantIdentitySyncPolicyPartner(object):
    props = {
        'displayName': Edm.String,
        'externalCloudAuthorizedApplicationId': Edm.String,
        'tenantId': Edm.String,
        'userSyncInbound': crossTenantUserSyncInbound,
    }
    rels = [

    ]


class directoryObjectPartnerReference(directoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'externalPartnerTenantId': Edm.Guid,
        'objectType': Edm.String,
    }
    rels = [

    ]


class directoryRole(directoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'roleTemplateId': Edm.String,
    }
    rels = [
        'members',
        'scopedMembers',
    ]


class directoryRoleTemplate(directoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class directorySettingTemplate(directoryObject):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'values': Collection,
    }
    rels = [

    ]


class domain(entity):
    props = {
        'authenticationType': Edm.String,
        'availabilityStatus': Edm.String,
        'isAdminManaged': Edm.Boolean,
        'isDefault': Edm.Boolean,
        'isInitial': Edm.Boolean,
        'isRoot': Edm.Boolean,
        'isVerified': Edm.Boolean,
        'passwordNotificationWindowInDays': Edm.Int32,
        'passwordValidityPeriodInDays': Edm.Int32,
        'state': domainState,
        'supportedServices': Collection,
    }
    rels = [
        'domainNameReferences',
        'federationConfiguration',
        'rootDomain',
        'serviceConfigurationRecords',
        'sharedEmailDomainInvitations',
        'verificationDnsRecords',
    ]


class domainDnsRecord(entity):
    props = {
        'isOptional': Edm.Boolean,
        'label': Edm.String,
        'recordType': Edm.String,
        'supportedService': Edm.String,
        'ttl': Edm.Int32,
    }
    rels = [

    ]


class sharedEmailDomainInvitation(entity):
    props = {
        'expiryTime': Edm.DateTimeOffset,
        'invitationDomain': Edm.String,
        'invitationStatus': Edm.String,
    }
    rels = [

    ]


class externalDomainName(entity):
    props = {

    }
    rels = [

    ]


class multiTenantOrganization(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'state': multiTenantOrganizationState,
    }
    rels = [
        'joinRequest',
        'tenants',
    ]


class multiTenantOrganizationJoinRequestRecord(entity):
    props = {
        'addedByTenantId': Edm.String,
        'memberState': multiTenantOrganizationMemberState,
        'role': multiTenantOrganizationMemberRole,
        'transitionDetails': multiTenantOrganizationJoinRequestTransitionDetails,
    }
    rels = [

    ]


class multiTenantOrganizationMember(directoryObject):
    props = {
        'addedByTenantId': Edm.Guid,
        'addedDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'joinedDateTime': Edm.DateTimeOffset,
        'role': multiTenantOrganizationMemberRole,
        'state': multiTenantOrganizationMemberState,
        'tenantId': Edm.String,
        'transitionDetails': multiTenantOrganizationMemberTransitionDetails,
    }
    rels = [

    ]


class multiTenantOrganizationIdentitySyncPolicyTemplate(entity):
    props = {
        'templateApplicationLevel': templateApplicationLevel,
        'userSyncInbound': crossTenantUserSyncInbound,
    }
    rels = [

    ]


class multiTenantOrganizationPartnerConfigurationTemplate(entity):
    props = {
        'automaticUserConsentSettings': inboundOutboundPolicyConfiguration,
        'b2bCollaborationInbound': crossTenantAccessPolicyB2BSetting,
        'b2bCollaborationOutbound': crossTenantAccessPolicyB2BSetting,
        'b2bDirectConnectInbound': crossTenantAccessPolicyB2BSetting,
        'b2bDirectConnectOutbound': crossTenantAccessPolicyB2BSetting,
        'inboundTrust': crossTenantAccessPolicyInboundTrust,
        'templateApplicationLevel': templateApplicationLevel,
    }
    rels = [

    ]


class organization(directoryObject):
    props = {
        'assignedPlans': Collection,
        'businessPhones': Collection,
        'city': Edm.String,
        'country': Edm.String,
        'countryLetterCode': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'defaultUsageLocation': Edm.String,
        'directorySizeQuota': directorySizeQuota,
        'displayName': Edm.String,
        'isMultipleDataLocationsForServicesEnabled': Edm.Boolean,
        'marketingNotificationEmails': Collection,
        'onPremisesLastPasswordSyncDateTime': Edm.DateTimeOffset,
        'onPremisesLastSyncDateTime': Edm.DateTimeOffset,
        'onPremisesSyncEnabled': Edm.Boolean,
        'partnerTenantType': partnerTenantType,
        'postalCode': Edm.String,
        'preferredLanguage': Edm.String,
        'privacyProfile': privacyProfile,
        'provisionedPlans': Collection,
        'securityComplianceNotificationMails': Collection,
        'securityComplianceNotificationPhones': Collection,
        'state': Edm.String,
        'street': Edm.String,
        'technicalNotificationMails': Collection,
        'tenantType': Edm.String,
        'verifiedDomains': Collection,
        'certificateConnectorSetting': certificateConnectorSetting,
        'mobileDeviceManagementAuthority': mdmAuthority,
    }
    rels = [
        'branding',
        'certificateBasedAuthConfiguration',
        'partnerInformation',
        'extensions',
        'settings',
    ]


class organizationalBrandingProperties(entity):
    props = {
        'backgroundColor': Edm.String,
        'backgroundImage': Edm.Stream,
        'backgroundImageRelativeUrl': Edm.String,
        'bannerLogo': Edm.Stream,
        'bannerLogoRelativeUrl': Edm.String,
        'cdnList': Collection,
        'contentCustomization': contentCustomization,
        'customAccountResetCredentialsUrl': Edm.String,
        'customCannotAccessYourAccountText': Edm.String,
        'customCannotAccessYourAccountUrl': Edm.String,
        'customCSS': Edm.Stream,
        'customCSSRelativeUrl': Edm.String,
        'customForgotMyPasswordText': Edm.String,
        'customPrivacyAndCookiesText': Edm.String,
        'customPrivacyAndCookiesUrl': Edm.String,
        'customResetItNowText': Edm.String,
        'customTermsOfUseText': Edm.String,
        'customTermsOfUseUrl': Edm.String,
        'favicon': Edm.Stream,
        'faviconRelativeUrl': Edm.String,
        'headerBackgroundColor': Edm.String,
        'headerLogo': Edm.Stream,
        'headerLogoRelativeUrl': Edm.String,
        'loginPageLayoutConfiguration': loginPageLayoutConfiguration,
        'loginPageTextVisibilitySettings': loginPageTextVisibilitySettings,
        'signInPageText': Edm.String,
        'squareLogo': Edm.Stream,
        'squareLogoDark': Edm.Stream,
        'squareLogoDarkRelativeUrl': Edm.String,
        'squareLogoRelativeUrl': Edm.String,
        'usernameHintText': Edm.String,
    }
    rels = [

    ]


class partnerInformation(object):
    props = {
        'commerceUrl': Edm.String,
        'companyName': Edm.String,
        'companyType': partnerTenantType,
        'helpUrl': Edm.String,
        'partnerTenantId': Edm.String,
        'supportEmails': Collection,
        'supportTelephones': Collection,
        'supportUrl': Edm.String,
    }
    rels = [

    ]


class organizationSettings(entity):
    props = {

    }
    rels = [
        'microsoftApplicationDataAccess',
        'contactInsights',
        'itemInsights',
        'peopleInsights',
    ]


class orgContact(directoryObject):
    props = {
        'addresses': Collection,
        'companyName': Edm.String,
        'department': Edm.String,
        'displayName': Edm.String,
        'givenName': Edm.String,
        'jobTitle': Edm.String,
        'mail': Edm.String,
        'mailNickname': Edm.String,
        'onPremisesLastSyncDateTime': Edm.DateTimeOffset,
        'onPremisesProvisioningErrors': Collection,
        'onPremisesSyncEnabled': Edm.Boolean,
        'phones': Collection,
        'proxyAddresses': Collection,
        'serviceProvisioningErrors': Collection,
        'surname': Edm.String,
    }
    rels = [
        'directReports',
        'manager',
        'memberOf',
        'transitiveMemberOf',
        'transitiveReports',
    ]


class tenantReference(object):
    props = {
        'tenantId': Edm.String,
    }
    rels = [

    ]


class permissionGrantConditionSet(entity):
    props = {
        'certifiedClientApplicationsOnly': Edm.Boolean,
        'clientApplicationIds': Collection,
        'clientApplicationPublisherIds': Collection,
        'clientApplicationsFromVerifiedPublisherOnly': Edm.Boolean,
        'clientApplicationTenantIds': Collection,
        'permissionClassification': Edm.String,
        'permissions': Collection,
        'permissionType': permissionType,
        'resourceApplication': Edm.String,
        'scopeSensitivityLabels': scopeSensitivityLabels,
    }
    rels = [

    ]


class unifiedRoleAssignment(entity):
    props = {
        'appScopeId': Edm.String,
        'condition': Edm.String,
        'directoryScopeId': Edm.String,
        'principalId': Edm.String,
        'principalOrganizationId': Edm.String,
        'resourceScope': Edm.String,
        'roleDefinitionId': Edm.String,
    }
    rels = [
        'appScope',
        'directoryScope',
        'principal',
        'roleDefinition',
    ]


class unifiedRoleScheduleInstanceBase(entity):
    props = {
        'appScopeId': Edm.String,
        'directoryScopeId': Edm.String,
        'principalId': Edm.String,
        'roleDefinitionId': Edm.String,
    }
    rels = [
        'appScope',
        'directoryScope',
        'principal',
        'roleDefinition',
    ]


class request(entity):
    props = {
        'approvalId': Edm.String,
        'completedDateTime': Edm.DateTimeOffset,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'customData': Edm.String,
        'status': Edm.String,
    }
    rels = [

    ]


class unifiedRoleScheduleBase(entity):
    props = {
        'appScopeId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'createdUsing': Edm.String,
        'directoryScopeId': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'principalId': Edm.String,
        'roleDefinitionId': Edm.String,
        'status': Edm.String,
    }
    rels = [
        'appScope',
        'directoryScope',
        'principal',
        'roleDefinition',
    ]


class targetDeviceGroup(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [

    ]


class servicePrincipalCreationConditionSet(entity):
    props = {
        'applicationIds': Collection,
        'applicationPublisherIds': Collection,
        'applicationsFromVerifiedPublisherOnly': Edm.Boolean,
        'applicationTenantIds': Collection,
        'certifiedApplicationsOnly': Edm.Boolean,
    }
    rels = [

    ]


class strongAuthenticationDetail(entity):
    props = {
        'encryptedPinHashHistory': Edm.Binary,
        'proofupTime': Edm.Int64,
    }
    rels = [

    ]


class strongAuthenticationPhoneAppDetail(entity):
    props = {
        'authenticationType': Edm.String,
        'authenticatorFlavor': Edm.String,
        'deviceId': Edm.Guid,
        'deviceName': Edm.String,
        'deviceTag': Edm.String,
        'deviceToken': Edm.String,
        'hashFunction': Edm.String,
        'lastAuthenticatedDateTime': Edm.DateTimeOffset,
        'notificationType': Edm.String,
        'oathSecretKey': Edm.String,
        'oathTokenMetadata': oathTokenMetadata,
        'oathTokenTimeDriftInSeconds': Edm.Int32,
        'phoneAppVersion': Edm.String,
        'tenantDeviceId': Edm.String,
        'tokenGenerationIntervalInSeconds': Edm.Int32,
    }
    rels = [

    ]


class subscribedSku(entity):
    props = {
        'accountId': Edm.String,
        'accountName': Edm.String,
        'appliesTo': Edm.String,
        'capabilityStatus': Edm.String,
        'consumedUnits': Edm.Int32,
        'prepaidUnits': licenseUnitsDetail,
        'servicePlans': Collection,
        'skuId': Edm.Guid,
        'skuPartNumber': Edm.String,
        'subscriptionIds': Collection,
    }
    rels = [

    ]


class tenantRelationship(object):
    props = {

    }
    rels = [
        'multiTenantOrganization',
        'managedTenants',
        'delegatedAdminCustomers',
        'delegatedAdminRelationships',
    ]


class delegatedAdminCustomer(entity):
    props = {
        'displayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [
        'serviceManagementDetails',
    ]


class delegatedAdminRelationship(entity):
    props = {
        'accessDetails': delegatedAdminAccessDetails,
        'activatedDateTime': Edm.DateTimeOffset,
        'autoExtendDuration': Edm.Duration,
        'createdDateTime': Edm.DateTimeOffset,
        'customer': delegatedAdminRelationshipCustomerParticipant,
        'displayName': Edm.String,
        'duration': Edm.Duration,
        'endDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': delegatedAdminRelationshipStatus,
    }
    rels = [
        'accessAssignments',
        'operations',
        'requests',
    ]


class browserSharedCookie(entity):
    props = {
        'comment': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'deletedDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'history': Collection,
        'hostOnly': Edm.Boolean,
        'hostOrDomain': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'path': Edm.String,
        'sourceEnvironment': browserSharedCookieSourceEnvironment,
        'status': browserSharedCookieStatus,
    }
    rels = [

    ]


class browserSite(entity):
    props = {
        'allowRedirect': Edm.Boolean,
        'comment': Edm.String,
        'compatibilityMode': browserSiteCompatibilityMode,
        'createdDateTime': Edm.DateTimeOffset,
        'deletedDateTime': Edm.DateTimeOffset,
        'history': Collection,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'mergeType': browserSiteMergeType,
        'status': browserSiteStatus,
        'targetEnvironment': browserSiteTargetEnvironment,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class browserSiteList(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'publishedBy': identitySet,
        'publishedDateTime': Edm.DateTimeOffset,
        'revision': Edm.String,
        'status': browserSiteListStatus,
    }
    rels = [
        'sharedCookies',
        'sites',
    ]


class internetExplorerMode(entity):
    props = {

    }
    rels = [
        'siteLists',
    ]


class educationRoot(object):
    props = {

    }
    rels = [
        'reports',
        'classes',
        'me',
        'schools',
        'users',
    ]


class reportsRoot(entity):
    props = {

    }
    rels = [
        'readingAssignmentSubmissions',
        'reflectCheckInResponses',
    ]


class educationClass(entity):
    props = {
        'classCode': Edm.String,
        'course': educationCourse,
        'createdBy': identitySet,
        'description': Edm.String,
        'displayName': Edm.String,
        'externalId': Edm.String,
        'externalName': Edm.String,
        'externalSource': educationExternalSource,
        'externalSourceDetail': Edm.String,
        'grade': Edm.String,
        'mailNickname': Edm.String,
        'term': educationTerm,
    }
    rels = [
        'assignmentCategories',
        'assignmentDefaults',
        'assignments',
        'assignmentSettings',
        'modules',
        'group',
        'members',
        'schools',
        'teachers',
    ]


class educationUser(entity):
    props = {
        'relatedContacts': Collection,
        'accountEnabled': Edm.Boolean,
        'assignedLicenses': Collection,
        'assignedPlans': Collection,
        'businessPhones': Collection,
        'createdBy': identitySet,
        'department': Edm.String,
        'displayName': Edm.String,
        'externalSource': educationExternalSource,
        'externalSourceDetail': Edm.String,
        'givenName': Edm.String,
        'mail': Edm.String,
        'mailingAddress': physicalAddress,
        'mailNickname': Edm.String,
        'middleName': Edm.String,
        'mobilePhone': Edm.String,
        'officeLocation': Edm.String,
        'onPremisesInfo': educationOnPremisesInfo,
        'passwordPolicies': Edm.String,
        'passwordProfile': passwordProfile,
        'preferredLanguage': Edm.String,
        'primaryRole': educationUserRole,
        'provisionedPlans': Collection,
        'refreshTokensValidFromDateTime': Edm.DateTimeOffset,
        'residenceAddress': physicalAddress,
        'showInAddressList': Edm.Boolean,
        'student': educationStudent,
        'surname': Edm.String,
        'teacher': educationTeacher,
        'usageLocation': Edm.String,
        'userPrincipalName': Edm.String,
        'userType': Edm.String,
    }
    rels = [
        'assignments',
        'rubrics',
        'classes',
        'schools',
        'taughtClasses',
        'user',
    ]


class educationOrganization(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'externalSource': educationExternalSource,
        'externalSourceDetail': Edm.String,
    }
    rels = [

    ]


class readingAssignmentSubmission(entity):
    props = {
        'accuracyScore': Edm.Double,
        'action': Edm.String,
        'assignmentId': Edm.String,
        'challengingWords': Collection,
        'classId': Edm.String,
        'insertions': Edm.Int64,
        'mispronunciations': Edm.Int64,
        'missedExclamationMarks': Edm.Int64,
        'missedPeriods': Edm.Int64,
        'missedQuestionMarks': Edm.Int64,
        'missedShorts': Edm.Int64,
        'monotoneScore': Edm.Double,
        'omissions': Edm.Int64,
        'repetitions': Edm.Int64,
        'selfCorrections': Edm.Int64,
        'studentId': Edm.String,
        'submissionDateTime': Edm.DateTimeOffset,
        'submissionId': Edm.String,
        'unexpectedPauses': Edm.Int64,
        'wordCount': Edm.Int64,
        'wordsPerMinute': Edm.Double,
    }
    rels = [

    ]


class reflectCheckInResponse(entity):
    props = {
        'checkInId': Edm.String,
        'checkInTitle': Edm.String,
        'classId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'creatorId': Edm.String,
        'isClosed': Edm.Boolean,
        'responderId': Edm.String,
        'responseEmotion': responseEmotionType,
        'responseFeedback': responseFeedbackType,
        'submitDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class educationAssignment(entity):
    props = {
        'addedStudentAction': educationAddedStudentAction,
        'addToCalendarAction': educationAddToCalendarOptions,
        'allowLateSubmissions': Edm.Boolean,
        'allowStudentsToAddResourcesToSubmission': Edm.Boolean,
        'assignDateTime': Edm.DateTimeOffset,
        'assignedDateTime': Edm.DateTimeOffset,
        'assignTo': educationAssignmentRecipient,
        'classId': Edm.String,
        'closeDateTime': Edm.DateTimeOffset,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'dueDateTime': Edm.DateTimeOffset,
        'feedbackResourcesFolderUrl': Edm.String,
        'grading': educationAssignmentGradeType,
        'instructions': educationItemBody,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'moduleUrl': Edm.String,
        'notificationChannelUrl': Edm.String,
        'resourcesFolderUrl': Edm.String,
        'status': educationAssignmentStatus,
        'webUrl': Edm.String,
    }
    rels = [
        'categories',
        'gradingCategory',
        'gradingScheme',
        'resources',
        'rubric',
        'submissions',
    ]


class educationCategory(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [

    ]


class educationGradingCategory(entity):
    props = {
        'displayName': Edm.String,
        'percentageWeight': Edm.Int32,
    }
    rels = [

    ]


class educationGradingScheme(entity):
    props = {
        'displayName': Edm.String,
        'grades': Collection,
        'hidePointsDuringGrading': Edm.Boolean,
    }
    rels = [

    ]


class educationAssignmentResource(entity):
    props = {
        'distributeForStudentWork': Edm.Boolean,
        'resource': educationResource,
    }
    rels = [
        'dependentResources',
    ]


class educationRubric(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': educationItemBody,
        'displayName': Edm.String,
        'grading': educationAssignmentGradeType,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'levels': Collection,
        'qualities': Collection,
    }
    rels = [

    ]


class educationSubmission(entity):
    props = {
        'assignmentId': Edm.String,
        'excusedBy': identitySet,
        'excusedDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'reassignedBy': identitySet,
        'reassignedDateTime': Edm.DateTimeOffset,
        'recipient': educationSubmissionRecipient,
        'resourcesFolderUrl': Edm.String,
        'returnedBy': identitySet,
        'returnedDateTime': Edm.DateTimeOffset,
        'status': educationSubmissionStatus,
        'submittedBy': identitySet,
        'submittedDateTime': Edm.DateTimeOffset,
        'unsubmittedBy': identitySet,
        'unsubmittedDateTime': Edm.DateTimeOffset,
        'webUrl': Edm.String,
    }
    rels = [
        'outcomes',
        'resources',
        'submittedResources',
    ]


class educationAssignmentDefaults(entity):
    props = {
        'addedStudentAction': educationAddedStudentAction,
        'addToCalendarAction': educationAddToCalendarOptions,
        'dueTime': Edm.TimeOfDay,
        'notificationChannelUrl': Edm.String,
    }
    rels = [

    ]


class educationAssignmentSettings(entity):
    props = {
        'submissionAnimationDisabled': Edm.Boolean,
    }
    rels = [
        'defaultGradingScheme',
        'gradingCategories',
        'gradingSchemes',
    ]


class educationModule(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'isPinned': Edm.Boolean,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'resourcesFolderUrl': Edm.String,
        'status': educationModuleStatus,
    }
    rels = [
        'resources',
    ]


class educationOutcome(entity):
    props = {
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class educationModuleResource(entity):
    props = {
        'resource': educationResource,
    }
    rels = [

    ]


class educationSubmissionResource(entity):
    props = {
        'assignmentResourceUrl': Edm.String,
        'resource': educationResource,
    }
    rels = [
        'dependentResources',
    ]


class restorePoint(entity):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'protectionDateTime': Edm.DateTimeOffset,
        'tags': restorePointTags,
    }
    rels = [
        'protectionUnit',
    ]


class protectionRuleBase(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'error': publicError,
        'isAutoApplyEnabled': Edm.Boolean,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': protectionRuleStatus,
    }
    rels = [

    ]


class protectionUnitBase(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'error': publicError,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'policyId': Edm.String,
        'protectionSources': protectionSource,
        'status': protectionUnitStatus,
    }
    rels = [

    ]


class protectionUnitsBulkJobBase(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'error': publicError,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': protectionUnitsBulkJobStatus,
    }
    rels = [

    ]


class protectionPolicyBase(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'retentionSettings': Collection,
        'status': protectionPolicyStatus,
    }
    rels = [

    ]


class restoreSessionBase(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'error': publicError,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'restoreJobType': restoreJobType,
        'restoreSessionArtifactCount': restoreSessionArtifactCount,
        'status': restoreSessionStatus,
    }
    rels = [

    ]


class serviceApp(entity):
    props = {
        'application': identity,
        'effectiveDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'registrationDateTime': Edm.DateTimeOffset,
        'status': serviceAppStatus,
    }
    rels = [

    ]


class restoreArtifactBase(entity):
    props = {
        'completionDateTime': Edm.DateTimeOffset,
        'destinationType': destinationType,
        'error': publicError,
        'startDateTime': Edm.DateTimeOffset,
        'status': artifactRestoreStatus,
    }
    rels = [
        'restorePoint',
    ]


class restoreArtifactsBulkRequestBase(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'destinationType': destinationType,
        'displayName': Edm.String,
        'error': publicError,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'protectionTimePeriod': timePeriod,
        'protectionUnitIds': Collection,
        'restorePointPreference': restorePointPreference,
        'status': restoreArtifactsBulkRequestStatus,
        'tags': restorePointTags,
    }
    rels = [

    ]


class network(object):
    props = {

    }
    rels = [

    ]


class exactMatchJobBase(entity):
    props = {
        'completionDateTime': Edm.DateTimeOffset,
        'creationDateTime': Edm.DateTimeOffset,
        'error': classificationError,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class lookupResultRow(entity):
    props = {
        'row': Edm.String,
    }
    rels = [

    ]


class itemActivityOLD(entity):
    props = {
        'action': itemActionSet,
        'actor': identitySet,
        'times': itemActivityTimeSet,
    }
    rels = [
        'driveItem',
        'listItem',
    ]


class workbook(entity):
    props = {

    }
    rels = [
        'application',
        'comments',
        'functions',
        'names',
        'operations',
        'tables',
        'worksheets',
    ]


class itemRetentionLabel(entity):
    props = {
        'isLabelAppliedExplicitly': Edm.Boolean,
        'labelAppliedBy': identitySet,
        'labelAppliedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'retentionSettings': retentionLabelSettings,
    }
    rels = [

    ]


class subscription(entity):
    props = {
        'applicationId': Edm.String,
        'changeType': Edm.String,
        'clientState': Edm.String,
        'creatorId': Edm.String,
        'encryptionCertificate': Edm.String,
        'encryptionCertificateId': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'includeResourceData': Edm.Boolean,
        'latestSupportedTlsVersion': Edm.String,
        'lifecycleNotificationUrl': Edm.String,
        'notificationContentType': Edm.String,
        'notificationQueryOptions': Edm.String,
        'notificationUrl': Edm.String,
        'notificationUrlAppId': Edm.String,
        'resource': Edm.String,
    }
    rels = [

    ]


class thumbnailSet(entity):
    props = {
        'large': thumbnail,
        'medium': thumbnail,
        'small': thumbnail,
        'source': thumbnail,
    }
    rels = [

    ]


class baseItemVersion(entity):
    props = {
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'publication': publicationFacet,
    }
    rels = [

    ]


class workbookApplication(entity):
    props = {
        'calculationMode': Edm.String,
    }
    rels = [

    ]


class workbookComment(entity):
    props = {
        'content': Edm.String,
        'contentType': Edm.String,
    }
    rels = [
        'replies',
        'task',
    ]


class workbookFunctions(entity):
    props = {

    }
    rels = [

    ]


class workbookNamedItem(entity):
    props = {
        'comment': Edm.String,
        'name': Edm.String,
        'scope': Edm.String,
        'type': Edm.String,
        'value': Json,
        'visible': Edm.Boolean,
    }
    rels = [
        'worksheet',
    ]


class workbookOperation(entity):
    props = {
        'error': workbookOperationError,
        'resourceLocation': Edm.String,
        'status': workbookOperationStatus,
    }
    rels = [

    ]


class workbookTable(entity):
    props = {
        'highlightFirstColumn': Edm.Boolean,
        'highlightLastColumn': Edm.Boolean,
        'legacyId': Edm.String,
        'name': Edm.String,
        'showBandedColumns': Edm.Boolean,
        'showBandedRows': Edm.Boolean,
        'showFilterButton': Edm.Boolean,
        'showHeaders': Edm.Boolean,
        'showTotals': Edm.Boolean,
        'style': Edm.String,
    }
    rels = [
        'columns',
        'rows',
        'sort',
        'worksheet',
    ]


class workbookWorksheet(entity):
    props = {
        'name': Edm.String,
        'position': Edm.Int32,
        'visibility': Edm.String,
    }
    rels = [
        'charts',
        'names',
        'pivotTables',
        'protection',
        'tables',
        'tasks',
    ]


class workbookChart(entity):
    props = {
        'height': Edm.Double,
        'left': Edm.Double,
        'name': Edm.String,
        'top': Edm.Double,
        'width': Edm.Double,
    }
    rels = [
        'axes',
        'dataLabels',
        'format',
        'legend',
        'series',
        'title',
        'worksheet',
    ]


class workbookChartAxes(entity):
    props = {

    }
    rels = [
        'categoryAxis',
        'seriesAxis',
        'valueAxis',
    ]


class workbookChartDataLabels(entity):
    props = {
        'position': Edm.String,
        'separator': Edm.String,
        'showBubbleSize': Edm.Boolean,
        'showCategoryName': Edm.Boolean,
        'showLegendKey': Edm.Boolean,
        'showPercentage': Edm.Boolean,
        'showSeriesName': Edm.Boolean,
        'showValue': Edm.Boolean,
    }
    rels = [
        'format',
    ]


class workbookChartAreaFormat(entity):
    props = {

    }
    rels = [
        'fill',
        'font',
    ]


class workbookChartLegend(entity):
    props = {
        'overlay': Edm.Boolean,
        'position': Edm.String,
        'visible': Edm.Boolean,
    }
    rels = [
        'format',
    ]


class workbookChartSeries(entity):
    props = {
        'name': Edm.String,
    }
    rels = [
        'format',
        'points',
    ]


class workbookChartTitle(entity):
    props = {
        'overlay': Edm.Boolean,
        'text': Edm.String,
        'visible': Edm.Boolean,
    }
    rels = [
        'format',
    ]


class workbookChartFill(entity):
    props = {

    }
    rels = [

    ]


class workbookChartFont(entity):
    props = {
        'bold': Edm.Boolean,
        'color': Edm.String,
        'italic': Edm.Boolean,
        'name': Edm.String,
        'size': Edm.Double,
        'underline': Edm.String,
    }
    rels = [

    ]


class workbookChartAxis(entity):
    props = {
        'majorUnit': Json,
        'maximum': Json,
        'minimum': Json,
        'minorUnit': Json,
    }
    rels = [
        'format',
        'majorGridlines',
        'minorGridlines',
        'title',
    ]


class workbookChartAxisFormat(entity):
    props = {

    }
    rels = [
        'font',
        'line',
    ]


class workbookChartGridlines(entity):
    props = {
        'visible': Edm.Boolean,
    }
    rels = [
        'format',
    ]


class workbookChartAxisTitle(entity):
    props = {
        'text': Edm.String,
        'visible': Edm.Boolean,
    }
    rels = [
        'format',
    ]


class workbookChartLineFormat(entity):
    props = {
        'color': Edm.String,
    }
    rels = [

    ]


class workbookChartAxisTitleFormat(entity):
    props = {

    }
    rels = [
        'font',
    ]


class workbookChartDataLabelFormat(entity):
    props = {

    }
    rels = [
        'fill',
        'font',
    ]


class workbookChartGridlinesFormat(entity):
    props = {

    }
    rels = [
        'line',
    ]


class workbookChartLegendFormat(entity):
    props = {

    }
    rels = [
        'fill',
        'font',
    ]


class workbookChartPoint(entity):
    props = {
        'value': Json,
    }
    rels = [
        'format',
    ]


class workbookChartPointFormat(entity):
    props = {

    }
    rels = [
        'fill',
    ]


class workbookChartSeriesFormat(entity):
    props = {

    }
    rels = [
        'fill',
        'line',
    ]


class workbookChartTitleFormat(entity):
    props = {

    }
    rels = [
        'fill',
        'font',
    ]


class workbookCommentReply(entity):
    props = {
        'content': Edm.String,
        'contentType': Edm.String,
    }
    rels = [
        'task',
    ]


class workbookDocumentTask(entity):
    props = {
        'assignees': Collection,
        'completedBy': workbookEmailIdentity,
        'completedDateTime': Edm.DateTimeOffset,
        'createdBy': workbookEmailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'percentComplete': Edm.Int32,
        'priority': Edm.Int32,
        'startAndDueDateTime': workbookDocumentTaskSchedule,
        'title': Edm.String,
    }
    rels = [
        'changes',
        'comment',
    ]


class workbookDocumentTaskChange(entity):
    props = {
        'assignee': workbookEmailIdentity,
        'changedBy': workbookEmailIdentity,
        'commentId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'dueDateTime': Edm.DateTimeOffset,
        'percentComplete': Edm.Int32,
        'priority': Edm.Int32,
        'startDateTime': Edm.DateTimeOffset,
        'title': Edm.String,
        'type': Edm.String,
        'undoChangeId': Edm.String,
    }
    rels = [

    ]


class workbookFilter(entity):
    props = {
        'criteria': workbookFilterCriteria,
    }
    rels = [

    ]


class workbookFormatProtection(entity):
    props = {
        'formulaHidden': Edm.Boolean,
        'locked': Edm.Boolean,
    }
    rels = [

    ]


class workbookFunctionResult(entity):
    props = {
        'error': Edm.String,
        'value': Json,
    }
    rels = [

    ]


class workbookPivotTable(entity):
    props = {
        'name': Edm.String,
    }
    rels = [
        'worksheet',
    ]


class workbookRange(entity):
    props = {
        'address': Edm.String,
        'addressLocal': Edm.String,
        'cellCount': Edm.Int32,
        'columnCount': Edm.Int32,
        'columnHidden': Edm.Boolean,
        'columnIndex': Edm.Int32,
        'formulas': Json,
        'formulasLocal': Json,
        'formulasR1C1': Json,
        'hidden': Edm.Boolean,
        'numberFormat': Json,
        'rowCount': Edm.Int32,
        'rowHidden': Edm.Boolean,
        'rowIndex': Edm.Int32,
        'text': Json,
        'values': Json,
        'valueTypes': Json,
    }
    rels = [
        'format',
        'sort',
        'worksheet',
    ]


class workbookRangeFormat(entity):
    props = {
        'columnWidth': Edm.Double,
        'horizontalAlignment': Edm.String,
        'rowHeight': Edm.Double,
        'verticalAlignment': Edm.String,
        'wrapText': Edm.Boolean,
    }
    rels = [
        'borders',
        'fill',
        'font',
        'protection',
    ]


class workbookRangeSort(entity):
    props = {

    }
    rels = [

    ]


class workbookRangeBorder(entity):
    props = {
        'color': Edm.String,
        'sideIndex': Edm.String,
        'style': Edm.String,
        'weight': Edm.String,
    }
    rels = [

    ]


class workbookRangeFill(entity):
    props = {
        'color': Edm.String,
    }
    rels = [

    ]


class workbookRangeFont(entity):
    props = {
        'bold': Edm.Boolean,
        'color': Edm.String,
        'italic': Edm.Boolean,
        'name': Edm.String,
        'size': Edm.Double,
        'underline': Edm.String,
    }
    rels = [

    ]


class workbookRangeView(entity):
    props = {
        'cellAddresses': Json,
        'columnCount': Edm.Int32,
        'formulas': Json,
        'formulasLocal': Json,
        'formulasR1C1': Json,
        'index': Edm.Int32,
        'numberFormat': Json,
        'rowCount': Edm.Int32,
        'text': Json,
        'values': Json,
        'valueTypes': Json,
    }
    rels = [
        'rows',
    ]


class workbookTableColumn(entity):
    props = {
        'index': Edm.Int32,
        'name': Edm.String,
        'values': Json,
    }
    rels = [
        'filter',
    ]


class workbookTableRow(entity):
    props = {
        'index': Edm.Int32,
        'values': Json,
    }
    rels = [

    ]


class workbookTableSort(entity):
    props = {
        'fields': Collection,
        'matchCase': Edm.Boolean,
        'method': Edm.String,
    }
    rels = [

    ]


class workbookWorksheetProtection(entity):
    props = {
        'options': workbookWorksheetProtectionOptions,
        'protected': Edm.Boolean,
    }
    rels = [

    ]


class place(entity):
    props = {
        'address': physicalAddress,
        'displayName': Edm.String,
        'geoCoordinates': outlookGeoCoordinates,
        'phone': Edm.String,
        'placeId': Edm.String,
    }
    rels = [

    ]


class workplace(object):
    props = {

    }
    rels = [
        'sensorDevices',
    ]


class workplaceSensorDevice(entity):
    props = {
        'description': Edm.String,
        'deviceId': Edm.String,
        'displayName': Edm.String,
        'ipV4Address': Edm.String,
        'ipV6Address': Edm.String,
        'macAddress': Edm.String,
        'manufacturer': Edm.String,
        'placeId': Edm.String,
        'sensors': Collection,
        'tags': Collection,
    }
    rels = [

    ]


class attachment(entity):
    props = {
        'contentType': Edm.String,
        'isInline': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'size': Edm.Int32,
    }
    rels = [

    ]


class calendarPermission(entity):
    props = {
        'allowedRoles': Collection,
        'emailAddress': emailAddress,
        'isInsideOrganization': Edm.Boolean,
        'isRemovable': Edm.Boolean,
        'role': calendarRoleType,
    }
    rels = [

    ]


class multiValueLegacyExtendedProperty(entity):
    props = {
        'value': Collection,
    }
    rels = [

    ]


class singleValueLegacyExtendedProperty(entity):
    props = {
        'value': Edm.String,
    }
    rels = [

    ]


class mailbox(directoryObject):
    props = {

    }
    rels = [
        'folders',
    ]


class messageTrace(entity):
    props = {
        'destinationIPAddress': Edm.String,
        'messageId': Edm.String,
        'receivedDateTime': Edm.DateTimeOffset,
        'senderEmail': Edm.String,
        'size': Edm.Int32,
        'sourceIPAddress': Edm.String,
        'subject': Edm.String,
    }
    rels = [
        'recipients',
    ]


class exchangeSettings(entity):
    props = {
        'inPlaceArchiveMailboxId': Edm.String,
        'primaryMailboxId': Edm.String,
    }
    rels = [

    ]


class inferenceClassificationOverride(entity):
    props = {
        'classifyAs': inferenceClassificationType,
        'senderEmailAddress': emailAddress,
    }
    rels = [

    ]


class mailboxFolder(entity):
    props = {
        'childFolderCount': Edm.Int32,
        'displayName': Edm.String,
        'parentFolderId': Edm.String,
        'parentMailboxUrl': Edm.String,
        'totalItemCount': Edm.Int32,
        'type': Edm.String,
    }
    rels = [
        'childFolders',
        'items',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class messageRule(entity):
    props = {
        'actions': messageRuleActions,
        'conditions': messageRulePredicates,
        'displayName': Edm.String,
        'exceptions': messageRulePredicates,
        'hasError': Edm.Boolean,
        'isEnabled': Edm.Boolean,
        'isReadOnly': Edm.Boolean,
        'sequence': Edm.Int32,
    }
    rels = [

    ]


class mailFolderOperation(entity):
    props = {
        'resourceLocation': Edm.String,
        'status': mailFolderOperationStatus,
    }
    rels = [

    ]


class userConfiguration(entity):
    props = {
        'binaryData': Edm.Binary,
    }
    rels = [

    ]


class mention(entity):
    props = {
        'application': Edm.String,
        'clientReference': Edm.String,
        'createdBy': emailAddress,
        'createdDateTime': Edm.DateTimeOffset,
        'deepLink': Edm.String,
        'mentioned': emailAddress,
        'mentionText': Edm.String,
        'serverCreatedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class outlookCategory(entity):
    props = {
        'color': categoryColor,
        'displayName': Edm.String,
    }
    rels = [

    ]


class outlookTaskFolder(entity):
    props = {
        'changeKey': Edm.String,
        'isDefaultFolder': Edm.Boolean,
        'name': Edm.String,
        'parentGroupKey': Edm.Guid,
    }
    rels = [
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
        'tasks',
    ]


class outlookTaskGroup(entity):
    props = {
        'changeKey': Edm.String,
        'groupKey': Edm.Guid,
        'isDefaultGroup': Edm.Boolean,
        'name': Edm.String,
    }
    rels = [
        'taskFolders',
    ]


class userInsightsSettings(entity):
    props = {
        'isEnabled': Edm.Boolean,
    }
    rels = [

    ]


class windowsSetting(entity):
    props = {
        'payloadType': Edm.String,
        'settingType': windowsSettingType,
        'windowsDeviceId': Edm.String,
    }
    rels = [
        'instances',
    ]


class contactMergeSuggestions(entity):
    props = {
        'isEnabled': Edm.Boolean,
    }
    rels = [

    ]


class regionalAndLanguageSettings(entity):
    props = {
        'authoringLanguages': Collection,
        'defaultDisplayLanguage': localeInfo,
        'defaultRegionalFormat': localeInfo,
        'defaultSpeechInputLanguage': localeInfo,
        'defaultTranslationLanguage': localeInfo,
        'regionalFormatOverrides': regionalFormatOverrides,
        'translationPreferences': translationPreferences,
    }
    rels = [

    ]


class changeTrackedEntity(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class userStorage(entity):
    props = {

    }
    rels = [
        'quota',
    ]


class fileStorage(entity):
    props = {

    }
    rels = [
        'containers',
        'deletedContainers',
    ]


class fileStorageContainer(entity):
    props = {
        'assignedSensitivityLabel': assignedLabel,
        'containerTypeId': Edm.Guid,
        'createdDateTime': Edm.DateTimeOffset,
        'customProperties': fileStorageContainerCustomPropertyDictionary,
        'description': Edm.String,
        'displayName': Edm.String,
        'externalGroupId': Edm.Guid,
        'isItemVersioningEnabled': Edm.Boolean,
        'itemMajorVersionLimit': Edm.Int32,
        'lockState': siteLockState,
        'owners': Collection,
        'ownershipType': fileStorageContainerOwnershipType,
        'settings': fileStorageContainerSettings,
        'status': fileStorageContainerStatus,
        'storageUsedInBytes': Edm.Int64,
        'viewpoint': fileStorageContainerViewpoint,
    }
    rels = [
        'columns',
        'drive',
        'permissions',
        'recycleBin',
    ]


class sharepointSettings(entity):
    props = {
        'allowedDomainGuidsForSyncApp': Collection,
        'availableManagedPathsForSiteCreation': Collection,
        'deletedUserPersonalSiteRetentionPeriodInDays': Edm.Int32,
        'excludedFileExtensionsForSyncApp': Collection,
        'idleSessionSignOut': idleSessionSignOut,
        'imageTaggingOption': imageTaggingChoice,
        'isCommentingOnSitePagesEnabled': Edm.Boolean,
        'isFileActivityNotificationEnabled': Edm.Boolean,
        'isLegacyAuthProtocolsEnabled': Edm.Boolean,
        'isLoopEnabled': Edm.Boolean,
        'isMacSyncAppEnabled': Edm.Boolean,
        'isRequireAcceptingUserToMatchInvitedUserEnabled': Edm.Boolean,
        'isResharingByExternalUsersEnabled': Edm.Boolean,
        'isSharePointMobileNotificationEnabled': Edm.Boolean,
        'isSharePointNewsfeedEnabled': Edm.Boolean,
        'isSiteCreationEnabled': Edm.Boolean,
        'isSiteCreationUIEnabled': Edm.Boolean,
        'isSitePagesCreationEnabled': Edm.Boolean,
        'isSitesStorageLimitAutomatic': Edm.Boolean,
        'isSyncButtonHiddenOnPersonalSite': Edm.Boolean,
        'isUnmanagedSyncAppForTenantRestricted': Edm.Boolean,
        'personalSiteDefaultStorageLimitInMB': Edm.Int64,
        'sharingAllowedDomainList': Collection,
        'sharingBlockedDomainList': Collection,
        'sharingCapability': sharingCapabilities,
        'sharingDomainRestrictionMode': sharingDomainRestrictionMode,
        'siteCreationDefaultManagedPath': Edm.String,
        'siteCreationDefaultStorageLimitInMB': Edm.Int32,
        'tenantDefaultTimezone': Edm.String,
    }
    rels = [

    ]


class storage(object):
    props = {

    }
    rels = [
        'fileStorage',
        'settings',
    ]


class storageSettings(entity):
    props = {

    }
    rels = [
        'quota',
    ]


class canvasLayout(entity):
    props = {

    }
    rels = [
        'horizontalSections',
        'verticalSection',
    ]


class horizontalSection(entity):
    props = {
        'emphasis': sectionEmphasisType,
        'layout': horizontalSectionLayoutType,
    }
    rels = [
        'columns',
    ]


class verticalSection(entity):
    props = {
        'emphasis': sectionEmphasisType,
    }
    rels = [
        'webparts',
    ]


class columnLink(entity):
    props = {
        'name': Edm.String,
    }
    rels = [

    ]


class employeeExperience(object):
    props = {

    }
    rels = [
        'communities',
        'engagementAsyncOperations',
        'goals',
        'learningCourseActivities',
        'learningProviders',
    ]


class community(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'groupId': Edm.String,
        'privacy': communityPrivacy,
    }
    rels = [
        'group',
        'owners',
    ]


class goals(entity):
    props = {

    }
    rels = [
        'exportJobs',
    ]


class learningCourseActivity(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'completionPercentage': Edm.Int32,
        'externalcourseActivityId': Edm.String,
        'learnerUserId': Edm.String,
        'learningContentId': Edm.String,
        'learningProviderId': Edm.String,
        'status': courseStatus,
    }
    rels = [

    ]


class learningProvider(entity):
    props = {
        'displayName': Edm.String,
        'isCourseActivitySyncEnabled': Edm.Boolean,
        'loginWebUrl': Edm.String,
        'longLogoWebUrlForDarkTheme': Edm.String,
        'longLogoWebUrlForLightTheme': Edm.String,
        'squareLogoWebUrlForDarkTheme': Edm.String,
        'squareLogoWebUrlForLightTheme': Edm.String,
    }
    rels = [
        'learningContents',
        'learningCourseActivities',
    ]


class fieldValueSet(entity):
    props = {

    }
    rels = [

    ]


class horizontalSectionColumn(entity):
    props = {
        'width': Edm.Int32,
    }
    rels = [
        'webparts',
    ]


class webPart(entity):
    props = {

    }
    rels = [

    ]


class itemActivity(entity):
    props = {
        'access': accessAction,
        'activityDateTime': Edm.DateTimeOffset,
        'actor': identitySet,
    }
    rels = [
        'driveItem',
    ]


class itemActivityStat(entity):
    props = {
        'access': itemActionStat,
        'create': itemActionStat,
        'delete': itemActionStat,
        'edit': itemActionStat,
        'endDateTime': Edm.DateTimeOffset,
        'incompleteData': incompleteData,
        'isTrending': Edm.Boolean,
        'move': itemActionStat,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'activities',
    ]


class meetingAttendanceReport(entity):
    props = {
        'externalEventInformation': Collection,
        'meetingEndDateTime': Edm.DateTimeOffset,
        'meetingStartDateTime': Edm.DateTimeOffset,
        'totalParticipantCount': Edm.Int32,
    }
    rels = [
        'attendanceRecords',
    ]


class meetingRegistrationBase(entity):
    props = {
        'allowedRegistrant': meetingAudience,
    }
    rels = [
        'registrants',
    ]


class callAiInsight(entity):
    props = {
        'actionItems': Collection,
        'callId': Edm.String,
        'contentCorrelationId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'endDateTime': Edm.DateTimeOffset,
        'meetingNotes': Collection,
        'viewpoint': callAiInsightViewPoint,
    }
    rels = [

    ]


class callRecording(entity):
    props = {
        'callId': Edm.String,
        'content': Edm.Stream,
        'contentCorrelationId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'endDateTime': Edm.DateTimeOffset,
        'meetingId': Edm.String,
        'meetingOrganizer': identitySet,
        'recordingContentUrl': Edm.String,
    }
    rels = [

    ]


class callTranscript(entity):
    props = {
        'callId': Edm.String,
        'content': Edm.Stream,
        'contentCorrelationId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'endDateTime': Edm.DateTimeOffset,
        'meetingId': Edm.String,
        'meetingOrganizer': identitySet,
        'metadataContent': Edm.Stream,
        'transcriptContentUrl': Edm.String,
    }
    rels = [

    ]


class messageEvent(entity):
    props = {
        'dateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'eventType': messageEventType,
    }
    rels = [

    ]


class messageRecipient(entity):
    props = {
        'deliveryStatus': messageStatus,
        'recipientEmail': Edm.String,
    }
    rels = [
        'events',
    ]


class schemaExtension(entity):
    props = {
        'description': Edm.String,
        'owner': Edm.String,
        'properties': Collection,
        'status': Edm.String,
        'targetTypes': Collection,
    }
    rels = [

    ]


class applicationSegment(entity):
    props = {

    }
    rels = [

    ]


class connector(entity):
    props = {
        'externalIp': Edm.String,
        'machineName': Edm.String,
        'status': connectorStatus,
        'version': Edm.String,
    }
    rels = [
        'memberOf',
    ]


class corsConfiguration_v2(entity):
    props = {
        'allowedHeaders': Collection,
        'allowedMethods': Collection,
        'allowedOrigins': Collection,
        'maxAgeInSeconds': Edm.Int32,
        'resource': Edm.String,
    }
    rels = [

    ]


class onPremisesAgent(entity):
    props = {
        'externalIp': Edm.String,
        'machineName': Edm.String,
        'status': agentStatus,
        'supportedPublishingTypes': Collection,
    }
    rels = [
        'agentGroups',
    ]


class onPremisesAgentGroup(entity):
    props = {
        'displayName': Edm.String,
        'isDefault': Edm.Boolean,
        'publishingType': onPremisesPublishingType,
    }
    rels = [
        'agents',
        'publishedResources',
    ]


class publishedResource(entity):
    props = {
        'displayName': Edm.String,
        'publishingType': onPremisesPublishingType,
        'resourceName': Edm.String,
    }
    rels = [
        'agentGroups',
    ]


class onPremisesPublishingProfile(entity):
    props = {
        'hybridAgentUpdaterConfiguration': hybridAgentUpdaterConfiguration,
        'isDefaultAccessEnabled': Edm.Boolean,
        'isEnabled': Edm.Boolean,
    }
    rels = [
        'agentGroups',
        'agents',
        'applicationSegments',
        'connectorGroups',
        'connectors',
        'publishedResources',
    ]


class attributeMappingFunctionSchema(entity):
    props = {
        'parameters': Collection,
    }
    rels = [

    ]


class bulkUpload(entity):
    props = {

    }
    rels = [

    ]


class directoryDefinition(entity):
    props = {
        'discoverabilities': directoryDefinitionDiscoverabilities,
        'discoveryDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'objects': Collection,
        'readOnly': Edm.Boolean,
        'version': Edm.String,
    }
    rels = [

    ]


class filterOperatorSchema(entity):
    props = {
        'arity': scopeOperatorType,
        'multivaluedComparisonType': scopeOperatorMultiValuedComparisonType,
        'supportedAttributeTypes': Collection,
    }
    rels = [

    ]


class synchronizationJob(entity):
    props = {
        'schedule': synchronizationSchedule,
        'status': synchronizationStatus,
        'synchronizationJobSettings': Collection,
        'templateId': Edm.String,
    }
    rels = [
        'bulkUpload',
        'schema',
    ]


class synchronizationTemplate(entity):
    props = {
        'applicationId': Edm.Guid,
        'default': Edm.Boolean,
        'description': Edm.String,
        'discoverable': Edm.Boolean,
        'factoryTag': Edm.String,
        'metadata': Collection,
    }
    rels = [
        'schema',
    ]


class synchronizationSchema(entity):
    props = {
        'synchronizationRules': Collection,
        'version': Edm.String,
    }
    rels = [
        'directories',
    ]


class cloudCommunications(object):
    props = {

    }
    rels = [
        'callRecords',
        'calls',
        'onlineMeetings',
        'presences',
    ]


class call(entity):
    props = {
        'activeModalities': Collection,
        'answeredBy': participantInfo,
        'callbackUri': Edm.String,
        'callChainId': Edm.String,
        'callOptions': callOptions,
        'callRoutes': Collection,
        'chatInfo': chatInfo,
        'direction': callDirection,
        'incomingContext': incomingContext,
        'mediaConfig': mediaConfig,
        'mediaState': callMediaState,
        'meetingCapability': meetingCapability,
        'meetingInfo': meetingInfo,
        'myParticipantId': Edm.String,
        'requestedModalities': Collection,
        'resultInfo': resultInfo,
        'ringingTimeoutInSeconds': Edm.Int32,
        'routingPolicies': Collection,
        'source': participantInfo,
        'state': callState,
        'subject': Edm.String,
        'targets': Collection,
        'tenantId': Edm.String,
        'terminationReason': Edm.String,
        'toneInfo': toneInfo,
        'transcription': callTranscriptionInfo,
    }
    rels = [
        'audioRoutingGroups',
        'contentSharingSessions',
        'operations',
        'participants',
    ]


class accessReview(entity):
    props = {
        'businessFlowTemplateId': Edm.String,
        'createdBy': userIdentity,
        'description': Edm.String,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'reviewedEntity': identity,
        'reviewerType': Edm.String,
        'settings': accessReviewSettings,
        'startDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
    }
    rels = [
        'decisions',
        'instances',
        'myDecisions',
        'reviewers',
    ]


class accessReviewDecision(entity):
    props = {
        'accessRecommendation': Edm.String,
        'accessReviewId': Edm.String,
        'appliedBy': userIdentity,
        'appliedDateTime': Edm.DateTimeOffset,
        'applyResult': Edm.String,
        'justification': Edm.String,
        'reviewedBy': userIdentity,
        'reviewedDateTime': Edm.DateTimeOffset,
        'reviewResult': Edm.String,
    }
    rels = [

    ]


class accessReviewReviewer(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class accessReviewHistoryDefinition(entity):
    props = {
        'createdBy': userIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'decisions': Collection,
        'displayName': Edm.String,
        'downloadUri': Edm.String,
        'fulfilledDateTime': Edm.DateTimeOffset,
        'reviewHistoryPeriodEndDateTime': Edm.DateTimeOffset,
        'reviewHistoryPeriodStartDateTime': Edm.DateTimeOffset,
        'scheduleSettings': accessReviewHistoryScheduleSettings,
        'scopes': Collection,
        'status': accessReviewHistoryStatus,
    }
    rels = [
        'instances',
    ]


class accessReviewHistoryInstance(entity):
    props = {
        'downloadUri': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'fulfilledDateTime': Edm.DateTimeOffset,
        'reviewHistoryPeriodEndDateTime': Edm.DateTimeOffset,
        'reviewHistoryPeriodStartDateTime': Edm.DateTimeOffset,
        'runDateTime': Edm.DateTimeOffset,
        'status': accessReviewHistoryStatus,
    }
    rels = [

    ]


class accessReviewInstanceDecisionItem(entity):
    props = {
        'accessReviewId': Edm.String,
        'appliedBy': userIdentity,
        'appliedDateTime': Edm.DateTimeOffset,
        'applyResult': Edm.String,
        'decision': Edm.String,
        'justification': Edm.String,
        'principal': identity,
        'principalLink': Edm.String,
        'principalResourceMembership': decisionItemPrincipalResourceMembership,
        'recommendation': Edm.String,
        'resource': accessReviewInstanceDecisionItemResource,
        'resourceLink': Edm.String,
        'reviewedBy': userIdentity,
        'reviewedDateTime': Edm.DateTimeOffset,
        'target': accessReviewInstanceDecisionItemTarget,
    }
    rels = [
        'insights',
        'instance',
    ]


class accessReviewScheduleDefinition(entity):
    props = {
        'additionalNotificationRecipients': Collection,
        'backupReviewers': Collection,
        'createdBy': userIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'descriptionForAdmins': Edm.String,
        'descriptionForReviewers': Edm.String,
        'displayName': Edm.String,
        'fallbackReviewers': Collection,
        'instanceEnumerationScope': accessReviewScope,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'reviewers': Collection,
        'scope': accessReviewScope,
        'settings': accessReviewScheduleSettings,
        'stageSettings': Collection,
        'status': Edm.String,
    }
    rels = [
        'instances',
    ]


class accessReviewStage(entity):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'fallbackReviewers': Collection,
        'reviewers': Collection,
        'startDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
    }
    rels = [
        'decisions',
    ]


class approvalStep(entity):
    props = {
        'assignedToMe': Edm.Boolean,
        'displayName': Edm.String,
        'justification': Edm.String,
        'reviewedBy': identity,
        'reviewedDateTime': Edm.DateTimeOffset,
        'reviewResult': Edm.String,
        'status': Edm.String,
    }
    rels = [

    ]


class approvalWorkflowProvider(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [
        'businessFlows',
        'businessFlowsWithRequestsAwaitingMyDecision',
        'policyTemplates',
    ]


class businessFlow(entity):
    props = {
        'customData': Edm.String,
        'deDuplicationId': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'policy': governancePolicy,
        'policyTemplateId': Edm.String,
        'recordVersion': Edm.String,
        'schemaId': Edm.String,
        'settings': businessFlowSettings,
    }
    rels = [

    ]


class governancePolicyTemplate(entity):
    props = {
        'displayName': Edm.String,
        'policy': governancePolicy,
        'settings': businessFlowSettings,
    }
    rels = [

    ]


class businessFlowTemplate(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [

    ]


class accessPackageAssignmentPolicy(entity):
    props = {
        'accessPackageId': Edm.String,
        'accessPackageNotificationSettings': accessPackageNotificationSettings,
        'accessReviewSettings': assignmentReviewSettings,
        'canExtend': Edm.Boolean,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'durationInDays': Edm.Int32,
        'expirationDateTime': Edm.DateTimeOffset,
        'modifiedBy': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'questions': Collection,
        'requestApprovalSettings': approvalSettings,
        'requestorSettings': requestorSettings,
        'verifiableCredentialSettings': verifiableCredentialSettings,
    }
    rels = [
        'accessPackage',
        'accessPackageCatalog',
        'customExtensionHandlers',
        'customExtensionStageSettings',
    ]


class accessPackageAssignmentRequest(entity):
    props = {
        'answers': Collection,
        'completedDate': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'customExtensionCalloutInstances': Collection,
        'customExtensionHandlerInstances': Collection,
        'expirationDateTime': Edm.DateTimeOffset,
        'history': Collection,
        'isValidationOnly': Edm.Boolean,
        'justification': Edm.String,
        'requestState': Edm.String,
        'requestStatus': Edm.String,
        'requestType': Edm.String,
        'schedule': requestSchedule,
        'verifiedCredentialsData': Collection,
    }
    rels = [
        'accessPackage',
        'accessPackageAssignment',
        'requestor',
    ]


class accessPackageAssignmentResourceRole(entity):
    props = {
        'originId': Edm.String,
        'originSystem': Edm.String,
        'status': Edm.String,
    }
    rels = [
        'accessPackageAssignments',
        'accessPackageResourceRole',
        'accessPackageResourceScope',
        'accessPackageSubject',
    ]


class accessPackageAssignment(entity):
    props = {
        'accessPackageId': Edm.String,
        'assignmentPolicyId': Edm.String,
        'assignmentState': Edm.String,
        'assignmentStatus': Edm.String,
        'catalogId': Edm.String,
        'customExtensionCalloutInstances': Collection,
        'expiredDateTime': Edm.DateTimeOffset,
        'isExtended': Edm.Boolean,
        'schedule': requestSchedule,
        'targetId': Edm.String,
    }
    rels = [
        'accessPackage',
        'accessPackageAssignmentPolicy',
        'accessPackageAssignmentRequests',
        'accessPackageAssignmentResourceRoles',
        'target',
    ]


class accessPackageCatalog(entity):
    props = {
        'catalogStatus': Edm.String,
        'catalogType': Edm.String,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'isExternallyVisible': Edm.Boolean,
        'modifiedBy': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'uniqueName': Edm.String,
    }
    rels = [
        'accessPackageCustomWorkflowExtensions',
        'accessPackageResourceRoles',
        'accessPackageResources',
        'accessPackageResourceScopes',
        'accessPackages',
        'customAccessPackageWorkflowExtensions',
    ]


class accessPackageResourceEnvironment(entity):
    props = {
        'connectionInfo': connectionInfo,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'isDefaultEnvironment': Edm.Boolean,
        'modifiedBy': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'originId': Edm.String,
        'originSystem': Edm.String,
    }
    rels = [
        'accessPackageResources',
    ]


class accessPackageResourceRequest(entity):
    props = {
        'catalogId': Edm.String,
        'executeImmediately': Edm.Boolean,
        'expirationDateTime': Edm.DateTimeOffset,
        'isValidationOnly': Edm.Boolean,
        'justification': Edm.String,
        'requestState': Edm.String,
        'requestStatus': Edm.String,
        'requestType': Edm.String,
    }
    rels = [
        'accessPackageResource',
        'requestor',
    ]


class accessPackageResourceRoleScope(entity):
    props = {
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'modifiedBy': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'accessPackageResourceRole',
        'accessPackageResourceScope',
    ]


class accessPackageResource(entity):
    props = {
        'addedBy': Edm.String,
        'addedOn': Edm.DateTimeOffset,
        'attributes': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'isPendingOnboarding': Edm.Boolean,
        'originId': Edm.String,
        'originSystem': Edm.String,
        'resourceType': Edm.String,
        'url': Edm.String,
    }
    rels = [
        'accessPackageResourceEnvironment',
        'accessPackageResourceRoles',
        'accessPackageResourceScopes',
    ]


class accessPackage(entity):
    props = {
        'catalogId': Edm.String,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'isHidden': Edm.Boolean,
        'isRoleScopesVisible': Edm.Boolean,
        'modifiedBy': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'uniqueName': Edm.String,
    }
    rels = [
        'accessPackageAssignmentPolicies',
        'accessPackageCatalog',
        'accessPackageResourceRoleScopes',
        'accessPackagesIncompatibleWith',
        'incompatibleAccessPackages',
        'incompatibleGroups',
    ]


class connectedOrganization(entity):
    props = {
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'identitySources': Collection,
        'modifiedBy': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'state': connectedOrganizationState,
    }
    rels = [
        'externalSponsors',
        'internalSponsors',
    ]


class entitlementManagementSettings(entity):
    props = {
        'daysUntilExternalUserDeletedAfterBlocked': Edm.Int32,
        'externalUserLifecycleAction': Edm.String,
    }
    rels = [

    ]


class accessPackageSubject(entity):
    props = {
        'altSecId': Edm.String,
        'cleanupScheduledDateTime': Edm.DateTimeOffset,
        'connectedOrganizationId': Edm.String,
        'displayName': Edm.String,
        'email': Edm.String,
        'objectId': Edm.String,
        'onPremisesSecurityIdentifier': Edm.String,
        'principalName': Edm.String,
        'subjectLifecycle': accessPackageSubjectLifecycle,
        'type': Edm.String,
    }
    rels = [
        'connectedOrganization',
    ]


class permissionsRequestChange(entity):
    props = {
        'activeOccurrenceStatus': permissionsRequestOccurrenceStatus,
        'modificationDateTime': Edm.DateTimeOffset,
        'permissionsRequestId': Edm.String,
        'statusDetail': statusDetail,
        'ticketId': Edm.String,
    }
    rels = [

    ]


class scheduledPermissionsRequest(entity):
    props = {
        'action': unifiedRoleScheduleRequestActions,
        'createdDateTime': Edm.DateTimeOffset,
        'justification': Edm.String,
        'notes': Edm.String,
        'requestedPermissions': permissionsDefinition,
        'scheduleInfo': requestSchedule,
        'statusDetail': statusDetail,
        'ticketInfo': ticketInfo,
    }
    rels = [

    ]


class privilegedAccessGroup(entity):
    props = {

    }
    rels = [
        'assignmentApprovals',
        'assignmentScheduleInstances',
        'assignmentScheduleRequests',
        'assignmentSchedules',
        'eligibilityScheduleInstances',
        'eligibilityScheduleRequests',
        'eligibilitySchedules',
    ]


class privilegedAccessScheduleInstance(entity):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class privilegedAccessSchedule(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'createdUsing': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
        'scheduleInfo': requestSchedule,
        'status': Edm.String,
    }
    rels = [

    ]


class program(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [
        'controls',
    ]


class programControl(entity):
    props = {
        'controlId': Edm.String,
        'controlTypeId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'owner': userIdentity,
        'programId': Edm.String,
        'resource': programResource,
        'status': Edm.String,
    }
    rels = [
        'program',
    ]


class programControlType(entity):
    props = {
        'controlTypeGroupId': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class agreement(entity):
    props = {
        'displayName': Edm.String,
        'isPerDeviceAcceptanceRequired': Edm.Boolean,
        'isViewingBeforeAcceptanceRequired': Edm.Boolean,
        'termsExpiration': termsExpiration,
        'userReacceptRequiredFrequency': Edm.Duration,
    }
    rels = [
        'acceptances',
        'file',
        'files',
    ]


class agreementFileProperties(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'fileData': agreementFileData,
        'fileName': Edm.String,
        'isDefault': Edm.Boolean,
        'isMajorVersion': Edm.Boolean,
        'language': Edm.String,
    }
    rels = [

    ]


class identityProtectionRoot(object):
    props = {

    }
    rels = [
        'riskDetections',
        'riskyServicePrincipals',
        'riskyUsers',
        'servicePrincipalRiskDetections',
    ]


class riskDetection(entity):
    props = {
        'activity': activityType,
        'activityDateTime': Edm.DateTimeOffset,
        'additionalInfo': Edm.String,
        'correlationId': Edm.String,
        'detectedDateTime': Edm.DateTimeOffset,
        'detectionTimingType': riskDetectionTimingType,
        'ipAddress': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'location': signInLocation,
        'mitreTechniqueId': Edm.String,
        'requestId': Edm.String,
        'riskDetail': riskDetail,
        'riskEventType': Edm.String,
        'riskLevel': riskLevel,
        'riskState': riskState,
        'riskType': riskEventType,
        'source': Edm.String,
        'tokenIssuerType': tokenIssuerType,
        'userDisplayName': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class riskyServicePrincipal(entity):
    props = {
        'accountEnabled': Edm.Boolean,
        'appId': Edm.String,
        'displayName': Edm.String,
        'isEnabled': Edm.Boolean,
        'isProcessing': Edm.Boolean,
        'riskDetail': riskDetail,
        'riskLastUpdatedDateTime': Edm.DateTimeOffset,
        'riskLevel': riskLevel,
        'riskState': riskState,
        'servicePrincipalType': Edm.String,
    }
    rels = [
        'history',
    ]


class riskyUser(entity):
    props = {
        'isDeleted': Edm.Boolean,
        'isProcessing': Edm.Boolean,
        'riskDetail': riskDetail,
        'riskLastUpdatedDateTime': Edm.DateTimeOffset,
        'riskLevel': riskLevel,
        'riskState': riskState,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'history',
    ]


class servicePrincipalRiskDetection(entity):
    props = {
        'activity': activityType,
        'activityDateTime': Edm.DateTimeOffset,
        'additionalInfo': Edm.String,
        'appId': Edm.String,
        'correlationId': Edm.String,
        'detectedDateTime': Edm.DateTimeOffset,
        'detectionTimingType': riskDetectionTimingType,
        'ipAddress': Edm.String,
        'keyIds': Collection,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'location': signInLocation,
        'mitreTechniqueId': Edm.String,
        'requestId': Edm.String,
        'riskDetail': riskDetail,
        'riskEventType': Edm.String,
        'riskLevel': riskLevel,
        'riskState': riskState,
        'servicePrincipalDisplayName': Edm.String,
        'servicePrincipalId': Edm.String,
        'source': Edm.String,
        'tokenIssuerType': tokenIssuerType,
    }
    rels = [

    ]


class customExtensionHandler(entity):
    props = {
        'stage': accessPackageCustomExtensionStage,
    }
    rels = [
        'customExtension',
    ]


class customExtensionStageSetting(entity):
    props = {
        'stage': accessPackageCustomExtensionStage,
    }
    rels = [
        'customExtension',
    ]


class accessPackageResourceRole(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'originId': Edm.String,
        'originSystem': Edm.String,
    }
    rels = [
        'accessPackageResource',
    ]


class accessPackageResourceScope(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isRootScope': Edm.Boolean,
        'originId': Edm.String,
        'originSystem': Edm.String,
        'roleOriginId': Edm.String,
        'url': Edm.String,
    }
    rels = [
        'accessPackageResource',
    ]


class authorizationSystem(entity):
    props = {
        'authorizationSystemId': Edm.String,
        'authorizationSystemName': Edm.String,
        'authorizationSystemType': Edm.String,
    }
    rels = [
        'dataCollectionInfo',
    ]


class informationProtectionLabel(entity):
    props = {
        'color': Edm.String,
        'description': Edm.String,
        'isActive': Edm.Boolean,
        'name': Edm.String,
        'parent': parentLabelDetails,
        'sensitivity': Edm.Int32,
        'tooltip': Edm.String,
    }
    rels = [

    ]


class deviceManagementCachedReportConfiguration(entity):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'filter': Edm.String,
        'lastRefreshDateTime': Edm.DateTimeOffset,
        'metadata': Edm.String,
        'orderBy': Collection,
        'reportName': Edm.String,
        'select': Collection,
        'status': deviceManagementReportStatus,
    }
    rels = [

    ]


class deviceManagementExportJob(entity):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'filter': Edm.String,
        'format': deviceManagementReportFileFormat,
        'localizationType': deviceManagementExportJobLocalizationType,
        'reportName': Edm.String,
        'requestDateTime': Edm.DateTimeOffset,
        'search': Edm.String,
        'select': Collection,
        'snapshotId': Edm.String,
        'status': deviceManagementReportStatus,
        'url': Edm.String,
    }
    rels = [

    ]


class mobileApp(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'dependentAppCount': Edm.Int32,
        'description': Edm.String,
        'developer': Edm.String,
        'displayName': Edm.String,
        'informationUrl': Edm.String,
        'isAssigned': Edm.Boolean,
        'isFeatured': Edm.Boolean,
        'largeIcon': mimeContent,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'notes': Edm.String,
        'owner': Edm.String,
        'privacyInformationUrl': Edm.String,
        'publisher': Edm.String,
        'publishingState': mobileAppPublishingState,
        'roleScopeTagIds': Collection,
        'supersededAppCount': Edm.Int32,
        'supersedingAppCount': Edm.Int32,
        'uploadState': Edm.Int32,
    }
    rels = [
        'assignments',
        'categories',
        'relationships',
    ]


class managedDeviceMobileAppConfiguration(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'targetedMobileApps': Collection,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
        'deviceStatuses',
        'deviceStatusSummary',
        'userStatuses',
        'userStatusSummary',
    ]


class deviceAppManagement(entity):
    props = {
        'isEnabledForMicrosoftStoreForBusiness': Edm.Boolean,
        'microsoftStoreForBusinessLanguage': Edm.String,
        'microsoftStoreForBusinessLastCompletedApplicationSyncTime': Edm.DateTimeOffset,
        'microsoftStoreForBusinessLastSuccessfulSyncDateTime': Edm.DateTimeOffset,
        'microsoftStoreForBusinessPortalSelection': microsoftStoreForBusinessPortalSelectionOptions,
    }
    rels = [
        'managedEBookCategories',
        'enterpriseCodeSigningCertificates',
        'iosLobAppProvisioningConfigurations',
        'mobileAppCatalogPackages',
        'mobileAppCategories',
        'mobileAppConfigurations',
        'mobileAppRelationships',
        'mobileApps',
        'symantecCodeSigningCertificate',
        'managedEBooks',
        'policySets',
        'vppTokens',
        'windowsManagementApp',
        'androidManagedAppProtections',
        'defaultManagedAppProtections',
        'iosManagedAppProtections',
        'managedAppPolicies',
        'managedAppRegistrations',
        'managedAppStatuses',
        'mdmWindowsInformationProtectionPolicies',
        'targetedManagedAppConfigurations',
        'windowsInformationProtectionDeviceRegistrations',
        'windowsInformationProtectionPolicies',
        'windowsInformationProtectionWipeActions',
        'windowsManagedAppProtections',
        'deviceAppManagementTasks',
        'wdacSupplementalPolicies',
    ]


class managedEBookCategory(entity):
    props = {
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class enterpriseCodeSigningCertificate(entity):
    props = {
        'content': Edm.Binary,
        'expirationDateTime': Edm.DateTimeOffset,
        'issuer': Edm.String,
        'issuerName': Edm.String,
        'status': certificateStatus,
        'subject': Edm.String,
        'subjectName': Edm.String,
        'uploadDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class iosLobAppProvisioningConfiguration(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'payload': Edm.Binary,
        'payloadFileName': Edm.String,
        'roleScopeTagIds': Collection,
        'version': Edm.Int32,
    }
    rels = [
        'assignments',
        'deviceStatuses',
        'groupAssignments',
        'userStatuses',
    ]


class mobileAppCatalogPackage(entity):
    props = {
        'productDisplayName': Edm.String,
        'productId': Edm.String,
        'publisherDisplayName': Edm.String,
        'versionDisplayName': Edm.String,
    }
    rels = [

    ]


class mobileAppCategory(entity):
    props = {
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class mobileAppRelationship(entity):
    props = {
        'sourceDisplayName': Edm.String,
        'sourceDisplayVersion': Edm.String,
        'sourceId': Edm.String,
        'sourcePublisherDisplayName': Edm.String,
        'targetDisplayName': Edm.String,
        'targetDisplayVersion': Edm.String,
        'targetId': Edm.String,
        'targetPublisher': Edm.String,
        'targetPublisherDisplayName': Edm.String,
        'targetType': mobileAppRelationshipType,
    }
    rels = [

    ]


class symantecCodeSigningCertificate(entity):
    props = {
        'content': Edm.Binary,
        'expirationDateTime': Edm.DateTimeOffset,
        'issuer': Edm.String,
        'issuerName': Edm.String,
        'password': Edm.String,
        'status': certificateStatus,
        'subject': Edm.String,
        'subjectName': Edm.String,
        'uploadDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class managedEBook(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'informationUrl': Edm.String,
        'largeCover': mimeContent,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'privacyInformationUrl': Edm.String,
        'publishedDateTime': Edm.DateTimeOffset,
        'publisher': Edm.String,
    }
    rels = [
        'assignments',
        'categories',
        'deviceStates',
        'installSummary',
        'userStateSummary',
    ]


class policySet(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'errorCode': errorCode,
        'guidedDeploymentTags': Collection,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTags': Collection,
        'status': policySetStatus,
    }
    rels = [
        'assignments',
        'items',
    ]


class vppToken(entity):
    props = {
        'appleId': Edm.String,
        'automaticallyUpdateApps': Edm.Boolean,
        'claimTokenManagementFromExternalMdm': Edm.Boolean,
        'countryOrRegion': Edm.String,
        'dataSharingConsentGranted': Edm.Boolean,
        'displayName': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'lastSyncStatus': vppTokenSyncStatus,
        'locationName': Edm.String,
        'organizationName': Edm.String,
        'roleScopeTagIds': Collection,
        'state': vppTokenState,
        'token': Edm.String,
        'tokenActionResults': Collection,
        'vppTokenAccountType': vppTokenAccountType,
    }
    rels = [

    ]


class windowsManagementApp(entity):
    props = {
        'availableVersion': Edm.String,
        'managedInstaller': managedInstallerStatus,
        'managedInstallerConfiguredDateTime': Edm.String,
    }
    rels = [
        'healthStates',
    ]


class managedAppPolicy(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'version': Edm.String,
    }
    rels = [

    ]


class managedAppStatus(entity):
    props = {
        'displayName': Edm.String,
        'version': Edm.String,
    }
    rels = [

    ]


class windowsInformationProtectionWipeAction(entity):
    props = {
        'lastCheckInDateTime': Edm.DateTimeOffset,
        'status': actionState,
        'targetedDeviceMacAddress': Edm.String,
        'targetedDeviceName': Edm.String,
        'targetedDeviceRegistrationId': Edm.String,
        'targetedUserId': Edm.String,
    }
    rels = [

    ]


class deviceAppManagementTask(entity):
    props = {
        'assignedTo': Edm.String,
        'category': deviceAppManagementTaskCategory,
        'createdDateTime': Edm.DateTimeOffset,
        'creator': Edm.String,
        'creatorNotes': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'dueDateTime': Edm.DateTimeOffset,
        'priority': deviceAppManagementTaskPriority,
        'status': deviceAppManagementTaskStatus,
    }
    rels = [

    ]


class windowsDefenderApplicationControlSupplementalPolicy(entity):
    props = {
        'content': Edm.Binary,
        'contentFileName': Edm.String,
        'creationDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'roleScopeTagIds': Collection,
        'version': Edm.String,
    }
    rels = [
        'assignments',
        'deploySummary',
        'deviceStatuses',
    ]


class iosLobAppProvisioningConfigurationAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationDeviceStatus(entity):
    props = {
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'deviceDisplayName': Edm.String,
        'deviceModel': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'platform': Edm.Int32,
        'status': complianceStatus,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class mobileAppProvisioningConfigGroupAssignment(entity):
    props = {
        'targetGroupId': Edm.String,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationUserStatus(entity):
    props = {
        'devicesCount': Edm.Int32,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'status': complianceStatus,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class iosVppAppAssignedLicense(entity):
    props = {
        'userEmailAddress': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class macOsVppAppAssignedLicense(entity):
    props = {
        'userEmailAddress': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationDeviceSummary(entity):
    props = {
        'configurationVersion': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableCount': Edm.Int32,
        'notApplicablePlatformCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationUserSummary(entity):
    props = {
        'configurationVersion': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class mobileAppContent(entity):
    props = {

    }
    rels = [
        'containedApps',
        'files',
    ]


class mobileContainedApp(entity):
    props = {

    }
    rels = [

    ]


class mobileAppAssignment(entity):
    props = {
        'intent': installIntent,
        'settings': mobileAppAssignmentSettings,
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class mobileAppContentFile(entity):
    props = {
        'azureStorageUri': Edm.String,
        'azureStorageUriExpirationDateTime': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'isCommitted': Edm.Boolean,
        'isDependency': Edm.Boolean,
        'isFrameworkFile': Edm.Boolean,
        'manifest': Edm.Binary,
        'name': Edm.String,
        'size': Edm.Int64,
        'sizeEncrypted': Edm.Int64,
        'sizeEncryptedInBytes': Edm.Int64,
        'sizeInBytes': Edm.Int64,
        'uploadState': mobileAppContentFileUploadState,
    }
    rels = [

    ]


class mobileAppInstallStatus(entity):
    props = {
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'displayVersion': Edm.String,
        'errorCode': Edm.Int32,
        'installState': resultantAppState,
        'installStateDetail': resultantAppStateDetail,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'mobileAppInstallStatusValue': resultantAppState,
        'osDescription': Edm.String,
        'osVersion': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'app',
    ]


class mobileAppInstallSummary(entity):
    props = {
        'failedDeviceCount': Edm.Int32,
        'failedUserCount': Edm.Int32,
        'installedDeviceCount': Edm.Int32,
        'installedUserCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'notApplicableUserCount': Edm.Int32,
        'notInstalledDeviceCount': Edm.Int32,
        'notInstalledUserCount': Edm.Int32,
        'pendingInstallDeviceCount': Edm.Int32,
        'pendingInstallUserCount': Edm.Int32,
    }
    rels = [

    ]


class userAppInstallStatus(entity):
    props = {
        'failedDeviceCount': Edm.Int32,
        'installedDeviceCount': Edm.Int32,
        'notInstalledDeviceCount': Edm.Int32,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'app',
        'deviceStatuses',
    ]


class deviceInstallState(entity):
    props = {
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'errorCode': Edm.String,
        'installState': installState,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'osDescription': Edm.String,
        'osVersion': Edm.String,
        'userName': Edm.String,
    }
    rels = [

    ]


class eBookInstallSummary(entity):
    props = {
        'failedDeviceCount': Edm.Int32,
        'failedUserCount': Edm.Int32,
        'installedDeviceCount': Edm.Int32,
        'installedUserCount': Edm.Int32,
        'notInstalledDeviceCount': Edm.Int32,
        'notInstalledUserCount': Edm.Int32,
    }
    rels = [

    ]


class managedEBookAssignment(entity):
    props = {
        'installIntent': installIntent,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class userInstallStateSummary(entity):
    props = {
        'failedDeviceCount': Edm.Int32,
        'installedDeviceCount': Edm.Int32,
        'notInstalledDeviceCount': Edm.Int32,
        'userName': Edm.String,
    }
    rels = [
        'deviceStates',
    ]


class managedMobileApp(entity):
    props = {
        'mobileAppIdentifier': mobileAppIdentifier,
        'version': Edm.String,
    }
    rels = [

    ]


class managedAppPolicyDeploymentSummary(entity):
    props = {
        'configurationDeployedUserCount': Edm.Int32,
        'configurationDeploymentSummaryPerApp': Collection,
        'displayName': Edm.String,
        'lastRefreshTime': Edm.DateTimeOffset,
        'version': Edm.String,
    }
    rels = [

    ]


class deviceCompliancePolicyAssignment(entity):
    props = {
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class settingStateDeviceSummary(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'conflictDeviceCount': Edm.Int32,
        'errorDeviceCount': Edm.Int32,
        'instancePath': Edm.String,
        'nonCompliantDeviceCount': Edm.Int32,
        'notApplicableDeviceCount': Edm.Int32,
        'remediatedDeviceCount': Edm.Int32,
        'settingName': Edm.String,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class deviceComplianceDeviceStatus(entity):
    props = {
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'deviceDisplayName': Edm.String,
        'deviceModel': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'platform': Edm.Int32,
        'status': complianceStatus,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceComplianceDeviceOverview(entity):
    props = {
        'configurationVersion': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableCount': Edm.Int32,
        'notApplicablePlatformCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class deviceComplianceScheduledActionForRule(entity):
    props = {
        'ruleName': Edm.String,
    }
    rels = [
        'scheduledActionConfigurations',
    ]


class deviceComplianceUserStatus(entity):
    props = {
        'devicesCount': Edm.Int32,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'status': complianceStatus,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceComplianceUserOverview(entity):
    props = {
        'configurationVersion': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class policySetItem(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'errorCode': errorCode,
        'guidedDeploymentTags': Collection,
        'itemType': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'payloadId': Edm.String,
        'status': policySetStatus,
    }
    rels = [

    ]


class deviceConfigurationAssignment(entity):
    props = {
        'intent': deviceConfigAssignmentIntent,
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceConfigurationDeviceStatus(entity):
    props = {
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'deviceDisplayName': Edm.String,
        'deviceModel': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'platform': Edm.Int32,
        'status': complianceStatus,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceConfigurationDeviceOverview(entity):
    props = {
        'configurationVersion': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableCount': Edm.Int32,
        'notApplicablePlatformCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class deviceConfigurationGroupAssignment(entity):
    props = {
        'excludeGroup': Edm.Boolean,
        'targetGroupId': Edm.String,
    }
    rels = [
        'deviceConfiguration',
    ]


class deviceConfigurationUserStatus(entity):
    props = {
        'devicesCount': Edm.Int32,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'status': complianceStatus,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceConfigurationUserOverview(entity):
    props = {
        'configurationVersion': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableCount': Edm.Int32,
        'pendingCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class enrollmentConfigurationAssignment(entity):
    props = {
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceManagementScriptAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceManagementScriptDeviceState(entity):
    props = {
        'errorCode': Edm.Int32,
        'errorDescription': Edm.String,
        'lastStateUpdateDateTime': Edm.DateTimeOffset,
        'resultMessage': Edm.String,
        'runState': runState,
    }
    rels = [
        'managedDevice',
    ]


class deviceManagementScriptGroupAssignment(entity):
    props = {
        'targetGroupId': Edm.String,
    }
    rels = [

    ]


class deviceManagementScriptRunSummary(entity):
    props = {
        'errorDeviceCount': Edm.Int32,
        'errorUserCount': Edm.Int32,
        'successDeviceCount': Edm.Int32,
        'successUserCount': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementScriptUserState(entity):
    props = {
        'errorDeviceCount': Edm.Int32,
        'successDeviceCount': Edm.Int32,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'deviceRunStates',
    ]


class policySetAssignment(entity):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class targetedManagedAppPolicyAssignment(entity):
    props = {
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class windowsAutopilotDeploymentProfileAssignment(entity):
    props = {
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class termsAndConditionsAcceptanceStatus(entity):
    props = {
        'acceptedDateTime': Edm.DateTimeOffset,
        'acceptedVersion': Edm.Int32,
        'userDisplayName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'termsAndConditions',
    ]


class termsAndConditionsAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class termsAndConditionsGroupAssignment(entity):
    props = {
        'targetGroupId': Edm.String,
    }
    rels = [
        'termsAndConditions',
    ]


class advancedThreatProtectionOnboardingDeviceSettingState(entity):
    props = {
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'deviceId': Edm.String,
        'deviceModel': Edm.String,
        'deviceName': Edm.String,
        'platformType': deviceType,
        'setting': Edm.String,
        'settingName': Edm.String,
        'state': complianceStatus,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class androidDeviceComplianceLocalActionBase(entity):
    props = {
        'gracePeriodInMinutes': Edm.Int32,
    }
    rels = [

    ]


class managedDeviceCertificateState(entity):
    props = {
        'certificateEnhancedKeyUsage': Edm.String,
        'certificateErrorCode': Edm.Int32,
        'certificateExpirationDateTime': Edm.DateTimeOffset,
        'certificateIssuanceDateTime': Edm.DateTimeOffset,
        'certificateIssuanceState': certificateIssuanceStates,
        'certificateIssuer': Edm.String,
        'certificateKeyLength': Edm.Int32,
        'certificateKeyStorageProvider': keyStorageProviderOption,
        'certificateKeyUsage': keyUsages,
        'certificateLastIssuanceStateChangedDateTime': Edm.DateTimeOffset,
        'certificateProfileDisplayName': Edm.String,
        'certificateRevokeStatus': certificateRevocationStatus,
        'certificateSerialNumber': Edm.String,
        'certificateSubjectAlternativeNameFormat': subjectAlternativeNameType,
        'certificateSubjectAlternativeNameFormatString': Edm.String,
        'certificateSubjectNameFormat': subjectNameFormat,
        'certificateSubjectNameFormatString': Edm.String,
        'certificateThumbprint': Edm.String,
        'certificateValidityPeriod': Edm.Int32,
        'certificateValidityPeriodUnits': certificateValidityPeriodScale,
        'deviceDisplayName': Edm.String,
        'devicePlatform': devicePlatformType,
        'lastCertificateStateChangeDateTime': Edm.DateTimeOffset,
        'userDisplayName': Edm.String,
    }
    rels = [

    ]


class deviceComplianceActionItem(entity):
    props = {
        'actionType': deviceComplianceActionType,
        'gracePeriodHours': Edm.Int32,
        'notificationMessageCCList': Collection,
        'notificationTemplateId': Edm.String,
    }
    rels = [

    ]


class deviceCompliancePolicyGroupAssignment(entity):
    props = {
        'excludeGroup': Edm.Boolean,
        'targetGroupId': Edm.String,
    }
    rels = [
        'deviceCompliancePolicy',
    ]


class deviceComplianceSettingState(entity):
    props = {
        'complianceGracePeriodExpirationDateTime': Edm.DateTimeOffset,
        'deviceId': Edm.String,
        'deviceModel': Edm.String,
        'deviceName': Edm.String,
        'platformType': deviceType,
        'setting': Edm.String,
        'settingName': Edm.String,
        'state': complianceStatus,
        'userEmail': Edm.String,
        'userId': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceSetupConfiguration(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'version': Edm.Int32,
    }
    rels = [

    ]


class hardwareConfigurationAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class hardwareConfigurationDeviceState(entity):
    props = {
        'assignmentFilterIds': Edm.String,
        'configurationError': Edm.String,
        'configurationOutput': Edm.String,
        'configurationState': runState,
        'deviceName': Edm.String,
        'internalVersion': Edm.Int32,
        'lastStateUpdateDateTime': Edm.DateTimeOffset,
        'osVersion': Edm.String,
        'upn': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class hardwareConfigurationRunSummary(entity):
    props = {
        'errorDeviceCount': Edm.Int32,
        'errorUserCount': Edm.Int32,
        'failedDeviceCount': Edm.Int32,
        'failedUserCount': Edm.Int32,
        'lastRunDateTime': Edm.DateTimeOffset,
        'notApplicableDeviceCount': Edm.Int32,
        'notApplicableUserCount': Edm.Int32,
        'pendingDeviceCount': Edm.Int32,
        'pendingUserCount': Edm.Int32,
        'successfulDeviceCount': Edm.Int32,
        'successfulUserCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
        'unknownUserCount': Edm.Int32,
    }
    rels = [

    ]


class hardwareConfigurationUserState(entity):
    props = {
        'errorDeviceCount': Edm.Int32,
        'failedDeviceCount': Edm.Int32,
        'lastStateUpdateDateTime': Edm.DateTimeOffset,
        'notApplicableDeviceCount': Edm.Int32,
        'pendingDeviceCount': Edm.Int32,
        'successfulDeviceCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
        'upn': Edm.String,
        'userEmail': Edm.String,
        'userName': Edm.String,
    }
    rels = [

    ]


class macOSSoftwareUpdateCategorySummary(entity):
    props = {
        'deviceId': Edm.String,
        'displayName': Edm.String,
        'failedUpdateCount': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'successfulUpdateCount': Edm.Int32,
        'totalUpdateCount': Edm.Int32,
        'updateCategory': macOSSoftwareUpdateCategory,
        'userId': Edm.String,
    }
    rels = [
        'updateStateSummaries',
    ]


class macOSSoftwareUpdateStateSummary(entity):
    props = {
        'displayName': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'productKey': Edm.String,
        'state': macOSSoftwareUpdateState,
        'updateCategory': macOSSoftwareUpdateCategory,
        'updateVersion': Edm.String,
    }
    rels = [

    ]


class windowsPrivacyDataAccessControlItem(entity):
    props = {
        'accessLevel': windowsPrivacyDataAccessLevel,
        'appDisplayName': Edm.String,
        'appPackageFamilyName': Edm.String,
        'dataCategory': windowsPrivacyDataCategory,
    }
    rels = [

    ]


class windowsAssignedAccessProfile(entity):
    props = {
        'appUserModelIds': Collection,
        'desktopAppPaths': Collection,
        'profileName': Edm.String,
        'showTaskBar': Edm.Boolean,
        'startMenuLayoutXml': Edm.Binary,
        'userAccounts': Collection,
    }
    rels = [

    ]


class windowsUpdateState(entity):
    props = {
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'featureUpdateVersion': Edm.String,
        'lastScanDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'qualityUpdateVersion': Edm.String,
        'status': windowsUpdateStatus,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceManagementComplianceActionItem(entity):
    props = {
        'actionType': deviceManagementComplianceActionType,
        'gracePeriodHours': Edm.Int32,
        'notificationMessageCCList': Collection,
        'notificationTemplateId': Edm.String,
    }
    rels = [

    ]


class deviceManagementConfigurationPolicyAssignment(entity):
    props = {
        'source': deviceAndAppManagementAssignmentSource,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceManagementComplianceScheduledActionForRule(entity):
    props = {
        'ruleName': Edm.String,
    }
    rels = [
        'scheduledActionConfigurations',
    ]


class deviceManagementConfigurationSetting(entity):
    props = {
        'settingInstance': deviceManagementConfigurationSettingInstance,
    }
    rels = [
        'settingDefinitions',
    ]


class deviceManagementSettingInstance(entity):
    props = {
        'definitionId': Edm.String,
        'valueJson': Edm.String,
    }
    rels = [

    ]


class deviceManagementIntentAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceManagementIntentDeviceSettingStateSummary(entity):
    props = {
        'compliantCount': Edm.Int32,
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'nonCompliantCount': Edm.Int32,
        'notApplicableCount': Edm.Int32,
        'remediatedCount': Edm.Int32,
        'settingName': Edm.String,
    }
    rels = [

    ]


class deviceManagementIntentDeviceState(entity):
    props = {
        'deviceDisplayName': Edm.String,
        'deviceId': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'state': complianceStatus,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceManagementIntentDeviceStateSummary(entity):
    props = {
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'notApplicableCount': Edm.Int32,
        'notApplicablePlatformCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementIntentUserState(entity):
    props = {
        'deviceCount': Edm.Int32,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'state': complianceStatus,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class deviceManagementIntentUserStateSummary(entity):
    props = {
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'failedCount': Edm.Int32,
        'notApplicableCount': Edm.Int32,
        'successCount': Edm.Int32,
    }
    rels = [

    ]


class securityBaselineStateSummary(entity):
    props = {
        'conflictCount': Edm.Int32,
        'errorCount': Edm.Int32,
        'notApplicableCount': Edm.Int32,
        'notSecureCount': Edm.Int32,
        'secureCount': Edm.Int32,
        'unknownCount': Edm.Int32,
    }
    rels = [

    ]


class securityBaselineDeviceState(entity):
    props = {
        'deviceDisplayName': Edm.String,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'state': securityBaselineComplianceState,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class securityBaselineSettingState(entity):
    props = {
        'contributingPolicies': Collection,
        'errorCode': Edm.String,
        'settingCategoryId': Edm.String,
        'settingCategoryName': Edm.String,
        'settingId': Edm.String,
        'settingName': Edm.String,
        'sourcePolicies': Collection,
        'state': securityBaselineComplianceState,
    }
    rels = [

    ]


class appLogCollectionRequest(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'customLogFolders': Collection,
        'errorMessage': Edm.String,
        'status': appLogUploadState,
    }
    rels = [

    ]


class deviceHealthScriptAssignment(entity):
    props = {
        'runRemediationScript': Edm.Boolean,
        'runSchedule': deviceHealthScriptRunSchedule,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class deviceComplianceScriptDeviceState(entity):
    props = {
        'detectionState': runState,
        'expectedStateUpdateDateTime': Edm.DateTimeOffset,
        'lastStateUpdateDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'scriptError': Edm.String,
        'scriptOutput': Edm.String,
    }
    rels = [
        'managedDevice',
    ]


class deviceComplianceScriptRunSummary(entity):
    props = {
        'detectionScriptErrorDeviceCount': Edm.Int32,
        'detectionScriptPendingDeviceCount': Edm.Int32,
        'issueDetectedDeviceCount': Edm.Int32,
        'lastScriptRunDateTime': Edm.DateTimeOffset,
        'noIssueDetectedDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class deviceHealthScriptDeviceState(entity):
    props = {
        'assignmentFilterIds': Collection,
        'detectionState': runState,
        'expectedStateUpdateDateTime': Edm.DateTimeOffset,
        'lastStateUpdateDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'postRemediationDetectionScriptError': Edm.String,
        'postRemediationDetectionScriptOutput': Edm.String,
        'preRemediationDetectionScriptError': Edm.String,
        'preRemediationDetectionScriptOutput': Edm.String,
        'remediationScriptError': Edm.String,
        'remediationState': remediationState,
    }
    rels = [
        'managedDevice',
    ]


class deviceHealthScriptRunSummary(entity):
    props = {
        'detectionScriptErrorDeviceCount': Edm.Int32,
        'detectionScriptNotApplicableDeviceCount': Edm.Int32,
        'detectionScriptPendingDeviceCount': Edm.Int32,
        'issueDetectedDeviceCount': Edm.Int32,
        'issueRemediatedCumulativeDeviceCount': Edm.Int32,
        'issueRemediatedDeviceCount': Edm.Int32,
        'issueReoccurredDeviceCount': Edm.Int32,
        'lastScriptRunDateTime': Edm.DateTimeOffset,
        'noIssueDetectedDeviceCount': Edm.Int32,
        'remediationScriptErrorDeviceCount': Edm.Int32,
        'remediationSkippedDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class malwareStateForWindowsDevice(entity):
    props = {
        'detectionCount': Edm.Int32,
        'deviceName': Edm.String,
        'executionState': windowsMalwareExecutionState,
        'initialDetectionDateTime': Edm.DateTimeOffset,
        'lastStateChangeDateTime': Edm.DateTimeOffset,
        'threatState': windowsMalwareThreatState,
    }
    rels = [

    ]


class userExperienceAnalyticsMetric(entity):
    props = {
        'unit': Edm.String,
        'value': Edm.Double,
    }
    rels = [

    ]


class userExperienceAnalyticsWorkFromAnywhereDevice(entity):
    props = {
        'autoPilotProfileAssigned': Edm.Boolean,
        'autoPilotRegistered': Edm.Boolean,
        'azureAdDeviceId': Edm.String,
        'azureAdJoinType': Edm.String,
        'azureAdRegistered': Edm.Boolean,
        'cloudIdentityScore': Edm.Double,
        'cloudManagementScore': Edm.Double,
        'cloudProvisioningScore': Edm.Double,
        'compliancePolicySetToIntune': Edm.Boolean,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'healthStatus': userExperienceAnalyticsHealthState,
        'isCloudManagedGatewayEnabled': Edm.Boolean,
        'managedBy': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'osCheckFailed': Edm.Boolean,
        'osDescription': Edm.String,
        'osVersion': Edm.String,
        'otherWorkloadsSetToIntune': Edm.Boolean,
        'ownership': Edm.String,
        'processor64BitCheckFailed': Edm.Boolean,
        'processorCoreCountCheckFailed': Edm.Boolean,
        'processorFamilyCheckFailed': Edm.Boolean,
        'processorSpeedCheckFailed': Edm.Boolean,
        'ramCheckFailed': Edm.Boolean,
        'secureBootCheckFailed': Edm.Boolean,
        'serialNumber': Edm.String,
        'storageCheckFailed': Edm.Boolean,
        'tenantAttached': Edm.Boolean,
        'tpmCheckFailed': Edm.Boolean,
        'upgradeEligibility': operatingSystemUpgradeEligibility,
        'windowsScore': Edm.Double,
        'workFromAnywhereScore': Edm.Double,
    }
    rels = [

    ]


class windowsDeviceMalwareState(entity):
    props = {
        'additionalInformationUrl': Edm.String,
        'category': windowsMalwareCategory,
        'detectionCount': Edm.Int32,
        'displayName': Edm.String,
        'executionState': windowsMalwareExecutionState,
        'initialDetectionDateTime': Edm.DateTimeOffset,
        'lastStateChangeDateTime': Edm.DateTimeOffset,
        'severity': windowsMalwareSeverity,
        'state': windowsMalwareState,
        'threatState': windowsMalwareThreatState,
    }
    rels = [

    ]


class windowsManagementAppHealthState(entity):
    props = {
        'deviceName': Edm.String,
        'deviceOSVersion': Edm.String,
        'healthState': healthState,
        'installedVersion': Edm.String,
        'lastCheckInDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class windowsManagementAppHealthSummary(entity):
    props = {
        'healthyDeviceCount': Edm.Int32,
        'unhealthyDeviceCount': Edm.Int32,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementResourceAccessProfileAssignment(entity):
    props = {
        'intent': deviceManagementResourceAccessProfileIntent,
        'sourceId': Edm.String,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class appleEnrollmentProfileAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class enrollmentProfile(entity):
    props = {
        'configurationEndpointUrl': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'enableAuthenticationViaCompanyPortal': Edm.Boolean,
        'requireCompanyPortalOnSetupAssistantEnrolledDevices': Edm.Boolean,
        'requiresUserAuthentication': Edm.Boolean,
    }
    rels = [

    ]


class importedAppleDeviceIdentity(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'discoverySource': discoverySource,
        'enrollmentState': enrollmentState,
        'isDeleted': Edm.Boolean,
        'isSupervised': Edm.Boolean,
        'lastContactedDateTime': Edm.DateTimeOffset,
        'platform': platform,
        'requestedEnrollmentProfileAssignmentDateTime': Edm.DateTimeOffset,
        'requestedEnrollmentProfileId': Edm.String,
        'serialNumber': Edm.String,
    }
    rels = [

    ]


class importedWindowsAutopilotDeviceIdentityUpload(entity):
    props = {
        'createdDateTimeUtc': Edm.DateTimeOffset,
        'status': importedWindowsAutopilotDeviceIdentityUploadStatus,
    }
    rels = [
        'deviceIdentities',
    ]


class groupPolicySettingMapping(entity):
    props = {
        'admxSettingDefinitionId': Edm.String,
        'childIdList': Collection,
        'intuneSettingDefinitionId': Edm.String,
        'intuneSettingUriList': Collection,
        'isMdmSupported': Edm.Boolean,
        'mdmCspName': Edm.String,
        'mdmMinimumOSVersion': Edm.Int32,
        'mdmSettingUri': Edm.String,
        'mdmSupportedState': mdmSupportedState,
        'parentId': Edm.String,
        'settingCategory': Edm.String,
        'settingDisplayName': Edm.String,
        'settingDisplayValue': Edm.String,
        'settingDisplayValueType': Edm.String,
        'settingName': Edm.String,
        'settingScope': groupPolicySettingScope,
        'settingType': groupPolicySettingType,
        'settingValue': Edm.String,
        'settingValueDisplayUnits': Edm.String,
        'settingValueType': Edm.String,
    }
    rels = [

    ]


class unsupportedGroupPolicyExtension(entity):
    props = {
        'extensionType': Edm.String,
        'namespaceUrl': Edm.String,
        'nodeName': Edm.String,
        'settingScope': groupPolicySettingScope,
    }
    rels = [

    ]


class groupPolicyConfigurationAssignment(entity):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class groupPolicyDefinitionValue(entity):
    props = {
        'configurationType': groupPolicyConfigurationType,
        'createdDateTime': Edm.DateTimeOffset,
        'enabled': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'definition',
        'presentationValues',
    ]


class groupPolicyPresentation(entity):
    props = {
        'label': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'definition',
    ]


class groupPolicyPresentationValue(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'definitionValue',
        'presentation',
    ]


class groupPolicyOperation(entity):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'operationStatus': groupPolicyOperationStatus,
        'operationType': groupPolicyOperationType,
        'statusDetails': Edm.String,
    }
    rels = [

    ]


class managedAppOperation(entity):
    props = {
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'state': Edm.String,
        'version': Edm.String,
    }
    rels = [

    ]


class windowsInformationProtectionAppLockerFile(entity):
    props = {
        'displayName': Edm.String,
        'file': Edm.Binary,
        'fileHash': Edm.String,
        'version': Edm.String,
    }
    rels = [

    ]


class microsoftTunnelServer(entity):
    props = {
        'agentImageDigest': Edm.String,
        'deploymentMode': microsoftTunnelDeploymentMode,
        'displayName': Edm.String,
        'lastCheckinDateTime': Edm.DateTimeOffset,
        'serverImageDigest': Edm.String,
        'tunnelServerHealthStatus': microsoftTunnelServerHealthStatus,
    }
    rels = [

    ]


class localizedNotificationMessage(entity):
    props = {
        'isDefault': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'locale': Edm.String,
        'messageTemplate': Edm.String,
        'subject': Edm.String,
    }
    rels = [

    ]


class appVulnerabilityManagedDevice(entity):
    props = {
        'displayName': Edm.String,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
    }
    rels = [

    ]


class appVulnerabilityMobileApp(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'mobileAppId': Edm.String,
        'mobileAppType': Edm.String,
        'version': Edm.String,
    }
    rels = [

    ]


class vulnerableManagedDevice(entity):
    props = {
        'displayName': Edm.String,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
    }
    rels = [

    ]


class roleScopeTagAutoAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class embeddedSIMActivationCodePoolAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class embeddedSIMDeviceState(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'deviceName': Edm.String,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'modifiedDateTime': Edm.DateTimeOffset,
        'state': embeddedSIMDeviceStateValue,
        'stateDetails': Edm.String,
        'universalIntegratedCircuitCardIdentifier': Edm.String,
        'userName': Edm.String,
    }
    rels = [

    ]


class deviceManagementAutopilotPolicyStatusDetail(entity):
    props = {
        'complianceStatus': deviceManagementAutopilotPolicyComplianceStatus,
        'displayName': Edm.String,
        'errorCode': Edm.Int32,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'policyType': deviceManagementAutopilotPolicyType,
        'trackedOnEnrollmentStatus': Edm.Boolean,
    }
    rels = [

    ]


class windowsDefenderApplicationControlSupplementalPolicyAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class windowsDefenderApplicationControlSupplementalPolicyDeploymentSummary(entity):
    props = {
        'deployedDeviceCount': Edm.Int32,
        'failedDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class windowsDefenderApplicationControlSupplementalPolicyDeploymentStatus(entity):
    props = {
        'deploymentStatus': windowsDefenderApplicationControlSupplementalPolicyStatuses,
        'deviceId': Edm.String,
        'deviceName': Edm.String,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'osDescription': Edm.String,
        'osVersion': Edm.String,
        'policyVersion': Edm.String,
        'userName': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [
        'policy',
    ]


class windowsDriverUpdateInventory(entity):
    props = {
        'applicableDeviceCount': Edm.Int32,
        'approvalStatus': driverApprovalStatus,
        'category': driverCategory,
        'deployDateTime': Edm.DateTimeOffset,
        'driverClass': Edm.String,
        'manufacturer': Edm.String,
        'name': Edm.String,
        'releaseDateTime': Edm.DateTimeOffset,
        'version': Edm.String,
    }
    rels = [

    ]


class windowsDriverUpdateProfileAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class windowsFeatureUpdateProfileAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class windowsQualityUpdatePolicyAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class windowsQualityUpdateProfileAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class intuneBrandingProfileAssignment(entity):
    props = {
        'target': deviceAndAppManagementAssignmentTarget,
    }
    rels = [

    ]


class m365AppsInstallationOptions(entity):
    props = {
        'appsForMac': appsInstallationOptionsForMac,
        'appsForWindows': appsInstallationOptionsForWindows,
        'updateChannel': appsUpdateChannelType,
    }
    rels = [

    ]


class serviceHealth(entity):
    props = {
        'service': Edm.String,
        'status': serviceHealthStatus,
    }
    rels = [
        'issues',
    ]


class serviceAnnouncementBase(entity):
    props = {
        'details': Collection,
        'endDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'title': Edm.String,
    }
    rels = [

    ]


class serviceAnnouncementAttachment(entity):
    props = {
        'content': Edm.Stream,
        'contentType': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'size': Edm.Int32,
    }
    rels = [

    ]


class uxSetting(entity):
    props = {
        'restrictNonAdminAccess': nonAdminSetting,
    }
    rels = [

    ]


class dataCollectionInfo(entity):
    props = {
        'entitlements': entitlementsDataCollectionInfo,
    }
    rels = [

    ]


class authorizationSystemTypeAction(entity):
    props = {
        'actionType': authorizationSystemActionType,
        'externalId': Edm.String,
        'resourceTypes': Collection,
        'severity': authorizationSystemActionSeverity,
    }
    rels = [

    ]


class awsPolicy(entity):
    props = {
        'awsPolicyType': awsPolicyType,
        'displayName': Edm.String,
        'externalId': Edm.String,
    }
    rels = [

    ]


class authorizationSystemResource(entity):
    props = {
        'displayName': Edm.String,
        'externalId': Edm.String,
        'resourceType': Edm.String,
    }
    rels = [
        'authorizationSystem',
    ]


class authorizationSystemTypeService(entity):
    props = {

    }
    rels = [
        'actions',
    ]


class azureRoleDefinition(entity):
    props = {
        'assignableScopes': Collection,
        'azureRoleDefinitionType': azureRoleDefinitionType,
        'displayName': Edm.String,
        'externalId': Edm.String,
    }
    rels = [

    ]


class gcpRole(entity):
    props = {
        'displayName': Edm.String,
        'externalId': Edm.String,
        'gcpRoleType': gcpRoleType,
        'scopes': Collection,
    }
    rels = [

    ]


class authorizationSystemIdentity(entity):
    props = {
        'displayName': Edm.String,
        'externalId': Edm.String,
        'source': authorizationSystemIdentitySource,
    }
    rels = [
        'authorizationSystem',
    ]


class assignedComputeInstanceDetails(entity):
    props = {

    }
    rels = [
        'accessedStorageBuckets',
        'assignedComputeInstance',
    ]


class finding(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class virtualMachineDetails(entity):
    props = {

    }
    rels = [
        'virtualMachine',
    ]


class permissionsAnalytics(entity):
    props = {

    }
    rels = [
        'findings',
        'permissionsCreepIndexDistributions',
    ]


class permissionsCreepIndexDistribution(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'highRiskProfile': riskProfile,
        'lowRiskProfile': riskProfile,
        'mediumRiskProfile': riskProfile,
    }
    rels = [
        'authorizationSystem',
    ]


class privilegeEscalation(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [
        'actions',
        'resources',
    ]


class awsStatement(object):
    props = {
        'actions': Collection,
        'condition': awsCondition,
        'effect': awsStatementEffect,
        'notActions': Collection,
        'notResources': Collection,
        'resources': Collection,
        'statementId': Edm.String,
    }
    rels = [

    ]


class permissionsDefinitionAwsPolicy(entity):
    props = {

    }
    rels = [

    ]


class permissionsDefinitionAzureRole(entity):
    props = {

    }
    rels = [

    ]


class permissionsDefinitionGcpRole(entity):
    props = {

    }
    rels = [

    ]


class permissionsDefinitionAuthorizationSystemIdentity(object):
    props = {
        'externalId': Edm.String,
        'identityType': permissionsDefinitionIdentityType,
        'source': permissionsDefinitionIdentitySource,
    }
    rels = [

    ]


class account(object):
    props = {
        'blocked': Edm.Boolean,
        'category': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'subCategory': Edm.String,
    }
    rels = [

    ]


class agedAccountsPayable(object):
    props = {
        'agedAsOfDate': Edm.Date,
        'balanceDue': Edm.Decimal,
        'currencyCode': Edm.String,
        'currentAmount': Edm.Decimal,
        'id': Edm.Guid,
        'name': Edm.String,
        'period1Amount': Edm.Decimal,
        'period2Amount': Edm.Decimal,
        'period3Amount': Edm.Decimal,
        'periodLengthFilter': Edm.String,
        'vendorId': Edm.String,
        'vendorNumber': Edm.String,
    }
    rels = [

    ]


class agedAccountsReceivable(object):
    props = {
        'agedAsOfDate': Edm.Date,
        'balanceDue': Edm.Decimal,
        'currencyCode': Edm.String,
        'currentAmount': Edm.Decimal,
        'customerId': Edm.String,
        'customerNumber': Edm.String,
        'id': Edm.Guid,
        'name': Edm.String,
        'period1Amount': Edm.Decimal,
        'period2Amount': Edm.Decimal,
        'period3Amount': Edm.Decimal,
        'periodLengthFilter': Edm.String,
    }
    rels = [

    ]


class company(object):
    props = {
        'businessProfileId': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'name': Edm.String,
        'systemVersion': Edm.String,
    }
    rels = [
        'accounts',
        'agedAccountsPayable',
        'agedAccountsReceivable',
        'companyInformation',
        'countriesRegions',
        'currencies',
        'customerPaymentJournals',
        'customerPayments',
        'customers',
        'dimensions',
        'dimensionValues',
        'employees',
        'generalLedgerEntries',
        'itemCategories',
        'items',
        'journalLines',
        'journals',
        'paymentMethods',
        'paymentTerms',
        'picture',
        'purchaseInvoiceLines',
        'purchaseInvoices',
        'salesCreditMemoLines',
        'salesCreditMemos',
        'salesInvoiceLines',
        'salesInvoices',
        'salesOrderLines',
        'salesOrders',
        'salesQuoteLines',
        'salesQuotes',
        'shipmentMethods',
        'taxAreas',
        'taxGroups',
        'unitsOfMeasure',
        'vendors',
    ]


class companyInformation(object):
    props = {
        'address': postalAddressType,
        'currencyCode': Edm.String,
        'currentFiscalYearStartDate': Edm.Date,
        'displayName': Edm.String,
        'email': Edm.String,
        'faxNumber': Edm.String,
        'id': Edm.Guid,
        'industry': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'phoneNumber': Edm.String,
        'picture': Edm.Stream,
        'taxRegistrationNumber': Edm.String,
        'website': Edm.String,
    }
    rels = [

    ]


class countryRegion(object):
    props = {
        'addressFormat': Edm.String,
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class currency(object):
    props = {
        'amountDecimalPlaces': Edm.String,
        'amountRoundingPrecision': Edm.Decimal,
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'symbol': Edm.String,
    }
    rels = [

    ]


class customerPaymentJournal(object):
    props = {
        'balancingAccountId': Edm.Guid,
        'balancingAccountNumber': Edm.String,
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'account',
        'customerPayments',
    ]


class customerPayment(object):
    props = {
        'amount': Edm.Decimal,
        'appliesToInvoiceId': Edm.Guid,
        'appliesToInvoiceNumber': Edm.String,
        'comment': Edm.String,
        'contactId': Edm.String,
        'customerId': Edm.Guid,
        'customerNumber': Edm.String,
        'description': Edm.String,
        'documentNumber': Edm.String,
        'externalDocumentNumber': Edm.String,
        'id': Edm.Guid,
        'journalDisplayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lineNumber': Edm.Int32,
        'postingDate': Edm.Date,
    }
    rels = [
        'customer',
    ]


class customer(object):
    props = {
        'address': postalAddressType,
        'blocked': Edm.String,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'displayName': Edm.String,
        'email': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'paymentMethodId': Edm.Guid,
        'paymentTermsId': Edm.Guid,
        'phoneNumber': Edm.String,
        'shipmentMethodId': Edm.Guid,
        'taxAreaDisplayName': Edm.String,
        'taxAreaId': Edm.Guid,
        'taxLiable': Edm.Boolean,
        'taxRegistrationNumber': Edm.String,
        'type': Edm.String,
        'website': Edm.String,
    }
    rels = [
        'currency',
        'paymentMethod',
        'paymentTerm',
        'picture',
        'shipmentMethod',
    ]


class dimension(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'dimensionValues',
    ]


class dimensionValue(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class employee(object):
    props = {
        'address': postalAddressType,
        'birthDate': Edm.Date,
        'displayName': Edm.String,
        'email': Edm.String,
        'employmentDate': Edm.Date,
        'givenName': Edm.String,
        'id': Edm.Guid,
        'jobTitle': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'middleName': Edm.String,
        'mobilePhone': Edm.String,
        'number': Edm.String,
        'personalEmail': Edm.String,
        'phoneNumber': Edm.String,
        'statisticsGroupCode': Edm.String,
        'status': Edm.String,
        'surname': Edm.String,
        'terminationDate': Edm.Date,
    }
    rels = [
        'picture',
    ]


class generalLedgerEntry(object):
    props = {
        'accountId': Edm.Guid,
        'accountNumber': Edm.String,
        'creditAmount': Edm.Decimal,
        'debitAmount': Edm.Decimal,
        'description': Edm.String,
        'documentNumber': Edm.String,
        'documentType': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'postingDate': Edm.Date,
    }
    rels = [
        'account',
    ]


class itemCategory(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class item(object):
    props = {
        'baseUnitOfMeasureId': Edm.Guid,
        'blocked': Edm.Boolean,
        'displayName': Edm.String,
        'gtin': Edm.String,
        'id': Edm.Guid,
        'inventory': Edm.Decimal,
        'itemCategoryCode': Edm.String,
        'itemCategoryId': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'priceIncludesTax': Edm.Boolean,
        'taxGroupCode': Edm.String,
        'taxGroupId': Edm.Guid,
        'type': Edm.String,
        'unitCost': Edm.Decimal,
        'unitPrice': Edm.Decimal,
    }
    rels = [
        'itemCategory',
        'picture',
    ]


class journalLine(object):
    props = {
        'accountId': Edm.Guid,
        'accountNumber': Edm.String,
        'amount': Edm.Decimal,
        'comment': Edm.String,
        'description': Edm.String,
        'documentNumber': Edm.String,
        'externalDocumentNumber': Edm.String,
        'id': Edm.Guid,
        'journalDisplayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lineNumber': Edm.Int32,
        'postingDate': Edm.Date,
    }
    rels = [
        'account',
    ]


class journal(object):
    props = {
        'balancingAccountId': Edm.Guid,
        'balancingAccountNumber': Edm.String,
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'account',
        'journalLines',
    ]


class paymentMethod(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class paymentTerm(object):
    props = {
        'calculateDiscountOnCreditMemos': Edm.Boolean,
        'code': Edm.String,
        'discountDateCalculation': Edm.String,
        'discountPercent': Edm.Decimal,
        'displayName': Edm.String,
        'dueDateCalculation': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class picture(object):
    props = {
        'content': Edm.Stream,
        'contentType': Edm.String,
        'height': Edm.Int32,
        'id': Edm.Guid,
        'width': Edm.Int32,
    }
    rels = [

    ]


class purchaseInvoiceLine(entity):
    props = {
        'accountId': Edm.Guid,
        'amountExcludingTax': Edm.Decimal,
        'amountIncludingTax': Edm.Decimal,
        'description': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'discountPercent': Edm.Decimal,
        'documentId': Edm.Guid,
        'expectedReceiptDate': Edm.Date,
        'invoiceDiscountAllocation': Edm.Decimal,
        'itemId': Edm.Guid,
        'lineType': Edm.String,
        'netAmount': Edm.Decimal,
        'netAmountIncludingTax': Edm.Decimal,
        'netTaxAmount': Edm.Decimal,
        'quantity': Edm.Decimal,
        'sequence': Edm.Int32,
        'taxCode': Edm.String,
        'taxPercent': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'unitCost': Edm.Decimal,
    }
    rels = [
        'account',
        'item',
    ]


class purchaseInvoice(object):
    props = {
        'buyFromAddress': postalAddressType,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'dueDate': Edm.Date,
        'id': Edm.Guid,
        'invoiceDate': Edm.Date,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'payToAddress': postalAddressType,
        'payToContact': Edm.String,
        'payToName': Edm.String,
        'payToVendorId': Edm.Guid,
        'payToVendorNumber': Edm.String,
        'pricesIncludeTax': Edm.Boolean,
        'shipToAddress': postalAddressType,
        'shipToContact': Edm.String,
        'shipToName': Edm.String,
        'status': Edm.String,
        'totalAmountExcludingTax': Edm.Decimal,
        'totalAmountIncludingTax': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'vendorId': Edm.Guid,
        'vendorInvoiceNumber': Edm.String,
        'vendorName': Edm.String,
        'vendorNumber': Edm.String,
    }
    rels = [
        'currency',
        'purchaseInvoiceLines',
        'vendor',
    ]


class salesCreditMemoLine(entity):
    props = {
        'accountId': Edm.Guid,
        'amountExcludingTax': Edm.Decimal,
        'amountIncludingTax': Edm.Decimal,
        'description': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'discountPercent': Edm.Decimal,
        'documentId': Edm.Guid,
        'invoiceDiscountAllocation': Edm.Decimal,
        'itemId': Edm.Guid,
        'lineType': Edm.String,
        'netAmount': Edm.Decimal,
        'netAmountIncludingTax': Edm.Decimal,
        'netTaxAmount': Edm.Decimal,
        'quantity': Edm.Decimal,
        'sequence': Edm.Int32,
        'shipmentDate': Edm.Date,
        'taxCode': Edm.String,
        'taxPercent': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'unitOfMeasureId': Edm.Guid,
        'unitPrice': Edm.Decimal,
    }
    rels = [
        'account',
        'item',
    ]


class salesCreditMemo(object):
    props = {
        'billingPostalAddress': postalAddressType,
        'billToCustomerId': Edm.Guid,
        'billToCustomerNumber': Edm.String,
        'billToName': Edm.String,
        'creditMemoDate': Edm.Date,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'customerId': Edm.Guid,
        'customerName': Edm.String,
        'customerNumber': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'dueDate': Edm.Date,
        'email': Edm.String,
        'externalDocumentNumber': Edm.String,
        'id': Edm.Guid,
        'invoiceId': Edm.Guid,
        'invoiceNumber': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'paymentTermsId': Edm.Guid,
        'phoneNumber': Edm.String,
        'pricesIncludeTax': Edm.Boolean,
        'salesperson': Edm.String,
        'sellingPostalAddress': postalAddressType,
        'status': Edm.String,
        'totalAmountExcludingTax': Edm.Decimal,
        'totalAmountIncludingTax': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
    }
    rels = [
        'currency',
        'customer',
        'paymentTerm',
        'salesCreditMemoLines',
    ]


class salesInvoiceLine(entity):
    props = {
        'accountId': Edm.Guid,
        'amountExcludingTax': Edm.Decimal,
        'amountIncludingTax': Edm.Decimal,
        'description': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'discountPercent': Edm.Decimal,
        'documentId': Edm.Guid,
        'invoiceDiscountAllocation': Edm.Decimal,
        'itemId': Edm.Guid,
        'lineType': Edm.String,
        'netAmount': Edm.Decimal,
        'netAmountIncludingTax': Edm.Decimal,
        'netTaxAmount': Edm.Decimal,
        'quantity': Edm.Decimal,
        'sequence': Edm.Int32,
        'shipmentDate': Edm.Date,
        'taxCode': Edm.String,
        'taxPercent': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'unitOfMeasureId': Edm.Guid,
        'unitPrice': Edm.Decimal,
    }
    rels = [
        'account',
        'item',
    ]


class salesInvoice(object):
    props = {
        'billingPostalAddress': postalAddressType,
        'billToCustomerId': Edm.Guid,
        'billToCustomerNumber': Edm.String,
        'billToName': Edm.String,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'customerId': Edm.Guid,
        'customerName': Edm.String,
        'customerNumber': Edm.String,
        'customerPurchaseOrderReference': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'dueDate': Edm.Date,
        'email': Edm.String,
        'externalDocumentNumber': Edm.String,
        'id': Edm.Guid,
        'invoiceDate': Edm.Date,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'orderId': Edm.Guid,
        'orderNumber': Edm.String,
        'paymentTermsId': Edm.Guid,
        'phoneNumber': Edm.String,
        'pricesIncludeTax': Edm.Boolean,
        'salesperson': Edm.String,
        'sellingPostalAddress': postalAddressType,
        'shipmentMethodId': Edm.Guid,
        'shippingPostalAddress': postalAddressType,
        'shipToContact': Edm.String,
        'shipToName': Edm.String,
        'status': Edm.String,
        'totalAmountExcludingTax': Edm.Decimal,
        'totalAmountIncludingTax': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
    }
    rels = [
        'currency',
        'customer',
        'paymentTerm',
        'salesInvoiceLines',
        'shipmentMethod',
    ]


class salesOrderLine(entity):
    props = {
        'accountId': Edm.Guid,
        'amountExcludingTax': Edm.Decimal,
        'amountIncludingTax': Edm.Decimal,
        'description': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'discountPercent': Edm.Decimal,
        'documentId': Edm.Guid,
        'invoiceDiscountAllocation': Edm.Decimal,
        'invoicedQuantity': Edm.Decimal,
        'invoiceQuantity': Edm.Decimal,
        'itemId': Edm.Guid,
        'lineType': Edm.String,
        'netAmount': Edm.Decimal,
        'netAmountIncludingTax': Edm.Decimal,
        'netTaxAmount': Edm.Decimal,
        'quantity': Edm.Decimal,
        'sequence': Edm.Int32,
        'shipmentDate': Edm.Date,
        'shippedQuantity': Edm.Decimal,
        'shipQuantity': Edm.Decimal,
        'taxCode': Edm.String,
        'taxPercent': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'unitOfMeasureId': Edm.Guid,
        'unitPrice': Edm.Decimal,
    }
    rels = [
        'account',
        'item',
    ]


class salesOrder(object):
    props = {
        'billingPostalAddress': postalAddressType,
        'billToCustomerId': Edm.Guid,
        'billToCustomerNumber': Edm.String,
        'billToName': Edm.String,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'customerId': Edm.Guid,
        'customerName': Edm.String,
        'customerNumber': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'email': Edm.String,
        'externalDocumentNumber': Edm.String,
        'fullyShipped': Edm.Boolean,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'orderDate': Edm.Date,
        'partialShipping': Edm.Boolean,
        'paymentTermsId': Edm.Guid,
        'phoneNumber': Edm.String,
        'pricesIncludeTax': Edm.Boolean,
        'requestedDeliveryDate': Edm.Date,
        'salesperson': Edm.String,
        'sellingPostalAddress': postalAddressType,
        'shippingPostalAddress': postalAddressType,
        'shipToContact': Edm.String,
        'shipToName': Edm.String,
        'status': Edm.String,
        'totalAmountExcludingTax': Edm.Decimal,
        'totalAmountIncludingTax': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
    }
    rels = [
        'currency',
        'customer',
        'paymentTerm',
        'salesOrderLines',
    ]


class salesQuoteLine(entity):
    props = {
        'accountId': Edm.Guid,
        'amountExcludingTax': Edm.Decimal,
        'amountIncludingTax': Edm.Decimal,
        'description': Edm.String,
        'discountAmount': Edm.Decimal,
        'discountAppliedBeforeTax': Edm.Boolean,
        'discountPercent': Edm.Decimal,
        'documentId': Edm.Guid,
        'itemId': Edm.Guid,
        'lineType': Edm.String,
        'netAmount': Edm.Decimal,
        'netAmountIncludingTax': Edm.Decimal,
        'netTaxAmount': Edm.Decimal,
        'quantity': Edm.Decimal,
        'sequence': Edm.Int32,
        'taxCode': Edm.String,
        'taxPercent': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'unitOfMeasureId': Edm.Guid,
        'unitPrice': Edm.Decimal,
    }
    rels = [
        'account',
        'item',
    ]


class salesQuote(object):
    props = {
        'acceptedDate': Edm.Date,
        'billingPostalAddress': postalAddressType,
        'billToCustomerId': Edm.Guid,
        'billToCustomerNumber': Edm.String,
        'billToName': Edm.String,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'customerId': Edm.Guid,
        'customerName': Edm.String,
        'customerNumber': Edm.String,
        'discountAmount': Edm.Decimal,
        'documentDate': Edm.Date,
        'dueDate': Edm.Date,
        'email': Edm.String,
        'externalDocumentNumber': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'paymentTermsId': Edm.Guid,
        'phoneNumber': Edm.String,
        'salesperson': Edm.String,
        'sellingPostalAddress': postalAddressType,
        'sentDate': Edm.DateTimeOffset,
        'shipmentMethodId': Edm.Guid,
        'shippingPostalAddress': postalAddressType,
        'shipToContact': Edm.String,
        'shipToName': Edm.String,
        'status': Edm.String,
        'totalAmountExcludingTax': Edm.Decimal,
        'totalAmountIncludingTax': Edm.Decimal,
        'totalTaxAmount': Edm.Decimal,
        'validUntilDate': Edm.Date,
    }
    rels = [
        'currency',
        'customer',
        'paymentTerm',
        'salesQuoteLines',
        'shipmentMethod',
    ]


class shipmentMethod(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class taxArea(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'taxType': Edm.String,
    }
    rels = [

    ]


class taxGroup(entity):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'taxType': Edm.String,
    }
    rels = [

    ]


class unitOfMeasure(object):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'id': Edm.Guid,
        'internationalStandardCode': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class vendor(object):
    props = {
        'address': postalAddressType,
        'balance': Edm.Decimal,
        'blocked': Edm.String,
        'currencyCode': Edm.String,
        'currencyId': Edm.Guid,
        'displayName': Edm.String,
        'email': Edm.String,
        'id': Edm.Guid,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'number': Edm.String,
        'paymentMethodId': Edm.Guid,
        'paymentTermsId': Edm.Guid,
        'phoneNumber': Edm.String,
        'taxLiable': Edm.Boolean,
        'taxRegistrationNumber': Edm.String,
        'website': Edm.String,
    }
    rels = [
        'currency',
        'paymentMethod',
        'paymentTerm',
        'picture',
    ]


class financials(object):
    props = {
        'id': Edm.Guid,
    }
    rels = [
        'companies',
    ]


class office365ActiveUserCounts(entity):
    props = {
        'exchange': Edm.Int64,
        'office365': Edm.Int64,
        'oneDrive': Edm.Int64,
        'reportDate': Edm.Date,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'sharePoint': Edm.Int64,
        'skypeForBusiness': Edm.Int64,
        'teams': Edm.Int64,
        'yammer': Edm.Int64,
    }
    rels = [

    ]


class office365ActiveUserDetail(entity):
    props = {
        'assignedProducts': Collection,
        'deletedDate': Edm.Date,
        'displayName': Edm.String,
        'exchangeLastActivityDate': Edm.Date,
        'exchangeLicenseAssignDate': Edm.Date,
        'hasExchangeLicense': Edm.Boolean,
        'hasOneDriveLicense': Edm.Boolean,
        'hasSharePointLicense': Edm.Boolean,
        'hasSkypeForBusinessLicense': Edm.Boolean,
        'hasTeamsLicense': Edm.Boolean,
        'hasYammerLicense': Edm.Boolean,
        'isDeleted': Edm.Boolean,
        'oneDriveLastActivityDate': Edm.Date,
        'oneDriveLicenseAssignDate': Edm.Date,
        'reportRefreshDate': Edm.Date,
        'sharePointLastActivityDate': Edm.Date,
        'sharePointLicenseAssignDate': Edm.Date,
        'skypeForBusinessLastActivityDate': Edm.Date,
        'skypeForBusinessLicenseAssignDate': Edm.Date,
        'teamsLastActivityDate': Edm.Date,
        'teamsLicenseAssignDate': Edm.Date,
        'userPrincipalName': Edm.String,
        'yammerLastActivityDate': Edm.Date,
        'yammerLicenseAssignDate': Edm.Date,
    }
    rels = [

    ]


class office365GroupsActivityCounts(entity):
    props = {
        'exchangeEmailsReceived': Edm.Int64,
        'reportDate': Edm.Date,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'teamsChannelMessages': Edm.Int64,
        'teamsMeetingsOrganized': Edm.Int64,
        'yammerMessagesLiked': Edm.Int64,
        'yammerMessagesPosted': Edm.Int64,
        'yammerMessagesRead': Edm.Int64,
    }
    rels = [

    ]


class office365GroupsActivityDetail(entity):
    props = {
        'exchangeMailboxStorageUsedInBytes': Edm.Int64,
        'exchangeMailboxTotalItemCount': Edm.Int64,
        'exchangeReceivedEmailCount': Edm.Int64,
        'externalMemberCount': Edm.Int64,
        'groupDisplayName': Edm.String,
        'groupId': Edm.String,
        'groupType': Edm.String,
        'isDeleted': Edm.Boolean,
        'lastActivityDate': Edm.Date,
        'memberCount': Edm.Int64,
        'ownerPrincipalName': Edm.String,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'sharePointActiveFileCount': Edm.Int64,
        'sharePointSiteStorageUsedInBytes': Edm.Int64,
        'sharePointTotalFileCount': Edm.Int64,
        'teamsChannelMessagesCount': Edm.Int64,
        'teamsMeetingsOrganizedCount': Edm.Int64,
        'yammerLikedMessageCount': Edm.Int64,
        'yammerPostedMessageCount': Edm.Int64,
        'yammerReadMessageCount': Edm.Int64,
    }
    rels = [

    ]


class office365GroupsActivityFileCounts(entity):
    props = {
        'active': Edm.Int64,
        'reportDate': Edm.Date,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'total': Edm.Int64,
    }
    rels = [

    ]


class office365GroupsActivityGroupCounts(entity):
    props = {
        'active': Edm.Int64,
        'reportDate': Edm.Date,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'total': Edm.Int64,
    }
    rels = [

    ]


class office365GroupsActivityStorage(entity):
    props = {
        'mailboxStorageUsedInBytes': Edm.Int64,
        'reportDate': Edm.Date,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'siteStorageUsedInBytes': Edm.Int64,
    }
    rels = [

    ]


class office365ServicesUserCounts(entity):
    props = {
        'exchangeActive': Edm.Int64,
        'exchangeInactive': Edm.Int64,
        'office365Active': Edm.Int64,
        'office365Inactive': Edm.Int64,
        'oneDriveActive': Edm.Int64,
        'oneDriveInactive': Edm.Int64,
        'reportPeriod': Edm.String,
        'reportRefreshDate': Edm.Date,
        'sharePointActive': Edm.Int64,
        'sharePointInactive': Edm.Int64,
        'skypeForBusinessActive': Edm.Int64,
        'skypeForBusinessInactive': Edm.Int64,
        'teamsActive': Edm.Int64,
        'teamsInactive': Edm.Int64,
        'yammerActive': Edm.Int64,
        'yammerInactive': Edm.Int64,
    }
    rels = [

    ]


class teamsChannelPlanner(entity):
    props = {

    }
    rels = [
        'plans',
    ]


class chatMessage(entity):
    props = {
        'attachments': Collection,
        'body': itemBody,
        'channelIdentity': channelIdentity,
        'chatId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'deletedDateTime': Edm.DateTimeOffset,
        'etag': Edm.String,
        'eventDetail': eventMessageDetail,
        'from': chatMessageFromIdentitySet,
        'importance': chatMessageImportance,
        'lastEditedDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'locale': Edm.String,
        'mentions': Collection,
        'messageHistory': Collection,
        'messageType': chatMessageType,
        'onBehalfOf': chatMessageFromIdentitySet,
        'policyViolation': chatMessagePolicyViolation,
        'reactions': Collection,
        'replyToId': Edm.String,
        'subject': Edm.String,
        'summary': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [
        'hostedContents',
        'replies',
    ]


class teamInfo(entity):
    props = {
        'displayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [
        'team',
    ]


class teamsTab(entity):
    props = {
        'configuration': teamsTabConfiguration,
        'displayName': Edm.String,
        'messageId': Edm.String,
        'sortOrderIndex': Edm.String,
        'teamsAppId': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [
        'teamsApp',
    ]


class planner(entity):
    props = {

    }
    rels = [
        'buckets',
        'plans',
        'rosters',
        'tasks',
    ]


class plannerRoster(entity):
    props = {
        'assignedSensitivityLabel': sensitivityLabelAssignment,
    }
    rels = [
        'members',
        'plans',
    ]


class plannerRosterMember(entity):
    props = {
        'roles': Collection,
        'tenantId': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class businessScenarioPlanReference(entity):
    props = {
        'title': Edm.String,
    }
    rels = [

    ]


class microsoftApplicationDataAccessSettings(entity):
    props = {
        'disabledForGroup': Edm.String,
        'isEnabledForAllMicrosoftApplications': Edm.Boolean,
    }
    rels = [

    ]


class sharedInsight(entity):
    props = {
        'lastShared': sharingDetail,
        'resourceReference': resourceReference,
        'resourceVisualization': resourceVisualization,
        'sharingHistory': Collection,
    }
    rels = [
        'lastSharedMethod',
        'resource',
    ]


class trending(entity):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'resourceReference': resourceReference,
        'resourceVisualization': resourceVisualization,
        'weight': Edm.Double,
    }
    rels = [
        'resource',
    ]


class usedInsight(entity):
    props = {
        'lastUsed': usageDetails,
        'resourceReference': resourceReference,
        'resourceVisualization': resourceVisualization,
    }
    rels = [
        'resource',
    ]


class insightsSettings(entity):
    props = {
        'disabledForGroup': Edm.String,
        'isEnabledInOrganization': Edm.Boolean,
    }
    rels = [

    ]


class onenoteEntityBaseModel(entity):
    props = {
        'self': Edm.String,
    }
    rels = [

    ]


class operation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastActionDateTime': Edm.DateTimeOffset,
        'status': operationStatus,
    }
    rels = [

    ]


class delegatedAdminAccessAssignment(entity):
    props = {
        'accessContainer': delegatedAdminAccessContainer,
        'accessDetails': delegatedAdminAccessDetails,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': delegatedAdminAccessAssignmentStatus,
    }
    rels = [

    ]


class delegatedAdminServiceManagementDetail(entity):
    props = {
        'serviceManagementUrl': Edm.String,
        'serviceName': Edm.String,
    }
    rels = [

    ]


class delegatedAdminRelationshipOperation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'data': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'operationType': delegatedAdminRelationshipOperationType,
        'status': longRunningOperationStatus,
    }
    rels = [

    ]


class delegatedAdminRelationshipRequest(entity):
    props = {
        'action': delegatedAdminRelationshipRequestAction,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': delegatedAdminRelationshipRequestStatus,
    }
    rels = [

    ]


class cloudClipboardItem(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'payloads': Collection,
    }
    rels = [

    ]


class windowsSettingInstance(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'payload': Edm.String,
    }
    rels = [

    ]


class profileCardProperty(entity):
    props = {
        'annotations': Collection,
        'directoryPropertyName': Edm.String,
    }
    rels = [

    ]


class pronounsSettings(entity):
    props = {
        'isEnabledInOrganization': Edm.Boolean,
    }
    rels = [

    ]


class itemFacet(entity):
    props = {
        'allowedAudiences': allowedAudiences,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'inference': inferenceData,
        'isSearchable': Edm.Boolean,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'source': personDataSources,
        'sources': Collection,
    }
    rels = [

    ]


class governanceResource(entity):
    props = {
        'displayName': Edm.String,
        'externalId': Edm.String,
        'registeredDateTime': Edm.DateTimeOffset,
        'registeredRoot': Edm.String,
        'status': Edm.String,
        'type': Edm.String,
    }
    rels = [
        'parent',
        'roleAssignmentRequests',
        'roleAssignments',
        'roleDefinitions',
        'roleSettings',
    ]


class governanceRoleAssignmentRequest(entity):
    props = {
        'assignmentState': Edm.String,
        'linkedEligibleRoleAssignmentId': Edm.String,
        'reason': Edm.String,
        'requestedDateTime': Edm.DateTimeOffset,
        'resourceId': Edm.String,
        'roleDefinitionId': Edm.String,
        'schedule': governanceSchedule,
        'status': governanceRoleAssignmentRequestStatus,
        'subjectId': Edm.String,
        'type': Edm.String,
    }
    rels = [
        'resource',
        'roleDefinition',
        'subject',
    ]


class governanceRoleAssignment(entity):
    props = {
        'assignmentState': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'externalId': Edm.String,
        'linkedEligibleRoleAssignmentId': Edm.String,
        'memberType': Edm.String,
        'resourceId': Edm.String,
        'roleDefinitionId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
        'subjectId': Edm.String,
    }
    rels = [
        'linkedEligibleRoleAssignment',
        'resource',
        'roleDefinition',
        'subject',
    ]


class governanceRoleDefinition(entity):
    props = {
        'displayName': Edm.String,
        'externalId': Edm.String,
        'resourceId': Edm.String,
        'templateId': Edm.String,
    }
    rels = [
        'resource',
        'roleSetting',
    ]


class governanceRoleSetting(entity):
    props = {
        'adminEligibleSettings': Collection,
        'adminMemberSettings': Collection,
        'isDefault': Edm.Boolean,
        'lastUpdatedBy': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'resourceId': Edm.String,
        'roleDefinitionId': Edm.String,
        'userEligibleSettings': Collection,
        'userMemberSettings': Collection,
    }
    rels = [
        'resource',
        'roleDefinition',
    ]


class governanceSubject(entity):
    props = {
        'displayName': Edm.String,
        'email': Edm.String,
        'principalName': Edm.String,
        'type': Edm.String,
    }
    rels = [

    ]


class unifiedRoleManagementAlertConfiguration(entity):
    props = {
        'alertDefinitionId': Edm.String,
        'isEnabled': Edm.Boolean,
        'scopeId': Edm.String,
        'scopeType': Edm.String,
    }
    rels = [
        'alertDefinition',
    ]


class unifiedRoleManagementAlertIncident(entity):
    props = {

    }
    rels = [

    ]


class privilegedAccess(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [
        'resources',
        'roleAssignmentRequests',
        'roleAssignments',
        'roleDefinitions',
        'roleSettings',
    ]


class unifiedRoleManagementAlertDefinition(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'howToPrevent': Edm.String,
        'isConfigurable': Edm.Boolean,
        'isRemediatable': Edm.Boolean,
        'mitigationSteps': Edm.String,
        'scopeId': Edm.String,
        'scopeType': Edm.String,
        'securityImpact': Edm.String,
        'severityLevel': alertSeverity,
    }
    rels = [

    ]


class unifiedRoleManagementAlert(entity):
    props = {
        'alertDefinitionId': Edm.String,
        'incidentCount': Edm.Int32,
        'isActive': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastScannedDateTime': Edm.DateTimeOffset,
        'scopeId': Edm.String,
        'scopeType': Edm.String,
    }
    rels = [
        'alertConfiguration',
        'alertDefinition',
        'alertIncidents',
    ]


class unifiedRoleManagementPolicyRule(entity):
    props = {
        'target': unifiedRoleManagementPolicyRuleTarget,
    }
    rels = [

    ]


class privilegedApproval(entity):
    props = {
        'approvalDuration': Edm.Duration,
        'approvalState': approvalState,
        'approvalType': Edm.String,
        'approverReason': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'requestorReason': Edm.String,
        'roleId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'userId': Edm.String,
    }
    rels = [
        'request',
        'roleInfo',
    ]


class privilegedRoleAssignmentRequest(entity):
    props = {
        'assignmentState': Edm.String,
        'duration': Edm.String,
        'reason': Edm.String,
        'requestedDateTime': Edm.DateTimeOffset,
        'roleId': Edm.String,
        'schedule': governanceSchedule,
        'status': Edm.String,
        'ticketNumber': Edm.String,
        'ticketSystem': Edm.String,
        'type': Edm.String,
        'userId': Edm.String,
    }
    rels = [
        'roleInfo',
    ]


class privilegedRole(entity):
    props = {
        'name': Edm.String,
    }
    rels = [
        'assignments',
        'settings',
        'summary',
    ]


class privilegedOperationEvent(entity):
    props = {
        'additionalInformation': Edm.String,
        'creationDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
        'referenceKey': Edm.String,
        'referenceSystem': Edm.String,
        'requestorId': Edm.String,
        'requestorName': Edm.String,
        'requestType': Edm.String,
        'roleId': Edm.String,
        'roleName': Edm.String,
        'tenantId': Edm.String,
        'userId': Edm.String,
        'userMail': Edm.String,
        'userName': Edm.String,
    }
    rels = [

    ]


class privilegedRoleAssignment(entity):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'isElevated': Edm.Boolean,
        'resultMessage': Edm.String,
        'roleId': Edm.String,
        'userId': Edm.String,
    }
    rels = [
        'roleInfo',
    ]


class privilegedRoleSettings(entity):
    props = {
        'approvalOnElevation': Edm.Boolean,
        'approverIds': Collection,
        'elevationDuration': Edm.Duration,
        'isMfaOnElevationConfigurable': Edm.Boolean,
        'lastGlobalAdmin': Edm.Boolean,
        'maxElavationDuration': Edm.Duration,
        'mfaOnElevation': Edm.Boolean,
        'minElevationDuration': Edm.Duration,
        'notificationToUserOnElevation': Edm.Boolean,
        'ticketingInfoOnElevation': Edm.Boolean,
    }
    rels = [

    ]


class privilegedRoleSummary(entity):
    props = {
        'elevatedCount': Edm.Int32,
        'managedCount': Edm.Int32,
        'mfaEnabled': Edm.Boolean,
        'status': roleSummaryStatus,
        'usersCount': Edm.Int32,
    }
    rels = [

    ]


class privilegedSignupStatus(entity):
    props = {
        'isRegistered': Edm.Boolean,
        'status': setupStatus,
    }
    rels = [

    ]


class tenantSetupInfo(entity):
    props = {
        'firstTimeSetup': Edm.Boolean,
        'relevantRolesSettings': Collection,
        'setupStatus': setupStatus,
        'skipSetup': Edm.Boolean,
        'userRolesActions': Edm.String,
    }
    rels = [
        'defaultRolesSettings',
    ]


class documentComment(entity):
    props = {
        'content': Edm.String,
    }
    rels = [
        'replies',
    ]


class documentCommentReply(entity):
    props = {
        'content': Edm.String,
        'location': Edm.String,
    }
    rels = [

    ]


class presentation(entity):
    props = {

    }
    rels = [
        'comments',
    ]


class printerBase(entity):
    props = {
        'capabilities': printerCapabilities,
        'defaults': printerDefaults,
        'displayName': Edm.String,
        'isAcceptingJobs': Edm.Boolean,
        'location': printerLocation,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'name': Edm.String,
        'status': printerStatus,
    }
    rels = [
        'jobs',
    ]


class printConnector(entity):
    props = {
        'appVersion': Edm.String,
        'deviceHealth': deviceHealth,
        'displayName': Edm.String,
        'fullyQualifiedDomainName': Edm.String,
        'location': printerLocation,
        'name': Edm.String,
        'operatingSystem': Edm.String,
        'registeredDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class printOperation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'status': printOperationStatus,
    }
    rels = [

    ]


class printService(entity):
    props = {

    }
    rels = [
        'endpoints',
    ]


class printTaskDefinition(entity):
    props = {
        'createdBy': appIdentity,
        'displayName': Edm.String,
    }
    rels = [
        'tasks',
    ]


class printDocument(entity):
    props = {
        'configuration': printerDocumentConfiguration,
        'contentType': Edm.String,
        'displayName': Edm.String,
        'downloadedDateTime': Edm.DateTimeOffset,
        'size': Edm.Int64,
        'uploadedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class printTaskTrigger(entity):
    props = {
        'event': printEvent,
    }
    rels = [
        'definition',
    ]


class printJob(entity):
    props = {
        'acknowledgedDateTime': Edm.DateTimeOffset,
        'completedDateTime': Edm.DateTimeOffset,
        'configuration': printJobConfiguration,
        'createdBy': userIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'errorCode': Edm.Int32,
        'isFetchable': Edm.Boolean,
        'redirectedFrom': Edm.String,
        'redirectedTo': Edm.String,
        'status': printJobStatus,
    }
    rels = [
        'documents',
        'tasks',
    ]


class printTask(entity):
    props = {
        'parentUrl': Edm.String,
        'status': printTaskStatus,
    }
    rels = [
        'definition',
        'trigger',
    ]


class printServiceEndpoint(entity):
    props = {
        'displayName': Edm.String,
        'name': Edm.String,
        'uri': Edm.String,
    }
    rels = [

    ]


class activityHistoryItem(entity):
    props = {
        'activeDurationSeconds': Edm.Int32,
        'createdDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
        'lastActiveDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'startedDateTime': Edm.DateTimeOffset,
        'status': status,
        'userTimezone': Edm.String,
    }
    rels = [
        'activity',
    ]


class payloadResponse(entity):
    props = {

    }
    rels = [

    ]


class dataPolicyOperation(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'progress': Edm.Double,
        'status': dataPolicyOperationStatus,
        'storageLocation': Edm.String,
        'submittedDateTime': Edm.DateTimeOffset,
        'userId': Edm.String,
    }
    rels = [

    ]


class endUserNotification(entity):
    props = {
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'notificationType': endUserNotificationType,
        'source': simulationContentSource,
        'status': simulationContentStatus,
        'supportedLocales': Collection,
    }
    rels = [
        'details',
    ]


class training(entity):
    props = {
        'availabilityStatus': trainingAvailabilityStatus,
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'customUrl': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'durationInMinutes': Edm.Int32,
        'hasEvaluation': Edm.Boolean,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'source': simulationContentSource,
        'supportedLocales': Collection,
        'tags': Collection,
        'type': trainingType,
    }
    rels = [
        'languageDetails',
    ]


class landingPage(entity):
    props = {
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'locale': Edm.String,
        'source': simulationContentSource,
        'status': simulationContentStatus,
        'supportedLocales': Collection,
    }
    rels = [
        'details',
    ]


class loginPage(entity):
    props = {
        'content': Edm.String,
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'language': Edm.String,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'source': simulationContentSource,
        'status': simulationContentStatus,
    }
    rels = [

    ]


class payload(entity):
    props = {
        'brand': payloadBrand,
        'complexity': payloadComplexity,
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'detail': payloadDetail,
        'displayName': Edm.String,
        'industry': payloadIndustry,
        'isAutomated': Edm.Boolean,
        'isControversial': Edm.Boolean,
        'isCurrentEvent': Edm.Boolean,
        'language': Edm.String,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'payloadTags': Collection,
        'platform': payloadDeliveryPlatform,
        'predictedCompromiseRate': Edm.Double,
        'simulationAttackType': simulationAttackType,
        'source': simulationContentSource,
        'status': simulationContentStatus,
        'technique': simulationAttackTechnique,
        'theme': payloadTheme,
    }
    rels = [

    ]


class simulationAutomation(entity):
    props = {
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastRunDateTime': Edm.DateTimeOffset,
        'nextRunDateTime': Edm.DateTimeOffset,
        'status': simulationAutomationStatus,
    }
    rels = [
        'runs',
    ]


class simulation(entity):
    props = {
        'attackTechnique': simulationAttackTechnique,
        'attackType': simulationAttackType,
        'automationId': Edm.String,
        'completionDateTime': Edm.DateTimeOffset,
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'durationInDays': Edm.Int32,
        'endUserNotificationSetting': endUserNotificationSetting,
        'excludedAccountTarget': accountTargetContent,
        'includedAccountTarget': accountTargetContent,
        'isAutomated': Edm.Boolean,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'launchDateTime': Edm.DateTimeOffset,
        'oAuthConsentAppDetail': oAuthConsentAppDetail,
        'payloadDeliveryPlatform': payloadDeliveryPlatform,
        'report': simulationReport,
        'status': simulationStatus,
        'trainingSetting': trainingSetting,
    }
    rels = [
        'landingPage',
        'loginPage',
        'payload',
    ]


class trainingCampaign(entity):
    props = {
        'campaignSchedule': campaignSchedule,
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'endUserNotificationSetting': endUserNotificationSetting,
        'excludedAccountTarget': accountTargetContent,
        'includedAccountTarget': accountTargetContent,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'report': trainingCampaignReport,
        'trainingSetting': trainingSetting,
    }
    rels = [

    ]


class endUserNotificationDetail(entity):
    props = {
        'emailContent': Edm.String,
        'isDefaultLangauge': Edm.Boolean,
        'language': Edm.String,
        'locale': Edm.String,
        'sentFrom': emailIdentity,
        'subject': Edm.String,
    }
    rels = [

    ]


class landingPageDetail(entity):
    props = {
        'content': Edm.String,
        'isDefaultLangauge': Edm.Boolean,
        'language': Edm.String,
    }
    rels = [

    ]


class simulationAutomationRun(entity):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'simulationId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
        'status': simulationAutomationRunStatus,
    }
    rels = [

    ]


class trainingLanguageDetail(entity):
    props = {
        'content': Edm.String,
        'createdBy': emailIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'isDefaultLangauge': Edm.Boolean,
        'lastModifiedBy': emailIdentity,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'locale': Edm.String,
    }
    rels = [

    ]


class commsOperation(entity):
    props = {
        'clientContext': Edm.String,
        'resultInfo': resultInfo,
        'status': operationStatus,
    }
    rels = [

    ]


class attendanceRecord(entity):
    props = {
        'attendanceIntervals': Collection,
        'emailAddress': Edm.String,
        'externalRegistrationInformation': virtualEventExternalRegistrationInformation,
        'identity': identity,
        'registrantId': Edm.String,
        'registrationId': Edm.String,
        'role': Edm.String,
        'totalAttendanceInSeconds': Edm.Int32,
    }
    rels = [

    ]


class audioRoutingGroup(entity):
    props = {
        'receivers': Collection,
        'routingMode': routingMode,
        'sources': Collection,
    }
    rels = [

    ]


class contentSharingSession(entity):
    props = {
        'pngOfCurrentSlide': Edm.Stream,
        'presenterParticipantId': Edm.String,
    }
    rels = [

    ]


class participant(entity):
    props = {
        'info': participantInfo,
        'isIdentityAnonymized': Edm.Boolean,
        'isInLobby': Edm.Boolean,
        'isMuted': Edm.Boolean,
        'mediaStreams': Collection,
        'metadata': Edm.String,
        'preferredDisplayName': Edm.String,
        'recordingInfo': recordingInfo,
        'removedState': removedState,
        'restrictedExperience': onlineMeetingRestricted,
        'rosterSequenceNumber': Edm.Int64,
    }
    rels = [

    ]


class callEvent(entity):
    props = {
        'callEventType': callEventType,
        'eventDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'participants',
    ]


class callSettings(entity):
    props = {

    }
    rels = [
        'delegates',
        'delegators',
    ]


class delegationSettings(entity):
    props = {
        'allowedActions': delegateAllowedActions,
        'createdDateTime': Edm.DateTimeOffset,
        'isActive': Edm.Boolean,
    }
    rels = [

    ]


class commsApplication(object):
    props = {

    }
    rels = [
        'calls',
        'onlineMeetings',
    ]


class deltaParticipants(entity):
    props = {
        'sequenceNumber': Edm.Int64,
    }
    rels = [
        'participants',
    ]


class meetingRegistrantBase(entity):
    props = {
        'joinWebUrl': Edm.String,
    }
    rels = [

    ]


class meetingRegistrationQuestion(entity):
    props = {
        'answerInputType': answerInputType,
        'answerOptions': Collection,
        'displayName': Edm.String,
        'isRequired': Edm.Boolean,
    }
    rels = [

    ]


class participantJoiningNotification(entity):
    props = {

    }
    rels = [
        'call',
    ]


class participantLeftNotification(entity):
    props = {
        'participantId': Edm.String,
    }
    rels = [
        'call',
    ]


class virtualEvent(entity):
    props = {
        'createdBy': communicationsIdentitySet,
        'description': itemBody,
        'displayName': Edm.String,
        'endDateTime': dateTimeTimeZone,
        'externalEventInformation': Collection,
        'settings': virtualEventSettings,
        'startDateTime': dateTimeTimeZone,
        'status': virtualEventStatus,
    }
    rels = [
        'presenters',
        'sessions',
    ]


class virtualEventPresenter(entity):
    props = {
        'email': Edm.String,
        'identity': identity,
        'presenterDetails': virtualEventPresenterDetails,
    }
    rels = [
        'sessions',
    ]


class virtualEventRegistration(entity):
    props = {
        'cancelationDateTime': Edm.DateTimeOffset,
        'email': Edm.String,
        'externalRegistrationInformation': virtualEventExternalRegistrationInformation,
        'firstName': Edm.String,
        'lastName': Edm.String,
        'preferredLanguage': Edm.String,
        'preferredTimezone': Edm.String,
        'registrationDateTime': Edm.DateTimeOffset,
        'registrationQuestionAnswers': Collection,
        'status': virtualEventAttendeeRegistrationStatus,
        'userId': Edm.String,
    }
    rels = [
        'sessions',
    ]


class virtualEventRegistrationConfiguration(entity):
    props = {
        'capacity': Edm.Int32,
        'registrationWebUrl': Edm.String,
    }
    rels = [
        'questions',
    ]


class virtualEventRegistrationQuestionBase(entity):
    props = {
        'displayName': Edm.String,
        'isRequired': Edm.Boolean,
    }
    rels = [

    ]


class authenticationMethod(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class connectionOperation(entity):
    props = {
        'error': publicError,
        'status': connectionOperationStatus,
    }
    rels = [

    ]


class external(entity):
    props = {

    }
    rels = [
        'connections',
    ]


class externalConnection(entity):
    props = {
        'configuration': configuration,
        'description': Edm.String,
        'name': Edm.String,
        'state': connectionState,
    }
    rels = [
        'groups',
        'items',
        'operations',
        'schema',
    ]


class externalGroup(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class externalItem(entity):
    props = {
        'acl': Collection,
        'content': externalItemContent,
        'properties': properties,
    }
    rels = [

    ]


class schema(entity):
    props = {
        'baseType': Edm.String,
        'properties': Collection,
    }
    rels = [

    ]


class teamworkPeripheral(entity):
    props = {
        'displayName': Edm.String,
        'productId': Edm.String,
        'vendorId': Edm.String,
    }
    rels = [

    ]


class aiInteraction(entity):
    props = {
        'appClass': Edm.String,
        'attachments': Collection,
        'body': itemBody,
        'contexts': Collection,
        'conversationType': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'etag': Edm.String,
        'from': identitySet,
        'interactionType': aiInteractionType,
        'links': Collection,
        'locale': Edm.String,
        'mentions': Collection,
        'requestId': Edm.String,
        'sessionId': Edm.String,
    }
    rels = [

    ]


class appCatalogs(object):
    props = {

    }
    rels = [
        'teamsApps',
    ]


class teamsApp(entity):
    props = {
        'displayName': Edm.String,
        'distributionMethod': teamsAppDistributionMethod,
        'externalId': Edm.String,
    }
    rels = [
        'appDefinitions',
    ]


class chatMessageInfo(entity):
    props = {
        'body': itemBody,
        'createdDateTime': Edm.DateTimeOffset,
        'eventDetail': eventMessageDetail,
        'from': chatMessageFromIdentitySet,
        'isDeleted': Edm.Boolean,
        'messageType': chatMessageType,
    }
    rels = [

    ]


class pinnedChatMessageInfo(entity):
    props = {

    }
    rels = [
        'message',
    ]


class teamworkHostedContent(entity):
    props = {
        'contentBytes': Edm.Binary,
        'contentType': Edm.String,
    }
    rels = [

    ]


class deletedChat(entity):
    props = {

    }
    rels = [

    ]


class deletedTeam(entity):
    props = {

    }
    rels = [
        'channels',
    ]


class teamsAppDefinition(entity):
    props = {
        'allowedInstallationScopes': teamsAppInstallationScopes,
        'authorization': teamsAppAuthorization,
        'azureADAppId': Edm.String,
        'createdBy': identitySet,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'publishingState': teamsAppPublishingState,
        'shortdescription': Edm.String,
        'teamsAppId': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'bot',
        'colorIcon',
        'dashboardCards',
        'outlineIcon',
    ]


class teamsAppDashboardCardDefinition(entity):
    props = {
        'contentSource': teamsAppDashboardCardContentSource,
        'defaultSize': teamsAppDashboardCardSize,
        'description': Edm.String,
        'displayName': Edm.String,
        'icon': teamsAppDashboardCardIcon,
        'pickerGroupId': Edm.String,
    }
    rels = [

    ]


class teamworkBot(entity):
    props = {

    }
    rels = [

    ]


class teamsAppIcon(entity):
    props = {
        'webUrl': Edm.String,
    }
    rels = [
        'hostedContent',
    ]


class teamsAppSettings(entity):
    props = {
        'allowUserRequestsForAppAccess': Edm.Boolean,
        'customAppSettings': customAppSettings,
        'isChatResourceSpecificConsentEnabled': Edm.Boolean,
        'isUserPersonalScopeResourceSpecificConsentEnabled': Edm.Boolean,
    }
    rels = [

    ]


class teamTemplate(entity):
    props = {

    }
    rels = [
        'definitions',
    ]


class teamwork(entity):
    props = {
        'isTeamsEnabled': Edm.Boolean,
        'region': Edm.String,
    }
    rels = [
        'workforceIntegrations',
        'deletedChats',
        'deletedTeams',
        'devices',
        'teamsAppSettings',
        'teamTemplates',
    ]


class teamworkDevice(entity):
    props = {
        'activityState': teamworkDeviceActivityState,
        'companyAssetTag': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'currentUser': teamworkUserIdentity,
        'deviceType': teamworkDeviceType,
        'hardwareDetail': teamworkHardwareDetail,
        'healthStatus': teamworkDeviceHealthStatus,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'notes': Edm.String,
    }
    rels = [
        'activity',
        'configuration',
        'health',
        'operations',
    ]


class teamworkDeviceActivity(entity):
    props = {
        'activePeripherals': teamworkActivePeripherals,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class teamworkDeviceConfiguration(entity):
    props = {
        'cameraConfiguration': teamworkCameraConfiguration,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayConfiguration': teamworkDisplayConfiguration,
        'hardwareConfiguration': teamworkHardwareConfiguration,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'microphoneConfiguration': teamworkMicrophoneConfiguration,
        'softwareVersions': teamworkDeviceSoftwareVersions,
        'speakerConfiguration': teamworkSpeakerConfiguration,
        'systemConfiguration': teamworkSystemConfiguration,
        'teamsClientConfiguration': teamworkTeamsClientConfiguration,
    }
    rels = [

    ]


class teamworkDeviceHealth(entity):
    props = {
        'connection': teamworkConnection,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'hardwareHealth': teamworkHardwareHealth,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'loginStatus': teamworkLoginStatus,
        'peripheralsHealth': teamworkPeripheralsHealth,
        'softwareUpdateHealth': teamworkSoftwareUpdateHealth,
    }
    rels = [

    ]


class teamworkDeviceOperation(entity):
    props = {
        'completedDateTime': Edm.DateTimeOffset,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'error': operationError,
        'lastActionBy': identitySet,
        'lastActionDateTime': Edm.DateTimeOffset,
        'operationType': teamworkDeviceOperationType,
        'startedDateTime': Edm.DateTimeOffset,
        'status': Edm.String,
    }
    rels = [

    ]


class teamworkTagMember(entity):
    props = {
        'displayName': Edm.String,
        'tenantId': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class shiftsRoleDefinition(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'shiftsRolePermissions': Collection,
    }
    rels = [

    ]


class workingTimeSchedule(entity):
    props = {

    }
    rels = [

    ]


class threatAssessmentResult(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'message': Edm.String,
        'resultType': threatAssessmentResultType,
    }
    rels = [

    ]


class attachmentBase(entity):
    props = {
        'contentType': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'size': Edm.Int32,
    }
    rels = [

    ]


class attachmentSession(entity):
    props = {
        'content': Edm.Stream,
        'expirationDateTime': Edm.DateTimeOffset,
        'nextExpectedRanges': Collection,
    }
    rels = [

    ]


class checklistItem(entity):
    props = {
        'checkedDateTime': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'isChecked': Edm.Boolean,
    }
    rels = [

    ]


class linkedResource(entity):
    props = {
        'applicationName': Edm.String,
        'displayName': Edm.String,
        'externalId': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class todoTaskList(entity):
    props = {
        'displayName': Edm.String,
        'isOwner': Edm.Boolean,
        'isShared': Edm.Boolean,
        'wellknownListName': wellknownListName,
    }
    rels = [
        'extensions',
        'tasks',
    ]


class todoTask(entity):
    props = {
        'body': itemBody,
        'bodyLastModifiedDateTime': Edm.DateTimeOffset,
        'categories': Collection,
        'completedDateTime': dateTimeTimeZone,
        'createdDateTime': Edm.DateTimeOffset,
        'dueDateTime': dateTimeTimeZone,
        'hasAttachments': Edm.Boolean,
        'importance': importance,
        'isReminderOn': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'recurrence': patternedRecurrence,
        'reminderDateTime': dateTimeTimeZone,
        'startDateTime': dateTimeTimeZone,
        'status': taskStatus,
        'title': Edm.String,
    }
    rels = [
        'attachments',
        'attachmentSessions',
        'checklistItems',
        'extensions',
        'linkedResources',
    ]


class storageQuotaBreakdown(entity):
    props = {
        'displayName': Edm.String,
        'manageWebUrl': Edm.String,
        'used': Edm.Int64,
    }
    rels = [

    ]


class unifiedStorageQuota(entity):
    props = {
        'deleted': Edm.Int64,
        'manageWebUrl': Edm.String,
        'remaining': Edm.Int64,
        'state': Edm.String,
        'total': Edm.Int64,
        'used': Edm.Int64,
    }
    rels = [
        'services',
    ]


class learningContent(entity):
    props = {
        'additionalTags': Collection,
        'contentWebUrl': Edm.String,
        'contributors': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'duration': Edm.Duration,
        'externalId': Edm.String,
        'format': Edm.String,
        'isActive': Edm.Boolean,
        'isPremium': Edm.Boolean,
        'isSearchable': Edm.Boolean,
        'languageTag': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'level': level,
        'numberOfPages': Edm.Int32,
        'skillTags': Collection,
        'sourceName': Edm.String,
        'thumbnailWebUrl': Edm.String,
        'title': Edm.String,
    }
    rels = [

    ]


class adminWindowsUpdates(entity):
    props = {

    }
    rels = [
        'catalog',
        'deploymentAudiences',
        'deployments',
        'products',
        'resourceConnections',
        'updatableAssets',
        'updatePolicies',
    ]


class document(entity):
    props = {

    }
    rels = [
        'comments',
    ]


class healthMonitoring_healthMonitoringRoot(entity):
    props = {

    }
    rels = [
        'alertConfigurations',
        'alerts',
    ]


class healthMonitoring_alert(entity):
    props = {
        'alertType': Collection, #extnamespace: healthMonitoring_alertType,
        'category': Collection, #extnamespace: healthMonitoring_category,
        'createdDateTime': Edm.DateTimeOffset,
        'documentation': Collection, #extnamespace: healthMonitoring_documentation,
        'enrichment': Collection, #extnamespace: healthMonitoring_enrichment,
        'scenario': Collection, #extnamespace: healthMonitoring_scenario,
        'signals': Collection, #extnamespace: healthMonitoring_signals,
        'state': Collection, #extnamespace: healthMonitoring_alertState,
    }
    rels = [

    ]


class healthMonitoring_alertConfiguration(entity):
    props = {
        'emailNotificationConfigurations': Collection,
    }
    rels = [

    ]


class networkaccess_alert(entity):
    props = {
        'actions': Collection,
        'alertType': Collection, #extnamespace: networkaccess_alertType,
        'creationDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'detectionTechnology': Edm.String,
        'displayName': Edm.String,
        'relatedResources': Collection,
        'severity': Collection, #extnamespace: networkaccess_alertSeverity,
        'vendorName': Edm.String,
    }
    rels = [
        'policy',
    ]


class networkaccess_policy(entity):
    props = {
        'description': Edm.String,
        'name': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'policyRules',
    ]


class networkaccess_logs(entity):
    props = {

    }
    rels = [
        'remoteNetworks',
        'traffic',
    ]


class networkaccess_remoteNetworkHealthEvent(entity):
    props = {
        'bgpRoutesAdvertisedCount': Edm.Int32,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'destinationIp': Edm.String,
        'receivedBytes': Edm.Int64,
        'remoteNetworkId': Edm.String,
        'sentBytes': Edm.Int64,
        'sourceIp': Edm.String,
        'status': Collection, #extnamespace: networkaccess_remoteNetworkStatus,
    }
    rels = [

    ]


class networkaccess_networkAccessTraffic(object):
    props = {
        'action': Collection, #extnamespace: networkaccess_filteringPolicyAction,
        'agentVersion': Edm.String,
        'applicationSnapshot': Collection, #extnamespace: networkaccess_applicationSnapshot,
        'connectionId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'destinationFQDN': Edm.String,
        'destinationIp': Edm.String,
        'destinationPort': Edm.Int32,
        'destinationUrl': Edm.String,
        'destinationWebCategory': Collection, #extnamespace: networkaccess_webCategory,
        'deviceCategory': Collection, #extnamespace: networkaccess_deviceCategory,
        'deviceId': Edm.String,
        'deviceOperatingSystem': Edm.String,
        'deviceOperatingSystemVersion': Edm.String,
        'filteringProfileId': Edm.String,
        'filteringProfileName': Edm.String,
        'headers': Collection, #extnamespace: networkaccess_headers,
        'httpMethod': Collection, #extnamespace: networkaccess_httpMethod,
        'initiatingProcessName': Edm.String,
        'networkProtocol': Collection, #extnamespace: networkaccess_networkingProtocol,
        'operationStatus': Collection, #extnamespace: networkaccess_networkTrafficOperationStatus,
        'policyId': Edm.String,
        'policyName': Edm.String,
        'policyRuleId': Edm.String,
        'policyRuleName': Edm.String,
        'popProcessingRegion': Edm.String,
        'privateAccessDetails': Collection, #extnamespace: networkaccess_privateAccessDetails,
        'receivedBytes': Edm.Int64,
        'remoteNetworkId': Edm.String,
        'resourceTenantId': Edm.String,
        'responseCode': Edm.Int32,
        'sentBytes': Edm.Int64,
        'sessionId': Edm.String,
        'sourceIp': Edm.String,
        'sourcePort': Edm.Int32,
        'tenantId': Edm.String,
        'threatType': Edm.String,
        'trafficType': Collection, #extnamespace: networkaccess_trafficType,
        'transactionId': Edm.String,
        'transportProtocol': Collection, #extnamespace: networkaccess_networkingProtocol,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'vendorNames': Collection,
    }
    rels = [
        'device',
        'user',
    ]


class networkaccess_networkAccessRoot(entity):
    props = {

    }
    rels = [
        'alerts',
        'logs',
        'reports',
        'connectivity',
        'filteringPolicies',
        'filteringProfiles',
        'forwardingPolicies',
        'forwardingProfiles',
        'settings',
        'tenantStatus',
    ]


class networkaccess_reports(entity):
    props = {

    }
    rels = [

    ]


class networkaccess_connectivity(entity):
    props = {
        'webCategories': Collection,
    }
    rels = [
        'branches',
        'remoteNetworks',
    ]


class networkaccess_profile(entity):
    props = {
        'description': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'state': Collection, #extnamespace: networkaccess_status,
        'version': Edm.String,
    }
    rels = [
        'policies',
    ]


class networkaccess_settings(entity):
    props = {

    }
    rels = [
        'conditionalAccess',
        'crossTenantAccess',
        'enrichedAuditLogs',
        'forwardingOptions',
    ]


class networkaccess_tenantStatus(entity):
    props = {
        'onboardingErrorMessage': Edm.String,
        'onboardingStatus': Collection, #extnamespace: networkaccess_onboardingStatus,
    }
    rels = [

    ]


class networkaccess_branchConnectivityConfiguration(object):
    props = {
        'branchId': Edm.String,
        'branchName': Edm.String,
    }
    rels = [
        'links',
    ]


class networkaccess_connectivityConfigurationLink(entity):
    props = {
        'displayName': Edm.String,
        'localConfigurations': Collection,
        'peerConfiguration': Collection, #extnamespace: networkaccess_peerConnectivityConfiguration,
    }
    rels = [

    ]


class networkaccess_branchSite(entity):
    props = {
        'bandwidthCapacity': Edm.Int64,
        'connectivityState': Collection, #extnamespace: networkaccess_connectivityState,
        'country': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'region': Collection, #extnamespace: networkaccess_region,
        'version': Edm.String,
    }
    rels = [
        'connectivityConfiguration',
        'deviceLinks',
        'forwardingProfiles',
    ]


class networkaccess_deviceLink(entity):
    props = {
        'bandwidthCapacityInMbps': Collection, #extnamespace: networkaccess_bandwidthCapacityInMbps,
        'bgpConfiguration': Collection, #extnamespace: networkaccess_bgpConfiguration,
        'deviceVendor': Collection, #extnamespace: networkaccess_deviceVendor,
        'ipAddress': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'redundancyConfiguration': Collection, #extnamespace: networkaccess_redundancyConfiguration,
        'tunnelConfiguration': Collection, #extnamespace: networkaccess_tunnelConfiguration,
    }
    rels = [

    ]


class networkaccess_conditionalAccessPolicy(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'modifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class networkaccess_conditionalAccessSettings(entity):
    props = {
        'signalingStatus': Collection, #extnamespace: networkaccess_status,
    }
    rels = [

    ]


class networkaccess_remoteNetwork(entity):
    props = {
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'region': Collection, #extnamespace: networkaccess_region,
        'version': Edm.String,
    }
    rels = [
        'connectivityConfiguration',
        'deviceLinks',
        'forwardingProfiles',
    ]


class networkaccess_crossTenantAccessSettings(entity):
    props = {
        'networkPacketTaggingStatus': Collection, #extnamespace: networkaccess_status,
    }
    rels = [

    ]


class networkaccess_enrichedAuditLogs(entity):
    props = {
        'exchange': Collection, #extnamespace: networkaccess_enrichedAuditLogsSettings,
        'sharepoint': Collection, #extnamespace: networkaccess_enrichedAuditLogsSettings,
        'teams': Collection, #extnamespace: networkaccess_enrichedAuditLogsSettings,
    }
    rels = [

    ]


class networkaccess_policyLink(entity):
    props = {
        'state': Collection, #extnamespace: networkaccess_status,
        'version': Edm.String,
    }
    rels = [
        'policy',
    ]


class networkaccess_policyRule(entity):
    props = {
        'name': Edm.String,
    }
    rels = [

    ]


class networkaccess_forwardingOptions(entity):
    props = {
        'skipDnsLookupState': Collection, #extnamespace: networkaccess_status,
    }
    rels = [

    ]


class networkaccess_remoteNetworkConnectivityConfiguration(object):
    props = {
        'remoteNetworkId': Edm.String,
        'remoteNetworkName': Edm.String,
    }
    rels = [
        'links',
    ]


class cloudLicensing_usageRight(entity):
    props = {
        'services': Collection,
        'skuId': Edm.Guid,
        'skuPartNumber': Edm.String,
    }
    rels = [

    ]


class ediscovery_ediscoveryroot(entity):
    props = {

    }
    rels = [
        'cases',
    ]


class ediscovery_caseOperation(entity):
    props = {
        'action': Collection, #extnamespace: ediscovery_caseAction,
        'completedDateTime': Edm.DateTimeOffset,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'percentProgress': Edm.Int32,
        'resultInfo': resultInfo,
        'status': Collection, #extnamespace: ediscovery_caseOperationStatus,
    }
    rels = [

    ]


class ediscovery_reviewSet(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
    }
    rels = [
        'queries',
    ]


class ediscovery_sourceCollection(entity):
    props = {
        'contentQuery': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'dataSourceScopes': Collection, #extnamespace: ediscovery_dataSourceScopes,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'additionalSources',
        'addToReviewSetOperation',
        'custodianSources',
        'lastEstimateStatisticsOperation',
        'noncustodialSources',
    ]


class ediscovery_case(entity):
    props = {
        'closedBy': identitySet,
        'closedDateTime': Edm.DateTimeOffset,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'externalId': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: ediscovery_caseStatus,
    }
    rels = [
        'custodians',
        'legalHolds',
        'noncustodialDataSources',
        'operations',
        'reviewSets',
        'settings',
        'sourceCollections',
        'tags',
    ]


class ediscovery_dataSourceContainer(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'holdStatus': Collection, #extnamespace: ediscovery_dataSourceHoldStatus,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'releasedDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: ediscovery_dataSourceContainerStatus,
    }
    rels = [
        'lastIndexOperation',
    ]


class ediscovery_legalHold(entity):
    props = {
        'contentQuery': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'errors': Collection,
        'isEnabled': Edm.Boolean,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: ediscovery_legalHoldStatus,
    }
    rels = [
        'siteSources',
        'unifiedGroupSources',
        'userSources',
    ]


class ediscovery_caseSettings(entity):
    props = {
        'ocr': Collection, #extnamespace: ediscovery_ocrSettings,
        'redundancyDetection': Collection, #extnamespace: ediscovery_redundancyDetectionSettings,
        'topicModeling': Collection, #extnamespace: ediscovery_topicModelingSettings,
    }
    rels = [

    ]


class ediscovery_tag(entity):
    props = {
        'childSelectability': Collection, #extnamespace: ediscovery_childSelectability,
        'createdBy': identitySet,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'childTags',
        'parent',
    ]


class ediscovery_dataSource(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'holdStatus': Collection, #extnamespace: ediscovery_dataSourceHoldStatus,
    }
    rels = [

    ]


class ediscovery_reviewSetQuery(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'query': Edm.String,
    }
    rels = [

    ]


class security_security(entity):
    props = {

    }
    rels = [
        'informationProtection',
    ]


class security_casesRoot(entity):
    props = {

    }
    rels = [
        'ediscoveryCases',
    ]


class security_dataDiscoveryRoot(entity):
    props = {

    }
    rels = [
        'cloudAppDiscovery',
    ]


class security_identityContainer(entity):
    props = {

    }
    rels = [
        'healthIssues',
        'sensors',
    ]


class security_informationProtection(entity):
    props = {

    }
    rels = [
        'labelPolicySettings',
        'sensitivityLabels',
    ]


class security_auditCoreRoot(entity):
    props = {

    }
    rels = [
        'queries',
    ]


class security_alert(entity):
    props = {
        'actorDisplayName': Edm.String,
        'additionalData': Collection, #extnamespace: security_dictionary,
        'alertPolicyId': Edm.String,
        'alertWebUrl': Edm.String,
        'assignedTo': Edm.String,
        'category': Edm.String,
        'classification': Collection, #extnamespace: security_alertClassification,
        'comments': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'detectionSource': Collection, #extnamespace: security_detectionSource,
        'detectorId': Edm.String,
        'determination': Collection, #extnamespace: security_alertDetermination,
        'evidence': Collection,
        'firstActivityDateTime': Edm.DateTimeOffset,
        'incidentId': Edm.String,
        'incidentWebUrl': Edm.String,
        'lastActivityDateTime': Edm.DateTimeOffset,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'mitreTechniques': Collection,
        'productName': Edm.String,
        'providerAlertId': Edm.String,
        'recommendedActions': Edm.String,
        'resolvedDateTime': Edm.DateTimeOffset,
        'serviceSource': Collection, #extnamespace: security_serviceSource,
        'severity': Collection, #extnamespace: security_alertSeverity,
        'status': Collection, #extnamespace: security_alertStatus,
        'systemTags': Collection,
        'tenantId': Edm.String,
        'threatDisplayName': Edm.String,
        'threatFamilyName': Edm.String,
        'title': Edm.String,
    }
    rels = [

    ]


class security_incident(entity):
    props = {
        'assignedTo': Edm.String,
        'classification': Collection, #extnamespace: security_alertClassification,
        'comments': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'customTags': Collection,
        'description': Edm.String,
        'determination': Collection, #extnamespace: security_alertDetermination,
        'displayName': Edm.String,
        'incidentWebUrl': Edm.String,
        'lastModifiedBy': Edm.String,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'recommendedActions': Edm.String,
        'recommendedHuntingQueries': Collection,
        'redirectIncidentId': Edm.String,
        'resolvingComment': Edm.String,
        'severity': Collection, #extnamespace: security_alertSeverity,
        'status': Collection, #extnamespace: security_incidentStatus,
        'summary': Edm.String,
        'systemTags': Collection,
        'tenantId': Edm.String,
    }
    rels = [
        'alerts',
    ]


class security_rulesRoot(entity):
    props = {

    }
    rels = [
        'detectionRules',
    ]


class security_collaborationRoot(entity):
    props = {

    }
    rels = [
        'analyzedEmails',
    ]


class security_labelsRoot(entity):
    props = {

    }
    rels = [
        'authorities',
        'categories',
        'citations',
        'departments',
        'filePlanReferences',
        'retentionLabels',
    ]


class security_triggersRoot(entity):
    props = {

    }
    rels = [
        'retentionEvents',
    ]


class security_triggerTypesRoot(entity):
    props = {

    }
    rels = [
        'retentionEventTypes',
    ]


class security_threatSubmissionRoot(entity):
    props = {

    }
    rels = [
        'emailThreats',
        'emailThreatSubmissionPolicies',
        'fileThreats',
        'urlThreats',
    ]


class security_threatIntelligence(entity):
    props = {

    }
    rels = [
        'articleIndicators',
        'articles',
        'hostComponents',
        'hostCookies',
        'hostPairs',
        'hostPorts',
        'hosts',
        'hostSslCertificates',
        'hostTrackers',
        'intelligenceProfileIndicators',
        'intelProfiles',
        'passiveDnsRecords',
        'sslCertificates',
        'subdomains',
        'vulnerabilities',
        'whoisHistoryRecords',
        'whoisRecords',
    ]


class security_case(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: security_caseStatus,
    }
    rels = [

    ]


class security_caseOperation(entity):
    props = {
        'action': Collection, #extnamespace: security_caseAction,
        'completedDateTime': Edm.DateTimeOffset,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'percentProgress': Edm.Int32,
        'resultInfo': resultInfo,
        'status': Collection, #extnamespace: security_caseOperationStatus,
    }
    rels = [

    ]


class security_dataSet(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class security_dataSource(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'holdStatus': Collection, #extnamespace: security_dataSourceHoldStatus,
    }
    rels = [

    ]


class security_dataSourceContainer(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'holdStatus': Collection, #extnamespace: security_dataSourceHoldStatus,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'releasedDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: security_dataSourceContainerStatus,
    }
    rels = [

    ]


class security_search(entity):
    props = {
        'contentQuery': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class security_policyBase(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: security_policyStatus,
    }
    rels = [

    ]


class security_ediscoveryCaseSettings(entity):
    props = {
        'ocr': Collection, #extnamespace: security_ocrSettings,
        'redundancyDetection': Collection, #extnamespace: security_redundancyDetectionSettings,
        'topicModeling': Collection, #extnamespace: security_topicModelingSettings,
    }
    rels = [

    ]


class security_tag(entity):
    props = {
        'createdBy': identitySet,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class security_ediscoveryCaseMember(entity):
    props = {
        'displayName': Edm.String,
        'recipientType': Collection, #extnamespace: security_recipientType,
        'smtpAddress': Edm.String,
    }
    rels = [

    ]


class security_file(entity):
    props = {
        'content': Edm.Stream,
        'dateTime': Edm.DateTimeOffset,
        'extension': Edm.String,
        'extractedTextContent': Edm.Stream,
        'mediaType': Edm.String,
        'name': Edm.String,
        'otherProperties': Collection, #extnamespace: security_stringValueDictionary,
        'processingStatus': Collection, #extnamespace: security_fileProcessingStatus,
        'senderOrAuthors': Collection,
        'size': Edm.Int64,
        'sourceType': Collection, #extnamespace: security_sourceType,
        'subjectTitle': Edm.String,
    }
    rels = [

    ]


class security_cloudAppDiscoveryReport(entity):
    props = {
        'anonymizeMachineData': Edm.Boolean,
        'anonymizeUserData': Edm.Boolean,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'isSnapshotReport': Edm.Boolean,
        'lastDataReceivedDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'logDataProvider': Collection, #extnamespace: security_logDataProvider,
        'logFileCount': Edm.Int32,
        'receiverProtocol': Collection, #extnamespace: security_receiverProtocol,
        'supportedEntityTypes': Collection,
        'supportedTrafficTypes': Collection,
    }
    rels = [

    ]


class security_dataDiscoveryReport(entity):
    props = {

    }
    rels = [
        'uploadedStreams',
    ]


class security_discoveredCloudAppDetail(entity):
    props = {
        'category': Collection, #extnamespace: security_appCategory,
        'description': Edm.String,
        'displayName': Edm.String,
        'domains': Collection,
        'downloadNetworkTrafficInBytes': Edm.Int64,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'ipAddressCount': Edm.Int64,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'riskScore': Edm.Int64,
        'tags': Collection,
        'transactionCount': Edm.Int64,
        'uploadNetworkTrafficInBytes': Edm.Int64,
        'userCount': Edm.Int64,
    }
    rels = [
        'appInfo',
        'ipAddresses',
        'users',
    ]


class security_discoveredCloudAppInfo(entity):
    props = {
        'csaStarLevel': Collection, #extnamespace: security_appInfoCsaStarLevel,
        'dataAtRestEncryptionMethod': Collection, #extnamespace: security_appInfoDataAtRestEncryptionMethod,
        'dataCenter': Edm.String,
        'dataRetentionPolicy': Collection, #extnamespace: security_appInfoDataRetentionPolicy,
        'dataTypes': Collection, #extnamespace: security_appInfoUploadedDataTypes,
        'domainRegistrationDateTime': Edm.DateTimeOffset,
        'encryptionProtocol': Collection, #extnamespace: security_appInfoEncryptionProtocol,
        'fedRampLevel': Collection, #extnamespace: security_appInfoFedRampLevel,
        'founded': Edm.Int32,
        'gdprReadinessStatement': Edm.String,
        'headquarters': Edm.String,
        'holding': Collection, #extnamespace: security_appInfoHolding,
        'hostingCompany': Edm.String,
        'isAdminAuditTrail': Collection, #extnamespace: security_cloudAppInfoState,
        'isCobitCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isCoppaCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isDataAuditTrail': Collection, #extnamespace: security_cloudAppInfoState,
        'isDataClassification': Collection, #extnamespace: security_cloudAppInfoState,
        'isDataOwnership': Collection, #extnamespace: security_cloudAppInfoState,
        'isDisasterRecoveryPlan': Collection, #extnamespace: security_cloudAppInfoState,
        'isDmca': Collection, #extnamespace: security_cloudAppInfoState,
        'isFerpaCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isFfiecCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isFileSharing': Collection, #extnamespace: security_cloudAppInfoState,
        'isFinraCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isFismaCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isGaapCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprDataProtectionImpactAssessment': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprDataProtectionOfficer': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprDataProtectionSecureCrossBorderDataTransfer': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprImpactAssessment': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprLawfulBasisForProcessing': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprReportDataBreaches': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightsRelatedToAutomatedDecisionMaking': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToAccess': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToBeInformed': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToDataPortablility': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToErasure': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToObject': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToRectification': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprRightToRestrictionOfProcessing': Collection, #extnamespace: security_cloudAppInfoState,
        'isGdprSecureCrossBorderDataControl': Collection, #extnamespace: security_cloudAppInfoState,
        'isGlbaCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isHipaaCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isHitrustCsfCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isHttpSecurityHeadersContentSecurityPolicy': Collection, #extnamespace: security_cloudAppInfoState,
        'isHttpSecurityHeadersStrictTransportSecurity': Collection, #extnamespace: security_cloudAppInfoState,
        'isHttpSecurityHeadersXContentTypeOptions': Collection, #extnamespace: security_cloudAppInfoState,
        'isHttpSecurityHeadersXFrameOptions': Collection, #extnamespace: security_cloudAppInfoState,
        'isHttpSecurityHeadersXXssProtection': Collection, #extnamespace: security_cloudAppInfoState,
        'isIpAddressRestriction': Collection, #extnamespace: security_cloudAppInfoState,
        'isIsae3402Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isIso27001Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isIso27017Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isIso27018Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isItarCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isMultiFactorAuthentication': Collection, #extnamespace: security_cloudAppInfoState,
        'isPasswordPolicy': Collection, #extnamespace: security_cloudAppInfoState,
        'isPasswordPolicyChangePasswordPeriod': Collection, #extnamespace: security_cloudAppInfoState,
        'isPasswordPolicyCharacterCombination': Collection, #extnamespace: security_cloudAppInfoState,
        'isPasswordPolicyPasswordHistoryAndReuse': Collection, #extnamespace: security_cloudAppInfoState,
        'isPasswordPolicyPasswordLengthLimit': Collection, #extnamespace: security_cloudAppInfoState,
        'isPasswordPolicyPersonalInformationUse': Collection, #extnamespace: security_cloudAppInfoState,
        'isPenetrationTesting': Collection, #extnamespace: security_cloudAppInfoState,
        'isPrivacyShieldCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isRememberPassword': Collection, #extnamespace: security_cloudAppInfoState,
        'isRequiresUserAuthentication': Collection, #extnamespace: security_cloudAppInfoState,
        'isSoc1Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isSoc2Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isSoc3Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isSoxCompliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isSp80053Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isSsae16Compliant': Collection, #extnamespace: security_cloudAppInfoState,
        'isSupportsSaml': Collection, #extnamespace: security_cloudAppInfoState,
        'isTrustedCertificate': Collection, #extnamespace: security_cloudAppInfoState,
        'isUserAuditTrail': Collection, #extnamespace: security_cloudAppInfoState,
        'isUserCanUploadData': Collection, #extnamespace: security_cloudAppInfoState,
        'isUserRolesSupport': Collection, #extnamespace: security_cloudAppInfoState,
        'isValidCertificateName': Collection, #extnamespace: security_cloudAppInfoState,
        'latestBreachDateTime': Edm.DateTimeOffset,
        'logonUrls': Edm.String,
        'pciDssVersion': Collection, #extnamespace: security_appInfoPciDssVersion,
        'vendor': Edm.String,
    }
    rels = [

    ]


class security_discoveredCloudAppIPAddress(object):
    props = {
        'ipAddress': Edm.String,
    }
    rels = [

    ]


class security_discoveredCloudAppUser(object):
    props = {
        'userIdentifier': Edm.String,
    }
    rels = [

    ]


class security_discoveredCloudAppDevice(object):
    props = {
        'name': Edm.String,
    }
    rels = [

    ]


class security_networkAdapter(entity):
    props = {
        'isEnabled': Edm.Boolean,
        'name': Edm.String,
    }
    rels = [

    ]


class security_healthIssue(entity):
    props = {
        'additionalInformation': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'domainNames': Collection,
        'healthIssueType': Collection, #extnamespace: security_healthIssueType,
        'issueTypeId': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'recommendations': Collection,
        'recommendedActionCommands': Collection,
        'sensorDNSNames': Collection,
        'severity': Collection, #extnamespace: security_healthIssueSeverity,
        'status': Collection, #extnamespace: security_healthIssueStatus,
    }
    rels = [

    ]


class security_sensor(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'deploymentStatus': Collection, #extnamespace: security_deploymentStatus,
        'displayName': Edm.String,
        'domainName': Edm.String,
        'healthStatus': Collection, #extnamespace: security_sensorHealthStatus,
        'openHealthIssuesCount': Edm.Int64,
        'sensorType': Collection, #extnamespace: security_sensorType,
        'settings': Collection, #extnamespace: security_sensorSettings,
        'version': Edm.String,
    }
    rels = [
        'healthIssues',
    ]


class security_informationProtectionPolicySetting(entity):
    props = {
        'defaultLabelId': Edm.String,
        'isDowngradeJustificationRequired': Edm.Boolean,
        'isMandatory': Edm.Boolean,
        'moreInfoUrl': Edm.String,
    }
    rels = [

    ]


class security_sensitivityLabel(entity):
    props = {
        'color': Edm.String,
        'contentFormats': Collection,
        'description': Edm.String,
        'hasProtection': Edm.Boolean,
        'isActive': Edm.Boolean,
        'isAppliable': Edm.Boolean,
        'name': Edm.String,
        'sensitivity': Edm.Int32,
        'tooltip': Edm.String,
    }
    rels = [
        'parent',
    ]


class security_auditLogQuery(entity):
    props = {
        'administrativeUnitIdFilters': Collection,
        'displayName': Edm.String,
        'filterEndDateTime': Edm.DateTimeOffset,
        'filterStartDateTime': Edm.DateTimeOffset,
        'ipAddressFilters': Collection,
        'keywordFilter': Edm.String,
        'objectIdFilters': Collection,
        'operationFilters': Collection,
        'recordTypeFilters': Collection,
        'serviceFilters': Collection,
        'status': Collection, #extnamespace: security_auditLogQueryStatus,
        'userPrincipalNameFilters': Collection,
    }
    rels = [
        'records',
    ]


class security_auditLogRecord(entity):
    props = {
        'administrativeUnits': Collection,
        'auditData': Collection, #extnamespace: security_auditData,
        'auditLogRecordType': Collection, #extnamespace: security_auditLogRecordType,
        'clientIp': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'objectId': Edm.String,
        'operation': Edm.String,
        'organizationId': Edm.String,
        'service': Edm.String,
        'userId': Edm.String,
        'userPrincipalName': Edm.String,
        'userType': Collection, #extnamespace: security_auditLogUserType,
    }
    rels = [

    ]


class security_protectionRule(entity):
    props = {
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'isEnabled': Edm.Boolean,
        'lastModifiedBy': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class security_analyzedEmail(entity):
    props = {
        'alertIds': Collection,
        'attachments': Collection,
        'authenticationDetails': Collection, #extnamespace: security_analyzedEmailAuthenticationDetail,
        'bulkComplaintLevel': Edm.String,
        'clientType': Edm.String,
        'contexts': Collection,
        'detectionMethods': Collection,
        'directionality': Collection, #extnamespace: security_antispamDirectionality,
        'distributionList': Edm.String,
        'dlpRules': Collection,
        'emailClusterId': Edm.String,
        'exchangeTransportRules': Collection,
        'forwardingDetail': Edm.String,
        'inboundConnectorFormattedName': Edm.String,
        'internetMessageId': Edm.String,
        'language': Edm.String,
        'latestDelivery': Collection, #extnamespace: security_analyzedEmailDeliveryDetail,
        'loggedDateTime': Edm.DateTimeOffset,
        'networkMessageId': Edm.String,
        'originalDelivery': Collection, #extnamespace: security_analyzedEmailDeliveryDetail,
        'overrideSources': Collection,
        'phishConfidenceLevel': Edm.String,
        'policy': Edm.String,
        'policyAction': Edm.String,
        'policyType': Edm.String,
        'primaryOverrideSource': Edm.String,
        'recipientDetail': Collection, #extnamespace: security_analyzedEmailRecipientDetail,
        'recipientEmailAddress': Edm.String,
        'returnPath': Edm.String,
        'senderDetail': Collection, #extnamespace: security_analyzedEmailSenderDetail,
        'sizeInBytes': Edm.Int32,
        'spamConfidenceLevel': Edm.String,
        'subject': Edm.String,
        'threatDetectionDetails': Collection,
        'threatTypes': Collection,
        'timelineEvents': Collection,
        'urls': Collection,
    }
    rels = [

    ]


class security_filePlanDescriptorTemplate(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
    }
    rels = [

    ]


class security_dispositionReviewStage(object):
    props = {
        'name': Edm.String,
        'reviewersEmailAddresses': Collection,
        'stageNumber': Edm.String,
    }
    rels = [

    ]


class security_filePlanDescriptor(entity):
    props = {
        'authority': Collection, #extnamespace: security_filePlanAuthority,
        'category': Collection, #extnamespace: security_filePlanAppliedCategory,
        'citation': Collection, #extnamespace: security_filePlanCitation,
        'department': Collection, #extnamespace: security_filePlanDepartment,
        'filePlanReference': Collection, #extnamespace: security_filePlanReference,
    }
    rels = [
        'authorityTemplate',
        'categoryTemplate',
        'citationTemplate',
        'departmentTemplate',
        'filePlanReferenceTemplate',
    ]


class security_retentionLabel(entity):
    props = {
        'actionAfterRetentionPeriod': Collection, #extnamespace: security_actionAfterRetentionPeriod,
        'behaviorDuringRetentionPeriod': Collection, #extnamespace: security_behaviorDuringRetentionPeriod,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'defaultRecordBehavior': Collection, #extnamespace: security_defaultRecordBehavior,
        'descriptionForAdmins': Edm.String,
        'descriptionForUsers': Edm.String,
        'displayName': Edm.String,
        'isInUse': Edm.Boolean,
        'labelToBeApplied': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'retentionDuration': Collection, #extnamespace: security_retentionDuration,
        'retentionTrigger': Collection, #extnamespace: security_retentionTrigger,
    }
    rels = [
        'descriptors',
        'dispositionReviewStages',
        'retentionEventType',
    ]


class security_retentionEvent(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'eventPropagationResults': Collection,
        'eventQueries': Collection,
        'eventStatus': Collection, #extnamespace: security_retentionEventStatus,
        'eventTriggerDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'lastStatusUpdateDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'retentionEventType',
    ]


class security_retentionEventType(entity):
    props = {
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class security_threatSubmission(entity):
    props = {
        'adminReview': Collection, #extnamespace: security_submissionAdminReview,
        'category': Collection, #extnamespace: security_submissionCategory,
        'clientSource': Collection, #extnamespace: security_submissionClientSource,
        'contentType': Collection, #extnamespace: security_submissionContentType,
        'createdBy': Collection, #extnamespace: security_submissionUserIdentity,
        'createdDateTime': Edm.DateTimeOffset,
        'result': Collection, #extnamespace: security_submissionResult,
        'source': Collection, #extnamespace: security_submissionSource,
        'status': Collection, #extnamespace: security_longRunningOperationStatus,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class security_emailThreatSubmissionPolicy(entity):
    props = {
        'customizedNotificationSenderEmailAddress': Edm.String,
        'customizedReportRecipientEmailAddress': Edm.String,
        'isAlwaysReportEnabledForUsers': Edm.Boolean,
        'isAskMeEnabledForUsers': Edm.Boolean,
        'isCustomizedMessageEnabled': Edm.Boolean,
        'isCustomizedMessageEnabledForPhishing': Edm.Boolean,
        'isCustomizedNotificationSenderEnabled': Edm.Boolean,
        'isNeverReportEnabledForUsers': Edm.Boolean,
        'isOrganizationBrandingEnabled': Edm.Boolean,
        'isReportFromQuarantineEnabled': Edm.Boolean,
        'isReportToCustomizedEmailAddressEnabled': Edm.Boolean,
        'isReportToMicrosoftEnabled': Edm.Boolean,
        'isReviewEmailNotificationEnabled': Edm.Boolean,
    }
    rels = [

    ]


class security_artifact(entity):
    props = {

    }
    rels = [

    ]


class security_article(entity):
    props = {
        'body': Collection, #extnamespace: security_formattedContent,
        'createdDateTime': Edm.DateTimeOffset,
        'imageUrl': Edm.String,
        'isFeatured': Edm.Boolean,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'summary': Collection, #extnamespace: security_formattedContent,
        'tags': Collection,
        'title': Edm.String,
    }
    rels = [
        'indicators',
    ]


class security_indicator(entity):
    props = {
        'source': Collection, #extnamespace: security_indicatorSource,
    }
    rels = [
        'artifact',
    ]


class security_hostPair(entity):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'linkKind': Edm.String,
    }
    rels = [
        'childHost',
        'parentHost',
    ]


class security_hostPort(entity):
    props = {
        'banners': Collection,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastScanDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'port': Edm.Int32,
        'protocol': Collection, #extnamespace: security_hostPortProtocol,
        'services': Collection,
        'status': Collection, #extnamespace: security_hostPortStatus,
        'timesObserved': Edm.Int32,
    }
    rels = [
        'host',
        'mostRecentSslCertificate',
    ]


class security_hostReputation(entity):
    props = {
        'classification': Collection, #extnamespace: security_hostReputationClassification,
        'rules': Collection,
        'score': Edm.Int32,
    }
    rels = [

    ]


class security_subdomain(entity):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'host',
    ]


class security_whoisBaseRecord(entity):
    props = {
        'abuse': Collection, #extnamespace: security_whoisContact,
        'admin': Collection, #extnamespace: security_whoisContact,
        'billing': Collection, #extnamespace: security_whoisContact,
        'domainStatus': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'lastUpdateDateTime': Edm.DateTimeOffset,
        'nameservers': Collection,
        'noc': Collection, #extnamespace: security_whoisContact,
        'rawWhoisText': Edm.String,
        'registrant': Collection, #extnamespace: security_whoisContact,
        'registrar': Collection, #extnamespace: security_whoisContact,
        'registrationDateTime': Edm.DateTimeOffset,
        'technical': Collection, #extnamespace: security_whoisContact,
        'whoisServer': Edm.String,
        'zone': Collection, #extnamespace: security_whoisContact,
    }
    rels = [
        'host',
    ]


class security_intelligenceProfile(entity):
    props = {
        'aliases': Collection,
        'countriesOrRegionsOfOrigin': Collection,
        'description': Collection, #extnamespace: security_formattedContent,
        'firstActiveDateTime': Edm.DateTimeOffset,
        'kind': Collection, #extnamespace: security_intelligenceProfileKind,
        'summary': Collection, #extnamespace: security_formattedContent,
        'targets': Collection,
        'title': Edm.String,
        'tradecraft': Collection, #extnamespace: security_formattedContent,
    }
    rels = [
        'indicators',
    ]


class security_vulnerability(entity):
    props = {
        'activeExploitsObserved': Edm.Boolean,
        'commonWeaknessEnumerationIds': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'cvss2Summary': Collection, #extnamespace: security_cvssSummary,
        'cvss3Summary': Collection, #extnamespace: security_cvssSummary,
        'description': Collection, #extnamespace: security_formattedContent,
        'exploits': Collection,
        'exploitsAvailable': Edm.Boolean,
        'hasChatter': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'priorityScore': Edm.Int32,
        'publishedDateTime': Edm.DateTimeOffset,
        'references': Collection,
        'remediation': Collection, #extnamespace: security_formattedContent,
        'severity': Collection, #extnamespace: security_vulnerabilitySeverity,
    }
    rels = [
        'articles',
        'components',
    ]


class security_vulnerabilityComponent(entity):
    props = {
        'name': Edm.String,
    }
    rels = [

    ]


class deviceManagement_monitoring(entity):
    props = {

    }
    rels = [
        'alertRecords',
        'alertRules',
    ]


class deviceManagement_alertRecord(entity):
    props = {
        'alertImpact': Collection, #extnamespace: deviceManagement_alertImpact,
        'alertRuleId': Edm.String,
        'alertRuleTemplate': Collection, #extnamespace: deviceManagement_alertRuleTemplate,
        'detectedDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'resolvedDateTime': Edm.DateTimeOffset,
        'severity': Collection, #extnamespace: deviceManagement_ruleSeverityType,
        'status': Collection, #extnamespace: deviceManagement_alertStatusType,
    }
    rels = [

    ]


class deviceManagement_alertRule(entity):
    props = {
        'alertRuleTemplate': Collection, #extnamespace: deviceManagement_alertRuleTemplate,
        'conditions': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'enabled': Edm.Boolean,
        'isSystemRule': Edm.Boolean,
        'notificationChannels': Collection,
        'severity': Collection, #extnamespace: deviceManagement_ruleSeverityType,
        'threshold': Collection, #extnamespace: deviceManagement_ruleThreshold,
    }
    rels = [

    ]


class termStore_store(entity):
    props = {
        'defaultLanguageTag': Edm.String,
        'languageTags': Collection,
    }
    rels = [
        'groups',
        'sets',
    ]


class termStore_group(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'parentSiteId': Edm.String,
        'scope': Collection, #extnamespace: termStore_termGroupScope,
    }
    rels = [
        'sets',
    ]


class termStore_set(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'localizedNames': Collection,
        'properties': Collection,
    }
    rels = [
        'children',
        'parentGroup',
        'relations',
        'terms',
    ]


class termStore_relation(entity):
    props = {
        'relationship': Collection, #extnamespace: termStore_relationType,
    }
    rels = [
        'fromTerm',
        'set',
        'toTerm',
    ]


class termStore_term(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'descriptions': Collection,
        'labels': Collection,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'properties': Collection,
    }
    rels = [
        'children',
        'relations',
        'set',
    ]


class callRecords_callRecord(entity):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'joinWebUrl': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'modalities': Collection,
        'organizer': identitySet,
        'participants': Collection,
        'startDateTime': Edm.DateTimeOffset,
        'type': Collection, #extnamespace: callRecords_callType,
        'version': Edm.Int64,
    }
    rels = [
        'organizer_v2',
        'participants_v2',
        'sessions',
    ]


class callRecords_participantBase(entity):
    props = {
        'administrativeUnitInfos': Collection,
        'identity': communicationsIdentitySet,
    }
    rels = [

    ]


class callRecords_session(entity):
    props = {
        'callee': Collection, #extnamespace: callRecords_endpoint,
        'caller': Collection, #extnamespace: callRecords_endpoint,
        'endDateTime': Edm.DateTimeOffset,
        'failureInfo': Collection, #extnamespace: callRecords_failureInfo,
        'isTest': Edm.Boolean,
        'modalities': Collection,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'segments',
    ]


class callRecords_segment(entity):
    props = {
        'callee': Collection, #extnamespace: callRecords_endpoint,
        'caller': Collection, #extnamespace: callRecords_endpoint,
        'endDateTime': Edm.DateTimeOffset,
        'failureInfo': Collection, #extnamespace: callRecords_failureInfo,
        'media': Collection,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class teamsAdministration_teamsAdminRoot(entity):
    props = {

    }
    rels = [
        'policy',
    ]


class teamsAdministration_teamsPolicyAssignment(entity):
    props = {

    }
    rels = [

    ]


class industryData_industryDataRoot(entity):
    props = {

    }
    rels = [
        'dataConnectors',
        'inboundFlows',
        'operations',
        'outboundProvisioningFlowSets',
        'referenceDefinitions',
        'roleGroups',
        'runs',
        'sourceSystems',
        'years',
    ]


class industryData_referenceDefinition(entity):
    props = {
        'code': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'isDisabled': Edm.Boolean,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'referenceType': Edm.String,
        'sortIndex': Edm.Int32,
        'source': Edm.String,
    }
    rels = [

    ]


class industryData_roleGroup(entity):
    props = {
        'displayName': Edm.String,
        'roles': Collection,
    }
    rels = [

    ]


class industryData_provisioningFlow(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'readinessStatus': Collection, #extnamespace: industryData_readinessStatus,
    }
    rels = [

    ]


class industryData_industryDataConnector(entity):
    props = {
        'displayName': Edm.String,
    }
    rels = [
        'sourceSystem',
    ]


class industryData_industryDataActivity(entity):
    props = {
        'displayName': Edm.String,
        'readinessStatus': Collection, #extnamespace: industryData_readinessStatus,
    }
    rels = [

    ]


class industryData_yearTimePeriodDefinition(entity):
    props = {
        'displayName': Edm.String,
        'endDate': Edm.Date,
        'startDate': Edm.Date,
        'year': Collection, #extnamespace: industryData_yearReferenceValue,
    }
    rels = [

    ]


class industryData_industryDataRunActivity(entity):
    props = {
        'blockingError': publicError,
        'displayName': Edm.String,
        'status': Collection, #extnamespace: industryData_industryDataActivityStatus,
    }
    rels = [
        'activity',
    ]


class industryData_sourceSystemDefinition(entity):
    props = {
        'displayName': Edm.String,
        'userMatchingSettings': Collection,
        'vendor': Edm.String,
    }
    rels = [

    ]


class industryData_outboundProvisioningFlowSet(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'filter': Collection, #extnamespace: industryData_filter,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'provisioningFlows',
    ]


class industryData_industryDataRun(entity):
    props = {
        'blockingError': publicError,
        'displayName': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: industryData_industryDataRunStatus,
    }
    rels = [
        'activities',
    ]


class managedTenants_managedTenant(entity):
    props = {

    }
    rels = [
        'aggregatedPolicyCompliances',
        'appPerformances',
        'auditEvents',
        'cloudPcConnections',
        'cloudPcDevices',
        'cloudPcsOverview',
        'conditionalAccessPolicyCoverages',
        'credentialUserRegistrationsSummaries',
        'deviceAppPerformances',
        'deviceCompliancePolicySettingStateSummaries',
        'deviceHealthStatuses',
        'managedDeviceCompliances',
        'managedDeviceComplianceTrends',
        'managedTenantAlertLogs',
        'managedTenantAlertRuleDefinitions',
        'managedTenantAlertRules',
        'managedTenantAlerts',
        'managedTenantApiNotifications',
        'managedTenantEmailNotifications',
        'managedTenantTicketingEndpoints',
        'managementActions',
        'managementActionTenantDeploymentStatuses',
        'managementIntents',
        'managementTemplateCollections',
        'managementTemplateCollectionTenantSummaries',
        'managementTemplates',
        'managementTemplateSteps',
        'managementTemplateStepTenantSummaries',
        'managementTemplateStepVersions',
        'myRoles',
        'tenantGroups',
        'tenants',
        'tenantsCustomizedInformation',
        'tenantsDetailedInformation',
        'tenantTags',
        'windowsDeviceMalwareStates',
        'windowsProtectionStates',
    ]


class managedTenants_aggregatedPolicyCompliance(entity):
    props = {
        'compliancePolicyId': Edm.String,
        'compliancePolicyName': Edm.String,
        'compliancePolicyPlatform': Edm.String,
        'compliancePolicyType': Edm.String,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'numberOfCompliantDevices': Edm.Int64,
        'numberOfErrorDevices': Edm.Int64,
        'numberOfNonCompliantDevices': Edm.Int64,
        'policyModifiedDateTime': Edm.DateTimeOffset,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_appPerformance(entity):
    props = {
        'appFriendlyName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'meanTimeToFailureInMinutes': Edm.Int32,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'totalActiveDeviceCount': Edm.Int32,
        'totalAppCrashCount': Edm.Int32,
        'totalAppFreezeCount': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_auditEvent(entity):
    props = {
        'activity': Edm.String,
        'activityDateTime': Edm.DateTimeOffset,
        'activityId': Edm.String,
        'category': Edm.String,
        'httpVerb': Edm.String,
        'initiatedByAppId': Edm.String,
        'initiatedByUpn': Edm.String,
        'initiatedByUserId': Edm.String,
        'ipAddress': Edm.String,
        'requestBody': Edm.String,
        'requestUrl': Edm.String,
        'tenantIds': Edm.String,
        'tenantNames': Edm.String,
    }
    rels = [

    ]


class managedTenants_cloudPcConnection(entity):
    props = {
        'displayName': Edm.String,
        'healthCheckStatus': Edm.String,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_cloudPcDevice(entity):
    props = {
        'cloudPcStatus': Edm.String,
        'deviceSpecification': Edm.String,
        'displayName': Edm.String,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'managedDeviceName': Edm.String,
        'provisioningPolicyId': Edm.String,
        'servicePlanName': Edm.String,
        'servicePlanType': Edm.String,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class managedTenants_cloudPcOverview(object):
    props = {
        'frontlineLicensesCount': Edm.Int32,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'numberOfCloudPcConnectionStatusFailed': Edm.Int32,
        'numberOfCloudPcConnectionStatusPassed': Edm.Int32,
        'numberOfCloudPcConnectionStatusPending': Edm.Int32,
        'numberOfCloudPcConnectionStatusRunning': Edm.Int32,
        'numberOfCloudPcConnectionStatusUnkownFutureValue': Edm.Int32,
        'numberOfCloudPcStatusDeprovisioning': Edm.Int32,
        'numberOfCloudPcStatusFailed': Edm.Int32,
        'numberOfCloudPcStatusInGracePeriod': Edm.Int32,
        'numberOfCloudPcStatusNotProvisioned': Edm.Int32,
        'numberOfCloudPcStatusProvisioned': Edm.Int32,
        'numberOfCloudPcStatusProvisioning': Edm.Int32,
        'numberOfCloudPcStatusUnknown': Edm.Int32,
        'numberOfCloudPcStatusUpgrading': Edm.Int32,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'totalBusinessLicenses': Edm.Int32,
        'totalCloudPcConnectionStatus': Edm.Int32,
        'totalCloudPcStatus': Edm.Int32,
        'totalEnterpriseLicenses': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_conditionalAccessPolicyCoverage(entity):
    props = {
        'conditionalAccessPolicyState': Edm.String,
        'latestPolicyModifiedDateTime': Edm.DateTimeOffset,
        'requiresDeviceCompliance': Edm.Boolean,
        'tenantDisplayName': Edm.String,
    }
    rels = [

    ]


class managedTenants_credentialUserRegistrationsSummary(entity):
    props = {
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'mfaAndSsprCapableUserCount': Edm.Int32,
        'mfaConditionalAccessPolicyState': Edm.String,
        'mfaExcludedUserCount': Edm.Int32,
        'mfaRegisteredUserCount': Edm.Int32,
        'securityDefaultsEnabled': Edm.Boolean,
        'ssprEnabledUserCount': Edm.Int32,
        'ssprRegisteredUserCount': Edm.Int32,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'tenantLicenseType': Edm.String,
        'totalUserCount': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_deviceAppPerformance(entity):
    props = {
        'appFriendlyName': Edm.String,
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appVersion': Edm.String,
        'deviceId': Edm.String,
        'deviceManufacturer': Edm.String,
        'deviceModel': Edm.String,
        'deviceName': Edm.String,
        'healthStatus': Edm.String,
        'isLatestUsedVersion': Edm.Int32,
        'isMostUsedVersion': Edm.Int32,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'totalAppCrashCount': Edm.Int32,
        'totalAppFreezeCount': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_deviceCompliancePolicySettingStateSummary(entity):
    props = {
        'conflictDeviceCount': Edm.Int32,
        'errorDeviceCount': Edm.Int32,
        'failedDeviceCount': Edm.Int32,
        'intuneAccountId': Edm.String,
        'intuneSettingId': Edm.String,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'notApplicableDeviceCount': Edm.Int32,
        'pendingDeviceCount': Edm.Int32,
        'policyType': Edm.String,
        'settingName': Edm.String,
        'succeededDeviceCount': Edm.Int32,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_deviceHealthStatus(entity):
    props = {
        'blueScreenCount': Edm.Int32,
        'bootTotalDurationInSeconds': Edm.Double,
        'deviceId': Edm.String,
        'deviceMake': Edm.String,
        'deviceModel': Edm.String,
        'deviceName': Edm.String,
        'healthStatus': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'osVersion': Edm.String,
        'primaryDiskType': Edm.String,
        'restartCount': Edm.Int32,
        'startupPerformanceScore': Edm.Double,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'topProcesses': Edm.String,
    }
    rels = [

    ]


class managedTenants_managedDeviceCompliance(entity):
    props = {
        'complianceStatus': Edm.String,
        'deviceType': Edm.String,
        'inGracePeriodUntilDateTime': Edm.DateTimeOffset,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'lastSyncDateTime': Edm.DateTimeOffset,
        'managedDeviceId': Edm.String,
        'managedDeviceName': Edm.String,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'osDescription': Edm.String,
        'osVersion': Edm.String,
        'ownerType': Edm.String,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_managedDeviceComplianceTrend(entity):
    props = {
        'compliantDeviceCount': Edm.Int32,
        'configManagerDeviceCount': Edm.Int32,
        'countDateTime': Edm.String,
        'errorDeviceCount': Edm.Int32,
        'inGracePeriodDeviceCount': Edm.Int32,
        'noncompliantDeviceCount': Edm.Int32,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
        'unknownDeviceCount': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_managedTenantAlertLog(entity):
    props = {
        'content': Collection, #extnamespace: managedTenants_alertLogContent,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'alert',
    ]


class managedTenants_managedTenantAlertRuleDefinition(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'definitionTemplate': Collection, #extnamespace: managedTenants_alertRuleDefinitionTemplate,
        'displayName': Edm.String,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'alertRules',
    ]


class managedTenants_managedTenantAlertRule(entity):
    props = {
        'alertDisplayName': Edm.String,
        'alertTTL': Edm.Int32,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'lastRunDateTime': Edm.DateTimeOffset,
        'notificationFinalDestinations': Collection, #extnamespace: managedTenants_notificationDestination,
        'severity': Collection, #extnamespace: managedTenants_alertSeverity,
        'targets': Collection,
        'tenantIds': Collection,
    }
    rels = [
        'alerts',
        'ruleDefinition',
    ]


class managedTenants_managedTenantAlert(entity):
    props = {
        'alertData': Collection, #extnamespace: managedTenants_alertData,
        'alertDataReferenceStrings': Collection,
        'alertRuleDisplayName': Edm.String,
        'assignedToUserId': Edm.String,
        'correlationCount': Edm.Int32,
        'correlationId': Edm.String,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'message': Edm.String,
        'severity': Collection, #extnamespace: managedTenants_alertSeverity,
        'status': Collection, #extnamespace: managedTenants_alertStatus,
        'tenantId': Edm.String,
        'title': Edm.String,
    }
    rels = [
        'alertLogs',
        'alertRule',
        'apiNotifications',
        'emailNotifications',
    ]


class managedTenants_managedTenantApiNotification(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'isAcknowledged': Edm.Boolean,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'message': Edm.String,
        'title': Edm.String,
        'userId': Edm.String,
    }
    rels = [
        'alert',
    ]


class managedTenants_managedTenantEmailNotification(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'emailAddresses': Collection,
        'emailBody': Edm.String,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'subject': Edm.String,
    }
    rels = [
        'alert',
    ]


class managedTenants_managedTenantTicketingEndpoint(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'emailAddress': Edm.String,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'phoneNumber': Edm.String,
    }
    rels = [

    ]


class managedTenants_managementAction(entity):
    props = {
        'category': Collection, #extnamespace: managedTenants_managementCategory,
        'description': Edm.String,
        'displayName': Edm.String,
        'referenceTemplateId': Edm.String,
        'referenceTemplateVersion': Edm.Int32,
        'workloadActions': Collection,
    }
    rels = [

    ]


class managedTenants_managementActionTenantDeploymentStatus(entity):
    props = {
        'statuses': Collection,
        'tenantGroupId': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_managementIntent(entity):
    props = {
        'displayName': Edm.String,
        'isGlobal': Edm.Boolean,
        'managementTemplates': Collection,
    }
    rels = [

    ]


class managedTenants_managementTemplateCollection(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'managementTemplates',
    ]


class managedTenants_managementTemplateCollectionTenantSummary(entity):
    props = {
        'completeStepsCount': Edm.Int32,
        'completeUsersCount': Edm.Int32,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'dismissedStepsCount': Edm.Int32,
        'excludedUsersCount': Edm.Int32,
        'excludedUsersDistinctCount': Edm.Int32,
        'incompleteStepsCount': Edm.Int32,
        'incompleteUsersCount': Edm.Int32,
        'ineligibleStepsCount': Edm.Int32,
        'isComplete': Edm.Boolean,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'managementTemplateCollectionDisplayName': Edm.String,
        'managementTemplateCollectionId': Edm.String,
        'regressedStepsCount': Edm.Int32,
        'regressedUsersCount': Edm.Int32,
        'tenantId': Edm.String,
        'unlicensedUsersCount': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_managementTemplate(entity):
    props = {
        'category': Collection, #extnamespace: managedTenants_managementCategory,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'informationLinks': Collection,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'parameters': Collection,
        'priority': Edm.Int32,
        'provider': Collection, #extnamespace: managedTenants_managementProvider,
        'userImpact': Edm.String,
        'version': Edm.Int32,
        'workloadActions': Collection,
    }
    rels = [
        'managementTemplateCollections',
        'managementTemplateSteps',
    ]


class managedTenants_managementTemplateStep(entity):
    props = {
        'category': Collection, #extnamespace: managedTenants_managementCategory,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'informationLinks': Collection,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'portalLink': actionUrl,
        'priority': Edm.Int32,
        'userImpact': Edm.String,
    }
    rels = [
        'acceptedVersion',
        'managementTemplate',
        'versions',
    ]


class managedTenants_managementTemplateStepTenantSummary(entity):
    props = {
        'assignedTenantsCount': Edm.Int32,
        'compliantTenantsCount': Edm.Int32,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'dismissedTenantsCount': Edm.Int32,
        'ineligibleTenantsCount': Edm.Int32,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'managementTemplateCollectionDisplayName': Edm.String,
        'managementTemplateCollectionId': Edm.String,
        'managementTemplateDisplayName': Edm.String,
        'managementTemplateId': Edm.String,
        'managementTemplateStepDisplayName': Edm.String,
        'managementTemplateStepId': Edm.String,
        'notCompliantTenantsCount': Edm.Int32,
    }
    rels = [

    ]


class managedTenants_managementTemplateStepVersion(entity):
    props = {
        'contentMarkdown': Edm.String,
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'version': Edm.Int32,
        'versionInformation': Edm.String,
    }
    rels = [
        'acceptedFor',
        'deployments',
        'templateStep',
    ]


class managedTenants_myRole(object):
    props = {
        'assignments': Collection,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_tenantGroup(entity):
    props = {
        'allTenantsIncluded': Edm.Boolean,
        'displayName': Edm.String,
        'managementActions': Collection,
        'managementIntents': Collection,
        'tenantIds': Collection,
    }
    rels = [

    ]


class managedTenants_tenant(entity):
    props = {
        'contract': Collection, #extnamespace: managedTenants_tenantContract,
        'createdDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'tenantId': Edm.String,
        'tenantStatusInformation': Collection, #extnamespace: managedTenants_tenantStatusInformation,
    }
    rels = [

    ]


class managedTenants_tenantCustomizedInformation(entity):
    props = {
        'businessRelationship': Edm.String,
        'complianceRequirements': Collection,
        'contacts': Collection,
        'displayName': Edm.String,
        'managedServicesPlans': Collection,
        'note': Edm.String,
        'noteLastModifiedDateTime': Edm.DateTimeOffset,
        'partnerRelationshipManagerUserIds': Collection,
        'tenantId': Edm.String,
        'website': Edm.String,
    }
    rels = [

    ]


class managedTenants_tenantDetailedInformation(entity):
    props = {
        'city': Edm.String,
        'countryCode': Edm.String,
        'countryName': Edm.String,
        'defaultDomainName': Edm.String,
        'displayName': Edm.String,
        'industryName': Edm.String,
        'region': Edm.String,
        'segmentName': Edm.String,
        'tenantId': Edm.String,
        'verticalName': Edm.String,
    }
    rels = [

    ]


class managedTenants_tenantTag(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'deletedDateTime': Edm.DateTimeOffset,
        'description': Edm.String,
        'displayName': Edm.String,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'tenants': Collection,
    }
    rels = [

    ]


class managedTenants_windowsDeviceMalwareState(entity):
    props = {
        'additionalInformationUrl': Edm.String,
        'detectionCount': Edm.Int32,
        'deviceDeleted': Edm.Boolean,
        'initialDetectionDateTime': Edm.DateTimeOffset,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'lastStateChangeDateTime': Edm.DateTimeOffset,
        'malwareCategory': Edm.String,
        'malwareDisplayName': Edm.String,
        'malwareExecutionState': Edm.String,
        'malwareId': Edm.String,
        'malwareSeverity': Edm.String,
        'malwareThreatState': Edm.String,
        'managedDeviceId': Edm.String,
        'managedDeviceName': Edm.String,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_windowsProtectionState(entity):
    props = {
        'antiMalwareVersion': Edm.String,
        'attentionRequired': Edm.Boolean,
        'deviceDeleted': Edm.Boolean,
        'devicePropertyRefreshDateTime': Edm.DateTimeOffset,
        'engineVersion': Edm.String,
        'fullScanOverdue': Edm.Boolean,
        'fullScanRequired': Edm.Boolean,
        'lastFullScanDateTime': Edm.DateTimeOffset,
        'lastFullScanSignatureVersion': Edm.String,
        'lastQuickScanDateTime': Edm.DateTimeOffset,
        'lastQuickScanSignatureVersion': Edm.String,
        'lastRefreshedDateTime': Edm.DateTimeOffset,
        'lastReportedDateTime': Edm.DateTimeOffset,
        'malwareProtectionEnabled': Edm.Boolean,
        'managedDeviceHealthState': Edm.String,
        'managedDeviceId': Edm.String,
        'managedDeviceName': Edm.String,
        'networkInspectionSystemEnabled': Edm.Boolean,
        'quickScanOverdue': Edm.Boolean,
        'realTimeProtectionEnabled': Edm.Boolean,
        'rebootRequired': Edm.Boolean,
        'signatureUpdateOverdue': Edm.Boolean,
        'signatureVersion': Edm.String,
        'tenantDisplayName': Edm.String,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class managedTenants_managementTemplateStepDeployment(entity):
    props = {
        'createdByUserId': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'error': Collection, #extnamespace: managedTenants_graphAPIErrorDetails,
        'lastActionByUserId': Edm.String,
        'lastActionDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: managedTenants_managementTemplateDeploymentStatus,
        'tenantId': Edm.String,
    }
    rels = [
        'templateStepVersion',
    ]


class partners_billing_billing(entity):
    props = {

    }
    rels = [
        'manifests',
        'operations',
        'reconciliation',
        'usage',
    ]


class partners_billing_azureUsage(entity):
    props = {

    }
    rels = [
        'billed',
        'unbilled',
    ]


class partners_billing_billedUsage(entity):
    props = {

    }
    rels = [

    ]


class partners_billing_unbilledUsage(entity):
    props = {

    }
    rels = [

    ]


class partners_billing_billedReconciliation(entity):
    props = {

    }
    rels = [

    ]


class partners_billing_manifest(entity):
    props = {
        'blobCount': Edm.Int32,
        'blobs': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'dataFormat': Edm.String,
        'eTag': Edm.String,
        'partitionType': Edm.String,
        'partnerTenantId': Edm.String,
        'rootDirectory': Edm.String,
        'sasToken': Edm.String,
        'schemaVersion': Edm.String,
    }
    rels = [

    ]


class partners_billing_operation(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastActionDateTime': Edm.DateTimeOffset,
        'status': longRunningOperationStatus,
    }
    rels = [

    ]


class partners_billing_billingReconciliation(entity):
    props = {

    }
    rels = [
        'billed',
    ]


class partner_security_partnerSecurity(entity):
    props = {

    }
    rels = [
        'securityAlerts',
        'securityScore',
    ]


class partner_security_partnerSecurityAlert(entity):
    props = {
        'activityLogs': Collection,
        'additionalDetails': Collection, #extnamespace: partner_security_additionalDataDictionary,
        'affectedResources': Collection,
        'alertType': Edm.String,
        'catalogOfferId': Edm.String,
        'confidenceLevel': Collection, #extnamespace: partner_security_securityAlertConfidence,
        'customerTenantId': Edm.String,
        'description': Edm.String,
        'detectedDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'firstObservedDateTime': Edm.DateTimeOffset,
        'isTest': Edm.Boolean,
        'lastObservedDateTime': Edm.DateTimeOffset,
        'resolvedBy': Edm.String,
        'resolvedOnDateTime': Edm.DateTimeOffset,
        'resolvedReason': Collection, #extnamespace: partner_security_securityAlertResolvedReason,
        'severity': Collection, #extnamespace: partner_security_securityAlertSeverity,
        'status': Collection, #extnamespace: partner_security_securityAlertStatus,
        'subscriptionId': Edm.String,
        'valueAddedResellerTenantId': Edm.String,
    }
    rels = [

    ]


class partner_security_partnerSecurityScore(entity):
    props = {
        'currentScore': Edm.Single,
        'lastRefreshDateTime': Edm.DateTimeOffset,
        'maxScore': Edm.Single,
        'updatedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'customerInsights',
        'history',
        'requirements',
    ]


class partner_security_securityRequirement(entity):
    props = {
        'actionUrl': Edm.String,
        'complianceStatus': Collection, #extnamespace: partner_security_complianceStatus,
        'helpUrl': Edm.String,
        'maxScore': Edm.Int64,
        'requirementType': Collection, #extnamespace: partner_security_securityRequirementType,
        'score': Edm.Int64,
        'state': Collection, #extnamespace: partner_security_securityRequirementState,
        'updatedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class partner_security_customerInsight(object):
    props = {
        'mfa': Collection, #extnamespace: partner_security_customerMfaInsight,
        'tenantId': Edm.String,
    }
    rels = [

    ]


class partner_security_securityScoreHistory(entity):
    props = {
        'compliantRequirementsCount': Edm.Int64,
        'createdDateTime': Edm.DateTimeOffset,
        'score': Edm.Single,
        'totalRequirementsCount': Edm.Int64,
    }
    rels = [

    ]


class search_searchAnswer(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'lastModifiedBy': Collection, #extnamespace: search_identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class externalConnectors_external(object):
    props = {

    }
    rels = [
        'industryData',
        'authorizationSystems',
        'connections',
    ]


class externalConnectors_externalConnection(entity):
    props = {
        'activitySettings': Collection, #extnamespace: externalConnectors_activitySettings,
        'complianceSettings': Collection, #extnamespace: externalConnectors_complianceSettings,
        'configuration': Collection, #extnamespace: externalConnectors_configuration,
        'connectorId': Edm.String,
        'description': Edm.String,
        'enabledContentExperiences': Collection, #extnamespace: externalConnectors_contentExperienceType,
        'ingestedItemsCount': Edm.Int64,
        'name': Edm.String,
        'searchSettings': Collection, #extnamespace: externalConnectors_searchSettings,
        'state': Collection, #extnamespace: externalConnectors_connectionState,
    }
    rels = [
        'groups',
        'items',
        'operations',
        'quota',
        'schema',
    ]


class externalConnectors_connectionOperation(entity):
    props = {
        'error': publicError,
        'status': Collection, #extnamespace: externalConnectors_connectionOperationStatus,
    }
    rels = [

    ]


class externalConnectors_connectionQuota(entity):
    props = {
        'itemsRemaining': Edm.Int64,
    }
    rels = [

    ]


class externalConnectors_externalActivity(entity):
    props = {
        'startDateTime': Edm.DateTimeOffset,
        'type': Collection, #extnamespace: externalConnectors_externalActivityType,
    }
    rels = [
        'performedBy',
    ]


class externalConnectors_identity(entity):
    props = {
        'type': Collection, #extnamespace: externalConnectors_identityType,
    }
    rels = [

    ]


class externalConnectors_externalGroup(entity):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [
        'members',
    ]


class externalConnectors_externalItem(entity):
    props = {
        'acl': Collection,
        'content': Collection, #extnamespace: externalConnectors_externalItemContent,
        'properties': Collection, #extnamespace: externalConnectors_properties,
    }
    rels = [
        'activities',
    ]


class externalConnectors_schema(entity):
    props = {
        'baseType': Edm.String,
        'properties': Collection,
    }
    rels = [

    ]


class windowsUpdates_catalog(entity):
    props = {

    }
    rels = [
        'entries',
    ]


class windowsUpdates_deploymentAudience(entity):
    props = {

    }
    rels = [
        'applicableContent',
        'exclusions',
        'members',
    ]


class windowsUpdates_deployment(entity):
    props = {
        'content': Collection, #extnamespace: windowsUpdates_deployableContent,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'settings': Collection, #extnamespace: windowsUpdates_deploymentSettings,
        'state': Collection, #extnamespace: windowsUpdates_deploymentState,
    }
    rels = [
        'audience',
    ]


class windowsUpdates_product(entity):
    props = {
        'friendlyNames': Collection,
        'groupName': Edm.String,
        'name': Edm.String,
    }
    rels = [
        'editions',
        'knownIssues',
        'revisions',
    ]


class windowsUpdates_resourceConnection(entity):
    props = {
        'state': Collection, #extnamespace: windowsUpdates_resourceConnectionState,
    }
    rels = [

    ]


class windowsUpdates_updatableAsset(entity):
    props = {

    }
    rels = [

    ]


class windowsUpdates_updatePolicy(entity):
    props = {
        'complianceChangeRules': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'deploymentSettings': Collection, #extnamespace: windowsUpdates_deploymentSettings,
    }
    rels = [
        'audience',
        'complianceChanges',
    ]


class windowsUpdates_catalogEntry(entity):
    props = {
        'deployableUntilDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
        'releaseDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class windowsUpdates_cveInformation(object):
    props = {
        'number': Edm.String,
        'url': Edm.String,
    }
    rels = [

    ]


class windowsUpdates_applicableContent(object):
    props = {
        'catalogEntryId': Edm.String,
    }
    rels = [
        'catalogEntry',
        'matchedDevices',
    ]


class windowsUpdates_applicableContentDeviceMatch(object):
    props = {
        'deviceId': Edm.String,
        'recommendedBy': Collection,
    }
    rels = [

    ]


class windowsUpdates_complianceChange(entity):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'isRevoked': Edm.Boolean,
        'revokedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'updatePolicy',
    ]


class windowsUpdates_edition(entity):
    props = {
        'deviceFamily': Edm.String,
        'endOfServiceDateTime': Edm.DateTimeOffset,
        'generalAvailabilityDateTime': Edm.DateTimeOffset,
        'isInService': Edm.Boolean,
        'name': Edm.String,
        'releasedName': Edm.String,
        'servicingPeriods': Collection,
    }
    rels = [

    ]


class windowsUpdates_knowledgeBaseArticle(entity):
    props = {
        'url': Edm.String,
    }
    rels = [

    ]


class windowsUpdates_knownIssue(entity):
    props = {
        'description': Edm.String,
        'knownIssueHistories': Collection,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'resolvedDateTime': Edm.DateTimeOffset,
        'safeguardHoldIds': Collection,
        'startDateTime': Edm.DateTimeOffset,
        'status': Collection, #extnamespace: windowsUpdates_windowsReleaseHealthStatus,
        'title': Edm.String,
        'webViewUrl': Edm.String,
    }
    rels = [
        'originatingKnowledgeBaseArticle',
        'resolvingKnowledgeBaseArticle',
    ]


class windowsUpdates_productRevision(entity):
    props = {
        'displayName': Edm.String,
        'isHotpatchUpdate': Edm.Boolean,
        'osBuild': Collection, #extnamespace: windowsUpdates_buildVersionDetails,
        'product': Edm.String,
        'releaseDateTime': Edm.DateTimeOffset,
        'version': Edm.String,
    }
    rels = [
        'catalogEntry',
        'knowledgeBaseArticle',
    ]


class identityGovernance_workflow(identityGovernance_workflowBase):
    props = {
        'deletedDateTime': Edm.DateTimeOffset,
        'id': Edm.String,
        'nextScheduleRunDateTime': Edm.DateTimeOffset,
        'version': Edm.Int32,
    }
    rels = [
        'executionScope',
        'runs',
        'taskReports',
        'userProcessingResults',
        'versions',
    ]


class identityGovernance_customTaskExtension(customCalloutExtension):
    props = {
        'callbackConfiguration': customExtensionCallbackConfiguration,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'createdBy',
        'lastModifiedBy',
    ]


class identityGovernance_workflowVersion(identityGovernance_workflowBase):
    props = {
        'versionNumber': Edm.Int32,
    }
    rels = [

    ]


class appManagementPolicy(policyBase):
    props = {
        'isEnabled': Edm.Boolean,
        'restrictions': customAppManagementConfiguration,
    }
    rels = [
        'appliesTo',
    ]


class stsPolicy(policyBase):
    props = {
        'definition': Collection,
        'isOrganizationDefault': Edm.Boolean,
    }
    rels = [
        'appliesTo',
    ]


class homeRealmDiscoveryPolicy(stsPolicy):
    props = {

    }
    rels = [

    ]


class tokenIssuancePolicy(stsPolicy):
    props = {

    }
    rels = [

    ]


class tokenLifetimePolicy(stsPolicy):
    props = {

    }
    rels = [

    ]


class event(outlookItem):
    props = {
        'allowNewTimeProposals': Edm.Boolean,
        'attendees': Collection,
        'body': itemBody,
        'bodyPreview': Edm.String,
        'cancelledOccurrences': Collection,
        'end': dateTimeTimeZone,
        'hasAttachments': Edm.Boolean,
        'hideAttendees': Edm.Boolean,
        'iCalUId': Edm.String,
        'importance': importance,
        'isAllDay': Edm.Boolean,
        'isCancelled': Edm.Boolean,
        'isDraft': Edm.Boolean,
        'isOnlineMeeting': Edm.Boolean,
        'isOrganizer': Edm.Boolean,
        'isReminderOn': Edm.Boolean,
        'location': location,
        'locations': Collection,
        'occurrenceId': Edm.String,
        'onlineMeeting': onlineMeetingInfo,
        'onlineMeetingProvider': onlineMeetingProviderType,
        'onlineMeetingUrl': Edm.String,
        'organizer': recipient,
        'originalEndTimeZone': Edm.String,
        'originalStart': Edm.DateTimeOffset,
        'originalStartTimeZone': Edm.String,
        'recurrence': patternedRecurrence,
        'reminderMinutesBeforeStart': Edm.Int32,
        'responseRequested': Edm.Boolean,
        'responseStatus': responseStatus,
        'sensitivity': sensitivity,
        'seriesMasterId': Edm.String,
        'showAs': freeBusyStatus,
        'start': dateTimeTimeZone,
        'subject': Edm.String,
        'transactionId': Edm.String,
        'type': eventType,
        'uid': Edm.String,
        'webLink': Edm.String,
    }
    rels = [
        'attachments',
        'calendar',
        'exceptionOccurrences',
        'extensions',
        'instances',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class drive(baseItem):
    props = {
        'driveType': Edm.String,
        'owner': identitySet,
        'quota': quota,
        'sharePointIds': sharepointIds,
        'system': systemFacet,
    }
    rels = [
        'activities',
        'bundles',
        'following',
        'items',
        'list',
        'root',
        'special',
    ]


class site(baseItem):
    props = {
        'deleted': deleted,
        'displayName': Edm.String,
        'isPersonalSite': Edm.Boolean,
        'root': root,
        'settings': siteSettings,
        'sharepointIds': sharepointIds,
        'siteCollection': siteCollection,
    }
    rels = [
        'informationProtection',
        'analytics',
        'columns',
        'contentModels',
        'contentTypes',
        'documentProcessingJobs',
        'drive',
        'drives',
        'externalColumns',
        'items',
        'lists',
        'operations',
        'pages',
        'pageTemplates',
        'permissions',
        'recycleBin',
        'sites',
        'termStore',
        'onenote',
    ]


class contact(outlookItem):
    props = {
        'assistantName': Edm.String,
        'birthday': Edm.DateTimeOffset,
        'children': Collection,
        'companyName': Edm.String,
        'department': Edm.String,
        'displayName': Edm.String,
        'emailAddresses': Collection,
        'fileAs': Edm.String,
        'flag': followupFlag,
        'gender': Edm.String,
        'generation': Edm.String,
        'givenName': Edm.String,
        'imAddresses': Collection,
        'initials': Edm.String,
        'isFavorite': Edm.Boolean,
        'jobTitle': Edm.String,
        'manager': Edm.String,
        'middleName': Edm.String,
        'nickName': Edm.String,
        'officeLocation': Edm.String,
        'parentFolderId': Edm.String,
        'personalNotes': Edm.String,
        'phones': Collection,
        'postalAddresses': Collection,
        'profession': Edm.String,
        'spouseName': Edm.String,
        'surname': Edm.String,
        'title': Edm.String,
        'websites': Collection,
        'weddingAnniversary': Edm.Date,
        'yomiCompanyName': Edm.String,
        'yomiGivenName': Edm.String,
        'yomiSurname': Edm.String,
    }
    rels = [
        'extensions',
        'multiValueExtendedProperties',
        'photo',
        'singleValueExtendedProperties',
    ]


class message(outlookItem):
    props = {
        'bccRecipients': Collection,
        'body': itemBody,
        'bodyPreview': Edm.String,
        'ccRecipients': Collection,
        'conversationId': Edm.String,
        'conversationIndex': Edm.Binary,
        'flag': followupFlag,
        'from': recipient,
        'hasAttachments': Edm.Boolean,
        'importance': importance,
        'inferenceClassification': inferenceClassificationType,
        'internetMessageHeaders': Collection,
        'internetMessageId': Edm.String,
        'isDeliveryReceiptRequested': Edm.Boolean,
        'isDraft': Edm.Boolean,
        'isRead': Edm.Boolean,
        'isReadReceiptRequested': Edm.Boolean,
        'mentionsPreview': mentionsPreview,
        'parentFolderId': Edm.String,
        'receivedDateTime': Edm.DateTimeOffset,
        'replyTo': Collection,
        'sender': recipient,
        'sentDateTime': Edm.DateTimeOffset,
        'subject': Edm.String,
        'toRecipients': Collection,
        'uniqueBody': itemBody,
        'unsubscribeData': Collection,
        'unsubscribeEnabled': Edm.Boolean,
        'webLink': Edm.String,
    }
    rels = [
        'attachments',
        'extensions',
        'mentions',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class mobileAppTroubleshootingEvent(deviceManagementTroubleshootingEvent):
    props = {
        'applicationId': Edm.String,
        'deviceId': Edm.String,
        'history': Collection,
        'managedDeviceIdentifier': Edm.String,
        'userId': Edm.String,
    }
    rels = [
        'appLogCollectionRequests',
    ]


class plannerUser(plannerDelta):
    props = {
        'favoritePlanReferences': plannerFavoritePlanReferenceCollection,
        'recentPlanReferences': plannerRecentPlanReferenceCollection,
    }
    rels = [
        'all',
        'favoritePlans',
        'myDayTasks',
        'plans',
        'recentPlans',
        'rosterPlans',
        'tasks',
    ]


class itemInsights(officeGraphInsights):
    props = {

    }
    rels = [

    ]


class onlineMeeting(onlineMeetingBase):
    props = {
        'alternativeRecording': Edm.Stream,
        'attendeeReport': Edm.Stream,
        'broadcastRecording': Edm.Stream,
        'broadcastSettings': broadcastMeetingSettings,
        'capabilities': Collection,
        'creationDateTime': Edm.DateTimeOffset,
        'endDateTime': Edm.DateTimeOffset,
        'externalId': Edm.String,
        'isBroadcast': Edm.Boolean,
        'joinUrl': Edm.String,
        'meetingTemplateId': Edm.String,
        'participants': meetingParticipants,
        'recording': Edm.Stream,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'meetingAttendanceReport',
        'registration',
        'aiInsights',
        'recordings',
        'transcripts',
    ]


class dailyInactiveUsersByApplicationMetric(inactiveUsersByApplicationMetricBase):
    props = {
        'inactive1DayCount': Edm.Int64,
    }
    rels = [

    ]


class dailyInactiveUsersMetric(inactiveUsersMetricBase):
    props = {
        'inactive1DayCount': Edm.Int64,
    }
    rels = [

    ]


class recommendation(recommendationBase):
    props = {

    }
    rels = [

    ]


class externalUserProfile(externalProfile):
    props = {

    }
    rels = [

    ]


class pendingExternalUserProfile(externalProfile):
    props = {

    }
    rels = [

    ]


class membershipOutlierInsight(governanceInsight):
    props = {
        'containerId': Edm.String,
        'memberId': Edm.String,
        'outlierContainerType': outlierContainerType,
        'outlierMemberType': outlierMemberType,
    }
    rels = [
        'container',
        'lastModifiedBy',
        'member',
    ]


class monthlyInactiveUsersByApplicationMetric(inactiveUsersByApplicationMetricBase):
    props = {
        'inactiveCalendarMonthCount': Edm.Int64,
    }
    rels = [

    ]


class monthlyInactiveUsersMetric(inactiveUsersMetricBase):
    props = {
        'inactiveCalendarMonthCount': Edm.Int64,
    }
    rels = [

    ]


class printUsageByPrinter(printUsage):
    props = {
        'printerId': Edm.String,
        'printerName': Edm.String,
    }
    rels = [

    ]


class printUsageByUser(printUsage):
    props = {
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class claimsMappingPolicy(stsPolicy):
    props = {

    }
    rels = [

    ]


class callActivityStatistics(activityStatistics):
    props = {
        'afterHours': Edm.Duration,
    }
    rels = [

    ]


class chatActivityStatistics(activityStatistics):
    props = {
        'afterHours': Edm.Duration,
    }
    rels = [

    ]


class emailActivityStatistics(activityStatistics):
    props = {
        'afterHours': Edm.Duration,
        'readEmail': Edm.Duration,
        'sentEmail': Edm.Duration,
    }
    rels = [

    ]


class focusActivityStatistics(activityStatistics):
    props = {

    }
    rels = [

    ]


class meetingActivityStatistics(activityStatistics):
    props = {
        'afterHours': Edm.Duration,
        'conflicting': Edm.Duration,
        'long': Edm.Duration,
        'multitasking': Edm.Duration,
        'organized': Edm.Duration,
        'recurring': Edm.Duration,
    }
    rels = [

    ]


class bookingBusiness(bookingNamedEntity):
    props = {
        'address': physicalAddress,
        'bookingPageSettings': bookingPageSettings,
        'businessHours': Collection,
        'businessType': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'defaultCurrencyIso': Edm.String,
        'email': Edm.String,
        'isPublished': Edm.Boolean,
        'languageTag': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'phone': Edm.String,
        'publicUrl': Edm.String,
        'schedulingPolicy': bookingSchedulingPolicy,
        'webSiteUrl': Edm.String,
    }
    rels = [
        'appointments',
        'calendarView',
        'customers',
        'customQuestions',
        'services',
        'staffMembers',
    ]


class emailAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'allowExternalIdToUseEmailOtp': externalEmailOtpState,
    }
    rels = [
        'includeTargets',
    ]


class externalAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'appId': Edm.String,
        'displayName': Edm.String,
        'openIdConnectSetting': openIdConnectSetting,
    }
    rels = [
        'includeTargets',
    ]


class fido2AuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'isAttestationEnforced': Edm.Boolean,
        'isSelfServiceRegistrationAllowed': Edm.Boolean,
        'keyRestrictions': fido2KeyRestrictions,
    }
    rels = [
        'includeTargets',
    ]


class passkeyAuthenticationMethodTarget(authenticationMethodTarget):
    props = {

    }
    rels = [

    ]


class fido2CombinationConfiguration(authenticationCombinationConfiguration):
    props = {
        'allowedAAGUIDs': Collection,
    }
    rels = [

    ]


class hardwareOathAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {

    }
    rels = [
        'includeTargets',
    ]


class microsoftAuthenticatorAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'featureSettings': microsoftAuthenticatorFeatureSettings,
        'isSoftwareOathEnabled': Edm.Boolean,
    }
    rels = [
        'includeTargets',
    ]


class microsoftAuthenticatorAuthenticationMethodTarget(authenticationMethodTarget):
    props = {
        'authenticationMode': microsoftAuthenticatorAuthenticationMode,
    }
    rels = [

    ]


class activityBasedTimeoutPolicy(stsPolicy):
    props = {

    }
    rels = [

    ]


class authorizationPolicy(policyBase):
    props = {
        'allowedToSignUpEmailBasedSubscriptions': Edm.Boolean,
        'allowedToUseSSPR': Edm.Boolean,
        'allowEmailVerifiedUsersToJoinOrganization': Edm.Boolean,
        'allowInvitesFrom': allowInvitesFrom,
        'allowUserConsentForRiskyApps': Edm.Boolean,
        'blockMsolPowerShell': Edm.Boolean,
        'defaultUserRolePermissions': defaultUserRolePermissions,
        'enabledPreviewFeatures': Collection,
        'guestUserRoleId': Edm.Guid,
        'permissionGrantPolicyIdsAssignedToDefaultUserRole': Collection,
    }
    rels = [
        'defaultUserRoleOverrides',
    ]


class tenantRelationshipAccessPolicyBase(policyBase):
    props = {
        'definition': Collection,
    }
    rels = [

    ]


class crossTenantAccessPolicy(tenantRelationshipAccessPolicyBase):
    props = {
        'allowedCloudEndpoints': Collection,
    }
    rels = [
        'default',
        'partners',
        'templates',
    ]


class tenantAppManagementPolicy(policyBase):
    props = {
        'applicationRestrictions': appManagementApplicationConfiguration,
        'isEnabled': Edm.Boolean,
        'servicePrincipalRestrictions': appManagementServicePrincipalConfiguration,
    }
    rels = [

    ]


class externalIdentitiesPolicy(policyBase):
    props = {
        'allowDeletedIdentitiesDataRemoval': Edm.Boolean,
        'allowExternalIdentitiesToLeave': Edm.Boolean,
    }
    rels = [

    ]


class permissionGrantPolicy(policyBase):
    props = {
        'includeAllPreApprovedApplications': Edm.Boolean,
        'resourceScopeType': resourceScopeType,
    }
    rels = [
        'excludes',
        'includes',
    ]


class servicePrincipalCreationPolicy(policyBase):
    props = {
        'isBuiltIn': Edm.Boolean,
    }
    rels = [
        'excludes',
        'includes',
    ]


class identitySecurityDefaultsEnforcementPolicy(policyBase):
    props = {
        'isEnabled': Edm.Boolean,
    }
    rels = [

    ]


class smsAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {

    }
    rels = [
        'includeTargets',
    ]


class smsAuthenticationMethodTarget(authenticationMethodTarget):
    props = {
        'isUsableForSignIn': Edm.Boolean,
    }
    rels = [

    ]


class softwareOathAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {

    }
    rels = [
        'includeTargets',
    ]


class temporaryAccessPassAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'defaultLength': Edm.Int32,
        'defaultLifetimeInMinutes': Edm.Int32,
        'isUsableOnce': Edm.Boolean,
        'maximumLifetimeInMinutes': Edm.Int32,
        'minimumLifetimeInMinutes': Edm.Int32,
    }
    rels = [
        'includeTargets',
    ]


class voiceAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'isOfficePhoneAllowed': Edm.Boolean,
    }
    rels = [
        'includeTargets',
    ]


class voiceAuthenticationMethodTarget(authenticationMethodTarget):
    props = {

    }
    rels = [

    ]


class x509CertificateAuthenticationMethodConfiguration(authenticationMethodConfiguration):
    props = {
        'authenticationModeConfiguration': x509CertificateAuthenticationModeConfiguration,
        'certificateUserBindings': Collection,
        'issuerHintsConfiguration': x509CertificateIssuerHintsConfiguration,
    }
    rels = [
        'includeTargets',
    ]


class x509CertificateCombinationConfiguration(authenticationCombinationConfiguration):
    props = {
        'allowedIssuerSkis': Collection,
        'allowedPolicyOIDs': Collection,
    }
    rels = [

    ]


class bookingPerson(bookingNamedEntity):
    props = {
        'emailAddress': Edm.String,
    }
    rels = [

    ]


class bookingCustomer(bookingPerson):
    props = {
        'addresses': Collection,
        'createdDateTime': Edm.DateTimeOffset,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'phones': Collection,
    }
    rels = [

    ]


class bookingService(bookingNamedEntity):
    props = {
        'additionalInformation': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'customQuestions': Collection,
        'defaultDuration': Edm.Duration,
        'defaultLocation': location,
        'defaultPrice': Edm.Double,
        'defaultPriceType': bookingPriceType,
        'defaultReminders': Collection,
        'description': Edm.String,
        'isAnonymousJoinEnabled': Edm.Boolean,
        'isCustomerAllowedToManageBooking': Edm.Boolean,
        'isHiddenFromCustomers': Edm.Boolean,
        'isLocationOnline': Edm.Boolean,
        'languageTag': Edm.String,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'maximumAttendeesCount': Edm.Int32,
        'notes': Edm.String,
        'postBuffer': Edm.Duration,
        'preBuffer': Edm.Duration,
        'schedulingPolicy': bookingSchedulingPolicy,
        'smsNotificationsEnabled': Edm.Boolean,
        'staffMemberIds': Collection,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class bookingStaffMember(bookingPerson):
    props = {
        'availabilityIsAffectedByPersonalCalendar': Edm.Boolean,
        'colorIndex': Edm.Int32,
        'createdDateTime': Edm.DateTimeOffset,
        'isEmailNotificationEnabled': Edm.Boolean,
        'lastUpdatedDateTime': Edm.DateTimeOffset,
        'membershipStatus': bookingStaffMembershipStatus,
        'role': bookingStaffRole,
        'timeZone': Edm.String,
        'useBusinessHours': Edm.Boolean,
        'workingHours': Collection,
    }
    rels = [

    ]


class plannerTask(plannerDelta):
    props = {
        'activeChecklistItemCount': Edm.Int32,
        'appliedCategories': plannerAppliedCategories,
        'archivalInfo': plannerArchivalInfo,
        'assigneePriority': Edm.String,
        'assignments': plannerAssignments,
        'bucketId': Edm.String,
        'checklistItemCount': Edm.Int32,
        'completedBy': identitySet,
        'completedDateTime': Edm.DateTimeOffset,
        'conversationThreadId': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'creationSource': plannerTaskCreation,
        'dueDateTime': Edm.DateTimeOffset,
        'hasDescription': Edm.Boolean,
        'isArchived': Edm.Boolean,
        'isOnMyDay': Edm.Boolean,
        'isOnMyDayLastModifiedDate': Edm.Date,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'orderHint': Edm.String,
        'percentComplete': Edm.Int32,
        'planId': Edm.String,
        'previewType': plannerPreviewType,
        'priority': Edm.Int32,
        'recurrence': plannerTaskRecurrence,
        'referenceCount': Edm.Int32,
        'specifiedCompletionRequirements': plannerTaskCompletionRequirements,
        'startDateTime': Edm.DateTimeOffset,
        'title': Edm.String,
    }
    rels = [
        'assignedToTaskBoardFormat',
        'bucketTaskBoardFormat',
        'details',
        'progressTaskBoardFormat',
    ]


class businessScenarioTask(plannerTask):
    props = {
        'businessScenarioProperties': businessScenarioProperties,
        'target': businessScenarioTaskTargetBase,
    }
    rels = [

    ]


class announcement(changeItemBase):
    props = {
        'announcementDateTime': Edm.DateTimeOffset,
        'changeType': changeAnnouncementChangeType,
        'impactLink': Edm.String,
        'isCustomerActionRequired': Edm.Boolean,
        'targetDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class b2cIdentityUserFlow(identityUserFlow):
    props = {
        'apiConnectorConfiguration': userFlowApiConnectorConfiguration,
        'defaultLanguageTag': Edm.String,
        'isLanguageCustomizationEnabled': Edm.Boolean,
    }
    rels = [
        'identityProviders',
        'languages',
        'userAttributeAssignments',
        'userFlowIdentityProviders',
    ]


class b2xIdentityUserFlow(identityUserFlow):
    props = {
        'apiConnectorConfiguration': userFlowApiConnectorConfiguration,
    }
    rels = [
        'identityProviders',
        'languages',
        'userAttributeAssignments',
        'userFlowIdentityProviders',
    ]


class customAuthenticationExtension(customCalloutExtension):
    props = {
        'behaviorOnError': customExtensionBehaviorOnError,
    }
    rels = [

    ]


class roadmap(changeItemBase):
    props = {
        'category': Edm.String,
        'changeItemState': changeItemState,
        'deliveryStage': roadmapItemDeliveryStage,
        'gotoLink': Edm.String,
        'publishedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class cloudPcBulkCreateSnapshot(cloudPcBulkAction):
    props = {
        'accessTier': cloudPcBlobAccessTier,
        'storageAccountId': Edm.String,
    }
    rels = [

    ]


class cloudPcBulkDisasterRecoveryFailback(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkDisasterRecoveryFailover(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkModifyDiskEncryptionType(cloudPcBulkAction):
    props = {
        'diskEncryptionType': cloudPcDiskEncryptionType,
    }
    rels = [

    ]


class cloudPcBulkMove(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkPowerOff(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkPowerOn(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkReprovision(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkResize(cloudPcBulkAction):
    props = {
        'targetServicePlanId': Edm.String,
    }
    rels = [

    ]


class cloudPcBulkRestart(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class cloudPcBulkRestore(cloudPcBulkAction):
    props = {
        'restorePointDateTime': Edm.DateTimeOffset,
        'timeRange': restoreTimeRange,
    }
    rels = [

    ]


class cloudPcBulkSetReviewStatus(cloudPcBulkAction):
    props = {
        'reviewStatus': cloudPcReviewStatus,
    }
    rels = [

    ]


class cloudPcBulkTroubleshoot(cloudPcBulkAction):
    props = {

    }
    rels = [

    ]


class groupPolicyUploadedDefinitionFile(groupPolicyDefinitionFile):
    props = {
        'content': Edm.Binary,
        'defaultLanguageCode': Edm.String,
        'groupPolicyUploadedLanguageFiles': Collection,
        'status': groupPolicyUploadedDefinitionFileStatus,
        'uploadDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'groupPolicyOperations',
    ]


class deviceAndAppManagementRoleAssignment(roleAssignment):
    props = {
        'members': Collection,
    }
    rels = [
        'roleScopeTags',
    ]


class list(baseItem):
    props = {
        'displayName': Edm.String,
        'list': listInfo,
        'sharepointIds': sharepointIds,
        'system': systemFacet,
    }
    rels = [
        'activities',
        'columns',
        'contentTypes',
        'drive',
        'items',
        'operations',
        'permissions',
        'subscriptions',
    ]


class richLongRunningOperation(longRunningOperation):
    props = {
        'error': publicError,
        'percentageComplete': Edm.Int32,
        'resourceId': Edm.String,
        'type': Edm.String,
    }
    rels = [

    ]


class baseSitePage(baseItem):
    props = {
        'pageLayout': pageLayoutType,
        'publishingState': publicationFacet,
        'title': Edm.String,
    }
    rels = [

    ]


class pageTemplate(baseSitePage):
    props = {
        'titleArea': titleArea,
    }
    rels = [
        'canvasLayout',
        'webParts',
    ]


class recycleBin(baseItem):
    props = {
        'settings': recycleBinSettings,
    }
    rels = [
        'items',
    ]


class onAttributeCollectionStartCustomExtension(customAuthenticationExtension):
    props = {

    }
    rels = [

    ]


class onAttributeCollectionSubmitCustomExtension(customAuthenticationExtension):
    props = {

    }
    rels = [

    ]


class onOtpSendCustomExtension(customAuthenticationExtension):
    props = {

    }
    rels = [

    ]


class onTokenIssuanceStartCustomExtension(customAuthenticationExtension):
    props = {
        'claimsForTokenConfiguration': Collection,
    }
    rels = [

    ]


class appleManagedIdentityProvider(identityProviderBase):
    props = {
        'certificateData': Edm.String,
        'developerId': Edm.String,
        'keyId': Edm.String,
        'serviceId': Edm.String,
    }
    rels = [

    ]


class builtInIdentityProvider(identityProviderBase):
    props = {
        'identityProviderType': Edm.String,
        'state': identityProviderState,
    }
    rels = [

    ]


class externalUsersSelfServiceSignUpEventsFlow(authenticationEventsFlow):
    props = {
        'onAttributeCollection': onAttributeCollectionHandler,
        'onAttributeCollectionStart': onAttributeCollectionStartHandler,
        'onAttributeCollectionSubmit': onAttributeCollectionSubmitHandler,
        'onAuthenticationMethodLoadStart': onAuthenticationMethodLoadStartHandler,
        'onInteractiveAuthFlowStart': onInteractiveAuthFlowStartHandler,
        'onUserCreateStart': onUserCreateStartHandler,
    }
    rels = [

    ]


class identityBuiltInUserFlowAttribute(identityUserFlowAttribute):
    props = {

    }
    rels = [

    ]


class identityCustomUserFlowAttribute(identityUserFlowAttribute):
    props = {

    }
    rels = [

    ]


class invokeUserFlowListener(authenticationListener):
    props = {

    }
    rels = [
        'userFlow',
    ]


class oidcIdentityProvider(identityProviderBase):
    props = {
        'clientAuthentication': oidcClientAuthentication,
        'clientId': Edm.String,
        'inboundClaimMapping': oidcInboundClaimMappingOverride,
        'issuer': Edm.String,
        'responseType': oidcResponseType,
        'scope': Edm.String,
        'wellKnownEndpoint': Edm.String,
    }
    rels = [

    ]


class onAttributeCollectionListener(authenticationEventListener):
    props = {
        'handler': onAttributeCollectionHandler,
    }
    rels = [

    ]


class onAttributeCollectionStartListener(authenticationEventListener):
    props = {
        'handler': onAttributeCollectionStartHandler,
    }
    rels = [

    ]


class onAttributeCollectionSubmitListener(authenticationEventListener):
    props = {
        'handler': onAttributeCollectionSubmitHandler,
    }
    rels = [

    ]


class onAuthenticationMethodLoadStartListener(authenticationEventListener):
    props = {
        'handler': onAuthenticationMethodLoadStartHandler,
    }
    rels = [

    ]


class onEmailOtpSendListener(authenticationEventListener):
    props = {
        'handler': onOtpSendHandler,
    }
    rels = [

    ]


class onInteractiveAuthFlowStartListener(authenticationEventListener):
    props = {
        'handler': onInteractiveAuthFlowStartHandler,
    }
    rels = [

    ]


class onTokenIssuanceStartListener(authenticationEventListener):
    props = {
        'handler': onTokenIssuanceStartHandler,
    }
    rels = [

    ]


class onUserCreateStartListener(authenticationEventListener):
    props = {
        'handler': onUserCreateStartHandler,
    }
    rels = [

    ]


class openIdConnectIdentityProvider(identityProviderBase):
    props = {
        'claimsMapping': claimsMapping,
        'clientId': Edm.String,
        'clientSecret': Edm.String,
        'domainHint': Edm.String,
        'metadataUrl': Edm.String,
        'responseMode': openIdConnectResponseMode,
        'responseType': openIdConnectResponseTypes,
        'scope': Edm.String,
    }
    rels = [

    ]


class openIdConnectProvider(identityProvider):
    props = {
        'claimsMapping': claimsMapping,
        'domainHint': Edm.String,
        'metadataUrl': Edm.String,
        'responseMode': openIdConnectResponseMode,
        'responseType': openIdConnectResponseTypes,
        'scope': Edm.String,
    }
    rels = [

    ]


class socialIdentityProvider(identityProviderBase):
    props = {
        'clientId': Edm.String,
        'clientSecret': Edm.String,
        'identityProviderType': Edm.String,
    }
    rels = [

    ]


class classificationJobResponse(jobResponseBase):
    props = {
        'result': detectedSensitiveContentWrapper,
    }
    rels = [

    ]


class exactMatchDataStore(exactMatchDataStoreBase):
    props = {

    }
    rels = [
        'sessions',
    ]


class dlpEvaluatePoliciesJobResponse(jobResponseBase):
    props = {
        'result': dlpPoliciesJobResult,
    }
    rels = [

    ]


class evaluateLabelJobResponse(jobResponseBase):
    props = {
        'result': evaluateLabelJobResultGroup,
    }
    rels = [

    ]


class certificateBasedApplicationConfiguration(trustedCertificateAuthorityAsEntityBase):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
    }
    rels = [

    ]


class mutualTlsOauthConfiguration(trustedCertificateAuthorityBase):
    props = {
        'displayName': Edm.String,
        'tlsClientAuthParameter': tlsClientRegistrationMetadata,
    }
    rels = [

    ]


class customSecurityAttributeStringValueExemption(customSecurityAttributeExemption):
    props = {
        'value': Edm.String,
    }
    rels = [

    ]


class samlOrWsFedProvider(identityProviderBase):
    props = {
        'issuerUri': Edm.String,
        'metadataExchangeUri': Edm.String,
        'passiveSignInUri': Edm.String,
        'preferredAuthenticationProtocol': authenticationProtocol,
        'signingCertificate': Edm.String,
    }
    rels = [

    ]


class internalDomainFederation(samlOrWsFedProvider):
    props = {
        'activeSignInUri': Edm.String,
        'federatedIdpMfaBehavior': federatedIdpMfaBehavior,
        'isSignedAuthenticationRequestRequired': Edm.Boolean,
        'nextSigningCertificate': Edm.String,
        'passwordResetUri': Edm.String,
        'promptLoginBehavior': promptLoginBehavior,
        'signingCertificateUpdateStatus': signingCertificateUpdateStatus,
        'signOutUri': Edm.String,
    }
    rels = [

    ]


class domainDnsCnameRecord(domainDnsRecord):
    props = {
        'canonicalName': Edm.String,
    }
    rels = [

    ]


class domainDnsMxRecord(domainDnsRecord):
    props = {
        'mailExchange': Edm.String,
        'preference': Edm.Int32,
    }
    rels = [

    ]


class domainDnsSrvRecord(domainDnsRecord):
    props = {
        'nameTarget': Edm.String,
        'port': Edm.Int32,
        'priority': Edm.Int32,
        'protocol': Edm.String,
        'service': Edm.String,
        'weight': Edm.Int32,
    }
    rels = [

    ]


class domainDnsTxtRecord(domainDnsRecord):
    props = {
        'text': Edm.String,
    }
    rels = [

    ]


class domainDnsUnavailableRecord(domainDnsRecord):
    props = {
        'description': Edm.String,
    }
    rels = [

    ]


class organizationalBranding(organizationalBrandingProperties):
    props = {

    }
    rels = [
        'localizations',
    ]


class organizationalBrandingLocalization(organizationalBrandingProperties):
    props = {

    }
    rels = [

    ]


class unifiedRoleAssignmentScheduleInstance(unifiedRoleScheduleInstanceBase):
    props = {
        'assignmentType': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'memberType': Edm.String,
        'roleAssignmentOriginId': Edm.String,
        'roleAssignmentScheduleId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'activatedUsing',
    ]


class unifiedRoleAssignmentScheduleRequest(request):
    props = {
        'action': Edm.String,
        'appScopeId': Edm.String,
        'directoryScopeId': Edm.String,
        'isValidationOnly': Edm.Boolean,
        'justification': Edm.String,
        'principalId': Edm.String,
        'roleDefinitionId': Edm.String,
        'scheduleInfo': requestSchedule,
        'targetScheduleId': Edm.String,
        'ticketInfo': ticketInfo,
    }
    rels = [
        'activatedUsing',
        'appScope',
        'directoryScope',
        'principal',
        'roleDefinition',
        'targetSchedule',
    ]


class unifiedRoleAssignmentSchedule(unifiedRoleScheduleBase):
    props = {
        'assignmentType': Edm.String,
        'memberType': Edm.String,
        'scheduleInfo': requestSchedule,
    }
    rels = [
        'activatedUsing',
    ]


class unifiedRoleEligibilityScheduleInstance(unifiedRoleScheduleInstanceBase):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'memberType': Edm.String,
        'roleEligibilityScheduleId': Edm.String,
        'startDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class unifiedRoleEligibilityScheduleRequest(request):
    props = {
        'action': Edm.String,
        'appScopeId': Edm.String,
        'directoryScopeId': Edm.String,
        'isValidationOnly': Edm.Boolean,
        'justification': Edm.String,
        'principalId': Edm.String,
        'roleDefinitionId': Edm.String,
        'scheduleInfo': requestSchedule,
        'targetScheduleId': Edm.String,
        'ticketInfo': ticketInfo,
    }
    rels = [
        'appScope',
        'directoryScope',
        'principal',
        'roleDefinition',
        'targetSchedule',
    ]


class unifiedRoleEligibilitySchedule(unifiedRoleScheduleBase):
    props = {
        'memberType': Edm.String,
        'scheduleInfo': requestSchedule,
    }
    rels = [

    ]


class samlOrWsFedExternalDomainFederation(samlOrWsFedProvider):
    props = {

    }
    rels = [
        'domains',
    ]


class educationSchool(educationOrganization):
    props = {
        'address': physicalAddress,
        'createdBy': identitySet,
        'externalId': Edm.String,
        'externalPrincipalId': Edm.String,
        'fax': Edm.String,
        'highestGrade': Edm.String,
        'lowestGrade': Edm.String,
        'phone': Edm.String,
        'principalEmail': Edm.String,
        'principalName': Edm.String,
        'schoolNumber': Edm.String,
    }
    rels = [
        'administrativeUnit',
        'classes',
        'users',
    ]


class educationFeedbackOutcome(educationOutcome):
    props = {
        'feedback': educationFeedback,
        'publishedFeedback': educationFeedback,
    }
    rels = [

    ]


class educationFeedbackResourceOutcome(educationOutcome):
    props = {
        'feedbackResource': educationResource,
        'resourceStatus': educationFeedbackResourceOutcomeStatus,
    }
    rels = [

    ]


class educationPointsOutcome(educationOutcome):
    props = {
        'points': educationAssignmentPointsGrade,
        'publishedPoints': educationAssignmentPointsGrade,
    }
    rels = [

    ]


class educationRubricOutcome(educationOutcome):
    props = {
        'publishedRubricQualityFeedback': Collection,
        'publishedRubricQualitySelectedLevels': Collection,
        'rubricQualityFeedback': Collection,
        'rubricQualitySelectedLevels': Collection,
    }
    rels = [

    ]


class driveProtectionRule(protectionRuleBase):
    props = {
        'driveExpression': Edm.String,
    }
    rels = [

    ]


class driveProtectionUnit(protectionUnitBase):
    props = {
        'directoryObjectId': Edm.String,
        'displayName': Edm.String,
        'email': Edm.String,
    }
    rels = [

    ]


class driveProtectionUnitsBulkAdditionJob(protectionUnitsBulkJobBase):
    props = {
        'directoryObjectIds': Collection,
        'drives': Collection,
    }
    rels = [

    ]


class exchangeProtectionPolicy(protectionPolicyBase):
    props = {

    }
    rels = [
        'mailboxInclusionRules',
        'mailboxProtectionUnits',
        'mailboxProtectionUnitsBulkAdditionJobs',
    ]


class exchangeRestoreSession(restoreSessionBase):
    props = {

    }
    rels = [
        'granularMailboxRestoreArtifacts',
        'mailboxRestoreArtifacts',
        'mailboxRestoreArtifactsBulkAdditionRequests',
    ]


class mailboxProtectionRule(protectionRuleBase):
    props = {
        'mailboxExpression': Edm.String,
    }
    rels = [

    ]


class mailboxProtectionUnit(protectionUnitBase):
    props = {
        'directoryObjectId': Edm.String,
        'displayName': Edm.String,
        'email': Edm.String,
        'mailboxType': mailboxType,
    }
    rels = [

    ]


class mailboxProtectionUnitsBulkAdditionJob(protectionUnitsBulkJobBase):
    props = {
        'directoryObjectIds': Collection,
        'mailboxes': Collection,
    }
    rels = [

    ]


class oneDriveForBusinessProtectionPolicy(protectionPolicyBase):
    props = {

    }
    rels = [
        'driveInclusionRules',
        'driveProtectionUnits',
        'driveProtectionUnitsBulkAdditionJobs',
    ]


class oneDriveForBusinessRestoreSession(restoreSessionBase):
    props = {

    }
    rels = [
        'driveRestoreArtifacts',
        'driveRestoreArtifactsBulkAdditionRequests',
    ]


class sharePointProtectionPolicy(protectionPolicyBase):
    props = {

    }
    rels = [
        'siteInclusionRules',
        'siteProtectionUnits',
        'siteProtectionUnitsBulkAdditionJobs',
    ]


class sharePointRestoreSession(restoreSessionBase):
    props = {

    }
    rels = [
        'siteRestoreArtifacts',
        'siteRestoreArtifactsBulkAdditionRequests',
    ]


class siteProtectionRule(protectionRuleBase):
    props = {
        'siteExpression': Edm.String,
    }
    rels = [

    ]


class siteProtectionUnit(protectionUnitBase):
    props = {
        'siteId': Edm.String,
        'siteName': Edm.String,
        'siteWebUrl': Edm.String,
    }
    rels = [

    ]


class siteProtectionUnitsBulkAdditionJob(protectionUnitsBulkJobBase):
    props = {
        'siteIds': Collection,
        'siteWebUrls': Collection,
    }
    rels = [

    ]


class driveRestoreArtifact(restoreArtifactBase):
    props = {
        'restoredSiteId': Edm.String,
        'restoredSiteName': Edm.String,
        'restoredSiteWebUrl': Edm.String,
    }
    rels = [

    ]


class driveRestoreArtifactsBulkAdditionRequest(restoreArtifactsBulkRequestBase):
    props = {
        'directoryObjectIds': Collection,
        'drives': Collection,
    }
    rels = [

    ]


class mailboxRestoreArtifact(restoreArtifactBase):
    props = {
        'restoredFolderId': Edm.String,
        'restoredFolderName': Edm.String,
        'restoredItemCount': Edm.Int32,
    }
    rels = [

    ]


class granularMailboxRestoreArtifact(mailboxRestoreArtifact):
    props = {
        'artifactCount': Edm.Int32,
        'searchResponseId': Edm.String,
    }
    rels = [

    ]


class mailboxRestoreArtifactsBulkAdditionRequest(restoreArtifactsBulkRequestBase):
    props = {
        'directoryObjectIds': Collection,
        'mailboxes': Collection,
    }
    rels = [

    ]


class siteRestoreArtifact(restoreArtifactBase):
    props = {
        'restoredSiteId': Edm.String,
        'restoredSiteName': Edm.String,
        'restoredSiteWebUrl': Edm.String,
    }
    rels = [

    ]


class siteRestoreArtifactsBulkAdditionRequest(restoreArtifactsBulkRequestBase):
    props = {
        'siteIds': Collection,
        'siteWebUrls': Collection,
    }
    rels = [

    ]


class exactMatchSessionBase(exactMatchJobBase):
    props = {
        'dataStoreId': Edm.String,
        'processingCompletionDateTime': Edm.DateTimeOffset,
        'remainingBlockCount': Edm.Int32,
        'remainingJobCount': Edm.Int32,
        'state': Edm.String,
        'totalBlockCount': Edm.Int32,
        'totalJobCount': Edm.Int32,
        'uploadCompletionDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class exactMatchSession(exactMatchSessionBase):
    props = {
        'checksum': Edm.String,
        'dataUploadURI': Edm.String,
        'fields': Collection,
        'fileName': Edm.String,
        'rowsPerBlock': Edm.Int32,
        'salt': Edm.String,
        'uploadAgentId': Edm.String,
    }
    rels = [
        'uploadAgent',
    ]


class exactMatchLookupJob(exactMatchJobBase):
    props = {
        'state': Edm.String,
    }
    rels = [
        'matchingRows',
    ]


class driveItem(baseItem):
    props = {
        'audio': audio,
        'bundle': bundle,
        'content': Edm.Stream,
        'contentStream': Edm.Stream,
        'cTag': Edm.String,
        'deleted': deleted,
        'file': file,
        'fileSystemInfo': fileSystemInfo,
        'folder': folder,
        'image': image,
        'location': geoCoordinates,
        'malware': malware,
        'media': media,
        'package': package,
        'pendingOperations': pendingOperations,
        'photo': photo,
        'publication': publicationFacet,
        'remoteItem': remoteItem,
        'root': root,
        'searchResult': searchResult,
        'shared': shared,
        'sharepointIds': sharepointIds,
        'size': Edm.Int64,
        'source': driveItemSource,
        'specialFolder': specialFolder,
        'video': video,
        'viewpoint': driveItemViewpoint,
        'webDavUrl': Edm.String,
    }
    rels = [
        'workbook',
        'activities',
        'analytics',
        'children',
        'listItem',
        'permissions',
        'retentionLabel',
        'subscriptions',
        'thumbnails',
        'versions',
    ]


class listItem(baseItem):
    props = {
        'contentType': contentTypeInfo,
        'deleted': deleted,
        'sharepointIds': sharepointIds,
    }
    rels = [
        'activities',
        'analytics',
        'documentSetVersions',
        'driveItem',
        'fields',
        'permissions',
        'versions',
    ]


class driveItemVersion(baseItemVersion):
    props = {
        'content': Edm.Stream,
        'size': Edm.Int64,
    }
    rels = [

    ]


class room(place):
    props = {
        'audioDeviceName': Edm.String,
        'bookingType': bookingType,
        'building': Edm.String,
        'capacity': Edm.Int32,
        'displayDeviceName': Edm.String,
        'emailAddress': Edm.String,
        'floorLabel': Edm.String,
        'floorNumber': Edm.Int32,
        'isWheelChairAccessible': Edm.Boolean,
        'label': Edm.String,
        'nickname': Edm.String,
        'tags': Collection,
        'videoDeviceName': Edm.String,
    }
    rels = [

    ]


class roomList(place):
    props = {
        'emailAddress': Edm.String,
    }
    rels = [
        'rooms',
        'workspaces',
    ]


class workspace(place):
    props = {
        'building': Edm.String,
        'capacity': Edm.Int32,
        'emailAddress': Edm.String,
        'floorLabel': Edm.String,
        'floorNumber': Edm.Int32,
        'isWheelChairAccessible': Edm.Boolean,
        'label': Edm.String,
        'nickname': Edm.String,
        'tags': Collection,
    }
    rels = [

    ]


class customAppScope(appScope):
    props = {
        'customAttributes': customAppScopeAttributesDictionary,
    }
    rels = [

    ]


class calendarSharingMessage(message):
    props = {
        'canAccept': Edm.Boolean,
        'sharingMessageAction': calendarSharingMessageAction,
        'sharingMessageActions': Collection,
        'suggestedCalendarName': Edm.String,
    }
    rels = [

    ]


class post(outlookItem):
    props = {
        'body': itemBody,
        'conversationId': Edm.String,
        'conversationThreadId': Edm.String,
        'from': recipient,
        'hasAttachments': Edm.Boolean,
        'importance': importance,
        'newParticipants': Collection,
        'receivedDateTime': Edm.DateTimeOffset,
        'sender': recipient,
    }
    rels = [
        'attachments',
        'extensions',
        'inReplyTo',
        'mentions',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class eventMessage(message):
    props = {
        'endDateTime': dateTimeTimeZone,
        'isAllDay': Edm.Boolean,
        'isDelegated': Edm.Boolean,
        'isOutOfDate': Edm.Boolean,
        'location': location,
        'meetingMessageType': meetingMessageType,
        'recurrence': patternedRecurrence,
        'startDateTime': dateTimeTimeZone,
        'type': eventType,
    }
    rels = [
        'event',
    ]


class eventMessageRequest(eventMessage):
    props = {
        'allowNewTimeProposals': Edm.Boolean,
        'meetingRequestType': meetingRequestType,
        'previousEndDateTime': dateTimeTimeZone,
        'previousLocation': location,
        'previousStartDateTime': dateTimeTimeZone,
        'responseRequested': Edm.Boolean,
    }
    rels = [

    ]


class eventMessageResponse(eventMessage):
    props = {
        'proposedNewTime': timeSlot,
        'responseType': responseType,
    }
    rels = [

    ]


class fileAttachment(attachment):
    props = {
        'contentBytes': Edm.Binary,
        'contentId': Edm.String,
        'contentLocation': Edm.String,
    }
    rels = [

    ]


class itemAttachment(attachment):
    props = {

    }
    rels = [
        'item',
    ]


class mailboxItem(outlookItem):
    props = {
        'size': Edm.Int64,
        'type': Edm.String,
    }
    rels = [
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class mailSearchFolder(mailFolder):
    props = {
        'filterQuery': Edm.String,
        'includeNestedFolders': Edm.Boolean,
        'isSupported': Edm.Boolean,
        'sourceFolderIds': Collection,
    }
    rels = [

    ]


class note(outlookItem):
    props = {
        'body': itemBody,
        'hasAttachments': Edm.Boolean,
        'isDeleted': Edm.Boolean,
        'subject': Edm.String,
    }
    rels = [
        'attachments',
        'extensions',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class openTypeExtension(extension):
    props = {
        'extensionName': Edm.String,
    }
    rels = [

    ]


class outlookTask(outlookItem):
    props = {
        'assignedTo': Edm.String,
        'body': itemBody,
        'completedDateTime': dateTimeTimeZone,
        'dueDateTime': dateTimeTimeZone,
        'hasAttachments': Edm.Boolean,
        'importance': importance,
        'isReminderOn': Edm.Boolean,
        'owner': Edm.String,
        'parentFolderId': Edm.String,
        'recurrence': patternedRecurrence,
        'reminderDateTime': dateTimeTimeZone,
        'sensitivity': sensitivity,
        'startDateTime': dateTimeTimeZone,
        'status': taskStatus,
        'subject': Edm.String,
    }
    rels = [
        'attachments',
        'multiValueExtendedProperties',
        'singleValueExtendedProperties',
    ]


class referenceAttachment(attachment):
    props = {
        'isFolder': Edm.Boolean,
        'permission': referenceAttachmentPermission,
        'previewUrl': Edm.String,
        'providerType': referenceAttachmentProvider,
        'sourceUrl': Edm.String,
        'thumbnailUrl': Edm.String,
    }
    rels = [

    ]


class updateAllMessagesReadStateOperation(mailFolderOperation):
    props = {

    }
    rels = [

    ]


class shiftPreferences(changeTrackedEntity):
    props = {
        'availability': Collection,
    }
    rels = [

    ]


class listItemVersion(baseItemVersion):
    props = {

    }
    rels = [
        'fields',
    ]


class documentSetVersion(listItemVersion):
    props = {
        'comment': Edm.String,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'items': Collection,
        'shouldCaptureMinorVersion': Edm.Boolean,
    }
    rels = [

    ]


class engagementAsyncOperation(longRunningOperation):
    props = {
        'operationType': engagementAsyncOperationType,
        'resourceId': Edm.String,
    }
    rels = [

    ]


class newsLinkPage(baseSitePage):
    props = {
        'bannerImageWebUrl': Edm.String,
        'newsSharepointIds': sharepointIds,
        'newsWebUrl': Edm.String,
    }
    rels = [

    ]


class recycleBinItem(baseItem):
    props = {
        'deletedDateTime': Edm.DateTimeOffset,
        'deletedFromLocation': Edm.String,
        'size': Edm.Int64,
    }
    rels = [

    ]


class sharedDriveItem(baseItem):
    props = {
        'owner': identitySet,
    }
    rels = [
        'driveItem',
        'items',
        'list',
        'listItem',
        'permission',
        'root',
        'site',
    ]


class sitePage(baseSitePage):
    props = {
        'promotionKind': pagePromotionType,
        'reactions': reactionsFacet,
        'showComments': Edm.Boolean,
        'showRecommendedPages': Edm.Boolean,
        'thumbnailWebUrl': Edm.String,
        'titleArea': titleArea,
    }
    rels = [
        'canvasLayout',
        'webParts',
    ]


class standardWebPart(webPart):
    props = {
        'containerTextWebPartId': Edm.String,
        'data': webPartData,
        'webPartType': Edm.String,
    }
    rels = [

    ]


class textWebPart(webPart):
    props = {
        'innerHtml': Edm.String,
    }
    rels = [

    ]


class videoNewsLinkPage(baseSitePage):
    props = {
        'bannerImageWebUrl': Edm.String,
        'newsSharepointIds': sharepointIds,
        'newsWebUrl': Edm.String,
        'videoDuration': Edm.Duration,
    }
    rels = [

    ]


class meetingRegistration(meetingRegistrationBase):
    props = {
        'description': Edm.String,
        'endDateTime': Edm.DateTimeOffset,
        'registrationPageViewCount': Edm.Int32,
        'registrationPageWebUrl': Edm.String,
        'speakers': Collection,
        'startDateTime': Edm.DateTimeOffset,
        'subject': Edm.String,
    }
    rels = [
        'customQuestions',
    ]


class ipApplicationSegment(applicationSegment):
    props = {
        'destinationHost': Edm.String,
        'destinationType': privateNetworkDestinationType,
        'port': Edm.Int32,
        'ports': Collection,
        'protocol': privateNetworkProtocol,
    }
    rels = [
        'application',
    ]


class webApplicationSegment(applicationSegment):
    props = {
        'alternateUrl': Edm.String,
        'externalUrl': Edm.String,
        'internalUrl': Edm.String,
    }
    rels = [
        'corsConfigurations',
    ]


class userConsentRequest(request):
    props = {
        'reason': Edm.String,
    }
    rels = [
        'approval',
    ]


class privilegedAccessGroupAssignmentScheduleInstance(privilegedAccessScheduleInstance):
    props = {
        'accessId': privilegedAccessGroupRelationships,
        'assignmentScheduleId': Edm.String,
        'assignmentType': privilegedAccessGroupAssignmentType,
        'groupId': Edm.String,
        'memberType': privilegedAccessGroupMemberType,
        'principalId': Edm.String,
    }
    rels = [
        'activatedUsing',
        'group',
        'principal',
    ]


class privilegedAccessScheduleRequest(request):
    props = {
        'action': scheduleRequestActions,
        'isValidationOnly': Edm.Boolean,
        'justification': Edm.String,
        'scheduleInfo': requestSchedule,
        'ticketInfo': ticketInfo,
    }
    rels = [

    ]


class privilegedAccessGroupAssignmentScheduleRequest(privilegedAccessScheduleRequest):
    props = {
        'accessId': privilegedAccessGroupRelationships,
        'groupId': Edm.String,
        'principalId': Edm.String,
        'targetScheduleId': Edm.String,
    }
    rels = [
        'activatedUsing',
        'group',
        'principal',
        'targetSchedule',
    ]


class privilegedAccessGroupAssignmentSchedule(privilegedAccessSchedule):
    props = {
        'accessId': privilegedAccessGroupRelationships,
        'assignmentType': privilegedAccessGroupAssignmentType,
        'groupId': Edm.String,
        'memberType': privilegedAccessGroupMemberType,
        'principalId': Edm.String,
    }
    rels = [
        'activatedUsing',
        'group',
        'principal',
    ]


class privilegedAccessGroupEligibilityScheduleInstance(privilegedAccessScheduleInstance):
    props = {
        'accessId': privilegedAccessGroupRelationships,
        'eligibilityScheduleId': Edm.String,
        'groupId': Edm.String,
        'memberType': privilegedAccessGroupMemberType,
        'principalId': Edm.String,
    }
    rels = [
        'group',
        'principal',
    ]


class privilegedAccessGroupEligibilityScheduleRequest(privilegedAccessScheduleRequest):
    props = {
        'accessId': privilegedAccessGroupRelationships,
        'groupId': Edm.String,
        'principalId': Edm.String,
        'targetScheduleId': Edm.String,
    }
    rels = [
        'group',
        'principal',
        'targetSchedule',
    ]


class privilegedAccessGroupEligibilitySchedule(privilegedAccessSchedule):
    props = {
        'accessId': privilegedAccessGroupRelationships,
        'groupId': Edm.String,
        'memberType': privilegedAccessGroupMemberType,
        'principalId': Edm.String,
    }
    rels = [
        'group',
        'principal',
    ]


class userSignInInsight(governanceInsight):
    props = {
        'lastSignInDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class agreementFile(agreementFileProperties):
    props = {

    }
    rels = [
        'localizations',
    ]


class agreementFileLocalization(agreementFileProperties):
    props = {

    }
    rels = [
        'versions',
    ]


class agreementFileVersion(agreementFileProperties):
    props = {

    }
    rels = [

    ]


class compliantNetworkNamedLocation(namedLocation):
    props = {
        'compliantNetworkType': compliantNetworkType,
        'isTrusted': Edm.Boolean,
    }
    rels = [

    ]


class conditionalAccessWhatIfPolicy(conditionalAccessPolicy):
    props = {
        'policyApplies': Edm.Boolean,
        'reasons': Collection,
    }
    rels = [

    ]


class countryNamedLocation(namedLocation):
    props = {
        'countriesAndRegions': Collection,
        'countryLookupMethod': countryLookupMethodType,
        'includeUnknownCountriesAndRegions': Edm.Boolean,
    }
    rels = [

    ]


class ipNamedLocation(namedLocation):
    props = {
        'ipRanges': Collection,
        'isTrusted': Edm.Boolean,
    }
    rels = [

    ]


class riskyServicePrincipalHistoryItem(riskyServicePrincipal):
    props = {
        'activity': riskServicePrincipalActivity,
        'initiatedBy': Edm.String,
        'servicePrincipalId': Edm.String,
    }
    rels = [

    ]


class riskyUserHistoryItem(riskyUser):
    props = {
        'activity': riskUserActivity,
        'initiatedBy': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class accessPackageAssignmentRequestWorkflowExtension(customCalloutExtension):
    props = {
        'callbackConfiguration': customExtensionCallbackConfiguration,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class accessPackageAssignmentWorkflowExtension(customCalloutExtension):
    props = {
        'callbackConfiguration': customExtensionCallbackConfiguration,
        'createdBy': Edm.String,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedBy': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class customAccessPackageWorkflowExtension(customCalloutExtension):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class androidForWorkApp(mobileApp):
    props = {
        'appIdentifier': Edm.String,
        'appStoreUrl': Edm.String,
        'packageId': Edm.String,
        'totalLicenseCount': Edm.Int32,
        'usedLicenseCount': Edm.Int32,
    }
    rels = [

    ]


class androidForWorkMobileAppConfiguration(managedDeviceMobileAppConfiguration):
    props = {
        'connectedAppsEnabled': Edm.Boolean,
        'packageId': Edm.String,
        'payloadJson': Edm.String,
        'permissionActions': Collection,
        'profileApplicability': androidProfileApplicability,
    }
    rels = [

    ]


class mobileLobApp(mobileApp):
    props = {
        'committedContentVersion': Edm.String,
        'fileName': Edm.String,
        'size': Edm.Int64,
    }
    rels = [
        'contentVersions',
    ]


class androidLobApp(mobileLobApp):
    props = {
        'minimumSupportedOperatingSystem': androidMinimumOperatingSystem,
        'packageId': Edm.String,
        'targetedPlatforms': androidTargetedPlatforms,
        'versionCode': Edm.String,
        'versionName': Edm.String,
    }
    rels = [

    ]


class androidManagedStoreApp(mobileApp):
    props = {
        'appIdentifier': Edm.String,
        'appStoreUrl': Edm.String,
        'appTracks': Collection,
        'isPrivate': Edm.Boolean,
        'isSystemApp': Edm.Boolean,
        'packageId': Edm.String,
        'supportsOemConfig': Edm.Boolean,
        'totalLicenseCount': Edm.Int32,
        'usedLicenseCount': Edm.Int32,
    }
    rels = [

    ]


class androidManagedStoreAppConfiguration(managedDeviceMobileAppConfiguration):
    props = {
        'appSupportsOemConfig': Edm.Boolean,
        'connectedAppsEnabled': Edm.Boolean,
        'packageId': Edm.String,
        'payloadJson': Edm.String,
        'permissionActions': Collection,
        'profileApplicability': androidProfileApplicability,
    }
    rels = [

    ]


class androidManagedStoreWebApp(androidManagedStoreApp):
    props = {

    }
    rels = [

    ]


class androidStoreApp(mobileApp):
    props = {
        'appStoreUrl': Edm.String,
        'minimumSupportedOperatingSystem': androidMinimumOperatingSystem,
        'packageId': Edm.String,
    }
    rels = [

    ]


class managedAppProtection(managedAppPolicy):
    props = {
        'allowedDataIngestionLocations': Collection,
        'allowedDataStorageLocations': Collection,
        'allowedInboundDataTransferSources': managedAppDataTransferLevel,
        'allowedOutboundClipboardSharingExceptionLength': Edm.Int32,
        'allowedOutboundClipboardSharingLevel': managedAppClipboardSharingLevel,
        'allowedOutboundDataTransferDestinations': managedAppDataTransferLevel,
        'appActionIfDeviceComplianceRequired': managedAppRemediationAction,
        'appActionIfMaximumPinRetriesExceeded': managedAppRemediationAction,
        'appActionIfUnableToAuthenticateUser': managedAppRemediationAction,
        'blockDataIngestionIntoOrganizationDocuments': Edm.Boolean,
        'contactSyncBlocked': Edm.Boolean,
        'dataBackupBlocked': Edm.Boolean,
        'deviceComplianceRequired': Edm.Boolean,
        'dialerRestrictionLevel': managedAppPhoneNumberRedirectLevel,
        'disableAppPinIfDevicePinIsSet': Edm.Boolean,
        'fingerprintBlocked': Edm.Boolean,
        'gracePeriodToBlockAppsDuringOffClockHours': Edm.Duration,
        'managedBrowser': managedBrowserType,
        'managedBrowserToOpenLinksRequired': Edm.Boolean,
        'maximumAllowedDeviceThreatLevel': managedAppDeviceThreatLevel,
        'maximumPinRetries': Edm.Int32,
        'maximumRequiredOsVersion': Edm.String,
        'maximumWarningOsVersion': Edm.String,
        'maximumWipeOsVersion': Edm.String,
        'minimumPinLength': Edm.Int32,
        'minimumRequiredAppVersion': Edm.String,
        'minimumRequiredOsVersion': Edm.String,
        'minimumWarningAppVersion': Edm.String,
        'minimumWarningOsVersion': Edm.String,
        'minimumWipeAppVersion': Edm.String,
        'minimumWipeOsVersion': Edm.String,
        'mobileThreatDefensePartnerPriority': mobileThreatDefensePartnerPriority,
        'mobileThreatDefenseRemediationAction': managedAppRemediationAction,
        'notificationRestriction': managedAppNotificationRestriction,
        'organizationalCredentialsRequired': Edm.Boolean,
        'periodBeforePinReset': Edm.Duration,
        'periodOfflineBeforeAccessCheck': Edm.Duration,
        'periodOfflineBeforeWipeIsEnforced': Edm.Duration,
        'periodOnlineBeforeAccessCheck': Edm.Duration,
        'pinCharacterSet': managedAppPinCharacterSet,
        'pinRequired': Edm.Boolean,
        'pinRequiredInsteadOfBiometricTimeout': Edm.Duration,
        'previousPinBlockCount': Edm.Int32,
        'printBlocked': Edm.Boolean,
        'protectedMessagingRedirectAppType': messagingRedirectAppType,
        'saveAsBlocked': Edm.Boolean,
        'simplePinBlocked': Edm.Boolean,
    }
    rels = [

    ]


class targetedManagedAppProtection(managedAppProtection):
    props = {
        'appGroupType': targetedManagedAppGroupType,
        'isAssigned': Edm.Boolean,
        'targetedAppManagementLevels': appManagementLevel,
    }
    rels = [
        'assignments',
    ]


class androidManagedAppProtection(targetedManagedAppProtection):
    props = {
        'allowedAndroidDeviceManufacturers': Edm.String,
        'allowedAndroidDeviceModels': Collection,
        'appActionIfAccountIsClockedOut': managedAppRemediationAction,
        'appActionIfAndroidDeviceManufacturerNotAllowed': managedAppRemediationAction,
        'appActionIfAndroidDeviceModelNotAllowed': managedAppRemediationAction,
        'appActionIfAndroidSafetyNetAppsVerificationFailed': managedAppRemediationAction,
        'appActionIfAndroidSafetyNetDeviceAttestationFailed': managedAppRemediationAction,
        'appActionIfDeviceLockNotSet': managedAppRemediationAction,
        'appActionIfDevicePasscodeComplexityLessThanHigh': managedAppRemediationAction,
        'appActionIfDevicePasscodeComplexityLessThanLow': managedAppRemediationAction,
        'appActionIfDevicePasscodeComplexityLessThanMedium': managedAppRemediationAction,
        'appActionIfSamsungKnoxAttestationRequired': managedAppRemediationAction,
        'approvedKeyboards': Collection,
        'biometricAuthenticationBlocked': Edm.Boolean,
        'blockAfterCompanyPortalUpdateDeferralInDays': Edm.Int32,
        'connectToVpnOnLaunch': Edm.Boolean,
        'customBrowserDisplayName': Edm.String,
        'customBrowserPackageId': Edm.String,
        'customDialerAppDisplayName': Edm.String,
        'customDialerAppPackageId': Edm.String,
        'deployedAppCount': Edm.Int32,
        'deviceLockRequired': Edm.Boolean,
        'disableAppEncryptionIfDeviceEncryptionIsEnabled': Edm.Boolean,
        'encryptAppData': Edm.Boolean,
        'exemptedAppPackages': Collection,
        'fingerprintAndBiometricEnabled': Edm.Boolean,
        'keyboardsRestricted': Edm.Boolean,
        'messagingRedirectAppDisplayName': Edm.String,
        'messagingRedirectAppPackageId': Edm.String,
        'minimumRequiredCompanyPortalVersion': Edm.String,
        'minimumRequiredPatchVersion': Edm.String,
        'minimumWarningCompanyPortalVersion': Edm.String,
        'minimumWarningPatchVersion': Edm.String,
        'minimumWipeCompanyPortalVersion': Edm.String,
        'minimumWipePatchVersion': Edm.String,
        'requireClass3Biometrics': Edm.Boolean,
        'requiredAndroidSafetyNetAppsVerificationType': androidManagedAppSafetyNetAppsVerificationType,
        'requiredAndroidSafetyNetDeviceAttestationType': androidManagedAppSafetyNetDeviceAttestationType,
        'requiredAndroidSafetyNetEvaluationType': androidManagedAppSafetyNetEvaluationType,
        'requirePinAfterBiometricChange': Edm.Boolean,
        'screenCaptureBlocked': Edm.Boolean,
        'warnAfterCompanyPortalUpdateDeferralInDays': Edm.Int32,
        'wipeAfterCompanyPortalUpdateDeferralInDays': Edm.Int32,
    }
    rels = [
        'apps',
        'deploymentSummary',
    ]


class defaultManagedAppProtection(managedAppProtection):
    props = {
        'allowedAndroidDeviceManufacturers': Edm.String,
        'allowedAndroidDeviceModels': Collection,
        'allowedIosDeviceModels': Edm.String,
        'allowWidgetContentSync': Edm.Boolean,
        'appActionIfAccountIsClockedOut': managedAppRemediationAction,
        'appActionIfAndroidDeviceManufacturerNotAllowed': managedAppRemediationAction,
        'appActionIfAndroidDeviceModelNotAllowed': managedAppRemediationAction,
        'appActionIfAndroidSafetyNetAppsVerificationFailed': managedAppRemediationAction,
        'appActionIfAndroidSafetyNetDeviceAttestationFailed': managedAppRemediationAction,
        'appActionIfDeviceLockNotSet': managedAppRemediationAction,
        'appActionIfDevicePasscodeComplexityLessThanHigh': managedAppRemediationAction,
        'appActionIfDevicePasscodeComplexityLessThanLow': managedAppRemediationAction,
        'appActionIfDevicePasscodeComplexityLessThanMedium': managedAppRemediationAction,
        'appActionIfIosDeviceModelNotAllowed': managedAppRemediationAction,
        'appDataEncryptionType': managedAppDataEncryptionType,
        'biometricAuthenticationBlocked': Edm.Boolean,
        'blockAfterCompanyPortalUpdateDeferralInDays': Edm.Int32,
        'connectToVpnOnLaunch': Edm.Boolean,
        'customBrowserDisplayName': Edm.String,
        'customBrowserPackageId': Edm.String,
        'customBrowserProtocol': Edm.String,
        'customDialerAppDisplayName': Edm.String,
        'customDialerAppPackageId': Edm.String,
        'customDialerAppProtocol': Edm.String,
        'customSettings': Collection,
        'deployedAppCount': Edm.Int32,
        'deviceLockRequired': Edm.Boolean,
        'disableAppEncryptionIfDeviceEncryptionIsEnabled': Edm.Boolean,
        'disableProtectionOfManagedOutboundOpenInData': Edm.Boolean,
        'encryptAppData': Edm.Boolean,
        'exemptedAppPackages': Collection,
        'exemptedAppProtocols': Collection,
        'faceIdBlocked': Edm.Boolean,
        'filterOpenInToOnlyManagedApps': Edm.Boolean,
        'fingerprintAndBiometricEnabled': Edm.Boolean,
        'messagingRedirectAppDisplayName': Edm.String,
        'messagingRedirectAppPackageId': Edm.String,
        'messagingRedirectAppUrlScheme': Edm.String,
        'minimumRequiredCompanyPortalVersion': Edm.String,
        'minimumRequiredPatchVersion': Edm.String,
        'minimumRequiredSdkVersion': Edm.String,
        'minimumWarningCompanyPortalVersion': Edm.String,
        'minimumWarningPatchVersion': Edm.String,
        'minimumWarningSdkVersion': Edm.String,
        'minimumWipeCompanyPortalVersion': Edm.String,
        'minimumWipePatchVersion': Edm.String,
        'minimumWipeSdkVersion': Edm.String,
        'protectInboundDataFromUnknownSources': Edm.Boolean,
        'requireClass3Biometrics': Edm.Boolean,
        'requiredAndroidSafetyNetAppsVerificationType': androidManagedAppSafetyNetAppsVerificationType,
        'requiredAndroidSafetyNetDeviceAttestationType': androidManagedAppSafetyNetDeviceAttestationType,
        'requiredAndroidSafetyNetEvaluationType': androidManagedAppSafetyNetEvaluationType,
        'requirePinAfterBiometricChange': Edm.Boolean,
        'screenCaptureBlocked': Edm.Boolean,
        'thirdPartyKeyboardsBlocked': Edm.Boolean,
        'warnAfterCompanyPortalUpdateDeferralInDays': Edm.Int32,
        'wipeAfterCompanyPortalUpdateDeferralInDays': Edm.Int32,
    }
    rels = [
        'apps',
        'deploymentSummary',
    ]


class iosManagedAppProtection(targetedManagedAppProtection):
    props = {
        'allowedIosDeviceModels': Edm.String,
        'allowWidgetContentSync': Edm.Boolean,
        'appActionIfAccountIsClockedOut': managedAppRemediationAction,
        'appActionIfIosDeviceModelNotAllowed': managedAppRemediationAction,
        'appDataEncryptionType': managedAppDataEncryptionType,
        'customBrowserProtocol': Edm.String,
        'customDialerAppProtocol': Edm.String,
        'deployedAppCount': Edm.Int32,
        'disableProtectionOfManagedOutboundOpenInData': Edm.Boolean,
        'exemptedAppProtocols': Collection,
        'exemptedUniversalLinks': Collection,
        'faceIdBlocked': Edm.Boolean,
        'filterOpenInToOnlyManagedApps': Edm.Boolean,
        'managedUniversalLinks': Collection,
        'messagingRedirectAppUrlScheme': Edm.String,
        'minimumRequiredSdkVersion': Edm.String,
        'minimumWarningSdkVersion': Edm.String,
        'minimumWipeSdkVersion': Edm.String,
        'protectInboundDataFromUnknownSources': Edm.Boolean,
        'thirdPartyKeyboardsBlocked': Edm.Boolean,
    }
    rels = [
        'apps',
        'deploymentSummary',
    ]


class windowsInformationProtection(managedAppPolicy):
    props = {
        'azureRightsManagementServicesAllowed': Edm.Boolean,
        'dataRecoveryCertificate': windowsInformationProtectionDataRecoveryCertificate,
        'enforcementLevel': windowsInformationProtectionEnforcementLevel,
        'enterpriseDomain': Edm.String,
        'enterpriseInternalProxyServers': Collection,
        'enterpriseIPRanges': Collection,
        'enterpriseIPRangesAreAuthoritative': Edm.Boolean,
        'enterpriseNetworkDomainNames': Collection,
        'enterpriseProtectedDomainNames': Collection,
        'enterpriseProxiedDomains': Collection,
        'enterpriseProxyServers': Collection,
        'enterpriseProxyServersAreAuthoritative': Edm.Boolean,
        'exemptApps': Collection,
        'iconsVisible': Edm.Boolean,
        'indexingEncryptedStoresOrItemsBlocked': Edm.Boolean,
        'isAssigned': Edm.Boolean,
        'neutralDomainResources': Collection,
        'protectedApps': Collection,
        'protectionUnderLockConfigRequired': Edm.Boolean,
        'revokeOnUnenrollDisabled': Edm.Boolean,
        'rightsManagementServicesTemplateId': Edm.Guid,
        'smbAutoEncryptedFileExtensions': Collection,
    }
    rels = [
        'assignments',
        'exemptAppLockerFiles',
        'protectedAppLockerFiles',
    ]


class mdmWindowsInformationProtectionPolicy(windowsInformationProtection):
    props = {

    }
    rels = [

    ]


class managedAppConfiguration(managedAppPolicy):
    props = {
        'customSettings': Collection,
    }
    rels = [
        'settings',
    ]


class targetedManagedAppConfiguration(managedAppConfiguration):
    props = {
        'appGroupType': targetedManagedAppGroupType,
        'deployedAppCount': Edm.Int32,
        'isAssigned': Edm.Boolean,
        'targetedAppManagementLevels': appManagementLevel,
    }
    rels = [
        'apps',
        'assignments',
        'deploymentSummary',
    ]


class windowsInformationProtectionPolicy(windowsInformationProtection):
    props = {
        'daysWithoutContactBeforeUnenroll': Edm.Int32,
        'mdmEnrollmentUrl': Edm.String,
        'minutesOfInactivityBeforeDeviceLock': Edm.Int32,
        'numberOfPastPinsRemembered': Edm.Int32,
        'passwordMaximumAttemptCount': Edm.Int32,
        'pinExpirationDays': Edm.Int32,
        'pinLowercaseLetters': windowsInformationProtectionPinCharacterRequirements,
        'pinMinimumLength': Edm.Int32,
        'pinSpecialCharacters': windowsInformationProtectionPinCharacterRequirements,
        'pinUppercaseLetters': windowsInformationProtectionPinCharacterRequirements,
        'revokeOnMdmHandoffDisabled': Edm.Boolean,
        'windowsHelloForBusinessBlocked': Edm.Boolean,
    }
    rels = [

    ]


class windowsManagedAppProtection(managedAppPolicy):
    props = {
        'allowedInboundDataTransferSources': windowsManagedAppDataTransferLevel,
        'allowedOutboundClipboardSharingLevel': windowsManagedAppClipboardSharingLevel,
        'allowedOutboundDataTransferDestinations': windowsManagedAppDataTransferLevel,
        'appActionIfUnableToAuthenticateUser': managedAppRemediationAction,
        'deployedAppCount': Edm.Int32,
        'isAssigned': Edm.Boolean,
        'maximumAllowedDeviceThreatLevel': managedAppDeviceThreatLevel,
        'maximumRequiredOsVersion': Edm.String,
        'maximumWarningOsVersion': Edm.String,
        'maximumWipeOsVersion': Edm.String,
        'minimumRequiredAppVersion': Edm.String,
        'minimumRequiredOsVersion': Edm.String,
        'minimumRequiredSdkVersion': Edm.String,
        'minimumWarningAppVersion': Edm.String,
        'minimumWarningOsVersion': Edm.String,
        'minimumWipeAppVersion': Edm.String,
        'minimumWipeOsVersion': Edm.String,
        'minimumWipeSdkVersion': Edm.String,
        'mobileThreatDefenseRemediationAction': managedAppRemediationAction,
        'periodOfflineBeforeAccessCheck': Edm.Duration,
        'periodOfflineBeforeWipeIsEnforced': Edm.Duration,
        'printBlocked': Edm.Boolean,
    }
    rels = [
        'apps',
        'assignments',
        'deploymentSummary',
    ]


class iosiPadOSWebClip(mobileApp):
    props = {
        'appUrl': Edm.String,
        'fullScreenEnabled': Edm.Boolean,
        'ignoreManifestScope': Edm.Boolean,
        'preComposedIconEnabled': Edm.Boolean,
        'targetApplicationBundleIdentifier': Edm.String,
        'useManagedBrowser': Edm.Boolean,
    }
    rels = [

    ]


class iosLobApp(mobileLobApp):
    props = {
        'applicableDeviceType': iosDeviceType,
        'buildNumber': Edm.String,
        'bundleId': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'minimumSupportedOperatingSystem': iosMinimumOperatingSystem,
        'versionNumber': Edm.String,
    }
    rels = [

    ]


class iosMobileAppConfiguration(managedDeviceMobileAppConfiguration):
    props = {
        'encodedSettingXml': Edm.Binary,
        'settings': Collection,
    }
    rels = [

    ]


class iosStoreApp(mobileApp):
    props = {
        'applicableDeviceType': iosDeviceType,
        'appStoreUrl': Edm.String,
        'bundleId': Edm.String,
        'minimumSupportedOperatingSystem': iosMinimumOperatingSystem,
    }
    rels = [

    ]


class iosVppApp(mobileApp):
    props = {
        'applicableDeviceType': iosDeviceType,
        'appStoreUrl': Edm.String,
        'bundleId': Edm.String,
        'licensingType': vppLicensingType,
        'releaseDateTime': Edm.DateTimeOffset,
        'revokeLicenseActionResults': Collection,
        'totalLicenseCount': Edm.Int32,
        'usedLicenseCount': Edm.Int32,
        'vppTokenAccountType': vppTokenAccountType,
        'vppTokenAppleId': Edm.String,
        'vppTokenDisplayName': Edm.String,
        'vppTokenId': Edm.String,
        'vppTokenOrganizationName': Edm.String,
    }
    rels = [
        'assignedLicenses',
    ]


class iosVppAppAssignedDeviceLicense(iosVppAppAssignedLicense):
    props = {
        'deviceName': Edm.String,
        'managedDeviceId': Edm.String,
    }
    rels = [

    ]


class iosVppAppAssignedUserLicense(iosVppAppAssignedLicense):
    props = {

    }
    rels = [

    ]


class macOSDmgApp(mobileLobApp):
    props = {
        'ignoreVersionDetection': Edm.Boolean,
        'includedApps': Collection,
        'minimumSupportedOperatingSystem': macOSMinimumOperatingSystem,
        'primaryBundleId': Edm.String,
        'primaryBundleVersion': Edm.String,
    }
    rels = [

    ]


class macOSLobApp(mobileLobApp):
    props = {
        'buildNumber': Edm.String,
        'bundleId': Edm.String,
        'childApps': Collection,
        'ignoreVersionDetection': Edm.Boolean,
        'installAsManaged': Edm.Boolean,
        'md5Hash': Collection,
        'md5HashChunkSize': Edm.Int32,
        'minimumSupportedOperatingSystem': macOSMinimumOperatingSystem,
        'versionNumber': Edm.String,
    }
    rels = [

    ]


class macOSMicrosoftDefenderApp(mobileApp):
    props = {

    }
    rels = [

    ]


class macOSMicrosoftEdgeApp(mobileApp):
    props = {
        'channel': microsoftEdgeChannel,
    }
    rels = [

    ]


class macOSOfficeSuiteApp(mobileApp):
    props = {

    }
    rels = [

    ]


class macOSPkgApp(mobileLobApp):
    props = {
        'ignoreVersionDetection': Edm.Boolean,
        'includedApps': Collection,
        'minimumSupportedOperatingSystem': macOSMinimumOperatingSystem,
        'postInstallScript': macOSAppScript,
        'preInstallScript': macOSAppScript,
        'primaryBundleId': Edm.String,
        'primaryBundleVersion': Edm.String,
    }
    rels = [

    ]


class macOsVppApp(mobileApp):
    props = {
        'appStoreUrl': Edm.String,
        'bundleId': Edm.String,
        'licensingType': vppLicensingType,
        'releaseDateTime': Edm.DateTimeOffset,
        'revokeLicenseActionResults': Collection,
        'totalLicenseCount': Edm.Int32,
        'usedLicenseCount': Edm.Int32,
        'vppTokenAccountType': vppTokenAccountType,
        'vppTokenAppleId': Edm.String,
        'vppTokenDisplayName': Edm.String,
        'vppTokenId': Edm.String,
        'vppTokenOrganizationName': Edm.String,
    }
    rels = [
        'assignedLicenses',
    ]


class macOSWebClip(mobileApp):
    props = {
        'appUrl': Edm.String,
        'fullScreenEnabled': Edm.Boolean,
        'preComposedIconEnabled': Edm.Boolean,
    }
    rels = [

    ]


class managedApp(mobileApp):
    props = {
        'appAvailability': managedAppAvailability,
        'version': Edm.String,
    }
    rels = [

    ]


class managedMobileLobApp(managedApp):
    props = {
        'committedContentVersion': Edm.String,
        'fileName': Edm.String,
        'size': Edm.Int64,
    }
    rels = [
        'contentVersions',
    ]


class managedAndroidLobApp(managedMobileLobApp):
    props = {
        'minimumSupportedOperatingSystem': androidMinimumOperatingSystem,
        'packageId': Edm.String,
        'targetedPlatforms': androidTargetedPlatforms,
        'versionCode': Edm.String,
        'versionName': Edm.String,
    }
    rels = [

    ]


class managedAndroidStoreApp(managedApp):
    props = {
        'appStoreUrl': Edm.String,
        'minimumSupportedOperatingSystem': androidMinimumOperatingSystem,
        'packageId': Edm.String,
    }
    rels = [

    ]


class managedIOSLobApp(managedMobileLobApp):
    props = {
        'applicableDeviceType': iosDeviceType,
        'buildNumber': Edm.String,
        'bundleId': Edm.String,
        'expirationDateTime': Edm.DateTimeOffset,
        'identityVersion': Edm.String,
        'minimumSupportedOperatingSystem': iosMinimumOperatingSystem,
        'versionNumber': Edm.String,
    }
    rels = [

    ]


class managedIOSStoreApp(managedApp):
    props = {
        'applicableDeviceType': iosDeviceType,
        'appStoreUrl': Edm.String,
        'bundleId': Edm.String,
        'minimumSupportedOperatingSystem': iosMinimumOperatingSystem,
    }
    rels = [

    ]


class microsoftStoreForBusinessApp(mobileApp):
    props = {
        'licenseType': microsoftStoreForBusinessLicenseType,
        'licensingType': vppLicensingType,
        'packageIdentityName': Edm.String,
        'productKey': Edm.String,
        'totalLicenseCount': Edm.Int32,
        'usedLicenseCount': Edm.Int32,
    }
    rels = [
        'containedApps',
    ]


class microsoftStoreForBusinessContainedApp(mobileContainedApp):
    props = {
        'appUserModelId': Edm.String,
    }
    rels = [

    ]


class mobileAppDependency(mobileAppRelationship):
    props = {
        'dependencyType': mobileAppDependencyType,
        'dependentAppCount': Edm.Int32,
        'dependsOnAppCount': Edm.Int32,
    }
    rels = [

    ]


class mobileAppSupersedence(mobileAppRelationship):
    props = {
        'supersededAppCount': Edm.Int32,
        'supersedenceType': mobileAppSupersedenceType,
        'supersedingAppCount': Edm.Int32,
    }
    rels = [

    ]


class officeSuiteApp(mobileApp):
    props = {
        'autoAcceptEula': Edm.Boolean,
        'excludedApps': excludedApps,
        'installProgressDisplayLevel': officeSuiteInstallProgressDisplayLevel,
        'localesToInstall': Collection,
        'officeConfigurationXml': Edm.Binary,
        'officePlatformArchitecture': windowsArchitecture,
        'officeSuiteAppDefaultFileFormat': officeSuiteDefaultFileFormatType,
        'productIds': Collection,
        'shouldUninstallOlderVersionsOfOffice': Edm.Boolean,
        'targetVersion': Edm.String,
        'updateChannel': officeUpdateChannel,
        'updateVersion': Edm.String,
        'useSharedComputerActivation': Edm.Boolean,
    }
    rels = [

    ]


class webApp(mobileApp):
    props = {
        'appUrl': Edm.String,
        'useManagedBrowser': Edm.Boolean,
    }
    rels = [

    ]


class win32LobApp(mobileLobApp):
    props = {
        'allowAvailableUninstall': Edm.Boolean,
        'applicableArchitectures': windowsArchitecture,
        'detectionRules': Collection,
        'displayVersion': Edm.String,
        'installCommandLine': Edm.String,
        'installExperience': win32LobAppInstallExperience,
        'minimumCpuSpeedInMHz': Edm.Int32,
        'minimumFreeDiskSpaceInMB': Edm.Int32,
        'minimumMemoryInMB': Edm.Int32,
        'minimumNumberOfProcessors': Edm.Int32,
        'minimumSupportedOperatingSystem': windowsMinimumOperatingSystem,
        'minimumSupportedWindowsRelease': Edm.String,
        'msiInformation': win32LobAppMsiInformation,
        'requirementRules': Collection,
        'returnCodes': Collection,
        'rules': Collection,
        'setupFilePath': Edm.String,
        'uninstallCommandLine': Edm.String,
    }
    rels = [

    ]


class win32CatalogApp(win32LobApp):
    props = {
        'mobileAppCatalogPackageId': Edm.String,
    }
    rels = [
        'latestUpgradeCatalogPackage',
        'referencedCatalogPackage',
    ]


class win32MobileAppCatalogPackage(mobileAppCatalogPackage):
    props = {
        'applicableArchitectures': windowsArchitecture,
        'branchDisplayName': Edm.String,
        'locales': Collection,
        'packageAutoUpdateCapable': Edm.Boolean,
    }
    rels = [

    ]


class windowsAppX(mobileLobApp):
    props = {
        'applicableArchitectures': windowsArchitecture,
        'identityName': Edm.String,
        'identityPublisherHash': Edm.String,
        'identityResourceIdentifier': Edm.String,
        'identityVersion': Edm.String,
        'isBundle': Edm.Boolean,
        'minimumSupportedOperatingSystem': windowsMinimumOperatingSystem,
    }
    rels = [

    ]


class windowsMicrosoftEdgeApp(mobileApp):
    props = {
        'channel': microsoftEdgeChannel,
        'displayLanguageLocale': Edm.String,
    }
    rels = [

    ]


class windowsMobileMSI(mobileLobApp):
    props = {
        'commandLine': Edm.String,
        'identityVersion': Edm.String,
        'ignoreVersionDetection': Edm.Boolean,
        'productCode': Edm.String,
        'productVersion': Edm.String,
        'useDeviceContext': Edm.Boolean,
    }
    rels = [

    ]


class windowsPhone81AppX(mobileLobApp):
    props = {
        'applicableArchitectures': windowsArchitecture,
        'identityName': Edm.String,
        'identityPublisherHash': Edm.String,
        'identityResourceIdentifier': Edm.String,
        'identityVersion': Edm.String,
        'minimumSupportedOperatingSystem': windowsMinimumOperatingSystem,
        'phoneProductIdentifier': Edm.String,
        'phonePublisherId': Edm.String,
    }
    rels = [

    ]


class windowsPhone81AppXBundle(windowsPhone81AppX):
    props = {
        'appXPackageInformationList': Collection,
    }
    rels = [

    ]


class windowsPhone81StoreApp(mobileApp):
    props = {
        'appStoreUrl': Edm.String,
    }
    rels = [

    ]


class windowsPhoneXAP(mobileLobApp):
    props = {
        'identityVersion': Edm.String,
        'minimumSupportedOperatingSystem': windowsMinimumOperatingSystem,
        'productIdentifier': Edm.String,
    }
    rels = [

    ]


class windowsStoreApp(mobileApp):
    props = {
        'appStoreUrl': Edm.String,
    }
    rels = [

    ]


class windowsUniversalAppX(mobileLobApp):
    props = {
        'applicableArchitectures': windowsArchitecture,
        'applicableDeviceTypes': windowsDeviceType,
        'identityName': Edm.String,
        'identityPublisherHash': Edm.String,
        'identityResourceIdentifier': Edm.String,
        'identityVersion': Edm.String,
        'isBundle': Edm.Boolean,
        'minimumSupportedOperatingSystem': windowsMinimumOperatingSystem,
    }
    rels = [
        'committedContainedApps',
    ]


class windowsUniversalAppXContainedApp(mobileContainedApp):
    props = {
        'appUserModelId': Edm.String,
    }
    rels = [

    ]


class windowsWebApp(mobileApp):
    props = {
        'appUrl': Edm.String,
    }
    rels = [

    ]


class winGetApp(mobileApp):
    props = {
        'installExperience': winGetAppInstallExperience,
        'manifestHash': Edm.String,
        'packageIdentifier': Edm.String,
    }
    rels = [

    ]


class iosVppEBook(managedEBook):
    props = {
        'appleId': Edm.String,
        'genres': Collection,
        'language': Edm.String,
        'roleScopeTagIds': Collection,
        'seller': Edm.String,
        'totalLicenseCount': Edm.Int32,
        'usedLicenseCount': Edm.Int32,
        'vppOrganizationName': Edm.String,
        'vppTokenId': Edm.Guid,
    }
    rels = [

    ]


class iosVppEBookAssignment(managedEBookAssignment):
    props = {

    }
    rels = [

    ]


class deviceCompliancePolicyPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class deviceConfigurationPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class deviceManagementConfigurationPolicyPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class deviceManagementScriptPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class enrollmentRestrictionsConfigurationPolicySetItem(policySetItem):
    props = {
        'limit': Edm.Int32,
        'priority': Edm.Int32,
    }
    rels = [

    ]


class iosLobAppProvisioningConfigurationPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class managedAppProtectionPolicySetItem(policySetItem):
    props = {
        'targetedAppManagementLevels': Edm.String,
    }
    rels = [

    ]


class managedDeviceMobileAppConfigurationPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class mdmWindowsInformationProtectionPolicyPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class mobileAppPolicySetItem(policySetItem):
    props = {
        'intent': installIntent,
        'settings': mobileAppAssignmentSettings,
    }
    rels = [

    ]


class payloadCompatibleAssignmentFilter(deviceAndAppManagementAssignmentFilter):
    props = {
        'payloadType': assignmentFilterPayloadType,
    }
    rels = [

    ]


class targetedManagedAppConfigurationPolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class windows10EnrollmentCompletionPageConfigurationPolicySetItem(policySetItem):
    props = {
        'priority': Edm.Int32,
    }
    rels = [

    ]


class windowsAutopilotDeploymentProfilePolicySetItem(policySetItem):
    props = {

    }
    rels = [

    ]


class androidCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [
        'rootCertificate',
    ]


class androidTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class androidCompliancePolicy(deviceCompliancePolicy):
    props = {
        'advancedThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'conditionStatementId': Edm.String,
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'minAndroidSecurityPatchLevel': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': androidRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'requiredPasswordComplexity': androidRequiredPasswordComplexity,
        'restrictedApps': Collection,
        'securityBlockDeviceAdministratorManagedDevices': Edm.Boolean,
        'securityBlockJailbrokenDevices': Edm.Boolean,
        'securityDisableUsbDebugging': Edm.Boolean,
        'securityPreventInstallAppsFromUnknownSources': Edm.Boolean,
        'securityRequireCompanyPortalAppIntegrity': Edm.Boolean,
        'securityRequireGooglePlayServices': Edm.Boolean,
        'securityRequireSafetyNetAttestationBasicIntegrity': Edm.Boolean,
        'securityRequireSafetyNetAttestationCertifiedDevice': Edm.Boolean,
        'securityRequireUpToDateSecurityProviders': Edm.Boolean,
        'securityRequireVerifyApps': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
    }
    rels = [

    ]


class androidCustomConfiguration(deviceConfiguration):
    props = {
        'omaSettings': Collection,
    }
    rels = [

    ]


class androidDeviceComplianceLocalActionLockDevice(androidDeviceComplianceLocalActionBase):
    props = {

    }
    rels = [

    ]


class androidDeviceComplianceLocalActionLockDeviceWithPasscode(androidDeviceComplianceLocalActionBase):
    props = {
        'passcode': Edm.String,
        'passcodeSignInFailureCountBeforeWipe': Edm.Int32,
    }
    rels = [

    ]


class androidDeviceOwnerCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [
        'rootCertificate',
    ]


class androidDeviceOwnerTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class androidDeviceOwnerCompliancePolicy(deviceCompliancePolicy):
    props = {
        'advancedThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'minAndroidSecurityPatchLevel': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinimumLetterCharacters': Edm.Int32,
        'passwordMinimumLowerCaseCharacters': Edm.Int32,
        'passwordMinimumNonLetterCharacters': Edm.Int32,
        'passwordMinimumNumericCharacters': Edm.Int32,
        'passwordMinimumSymbolCharacters': Edm.Int32,
        'passwordMinimumUpperCaseCharacters': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordCountToBlock': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': androidDeviceOwnerRequiredPasswordType,
        'requireNoPendingSystemUpdates': Edm.Boolean,
        'securityRequiredAndroidSafetyNetEvaluationType': androidSafetyNetEvaluationType,
        'securityRequireIntuneAppIntegrity': Edm.Boolean,
        'securityRequireSafetyNetAttestationBasicIntegrity': Edm.Boolean,
        'securityRequireSafetyNetAttestationCertifiedDevice': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
    }
    rels = [

    ]


class androidDeviceOwnerDerivedCredentialAuthenticationConfiguration(deviceConfiguration):
    props = {
        'certificateAccessType': androidDeviceOwnerCertificateAccessType,
        'silentCertificateAccessDetails': Collection,
    }
    rels = [
        'derivedCredentialSettings',
    ]


class androidDeviceOwnerWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'macAddressRandomizationMode': macAddressRandomizationMode,
        'networkName': Edm.String,
        'preSharedKey': Edm.String,
        'preSharedKeyIsSet': Edm.Boolean,
        'proxyAutomaticConfigurationUrl': Edm.String,
        'proxyExclusionList': Edm.String,
        'proxyManualAddress': Edm.String,
        'proxyManualPort': Edm.Int32,
        'proxySettings': wiFiProxySetting,
        'ssid': Edm.String,
        'wiFiSecurityType': androidDeviceOwnerWiFiSecurityType,
    }
    rels = [

    ]


class androidDeviceOwnerEnterpriseWiFiConfiguration(androidDeviceOwnerWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapType': androidEapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'innerAuthenticationProtocolForPeap': nonEapAuthenticationMethodForPeap,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'derivedCredentialSettings',
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
        'rootCertificatesForServerValidation',
    ]


class androidDeviceOwnerGeneralDeviceConfiguration(deviceConfiguration):
    props = {
        'accountsBlockModification': Edm.Boolean,
        'androidDeviceOwnerDelegatedScopeAppSettings': Collection,
        'appsAllowInstallFromUnknownSources': Edm.Boolean,
        'appsAutoUpdatePolicy': androidDeviceOwnerAppAutoUpdatePolicyType,
        'appsDefaultPermissionPolicy': androidDeviceOwnerDefaultAppPermissionPolicyType,
        'appsRecommendSkippingFirstUseHints': Edm.Boolean,
        'azureAdSharedDeviceDataClearApps': Collection,
        'bluetoothBlockConfiguration': Edm.Boolean,
        'bluetoothBlockContactSharing': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'cellularBlockWiFiTethering': Edm.Boolean,
        'certificateCredentialConfigurationDisabled': Edm.Boolean,
        'crossProfilePoliciesAllowCopyPaste': Edm.Boolean,
        'crossProfilePoliciesAllowDataSharing': androidDeviceOwnerCrossProfileDataSharing,
        'crossProfilePoliciesShowWorkContactsInPersonalProfile': Edm.Boolean,
        'dataRoamingBlocked': Edm.Boolean,
        'dateTimeConfigurationBlocked': Edm.Boolean,
        'detailedHelpText': androidDeviceOwnerUserFacingMessage,
        'deviceLocationMode': androidDeviceOwnerLocationMode,
        'deviceOwnerLockScreenMessage': androidDeviceOwnerUserFacingMessage,
        'enrollmentProfile': androidDeviceOwnerEnrollmentProfileType,
        'factoryResetBlocked': Edm.Boolean,
        'factoryResetDeviceAdministratorEmails': Collection,
        'globalProxy': androidDeviceOwnerGlobalProxy,
        'googleAccountsBlocked': Edm.Boolean,
        'kioskCustomizationDeviceSettingsBlocked': Edm.Boolean,
        'kioskCustomizationPowerButtonActionsBlocked': Edm.Boolean,
        'kioskCustomizationStatusBar': androidDeviceOwnerKioskCustomizationStatusBar,
        'kioskCustomizationSystemErrorWarnings': Edm.Boolean,
        'kioskCustomizationSystemNavigation': androidDeviceOwnerKioskCustomizationSystemNavigation,
        'kioskModeAppOrderEnabled': Edm.Boolean,
        'kioskModeAppPositions': Collection,
        'kioskModeApps': Collection,
        'kioskModeAppsInFolderOrderedByName': Edm.Boolean,
        'kioskModeBluetoothConfigurationEnabled': Edm.Boolean,
        'kioskModeDebugMenuEasyAccessEnabled': Edm.Boolean,
        'kioskModeExitCode': Edm.String,
        'kioskModeFlashlightConfigurationEnabled': Edm.Boolean,
        'kioskModeFolderIcon': androidDeviceOwnerKioskModeFolderIcon,
        'kioskModeGridHeight': Edm.Int32,
        'kioskModeGridWidth': Edm.Int32,
        'kioskModeIconSize': androidDeviceOwnerKioskModeIconSize,
        'kioskModeLockHomeScreen': Edm.Boolean,
        'kioskModeManagedFolders': Collection,
        'kioskModeManagedHomeScreenAutoSignout': Edm.Boolean,
        'kioskModeManagedHomeScreenInactiveSignOutDelayInSeconds': Edm.Int32,
        'kioskModeManagedHomeScreenInactiveSignOutNoticeInSeconds': Edm.Int32,
        'kioskModeManagedHomeScreenPinComplexity': kioskModeManagedHomeScreenPinComplexity,
        'kioskModeManagedHomeScreenPinRequired': Edm.Boolean,
        'kioskModeManagedHomeScreenPinRequiredToResume': Edm.Boolean,
        'kioskModeManagedHomeScreenSignInBackground': Edm.String,
        'kioskModeManagedHomeScreenSignInBrandingLogo': Edm.String,
        'kioskModeManagedHomeScreenSignInEnabled': Edm.Boolean,
        'kioskModeManagedSettingsEntryDisabled': Edm.Boolean,
        'kioskModeMediaVolumeConfigurationEnabled': Edm.Boolean,
        'kioskModeScreenOrientation': androidDeviceOwnerKioskModeScreenOrientation,
        'kioskModeScreenSaverConfigurationEnabled': Edm.Boolean,
        'kioskModeScreenSaverDetectMediaDisabled': Edm.Boolean,
        'kioskModeScreenSaverDisplayTimeInSeconds': Edm.Int32,
        'kioskModeScreenSaverImageUrl': Edm.String,
        'kioskModeScreenSaverStartDelayInSeconds': Edm.Int32,
        'kioskModeShowAppNotificationBadge': Edm.Boolean,
        'kioskModeShowDeviceInfo': Edm.Boolean,
        'kioskModeUseManagedHomeScreenApp': kioskModeType,
        'kioskModeVirtualHomeButtonEnabled': Edm.Boolean,
        'kioskModeVirtualHomeButtonType': androidDeviceOwnerVirtualHomeButtonType,
        'kioskModeWallpaperUrl': Edm.String,
        'kioskModeWifiAllowedSsids': Collection,
        'kioskModeWiFiConfigurationEnabled': Edm.Boolean,
        'locateDeviceLostModeEnabled': Edm.Boolean,
        'locateDeviceUserlessDisabled': Edm.Boolean,
        'microphoneForceMute': Edm.Boolean,
        'microsoftLauncherConfigurationEnabled': Edm.Boolean,
        'microsoftLauncherCustomWallpaperAllowUserModification': Edm.Boolean,
        'microsoftLauncherCustomWallpaperEnabled': Edm.Boolean,
        'microsoftLauncherCustomWallpaperImageUrl': Edm.String,
        'microsoftLauncherDockPresenceAllowUserModification': Edm.Boolean,
        'microsoftLauncherDockPresenceConfiguration': microsoftLauncherDockPresence,
        'microsoftLauncherFeedAllowUserModification': Edm.Boolean,
        'microsoftLauncherFeedEnabled': Edm.Boolean,
        'microsoftLauncherSearchBarPlacementConfiguration': microsoftLauncherSearchBarPlacement,
        'networkEscapeHatchAllowed': Edm.Boolean,
        'nfcBlockOutgoingBeam': Edm.Boolean,
        'passwordBlockKeyguard': Edm.Boolean,
        'passwordBlockKeyguardFeatures': Collection,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinimumLetterCharacters': Edm.Int32,
        'passwordMinimumLowerCaseCharacters': Edm.Int32,
        'passwordMinimumNonLetterCharacters': Edm.Int32,
        'passwordMinimumNumericCharacters': Edm.Int32,
        'passwordMinimumSymbolCharacters': Edm.Int32,
        'passwordMinimumUpperCaseCharacters': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordCountToBlock': Edm.Int32,
        'passwordRequiredType': androidDeviceOwnerRequiredPasswordType,
        'passwordRequireUnlock': androidDeviceOwnerRequiredPasswordUnlock,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'personalProfileAppsAllowInstallFromUnknownSources': Edm.Boolean,
        'personalProfileCameraBlocked': Edm.Boolean,
        'personalProfilePersonalApplications': Collection,
        'personalProfilePlayStoreMode': personalProfilePersonalPlayStoreMode,
        'personalProfileScreenCaptureBlocked': Edm.Boolean,
        'playStoreMode': androidDeviceOwnerPlayStoreMode,
        'screenCaptureBlocked': Edm.Boolean,
        'securityCommonCriteriaModeEnabled': Edm.Boolean,
        'securityDeveloperSettingsEnabled': Edm.Boolean,
        'securityRequireVerifyApps': Edm.Boolean,
        'shareDeviceLocationDisabled': Edm.Boolean,
        'shortHelpText': androidDeviceOwnerUserFacingMessage,
        'statusBarBlocked': Edm.Boolean,
        'stayOnModes': Collection,
        'storageAllowUsb': Edm.Boolean,
        'storageBlockExternalMedia': Edm.Boolean,
        'storageBlockUsbFileTransfer': Edm.Boolean,
        'systemUpdateFreezePeriods': Collection,
        'systemUpdateInstallType': androidDeviceOwnerSystemUpdateInstallType,
        'systemUpdateWindowEndMinutesAfterMidnight': Edm.Int32,
        'systemUpdateWindowStartMinutesAfterMidnight': Edm.Int32,
        'systemWindowsBlocked': Edm.Boolean,
        'usersBlockAdd': Edm.Boolean,
        'usersBlockRemove': Edm.Boolean,
        'volumeBlockAdjustment': Edm.Boolean,
        'vpnAlwaysOnLockdownMode': Edm.Boolean,
        'vpnAlwaysOnPackageIdentifier': Edm.String,
        'wifiBlockEditConfigurations': Edm.Boolean,
        'wifiBlockEditPolicyDefinedConfigurations': Edm.Boolean,
        'workProfilePasswordExpirationDays': Edm.Int32,
        'workProfilePasswordMinimumLength': Edm.Int32,
        'workProfilePasswordMinimumLetterCharacters': Edm.Int32,
        'workProfilePasswordMinimumLowerCaseCharacters': Edm.Int32,
        'workProfilePasswordMinimumNonLetterCharacters': Edm.Int32,
        'workProfilePasswordMinimumNumericCharacters': Edm.Int32,
        'workProfilePasswordMinimumSymbolCharacters': Edm.Int32,
        'workProfilePasswordMinimumUpperCaseCharacters': Edm.Int32,
        'workProfilePasswordPreviousPasswordCountToBlock': Edm.Int32,
        'workProfilePasswordRequiredType': androidDeviceOwnerRequiredPasswordType,
        'workProfilePasswordRequireUnlock': androidDeviceOwnerRequiredPasswordUnlock,
        'workProfilePasswordSignInFailureCountBeforeFactoryReset': Edm.Int32,
    }
    rels = [

    ]


class androidDeviceOwnerImportedPFXCertificateProfile(androidDeviceOwnerCertificateProfileBase):
    props = {
        'certificateAccessType': androidDeviceOwnerCertificateAccessType,
        'intendedPurpose': intendedPurpose,
        'silentCertificateAccessDetails': Collection,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidDeviceOwnerPkcsCertificateProfile(androidDeviceOwnerCertificateProfileBase):
    props = {
        'certificateAccessType': androidDeviceOwnerCertificateAccessType,
        'certificateStore': certificateStore,
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'certificationAuthorityType': deviceManagementCertificationAuthority,
        'customSubjectAlternativeNames': Collection,
        'silentCertificateAccessDetails': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidDeviceOwnerScepCertificateProfile(androidDeviceOwnerCertificateProfileBase):
    props = {
        'certificateAccessType': androidDeviceOwnerCertificateAccessType,
        'certificateStore': certificateStore,
        'customSubjectAlternativeNames': Collection,
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'silentCertificateAccessDetails': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class vpnConfiguration(deviceConfiguration):
    props = {
        'authenticationMethod': vpnAuthenticationMethod,
        'connectionName': Edm.String,
        'realm': Edm.String,
        'role': Edm.String,
        'servers': Collection,
    }
    rels = [

    ]


class androidDeviceOwnerVpnConfiguration(vpnConfiguration):
    props = {
        'alwaysOn': Edm.Boolean,
        'alwaysOnLockdown': Edm.Boolean,
        'connectionType': androidVpnConnectionType,
        'customData': Collection,
        'customKeyValueData': Collection,
        'microsoftTunnelSiteId': Edm.String,
        'proxyExclusionList': Collection,
        'proxyServer': vpnProxyServer,
        'targetedMobileApps': Collection,
        'targetedPackageIds': Collection,
    }
    rels = [
        'derivedCredentialSettings',
        'identityCertificate',
    ]


class androidEasEmailProfileConfiguration(deviceConfiguration):
    props = {
        'accountName': Edm.String,
        'authenticationMethod': easAuthenticationMethod,
        'customDomainName': Edm.String,
        'durationOfEmailToSync': emailSyncDuration,
        'emailAddressSource': userEmailSource,
        'emailSyncSchedule': emailSyncSchedule,
        'hostName': Edm.String,
        'requireSmime': Edm.Boolean,
        'requireSsl': Edm.Boolean,
        'syncCalendar': Edm.Boolean,
        'syncContacts': Edm.Boolean,
        'syncNotes': Edm.Boolean,
        'syncTasks': Edm.Boolean,
        'userDomainNameSource': domainNameSource,
        'usernameSource': androidUsernameSource,
    }
    rels = [
        'identityCertificate',
        'smimeSigningCertificate',
    ]


class androidWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'networkName': Edm.String,
        'ssid': Edm.String,
        'wiFiSecurityType': androidWiFiSecurityType,
    }
    rels = [

    ]


class androidEnterpriseWiFiConfiguration(androidWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapType': androidEapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'innerAuthenticationProtocolForPeap': nonEapAuthenticationMethodForPeap,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'passwordFormatString': Edm.String,
        'preSharedKey': Edm.String,
        'trustedServerCertificateNames': Collection,
        'usernameFormatString': Edm.String,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
    ]


class androidForWorkCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [
        'rootCertificate',
    ]


class androidForWorkTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class androidForWorkCompliancePolicy(deviceCompliancePolicy):
    props = {
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'minAndroidSecurityPatchLevel': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': androidRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'requiredPasswordComplexity': androidRequiredPasswordComplexity,
        'securityBlockJailbrokenDevices': Edm.Boolean,
        'securityDisableUsbDebugging': Edm.Boolean,
        'securityPreventInstallAppsFromUnknownSources': Edm.Boolean,
        'securityRequireCompanyPortalAppIntegrity': Edm.Boolean,
        'securityRequiredAndroidSafetyNetEvaluationType': androidSafetyNetEvaluationType,
        'securityRequireGooglePlayServices': Edm.Boolean,
        'securityRequireSafetyNetAttestationBasicIntegrity': Edm.Boolean,
        'securityRequireSafetyNetAttestationCertifiedDevice': Edm.Boolean,
        'securityRequireUpToDateSecurityProviders': Edm.Boolean,
        'securityRequireVerifyApps': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
        'workProfileInactiveBeforeScreenLockInMinutes': Edm.Int32,
        'workProfilePasswordExpirationInDays': Edm.Int32,
        'workProfilePasswordMinimumLength': Edm.Int32,
        'workProfilePasswordRequiredType': androidForWorkRequiredPasswordType,
        'workProfilePreviousPasswordBlockCount': Edm.Int32,
        'workProfileRequiredPasswordComplexity': androidRequiredPasswordComplexity,
        'workProfileRequirePassword': Edm.Boolean,
    }
    rels = [

    ]


class androidForWorkCustomConfiguration(deviceConfiguration):
    props = {
        'omaSettings': Collection,
    }
    rels = [

    ]


class androidForWorkEasEmailProfileBase(deviceConfiguration):
    props = {
        'authenticationMethod': easAuthenticationMethod,
        'durationOfEmailToSync': emailSyncDuration,
        'emailAddressSource': userEmailSource,
        'hostName': Edm.String,
        'requireSsl': Edm.Boolean,
        'usernameSource': androidUsernameSource,
    }
    rels = [
        'identityCertificate',
    ]


class androidForWorkWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'networkName': Edm.String,
        'ssid': Edm.String,
        'wiFiSecurityType': androidWiFiSecurityType,
    }
    rels = [

    ]


class androidForWorkEnterpriseWiFiConfiguration(androidForWorkWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapType': androidEapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'innerAuthenticationProtocolForPeap': nonEapAuthenticationMethodForPeap,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
    ]


class androidForWorkGeneralDeviceConfiguration(deviceConfiguration):
    props = {
        'allowedGoogleAccountDomains': Collection,
        'blockUnifiedPasswordForWorkProfile': Edm.Boolean,
        'passwordBlockFaceUnlock': Edm.Boolean,
        'passwordBlockFingerprintUnlock': Edm.Boolean,
        'passwordBlockIrisUnlock': Edm.Boolean,
        'passwordBlockTrustAgents': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequiredType': androidForWorkRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'requiredPasswordComplexity': androidRequiredPasswordComplexity,
        'securityRequireVerifyApps': Edm.Boolean,
        'vpnAlwaysOnPackageIdentifier': Edm.String,
        'vpnEnableAlwaysOnLockdownMode': Edm.Boolean,
        'workProfileAccountUse': androidWorkProfileAccountUse,
        'workProfileAllowWidgets': Edm.Boolean,
        'workProfileBlockAddingAccounts': Edm.Boolean,
        'workProfileBlockCamera': Edm.Boolean,
        'workProfileBlockCrossProfileCallerId': Edm.Boolean,
        'workProfileBlockCrossProfileContactsSearch': Edm.Boolean,
        'workProfileBlockCrossProfileCopyPaste': Edm.Boolean,
        'workProfileBlockNotificationsWhileDeviceLocked': Edm.Boolean,
        'workProfileBlockPersonalAppInstallsFromUnknownSources': Edm.Boolean,
        'workProfileBlockScreenCapture': Edm.Boolean,
        'workProfileBluetoothEnableContactSharing': Edm.Boolean,
        'workProfileDataSharingType': androidForWorkCrossProfileDataSharingType,
        'workProfileDefaultAppPermissionPolicy': androidForWorkDefaultAppPermissionPolicyType,
        'workProfilePasswordBlockFaceUnlock': Edm.Boolean,
        'workProfilePasswordBlockFingerprintUnlock': Edm.Boolean,
        'workProfilePasswordBlockIrisUnlock': Edm.Boolean,
        'workProfilePasswordBlockTrustAgents': Edm.Boolean,
        'workProfilePasswordExpirationDays': Edm.Int32,
        'workProfilePasswordMinimumLength': Edm.Int32,
        'workProfilePasswordMinLetterCharacters': Edm.Int32,
        'workProfilePasswordMinLowerCaseCharacters': Edm.Int32,
        'workProfilePasswordMinNonLetterCharacters': Edm.Int32,
        'workProfilePasswordMinNumericCharacters': Edm.Int32,
        'workProfilePasswordMinSymbolCharacters': Edm.Int32,
        'workProfilePasswordMinUpperCaseCharacters': Edm.Int32,
        'workProfilePasswordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'workProfilePasswordPreviousPasswordBlockCount': Edm.Int32,
        'workProfilePasswordRequiredType': androidForWorkRequiredPasswordType,
        'workProfilePasswordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'workProfileRequiredPasswordComplexity': androidRequiredPasswordComplexity,
        'workProfileRequirePassword': Edm.Boolean,
    }
    rels = [

    ]


class androidForWorkGmailEasConfiguration(androidForWorkEasEmailProfileBase):
    props = {

    }
    rels = [

    ]


class androidForWorkImportedPFXCertificateProfile(androidCertificateProfileBase):
    props = {
        'intendedPurpose': intendedPurpose,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidForWorkNineWorkEasConfiguration(androidForWorkEasEmailProfileBase):
    props = {
        'syncCalendar': Edm.Boolean,
        'syncContacts': Edm.Boolean,
        'syncTasks': Edm.Boolean,
    }
    rels = [

    ]


class androidForWorkPkcsCertificateProfile(androidForWorkCertificateProfileBase):
    props = {
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'subjectAlternativeNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidForWorkScepCertificateProfile(androidForWorkCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'customSubjectAlternativeNames': Collection,
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidForWorkVpnConfiguration(deviceConfiguration):
    props = {
        'authenticationMethod': vpnAuthenticationMethod,
        'connectionName': Edm.String,
        'connectionType': androidForWorkVpnConnectionType,
        'customData': Collection,
        'customKeyValueData': Collection,
        'fingerprint': Edm.String,
        'realm': Edm.String,
        'role': Edm.String,
        'servers': Collection,
    }
    rels = [
        'identityCertificate',
    ]


class androidGeneralDeviceConfiguration(deviceConfiguration):
    props = {
        'appsBlockClipboardSharing': Edm.Boolean,
        'appsBlockCopyPaste': Edm.Boolean,
        'appsBlockYouTube': Edm.Boolean,
        'appsHideList': Collection,
        'appsInstallAllowList': Collection,
        'appsLaunchBlockList': Collection,
        'bluetoothBlocked': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'cellularBlockDataRoaming': Edm.Boolean,
        'cellularBlockMessaging': Edm.Boolean,
        'cellularBlockVoiceRoaming': Edm.Boolean,
        'cellularBlockWiFiTethering': Edm.Boolean,
        'compliantAppListType': appListType,
        'compliantAppsList': Collection,
        'dateAndTimeBlockChanges': Edm.Boolean,
        'deviceSharingAllowed': Edm.Boolean,
        'diagnosticDataBlockSubmission': Edm.Boolean,
        'factoryResetBlocked': Edm.Boolean,
        'googleAccountBlockAutoSync': Edm.Boolean,
        'googlePlayStoreBlocked': Edm.Boolean,
        'kioskModeApps': Collection,
        'kioskModeBlockSleepButton': Edm.Boolean,
        'kioskModeBlockVolumeButtons': Edm.Boolean,
        'locationServicesBlocked': Edm.Boolean,
        'nfcBlocked': Edm.Boolean,
        'passwordBlockFingerprintUnlock': Edm.Boolean,
        'passwordBlockTrustAgents': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': androidRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'powerOffBlocked': Edm.Boolean,
        'requiredPasswordComplexity': androidRequiredPasswordComplexity,
        'screenCaptureBlocked': Edm.Boolean,
        'securityRequireVerifyApps': Edm.Boolean,
        'storageBlockGoogleBackup': Edm.Boolean,
        'storageBlockRemovableStorage': Edm.Boolean,
        'storageRequireDeviceEncryption': Edm.Boolean,
        'storageRequireRemovableStorageEncryption': Edm.Boolean,
        'voiceAssistantBlocked': Edm.Boolean,
        'voiceDialingBlocked': Edm.Boolean,
        'webBrowserBlockAutofill': Edm.Boolean,
        'webBrowserBlocked': Edm.Boolean,
        'webBrowserBlockJavaScript': Edm.Boolean,
        'webBrowserBlockPopups': Edm.Boolean,
        'webBrowserCookieSettings': webBrowserCookieSettings,
        'wiFiBlocked': Edm.Boolean,
    }
    rels = [

    ]


class androidImportedPFXCertificateProfile(androidCertificateProfileBase):
    props = {
        'intendedPurpose': intendedPurpose,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidOmaCpConfiguration(deviceConfiguration):
    props = {
        'configurationXml': Edm.Binary,
    }
    rels = [

    ]


class androidPkcsCertificateProfile(androidCertificateProfileBase):
    props = {
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'subjectAlternativeNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidScepCertificateProfile(androidCertificateProfileBase):
    props = {
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidVpnConfiguration(deviceConfiguration):
    props = {
        'authenticationMethod': vpnAuthenticationMethod,
        'connectionName': Edm.String,
        'connectionType': androidVpnConnectionType,
        'customData': Collection,
        'customKeyValueData': Collection,
        'fingerprint': Edm.String,
        'realm': Edm.String,
        'role': Edm.String,
        'servers': Collection,
    }
    rels = [
        'identityCertificate',
    ]


class androidWorkProfileCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [
        'rootCertificate',
    ]


class androidWorkProfileTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class androidWorkProfileCompliancePolicy(deviceCompliancePolicy):
    props = {
        'advancedThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'minAndroidSecurityPatchLevel': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': androidRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'requiredPasswordComplexity': androidRequiredPasswordComplexity,
        'securityBlockJailbrokenDevices': Edm.Boolean,
        'securityDisableUsbDebugging': Edm.Boolean,
        'securityPreventInstallAppsFromUnknownSources': Edm.Boolean,
        'securityRequireCompanyPortalAppIntegrity': Edm.Boolean,
        'securityRequiredAndroidSafetyNetEvaluationType': androidSafetyNetEvaluationType,
        'securityRequireGooglePlayServices': Edm.Boolean,
        'securityRequireSafetyNetAttestationBasicIntegrity': Edm.Boolean,
        'securityRequireSafetyNetAttestationCertifiedDevice': Edm.Boolean,
        'securityRequireUpToDateSecurityProviders': Edm.Boolean,
        'securityRequireVerifyApps': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
        'workProfileInactiveBeforeScreenLockInMinutes': Edm.Int32,
        'workProfilePasswordExpirationInDays': Edm.Int32,
        'workProfilePasswordMinimumLength': Edm.Int32,
        'workProfilePasswordRequiredType': androidWorkProfileRequiredPasswordType,
        'workProfilePreviousPasswordBlockCount': Edm.Int32,
        'workProfileRequiredPasswordComplexity': androidRequiredPasswordComplexity,
        'workProfileRequirePassword': Edm.Boolean,
    }
    rels = [

    ]


class androidWorkProfileCustomConfiguration(deviceConfiguration):
    props = {
        'omaSettings': Collection,
    }
    rels = [

    ]


class androidWorkProfileEasEmailProfileBase(deviceConfiguration):
    props = {
        'authenticationMethod': easAuthenticationMethod,
        'durationOfEmailToSync': emailSyncDuration,
        'emailAddressSource': userEmailSource,
        'hostName': Edm.String,
        'requireSsl': Edm.Boolean,
        'usernameSource': androidUsernameSource,
    }
    rels = [
        'identityCertificate',
    ]


class androidWorkProfileWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'networkName': Edm.String,
        'preSharedKey': Edm.String,
        'preSharedKeyIsSet': Edm.Boolean,
        'proxyAutomaticConfigurationUrl': Edm.String,
        'proxySettings': wiFiProxySetting,
        'ssid': Edm.String,
        'wiFiSecurityType': androidWiFiSecurityType,
    }
    rels = [

    ]


class androidWorkProfileEnterpriseWiFiConfiguration(androidWorkProfileWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapType': androidEapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'innerAuthenticationProtocolForPeap': nonEapAuthenticationMethodForPeap,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
    ]


class androidWorkProfileGeneralDeviceConfiguration(deviceConfiguration):
    props = {
        'allowedGoogleAccountDomains': Collection,
        'blockUnifiedPasswordForWorkProfile': Edm.Boolean,
        'passwordBlockFaceUnlock': Edm.Boolean,
        'passwordBlockFingerprintUnlock': Edm.Boolean,
        'passwordBlockIrisUnlock': Edm.Boolean,
        'passwordBlockTrustAgents': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequiredType': androidWorkProfileRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'requiredPasswordComplexity': androidRequiredPasswordComplexity,
        'securityRequireVerifyApps': Edm.Boolean,
        'vpnAlwaysOnPackageIdentifier': Edm.String,
        'vpnEnableAlwaysOnLockdownMode': Edm.Boolean,
        'workProfileAccountUse': androidWorkProfileAccountUse,
        'workProfileAllowAppInstallsFromUnknownSources': Edm.Boolean,
        'workProfileAllowWidgets': Edm.Boolean,
        'workProfileBlockAddingAccounts': Edm.Boolean,
        'workProfileBlockCamera': Edm.Boolean,
        'workProfileBlockCrossProfileCallerId': Edm.Boolean,
        'workProfileBlockCrossProfileContactsSearch': Edm.Boolean,
        'workProfileBlockCrossProfileCopyPaste': Edm.Boolean,
        'workProfileBlockNotificationsWhileDeviceLocked': Edm.Boolean,
        'workProfileBlockPersonalAppInstallsFromUnknownSources': Edm.Boolean,
        'workProfileBlockScreenCapture': Edm.Boolean,
        'workProfileBluetoothEnableContactSharing': Edm.Boolean,
        'workProfileDataSharingType': androidWorkProfileCrossProfileDataSharingType,
        'workProfileDefaultAppPermissionPolicy': androidWorkProfileDefaultAppPermissionPolicyType,
        'workProfilePasswordBlockFaceUnlock': Edm.Boolean,
        'workProfilePasswordBlockFingerprintUnlock': Edm.Boolean,
        'workProfilePasswordBlockIrisUnlock': Edm.Boolean,
        'workProfilePasswordBlockTrustAgents': Edm.Boolean,
        'workProfilePasswordExpirationDays': Edm.Int32,
        'workProfilePasswordMinimumLength': Edm.Int32,
        'workProfilePasswordMinLetterCharacters': Edm.Int32,
        'workProfilePasswordMinLowerCaseCharacters': Edm.Int32,
        'workProfilePasswordMinNonLetterCharacters': Edm.Int32,
        'workProfilePasswordMinNumericCharacters': Edm.Int32,
        'workProfilePasswordMinSymbolCharacters': Edm.Int32,
        'workProfilePasswordMinUpperCaseCharacters': Edm.Int32,
        'workProfilePasswordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'workProfilePasswordPreviousPasswordBlockCount': Edm.Int32,
        'workProfilePasswordRequiredType': androidWorkProfileRequiredPasswordType,
        'workProfilePasswordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'workProfileRequiredPasswordComplexity': androidRequiredPasswordComplexity,
        'workProfileRequirePassword': Edm.Boolean,
    }
    rels = [

    ]


class androidWorkProfileGmailEasConfiguration(androidWorkProfileEasEmailProfileBase):
    props = {

    }
    rels = [

    ]


class androidWorkProfileNineWorkEasConfiguration(androidWorkProfileEasEmailProfileBase):
    props = {
        'syncCalendar': Edm.Boolean,
        'syncContacts': Edm.Boolean,
        'syncTasks': Edm.Boolean,
    }
    rels = [

    ]


class androidWorkProfilePkcsCertificateProfile(androidWorkProfileCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'customSubjectAlternativeNames': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidWorkProfileScepCertificateProfile(androidWorkProfileCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'customSubjectAlternativeNames': Collection,
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class androidWorkProfileVpnConfiguration(deviceConfiguration):
    props = {
        'alwaysOn': Edm.Boolean,
        'alwaysOnLockdown': Edm.Boolean,
        'authenticationMethod': vpnAuthenticationMethod,
        'connectionName': Edm.String,
        'connectionType': androidWorkProfileVpnConnectionType,
        'customData': Collection,
        'customKeyValueData': Collection,
        'fingerprint': Edm.String,
        'microsoftTunnelSiteId': Edm.String,
        'proxyExclusionList': Collection,
        'proxyServer': vpnProxyServer,
        'realm': Edm.String,
        'role': Edm.String,
        'servers': Collection,
        'targetedMobileApps': Collection,
        'targetedPackageIds': Collection,
    }
    rels = [
        'identityCertificate',
    ]


class aospDeviceOwnerCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [
        'rootCertificate',
    ]


class aospDeviceOwnerTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class aospDeviceOwnerCompliancePolicy(deviceCompliancePolicy):
    props = {
        'minAndroidSecurityPatchLevel': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': androidDeviceOwnerRequiredPasswordType,
        'securityBlockJailbrokenDevices': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
    }
    rels = [

    ]


class aospDeviceOwnerDeviceConfiguration(deviceConfiguration):
    props = {
        'appsBlockInstallFromUnknownSources': Edm.Boolean,
        'bluetoothBlockConfiguration': Edm.Boolean,
        'bluetoothBlocked': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'factoryResetBlocked': Edm.Boolean,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordRequiredType': androidDeviceOwnerRequiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'screenCaptureBlocked': Edm.Boolean,
        'securityAllowDebuggingFeatures': Edm.Boolean,
        'storageBlockExternalMedia': Edm.Boolean,
        'storageBlockUsbFileTransfer': Edm.Boolean,
        'wifiBlockEditConfigurations': Edm.Boolean,
    }
    rels = [

    ]


class aospDeviceOwnerWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'networkName': Edm.String,
        'preSharedKey': Edm.String,
        'preSharedKeyIsSet': Edm.Boolean,
        'proxyAutomaticConfigurationUrl': Edm.String,
        'proxyExclusionList': Collection,
        'proxyManualAddress': Edm.String,
        'proxyManualPort': Edm.Int32,
        'proxySetting': wiFiProxySetting,
        'ssid': Edm.String,
        'wiFiSecurityType': aospDeviceOwnerWiFiSecurityType,
    }
    rels = [

    ]


class aospDeviceOwnerEnterpriseWiFiConfiguration(aospDeviceOwnerWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapType': androidEapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'innerAuthenticationProtocolForPeap': nonEapAuthenticationMethodForPeap,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
    ]


class aospDeviceOwnerPkcsCertificateProfile(aospDeviceOwnerCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'certificationAuthorityType': deviceManagementCertificationAuthority,
        'customSubjectAlternativeNames': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class aospDeviceOwnerScepCertificateProfile(aospDeviceOwnerCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'customSubjectAlternativeNames': Collection,
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class appleDeviceFeaturesConfigurationBase(deviceConfiguration):
    props = {
        'airPrintDestinations': Collection,
    }
    rels = [

    ]


class appleExpeditedCheckinConfigurationBase(deviceConfiguration):
    props = {
        'enableExpeditedCheckin': Edm.Boolean,
    }
    rels = [

    ]


class appleVpnConfiguration(deviceConfiguration):
    props = {
        'associatedDomains': Collection,
        'authenticationMethod': vpnAuthenticationMethod,
        'connectionName': Edm.String,
        'connectionType': appleVpnConnectionType,
        'customData': Collection,
        'customKeyValueData': Collection,
        'disableOnDemandUserOverride': Edm.Boolean,
        'disconnectOnIdle': Edm.Boolean,
        'disconnectOnIdleTimerInSeconds': Edm.Int32,
        'enablePerApp': Edm.Boolean,
        'enableSplitTunneling': Edm.Boolean,
        'excludedDomains': Collection,
        'identifier': Edm.String,
        'loginGroupOrDomain': Edm.String,
        'onDemandRules': Collection,
        'optInToDeviceIdSharing': Edm.Boolean,
        'providerType': vpnProviderType,
        'proxyServer': vpnProxyServer,
        'realm': Edm.String,
        'role': Edm.String,
        'safariDomains': Collection,
        'server': vpnServer,
    }
    rels = [

    ]


class defaultDeviceCompliancePolicy(deviceCompliancePolicy):
    props = {

    }
    rels = [

    ]


class easEmailProfileConfigurationBase(deviceConfiguration):
    props = {
        'customDomainName': Edm.String,
        'userDomainNameSource': domainNameSource,
        'usernameAADSource': usernameSource,
        'usernameSource': userEmailSource,
    }
    rels = [

    ]


class editionUpgradeConfiguration(deviceConfiguration):
    props = {
        'license': Edm.String,
        'licenseType': editionUpgradeLicenseType,
        'productKey': Edm.String,
        'targetEdition': windows10EditionType,
        'windowsSMode': windowsSModeConfiguration,
    }
    rels = [

    ]


class iosCertificateProfile(deviceConfiguration):
    props = {

    }
    rels = [

    ]


class iosCertificateProfileBase(iosCertificateProfile):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': appleSubjectNameFormat,
    }
    rels = [

    ]


class iosCompliancePolicy(deviceCompliancePolicy):
    props = {
        'advancedThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'managedEmailProfileRequired': Edm.Boolean,
        'osMaximumBuildVersion': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumBuildVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passcodeBlockSimple': Edm.Boolean,
        'passcodeExpirationDays': Edm.Int32,
        'passcodeMinimumCharacterSetCount': Edm.Int32,
        'passcodeMinimumLength': Edm.Int32,
        'passcodeMinutesOfInactivityBeforeLock': Edm.Int32,
        'passcodeMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passcodePreviousPasscodeBlockCount': Edm.Int32,
        'passcodeRequired': Edm.Boolean,
        'passcodeRequiredType': requiredPasswordType,
        'restrictedApps': Collection,
        'securityBlockJailbrokenDevices': Edm.Boolean,
    }
    rels = [

    ]


class iosCustomConfiguration(deviceConfiguration):
    props = {
        'payload': Edm.Binary,
        'payloadFileName': Edm.String,
        'payloadName': Edm.String,
    }
    rels = [

    ]


class iosDerivedCredentialAuthenticationConfiguration(deviceConfiguration):
    props = {

    }
    rels = [
        'derivedCredentialSettings',
    ]


class iosDeviceFeaturesConfiguration(appleDeviceFeaturesConfigurationBase):
    props = {
        'assetTagTemplate': Edm.String,
        'contentFilterSettings': iosWebContentFilterBase,
        'homeScreenDockIcons': Collection,
        'homeScreenGridHeight': Edm.Int32,
        'homeScreenGridWidth': Edm.Int32,
        'homeScreenPages': Collection,
        'iosSingleSignOnExtension': iosSingleSignOnExtension,
        'lockScreenFootnote': Edm.String,
        'notificationSettings': Collection,
        'singleSignOnExtension': singleSignOnExtension,
        'singleSignOnSettings': iosSingleSignOnSettings,
        'wallpaperDisplayLocation': iosWallpaperDisplayLocation,
        'wallpaperImage': mimeContent,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'singleSignOnExtensionPkinitCertificate',
    ]


class iosEasEmailProfileConfiguration(easEmailProfileConfigurationBase):
    props = {
        'accountName': Edm.String,
        'authenticationMethod': easAuthenticationMethod,
        'blockMovingMessagesToOtherEmailAccounts': Edm.Boolean,
        'blockSendingEmailFromThirdPartyApps': Edm.Boolean,
        'blockSyncingRecentlyUsedEmailAddresses': Edm.Boolean,
        'durationOfEmailToSync': emailSyncDuration,
        'easServices': easServices,
        'easServicesUserOverrideEnabled': Edm.Boolean,
        'emailAddressSource': userEmailSource,
        'encryptionCertificateType': emailCertificateType,
        'hostName': Edm.String,
        'perAppVPNProfileId': Edm.String,
        'requireSmime': Edm.Boolean,
        'requireSsl': Edm.Boolean,
        'signingCertificateType': emailCertificateType,
        'smimeEnablePerMessageSwitch': Edm.Boolean,
        'smimeEncryptByDefaultEnabled': Edm.Boolean,
        'smimeEncryptByDefaultUserOverrideEnabled': Edm.Boolean,
        'smimeEncryptionCertificateUserOverrideEnabled': Edm.Boolean,
        'smimeSigningCertificateUserOverrideEnabled': Edm.Boolean,
        'smimeSigningEnabled': Edm.Boolean,
        'smimeSigningUserOverrideEnabled': Edm.Boolean,
        'useOAuth': Edm.Boolean,
    }
    rels = [
        'derivedCredentialSettings',
        'identityCertificate',
        'smimeEncryptionCertificate',
        'smimeSigningCertificate',
    ]


class iosEducationDeviceConfiguration(deviceConfiguration):
    props = {

    }
    rels = [

    ]


class iosEduDeviceConfiguration(deviceConfiguration):
    props = {
        'deviceCertificateSettings': iosEduCertificateSettings,
        'studentCertificateSettings': iosEduCertificateSettings,
        'teacherCertificateSettings': iosEduCertificateSettings,
    }
    rels = [

    ]


class iosWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'disableMacAddressRandomization': Edm.Boolean,
        'networkName': Edm.String,
        'preSharedKey': Edm.String,
        'proxyAutomaticConfigurationUrl': Edm.String,
        'proxyManualAddress': Edm.String,
        'proxyManualPort': Edm.Int32,
        'proxySettings': wiFiProxySetting,
        'ssid': Edm.String,
        'wiFiSecurityType': wiFiSecurityType,
    }
    rels = [

    ]


class iosEnterpriseWiFiConfiguration(iosWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapFastConfiguration': eapFastConfiguration,
        'eapType': eapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'passwordFormatString': Edm.String,
        'trustedServerCertificateNames': Collection,
        'usernameFormatString': Edm.String,
    }
    rels = [
        'derivedCredentialSettings',
        'identityCertificateForClientAuthentication',
        'rootCertificatesForServerValidation',
    ]


class iosTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class iosExpeditedCheckinConfiguration(appleExpeditedCheckinConfigurationBase):
    props = {

    }
    rels = [

    ]


class iosGeneralDeviceConfiguration(deviceConfiguration):
    props = {
        'accountBlockModification': Edm.Boolean,
        'activationLockAllowWhenSupervised': Edm.Boolean,
        'airDropBlocked': Edm.Boolean,
        'airDropForceUnmanagedDropTarget': Edm.Boolean,
        'airPlayForcePairingPasswordForOutgoingRequests': Edm.Boolean,
        'airPrintBlockCredentialsStorage': Edm.Boolean,
        'airPrintBlocked': Edm.Boolean,
        'airPrintBlockiBeaconDiscovery': Edm.Boolean,
        'airPrintForceTrustedTLS': Edm.Boolean,
        'appClipsBlocked': Edm.Boolean,
        'appleNewsBlocked': Edm.Boolean,
        'applePersonalizedAdsBlocked': Edm.Boolean,
        'appleWatchBlockPairing': Edm.Boolean,
        'appleWatchForceWristDetection': Edm.Boolean,
        'appRemovalBlocked': Edm.Boolean,
        'appsSingleAppModeList': Collection,
        'appStoreBlockAutomaticDownloads': Edm.Boolean,
        'appStoreBlocked': Edm.Boolean,
        'appStoreBlockInAppPurchases': Edm.Boolean,
        'appStoreBlockUIAppInstallation': Edm.Boolean,
        'appStoreRequirePassword': Edm.Boolean,
        'appsVisibilityList': Collection,
        'appsVisibilityListType': appListType,
        'autoFillForceAuthentication': Edm.Boolean,
        'autoUnlockBlocked': Edm.Boolean,
        'blockSystemAppRemoval': Edm.Boolean,
        'bluetoothBlockModification': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'cellularBlockDataRoaming': Edm.Boolean,
        'cellularBlockGlobalBackgroundFetchWhileRoaming': Edm.Boolean,
        'cellularBlockPerAppDataModification': Edm.Boolean,
        'cellularBlockPersonalHotspot': Edm.Boolean,
        'cellularBlockPersonalHotspotModification': Edm.Boolean,
        'cellularBlockPlanModification': Edm.Boolean,
        'cellularBlockVoiceRoaming': Edm.Boolean,
        'certificatesBlockUntrustedTlsCertificates': Edm.Boolean,
        'classroomAppBlockRemoteScreenObservation': Edm.Boolean,
        'classroomAppForceUnpromptedScreenObservation': Edm.Boolean,
        'classroomForceAutomaticallyJoinClasses': Edm.Boolean,
        'classroomForceRequestPermissionToLeaveClasses': Edm.Boolean,
        'classroomForceUnpromptedAppAndDeviceLock': Edm.Boolean,
        'compliantAppListType': appListType,
        'compliantAppsList': Collection,
        'configurationProfileBlockChanges': Edm.Boolean,
        'contactsAllowManagedToUnmanagedWrite': Edm.Boolean,
        'contactsAllowUnmanagedToManagedRead': Edm.Boolean,
        'continuousPathKeyboardBlocked': Edm.Boolean,
        'dateAndTimeForceSetAutomatically': Edm.Boolean,
        'definitionLookupBlocked': Edm.Boolean,
        'deviceBlockEnableRestrictions': Edm.Boolean,
        'deviceBlockEraseContentAndSettings': Edm.Boolean,
        'deviceBlockNameModification': Edm.Boolean,
        'diagnosticDataBlockSubmission': Edm.Boolean,
        'diagnosticDataBlockSubmissionModification': Edm.Boolean,
        'documentsBlockManagedDocumentsInUnmanagedApps': Edm.Boolean,
        'documentsBlockUnmanagedDocumentsInManagedApps': Edm.Boolean,
        'emailInDomainSuffixes': Collection,
        'enterpriseAppBlockTrust': Edm.Boolean,
        'enterpriseAppBlockTrustModification': Edm.Boolean,
        'enterpriseBookBlockBackup': Edm.Boolean,
        'enterpriseBookBlockMetadataSync': Edm.Boolean,
        'esimBlockModification': Edm.Boolean,
        'faceTimeBlocked': Edm.Boolean,
        'filesNetworkDriveAccessBlocked': Edm.Boolean,
        'filesUsbDriveAccessBlocked': Edm.Boolean,
        'findMyDeviceInFindMyAppBlocked': Edm.Boolean,
        'findMyFriendsBlocked': Edm.Boolean,
        'findMyFriendsInFindMyAppBlocked': Edm.Boolean,
        'gameCenterBlocked': Edm.Boolean,
        'gamingBlockGameCenterFriends': Edm.Boolean,
        'gamingBlockMultiplayer': Edm.Boolean,
        'hostPairingBlocked': Edm.Boolean,
        'iBooksStoreBlocked': Edm.Boolean,
        'iBooksStoreBlockErotica': Edm.Boolean,
        'iCloudBlockActivityContinuation': Edm.Boolean,
        'iCloudBlockBackup': Edm.Boolean,
        'iCloudBlockDocumentSync': Edm.Boolean,
        'iCloudBlockManagedAppsSync': Edm.Boolean,
        'iCloudBlockPhotoLibrary': Edm.Boolean,
        'iCloudBlockPhotoStreamSync': Edm.Boolean,
        'iCloudBlockSharedPhotoStream': Edm.Boolean,
        'iCloudPrivateRelayBlocked': Edm.Boolean,
        'iCloudRequireEncryptedBackup': Edm.Boolean,
        'iTunesBlocked': Edm.Boolean,
        'iTunesBlockExplicitContent': Edm.Boolean,
        'iTunesBlockMusicService': Edm.Boolean,
        'iTunesBlockRadio': Edm.Boolean,
        'keyboardBlockAutoCorrect': Edm.Boolean,
        'keyboardBlockDictation': Edm.Boolean,
        'keyboardBlockPredictive': Edm.Boolean,
        'keyboardBlockShortcuts': Edm.Boolean,
        'keyboardBlockSpellCheck': Edm.Boolean,
        'keychainBlockCloudSync': Edm.Boolean,
        'kioskModeAllowAssistiveSpeak': Edm.Boolean,
        'kioskModeAllowAssistiveTouchSettings': Edm.Boolean,
        'kioskModeAllowAutoLock': Edm.Boolean,
        'kioskModeAllowColorInversionSettings': Edm.Boolean,
        'kioskModeAllowRingerSwitch': Edm.Boolean,
        'kioskModeAllowScreenRotation': Edm.Boolean,
        'kioskModeAllowSleepButton': Edm.Boolean,
        'kioskModeAllowTouchscreen': Edm.Boolean,
        'kioskModeAllowVoiceControlModification': Edm.Boolean,
        'kioskModeAllowVoiceOverSettings': Edm.Boolean,
        'kioskModeAllowVolumeButtons': Edm.Boolean,
        'kioskModeAllowZoomSettings': Edm.Boolean,
        'kioskModeAppStoreUrl': Edm.String,
        'kioskModeAppType': iosKioskModeAppType,
        'kioskModeBlockAutoLock': Edm.Boolean,
        'kioskModeBlockRingerSwitch': Edm.Boolean,
        'kioskModeBlockScreenRotation': Edm.Boolean,
        'kioskModeBlockSleepButton': Edm.Boolean,
        'kioskModeBlockTouchscreen': Edm.Boolean,
        'kioskModeBlockVolumeButtons': Edm.Boolean,
        'kioskModeBuiltInAppId': Edm.String,
        'kioskModeEnableVoiceControl': Edm.Boolean,
        'kioskModeManagedAppId': Edm.String,
        'kioskModeRequireAssistiveTouch': Edm.Boolean,
        'kioskModeRequireColorInversion': Edm.Boolean,
        'kioskModeRequireMonoAudio': Edm.Boolean,
        'kioskModeRequireVoiceOver': Edm.Boolean,
        'kioskModeRequireZoom': Edm.Boolean,
        'lockScreenBlockControlCenter': Edm.Boolean,
        'lockScreenBlockNotificationView': Edm.Boolean,
        'lockScreenBlockPassbook': Edm.Boolean,
        'lockScreenBlockTodayView': Edm.Boolean,
        'managedPasteboardRequired': Edm.Boolean,
        'mediaContentRatingApps': ratingAppsType,
        'mediaContentRatingAustralia': mediaContentRatingAustralia,
        'mediaContentRatingCanada': mediaContentRatingCanada,
        'mediaContentRatingFrance': mediaContentRatingFrance,
        'mediaContentRatingGermany': mediaContentRatingGermany,
        'mediaContentRatingIreland': mediaContentRatingIreland,
        'mediaContentRatingJapan': mediaContentRatingJapan,
        'mediaContentRatingNewZealand': mediaContentRatingNewZealand,
        'mediaContentRatingUnitedKingdom': mediaContentRatingUnitedKingdom,
        'mediaContentRatingUnitedStates': mediaContentRatingUnitedStates,
        'messagesBlocked': Edm.Boolean,
        'networkUsageRules': Collection,
        'nfcBlocked': Edm.Boolean,
        'notificationsBlockSettingsModification': Edm.Boolean,
        'onDeviceOnlyDictationForced': Edm.Boolean,
        'onDeviceOnlyTranslationForced': Edm.Boolean,
        'passcodeBlockFingerprintModification': Edm.Boolean,
        'passcodeBlockFingerprintUnlock': Edm.Boolean,
        'passcodeBlockModification': Edm.Boolean,
        'passcodeBlockSimple': Edm.Boolean,
        'passcodeExpirationDays': Edm.Int32,
        'passcodeMinimumCharacterSetCount': Edm.Int32,
        'passcodeMinimumLength': Edm.Int32,
        'passcodeMinutesOfInactivityBeforeLock': Edm.Int32,
        'passcodeMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passcodePreviousPasscodeBlockCount': Edm.Int32,
        'passcodeRequired': Edm.Boolean,
        'passcodeRequiredType': requiredPasswordType,
        'passcodeSignInFailureCountBeforeWipe': Edm.Int32,
        'passwordBlockAirDropSharing': Edm.Boolean,
        'passwordBlockAutoFill': Edm.Boolean,
        'passwordBlockProximityRequests': Edm.Boolean,
        'pkiBlockOTAUpdates': Edm.Boolean,
        'podcastsBlocked': Edm.Boolean,
        'privacyForceLimitAdTracking': Edm.Boolean,
        'proximityBlockSetupToNewDevice': Edm.Boolean,
        'safariBlockAutofill': Edm.Boolean,
        'safariBlocked': Edm.Boolean,
        'safariBlockJavaScript': Edm.Boolean,
        'safariBlockPopups': Edm.Boolean,
        'safariCookieSettings': webBrowserCookieSettings,
        'safariManagedDomains': Collection,
        'safariPasswordAutoFillDomains': Collection,
        'safariRequireFraudWarning': Edm.Boolean,
        'screenCaptureBlocked': Edm.Boolean,
        'sharedDeviceBlockTemporarySessions': Edm.Boolean,
        'siriBlocked': Edm.Boolean,
        'siriBlockedWhenLocked': Edm.Boolean,
        'siriBlockUserGeneratedContent': Edm.Boolean,
        'siriRequireProfanityFilter': Edm.Boolean,
        'softwareUpdatesEnforcedDelayInDays': Edm.Int32,
        'softwareUpdatesForceDelayed': Edm.Boolean,
        'spotlightBlockInternetResults': Edm.Boolean,
        'unpairedExternalBootToRecoveryAllowed': Edm.Boolean,
        'usbRestrictedModeBlocked': Edm.Boolean,
        'voiceDialingBlocked': Edm.Boolean,
        'vpnBlockCreation': Edm.Boolean,
        'wallpaperBlockModification': Edm.Boolean,
        'wiFiConnectOnlyToConfiguredNetworks': Edm.Boolean,
        'wiFiConnectToAllowedNetworksOnlyForced': Edm.Boolean,
        'wifiPowerOnForced': Edm.Boolean,
    }
    rels = [

    ]


class iosVpnConfiguration(appleVpnConfiguration):
    props = {
        'cloudName': Edm.String,
        'excludeList': Collection,
        'microsoftTunnelSiteId': Edm.String,
        'strictEnforcement': Edm.Boolean,
        'targetedMobileApps': Collection,
        'userDomain': Edm.String,
    }
    rels = [
        'derivedCredentialSettings',
        'identityCertificate',
    ]


class iosikEv2VpnConfiguration(iosVpnConfiguration):
    props = {
        'allowDefaultChildSecurityAssociationParameters': Edm.Boolean,
        'allowDefaultSecurityAssociationParameters': Edm.Boolean,
        'alwaysOnConfiguration': appleVpnAlwaysOnConfiguration,
        'childSecurityAssociationParameters': iosVpnSecurityAssociationParameters,
        'clientAuthenticationType': vpnClientAuthenticationType,
        'deadPeerDetectionRate': vpnDeadPeerDetectionRate,
        'disableMobilityAndMultihoming': Edm.Boolean,
        'disableRedirect': Edm.Boolean,
        'enableAlwaysOnConfiguration': Edm.Boolean,
        'enableCertificateRevocationCheck': Edm.Boolean,
        'enableEAP': Edm.Boolean,
        'enablePerfectForwardSecrecy': Edm.Boolean,
        'enableUseInternalSubnetAttributes': Edm.Boolean,
        'localIdentifier': vpnLocalIdentifier,
        'mtuSizeInBytes': Edm.Int32,
        'remoteIdentifier': Edm.String,
        'securityAssociationParameters': iosVpnSecurityAssociationParameters,
        'serverCertificateCommonName': Edm.String,
        'serverCertificateIssuerCommonName': Edm.String,
        'serverCertificateType': vpnServerCertificateType,
        'sharedSecret': Edm.String,
        'tlsMaximumVersion': Edm.String,
        'tlsMinimumVersion': Edm.String,
    }
    rels = [

    ]


class iosImportedPFXCertificateProfile(iosCertificateProfile):
    props = {
        'intendedPurpose': intendedPurpose,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class iosPkcsCertificateProfile(iosCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'customSubjectAlternativeNames': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class iosScepCertificateProfile(iosCertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'customSubjectAlternativeNames': Collection,
        'extendedKeyUsages': Collection,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
        'rootCertificate',
    ]


class iosUpdateConfiguration(deviceConfiguration):
    props = {
        'activeHoursEnd': Edm.TimeOfDay,
        'activeHoursStart': Edm.TimeOfDay,
        'customUpdateTimeWindows': Collection,
        'desiredOsVersion': Edm.String,
        'enforcedSoftwareUpdateDelayInDays': Edm.Int32,
        'isEnabled': Edm.Boolean,
        'scheduledInstallDays': Collection,
        'updateScheduleType': iosSoftwareUpdateScheduleType,
        'utcTimeOffsetInMinutes': Edm.Int32,
    }
    rels = [

    ]


class macOSCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': appleSubjectNameFormat,
    }
    rels = [

    ]


class macOSCompliancePolicy(deviceCompliancePolicy):
    props = {
        'advancedThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'firewallBlockAllIncoming': Edm.Boolean,
        'firewallEnabled': Edm.Boolean,
        'firewallEnableStealthMode': Edm.Boolean,
        'gatekeeperAllowedAppSource': macOSGatekeeperAppSources,
        'osMaximumBuildVersion': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumBuildVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'storageRequireEncryption': Edm.Boolean,
        'systemIntegrityProtectionEnabled': Edm.Boolean,
    }
    rels = [

    ]


class macOSCustomAppConfiguration(deviceConfiguration):
    props = {
        'bundleId': Edm.String,
        'configurationXml': Edm.Binary,
        'fileName': Edm.String,
    }
    rels = [

    ]


class macOSCustomConfiguration(deviceConfiguration):
    props = {
        'deploymentChannel': appleDeploymentChannel,
        'payload': Edm.Binary,
        'payloadFileName': Edm.String,
        'payloadName': Edm.String,
    }
    rels = [

    ]


class macOSDeviceFeaturesConfiguration(appleDeviceFeaturesConfigurationBase):
    props = {
        'adminShowHostInfo': Edm.Boolean,
        'appAssociatedDomains': Collection,
        'associatedDomains': Collection,
        'authorizedUsersListHidden': Edm.Boolean,
        'authorizedUsersListHideAdminUsers': Edm.Boolean,
        'authorizedUsersListHideLocalUsers': Edm.Boolean,
        'authorizedUsersListHideMobileAccounts': Edm.Boolean,
        'authorizedUsersListIncludeNetworkUsers': Edm.Boolean,
        'authorizedUsersListShowOtherManagedUsers': Edm.Boolean,
        'autoLaunchItems': Collection,
        'consoleAccessDisabled': Edm.Boolean,
        'contentCachingBlockDeletion': Edm.Boolean,
        'contentCachingClientListenRanges': Collection,
        'contentCachingClientPolicy': macOSContentCachingClientPolicy,
        'contentCachingDataPath': Edm.String,
        'contentCachingDisableConnectionSharing': Edm.Boolean,
        'contentCachingEnabled': Edm.Boolean,
        'contentCachingForceConnectionSharing': Edm.Boolean,
        'contentCachingKeepAwake': Edm.Boolean,
        'contentCachingLogClientIdentities': Edm.Boolean,
        'contentCachingMaxSizeBytes': Edm.Int64,
        'contentCachingParents': Collection,
        'contentCachingParentSelectionPolicy': macOSContentCachingParentSelectionPolicy,
        'contentCachingPeerFilterRanges': Collection,
        'contentCachingPeerListenRanges': Collection,
        'contentCachingPeerPolicy': macOSContentCachingPeerPolicy,
        'contentCachingPort': Edm.Int32,
        'contentCachingPublicRanges': Collection,
        'contentCachingShowAlerts': Edm.Boolean,
        'contentCachingType': macOSContentCachingType,
        'loginWindowText': Edm.String,
        'logOutDisabledWhileLoggedIn': Edm.Boolean,
        'macOSSingleSignOnExtension': macOSSingleSignOnExtension,
        'powerOffDisabledWhileLoggedIn': Edm.Boolean,
        'restartDisabled': Edm.Boolean,
        'restartDisabledWhileLoggedIn': Edm.Boolean,
        'screenLockDisableImmediate': Edm.Boolean,
        'shutDownDisabled': Edm.Boolean,
        'shutDownDisabledWhileLoggedIn': Edm.Boolean,
        'singleSignOnExtension': singleSignOnExtension,
        'sleepDisabled': Edm.Boolean,
    }
    rels = [
        'singleSignOnExtensionPkinitCertificate',
    ]


class macOSEndpointProtectionConfiguration(deviceConfiguration):
    props = {
        'advancedThreatProtectionAutomaticSampleSubmission': enablement,
        'advancedThreatProtectionCloudDelivered': enablement,
        'advancedThreatProtectionDiagnosticDataCollection': enablement,
        'advancedThreatProtectionExcludedExtensions': Collection,
        'advancedThreatProtectionExcludedFiles': Collection,
        'advancedThreatProtectionExcludedFolders': Collection,
        'advancedThreatProtectionExcludedProcesses': Collection,
        'advancedThreatProtectionRealTime': enablement,
        'fileVaultAllowDeferralUntilSignOut': Edm.Boolean,
        'fileVaultDisablePromptAtSignOut': Edm.Boolean,
        'fileVaultEnabled': Edm.Boolean,
        'fileVaultHidePersonalRecoveryKey': Edm.Boolean,
        'fileVaultInstitutionalRecoveryKeyCertificate': Edm.Binary,
        'fileVaultInstitutionalRecoveryKeyCertificateFileName': Edm.String,
        'fileVaultNumberOfTimesUserCanIgnore': Edm.Int32,
        'fileVaultPersonalRecoveryKeyHelpMessage': Edm.String,
        'fileVaultPersonalRecoveryKeyRotationInMonths': Edm.Int32,
        'fileVaultSelectedRecoveryKeyTypes': macOSFileVaultRecoveryKeyTypes,
        'firewallApplications': Collection,
        'firewallBlockAllIncoming': Edm.Boolean,
        'firewallEnabled': Edm.Boolean,
        'firewallEnableStealthMode': Edm.Boolean,
        'gatekeeperAllowedAppSource': macOSGatekeeperAppSources,
        'gatekeeperBlockOverride': Edm.Boolean,
    }
    rels = [

    ]


class macOSWiFiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'deploymentChannel': appleDeploymentChannel,
        'networkName': Edm.String,
        'preSharedKey': Edm.String,
        'proxyAutomaticConfigurationUrl': Edm.String,
        'proxyManualAddress': Edm.String,
        'proxyManualPort': Edm.Int32,
        'proxySettings': wiFiProxySetting,
        'ssid': Edm.String,
        'wiFiSecurityType': wiFiSecurityType,
    }
    rels = [

    ]


class macOSEnterpriseWiFiConfiguration(macOSWiFiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'eapFastConfiguration': eapFastConfiguration,
        'eapType': eapType,
        'innerAuthenticationProtocolForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
        'rootCertificatesForServerValidation',
    ]


class macOSTrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'deploymentChannel': appleDeploymentChannel,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class macOSExtensionsConfiguration(deviceConfiguration):
    props = {
        'kernelExtensionAllowedTeamIdentifiers': Collection,
        'kernelExtensionOverridesAllowed': Edm.Boolean,
        'kernelExtensionsAllowed': Collection,
        'systemExtensionsAllowed': Collection,
        'systemExtensionsAllowedTeamIdentifiers': Collection,
        'systemExtensionsAllowedTypes': Collection,
        'systemExtensionsBlockOverride': Edm.Boolean,
    }
    rels = [

    ]


class macOSGeneralDeviceConfiguration(deviceConfiguration):
    props = {
        'activationLockWhenSupervisedAllowed': Edm.Boolean,
        'addingGameCenterFriendsBlocked': Edm.Boolean,
        'airDropBlocked': Edm.Boolean,
        'appleWatchBlockAutoUnlock': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'classroomAppBlockRemoteScreenObservation': Edm.Boolean,
        'classroomAppForceUnpromptedScreenObservation': Edm.Boolean,
        'classroomForceAutomaticallyJoinClasses': Edm.Boolean,
        'classroomForceRequestPermissionToLeaveClasses': Edm.Boolean,
        'classroomForceUnpromptedAppAndDeviceLock': Edm.Boolean,
        'compliantAppListType': appListType,
        'compliantAppsList': Collection,
        'contentCachingBlocked': Edm.Boolean,
        'definitionLookupBlocked': Edm.Boolean,
        'emailInDomainSuffixes': Collection,
        'eraseContentAndSettingsBlocked': Edm.Boolean,
        'gameCenterBlocked': Edm.Boolean,
        'iCloudBlockActivityContinuation': Edm.Boolean,
        'iCloudBlockAddressBook': Edm.Boolean,
        'iCloudBlockBookmarks': Edm.Boolean,
        'iCloudBlockCalendar': Edm.Boolean,
        'iCloudBlockDocumentSync': Edm.Boolean,
        'iCloudBlockMail': Edm.Boolean,
        'iCloudBlockNotes': Edm.Boolean,
        'iCloudBlockPhotoLibrary': Edm.Boolean,
        'iCloudBlockReminders': Edm.Boolean,
        'iCloudDesktopAndDocumentsBlocked': Edm.Boolean,
        'iCloudPrivateRelayBlocked': Edm.Boolean,
        'iTunesBlockFileSharing': Edm.Boolean,
        'iTunesBlockMusicService': Edm.Boolean,
        'keyboardBlockDictation': Edm.Boolean,
        'keychainBlockCloudSync': Edm.Boolean,
        'multiplayerGamingBlocked': Edm.Boolean,
        'passwordBlockAirDropSharing': Edm.Boolean,
        'passwordBlockAutoFill': Edm.Boolean,
        'passwordBlockFingerprintUnlock': Edm.Boolean,
        'passwordBlockModification': Edm.Boolean,
        'passwordBlockProximityRequests': Edm.Boolean,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMaximumAttemptCount': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordMinutesUntilFailedLoginReset': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'privacyAccessControls': Collection,
        'safariBlockAutofill': Edm.Boolean,
        'screenCaptureBlocked': Edm.Boolean,
        'softwareUpdateMajorOSDeferredInstallDelayInDays': Edm.Int32,
        'softwareUpdateMinorOSDeferredInstallDelayInDays': Edm.Int32,
        'softwareUpdateNonOSDeferredInstallDelayInDays': Edm.Int32,
        'softwareUpdatesEnforcedDelayInDays': Edm.Int32,
        'spotlightBlockInternetResults': Edm.Boolean,
        'touchIdTimeoutInHours': Edm.Int32,
        'updateDelayPolicy': macOSSoftwareUpdateDelayPolicy,
        'wallpaperModificationBlocked': Edm.Boolean,
    }
    rels = [

    ]


class macOSImportedPFXCertificateProfile(macOSCertificateProfileBase):
    props = {
        'deploymentChannel': appleDeploymentChannel,
        'intendedPurpose': intendedPurpose,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class macOSPkcsCertificateProfile(macOSCertificateProfileBase):
    props = {
        'allowAllAppsAccess': Edm.Boolean,
        'certificateStore': certificateStore,
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'customSubjectAlternativeNames': Collection,
        'deploymentChannel': appleDeploymentChannel,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class macOSScepCertificateProfile(macOSCertificateProfileBase):
    props = {
        'allowAllAppsAccess': Edm.Boolean,
        'certificateStore': certificateStore,
        'customSubjectAlternativeNames': Collection,
        'deploymentChannel': appleDeploymentChannel,
        'extendedKeyUsages': Collection,
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
        'rootCertificate',
    ]


class macOSSoftwareUpdateConfiguration(deviceConfiguration):
    props = {
        'allOtherUpdateBehavior': macOSSoftwareUpdateBehavior,
        'configDataUpdateBehavior': macOSSoftwareUpdateBehavior,
        'criticalUpdateBehavior': macOSSoftwareUpdateBehavior,
        'customUpdateTimeWindows': Collection,
        'firmwareUpdateBehavior': macOSSoftwareUpdateBehavior,
        'maxUserDeferralsCount': Edm.Int32,
        'priority': macOSPriority,
        'updateScheduleType': macOSSoftwareUpdateScheduleType,
        'updateTimeWindowUtcOffsetInMinutes': Edm.Int32,
    }
    rels = [

    ]


class macOSVpnConfiguration(appleVpnConfiguration):
    props = {
        'deploymentChannel': appleDeploymentChannel,
    }
    rels = [
        'identityCertificate',
    ]


class macOSWiredNetworkConfiguration(deviceConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'deploymentChannel': appleDeploymentChannel,
        'eapFastConfiguration': eapFastConfiguration,
        'eapType': eapType,
        'enableOuterIdentityPrivacy': Edm.String,
        'networkInterface': wiredNetworkInterface,
        'networkName': Edm.String,
        'nonEapAuthenticationMethodForEapTtls': nonEapAuthenticationMethodForEapTtlsType,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForServerValidation',
    ]


class sharedPCConfiguration(deviceConfiguration):
    props = {
        'accountManagerPolicy': sharedPCAccountManagerPolicy,
        'allowedAccounts': sharedPCAllowedAccountType,
        'allowLocalStorage': Edm.Boolean,
        'disableAccountManager': Edm.Boolean,
        'disableEduPolicies': Edm.Boolean,
        'disablePowerPolicies': Edm.Boolean,
        'disableSignInOnResume': Edm.Boolean,
        'enabled': Edm.Boolean,
        'fastFirstSignIn': enablement,
        'idleTimeBeforeSleepInSeconds': Edm.Int32,
        'kioskAppDisplayName': Edm.String,
        'kioskAppUserModelId': Edm.String,
        'localStorage': enablement,
        'maintenanceStartTime': Edm.TimeOfDay,
        'setAccountManager': enablement,
        'setEduPolicies': enablement,
        'setPowerPolicies': enablement,
        'signInOnResume': enablement,
    }
    rels = [

    ]


class unsupportedDeviceConfiguration(deviceConfiguration):
    props = {
        'details': Collection,
        'originalEntityTypeName': Edm.String,
    }
    rels = [

    ]


class windowsCertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'keyStorageProvider': keyStorageProviderOption,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [

    ]


class windows10CertificateProfileBase(windowsCertificateProfileBase):
    props = {

    }
    rels = [

    ]


class windows10CompliancePolicy(deviceCompliancePolicy):
    props = {
        'activeFirewallRequired': Edm.Boolean,
        'antiSpywareRequired': Edm.Boolean,
        'antivirusRequired': Edm.Boolean,
        'bitLockerEnabled': Edm.Boolean,
        'codeIntegrityEnabled': Edm.Boolean,
        'configurationManagerComplianceRequired': Edm.Boolean,
        'defenderEnabled': Edm.Boolean,
        'defenderVersion': Edm.String,
        'deviceCompliancePolicyScript': deviceCompliancePolicyScript,
        'deviceThreatProtectionEnabled': Edm.Boolean,
        'deviceThreatProtectionRequiredSecurityLevel': deviceThreatProtectionLevel,
        'earlyLaunchAntiMalwareDriverEnabled': Edm.Boolean,
        'firmwareProtectionEnabled': Edm.Boolean,
        'kernelDmaProtectionEnabled': Edm.Boolean,
        'memoryIntegrityEnabled': Edm.Boolean,
        'mobileOsMaximumVersion': Edm.String,
        'mobileOsMinimumVersion': Edm.String,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredToUnlockFromIdle': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'requireHealthyDeviceReport': Edm.Boolean,
        'rtpEnabled': Edm.Boolean,
        'secureBootEnabled': Edm.Boolean,
        'signatureOutOfDate': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
        'tpmRequired': Edm.Boolean,
        'validOperatingSystemBuildRanges': Collection,
        'virtualizationBasedSecurityEnabled': Edm.Boolean,
        'wslDistributions': Collection,
    }
    rels = [

    ]


class windows10CustomConfiguration(deviceConfiguration):
    props = {
        'omaSettings': Collection,
    }
    rels = [

    ]


class windows10DeviceFirmwareConfigurationInterface(deviceConfiguration):
    props = {
        'bluetooth': enablement,
        'bootFromBuiltInNetworkAdapters': enablement,
        'bootFromExternalMedia': enablement,
        'cameras': enablement,
        'changeUefiSettingsPermission': changeUefiSettingsPermission,
        'frontCamera': enablement,
        'infraredCamera': enablement,
        'microphone': enablement,
        'microphonesAndSpeakers': enablement,
        'nearFieldCommunication': enablement,
        'radios': enablement,
        'rearCamera': enablement,
        'sdCard': enablement,
        'simultaneousMultiThreading': enablement,
        'usbTypeAPort': enablement,
        'virtualizationOfCpuAndIO': enablement,
        'wakeOnLAN': enablement,
        'wakeOnPower': enablement,
        'wiFi': enablement,
        'windowsPlatformBinaryTable': enablement,
        'wirelessWideAreaNetwork': enablement,
    }
    rels = [

    ]


class windows10EasEmailProfileConfiguration(easEmailProfileConfigurationBase):
    props = {
        'accountName': Edm.String,
        'durationOfEmailToSync': emailSyncDuration,
        'emailAddressSource': userEmailSource,
        'emailSyncSchedule': emailSyncSchedule,
        'hostName': Edm.String,
        'requireSsl': Edm.Boolean,
        'syncCalendar': Edm.Boolean,
        'syncContacts': Edm.Boolean,
        'syncTasks': Edm.Boolean,
    }
    rels = [

    ]


class windows10EndpointProtectionConfiguration(deviceConfiguration):
    props = {
        'applicationGuardAllowCameraMicrophoneRedirection': Edm.Boolean,
        'applicationGuardAllowFileSaveOnHost': Edm.Boolean,
        'applicationGuardAllowPersistence': Edm.Boolean,
        'applicationGuardAllowPrintToLocalPrinters': Edm.Boolean,
        'applicationGuardAllowPrintToNetworkPrinters': Edm.Boolean,
        'applicationGuardAllowPrintToPDF': Edm.Boolean,
        'applicationGuardAllowPrintToXPS': Edm.Boolean,
        'applicationGuardAllowVirtualGPU': Edm.Boolean,
        'applicationGuardBlockClipboardSharing': applicationGuardBlockClipboardSharingType,
        'applicationGuardBlockFileTransfer': applicationGuardBlockFileTransferType,
        'applicationGuardBlockNonEnterpriseContent': Edm.Boolean,
        'applicationGuardCertificateThumbprints': Collection,
        'applicationGuardEnabled': Edm.Boolean,
        'applicationGuardEnabledOptions': applicationGuardEnabledOptions,
        'applicationGuardForceAuditing': Edm.Boolean,
        'appLockerApplicationControl': appLockerApplicationControlType,
        'bitLockerAllowStandardUserEncryption': Edm.Boolean,
        'bitLockerDisableWarningForOtherDiskEncryption': Edm.Boolean,
        'bitLockerEnableStorageCardEncryptionOnMobile': Edm.Boolean,
        'bitLockerEncryptDevice': Edm.Boolean,
        'bitLockerFixedDrivePolicy': bitLockerFixedDrivePolicy,
        'bitLockerRecoveryPasswordRotation': bitLockerRecoveryPasswordRotationType,
        'bitLockerRemovableDrivePolicy': bitLockerRemovableDrivePolicy,
        'bitLockerSystemDrivePolicy': bitLockerSystemDrivePolicy,
        'defenderAdditionalGuardedFolders': Collection,
        'defenderAdobeReaderLaunchChildProcess': defenderProtectionType,
        'defenderAdvancedRansomewareProtectionType': defenderProtectionType,
        'defenderAllowBehaviorMonitoring': Edm.Boolean,
        'defenderAllowCloudProtection': Edm.Boolean,
        'defenderAllowEndUserAccess': Edm.Boolean,
        'defenderAllowIntrusionPreventionSystem': Edm.Boolean,
        'defenderAllowOnAccessProtection': Edm.Boolean,
        'defenderAllowRealTimeMonitoring': Edm.Boolean,
        'defenderAllowScanArchiveFiles': Edm.Boolean,
        'defenderAllowScanDownloads': Edm.Boolean,
        'defenderAllowScanNetworkFiles': Edm.Boolean,
        'defenderAllowScanRemovableDrivesDuringFullScan': Edm.Boolean,
        'defenderAllowScanScriptsLoadedInInternetExplorer': Edm.Boolean,
        'defenderAttackSurfaceReductionExcludedPaths': Collection,
        'defenderBlockEndUserAccess': Edm.Boolean,
        'defenderBlockPersistenceThroughWmiType': defenderAttackSurfaceType,
        'defenderCheckForSignaturesBeforeRunningScan': Edm.Boolean,
        'defenderCloudBlockLevel': defenderCloudBlockLevelType,
        'defenderCloudExtendedTimeoutInSeconds': Edm.Int32,
        'defenderDaysBeforeDeletingQuarantinedMalware': Edm.Int32,
        'defenderDetectedMalwareActions': defenderDetectedMalwareActions,
        'defenderDisableBehaviorMonitoring': Edm.Boolean,
        'defenderDisableCatchupFullScan': Edm.Boolean,
        'defenderDisableCatchupQuickScan': Edm.Boolean,
        'defenderDisableCloudProtection': Edm.Boolean,
        'defenderDisableIntrusionPreventionSystem': Edm.Boolean,
        'defenderDisableOnAccessProtection': Edm.Boolean,
        'defenderDisableRealTimeMonitoring': Edm.Boolean,
        'defenderDisableScanArchiveFiles': Edm.Boolean,
        'defenderDisableScanDownloads': Edm.Boolean,
        'defenderDisableScanNetworkFiles': Edm.Boolean,
        'defenderDisableScanRemovableDrivesDuringFullScan': Edm.Boolean,
        'defenderDisableScanScriptsLoadedInInternetExplorer': Edm.Boolean,
        'defenderEmailContentExecution': defenderProtectionType,
        'defenderEmailContentExecutionType': defenderAttackSurfaceType,
        'defenderEnableLowCpuPriority': Edm.Boolean,
        'defenderEnableScanIncomingMail': Edm.Boolean,
        'defenderEnableScanMappedNetworkDrivesDuringFullScan': Edm.Boolean,
        'defenderExploitProtectionXml': Edm.Binary,
        'defenderExploitProtectionXmlFileName': Edm.String,
        'defenderFileExtensionsToExclude': Collection,
        'defenderFilesAndFoldersToExclude': Collection,
        'defenderGuardedFoldersAllowedAppPaths': Collection,
        'defenderGuardMyFoldersType': folderProtectionType,
        'defenderNetworkProtectionType': defenderProtectionType,
        'defenderOfficeAppsExecutableContentCreationOrLaunch': defenderProtectionType,
        'defenderOfficeAppsExecutableContentCreationOrLaunchType': defenderAttackSurfaceType,
        'defenderOfficeAppsLaunchChildProcess': defenderProtectionType,
        'defenderOfficeAppsLaunchChildProcessType': defenderAttackSurfaceType,
        'defenderOfficeAppsOtherProcessInjection': defenderProtectionType,
        'defenderOfficeAppsOtherProcessInjectionType': defenderAttackSurfaceType,
        'defenderOfficeCommunicationAppsLaunchChildProcess': defenderProtectionType,
        'defenderOfficeMacroCodeAllowWin32Imports': defenderProtectionType,
        'defenderOfficeMacroCodeAllowWin32ImportsType': defenderAttackSurfaceType,
        'defenderPotentiallyUnwantedAppAction': defenderProtectionType,
        'defenderPreventCredentialStealingType': defenderProtectionType,
        'defenderProcessCreation': defenderProtectionType,
        'defenderProcessCreationType': defenderAttackSurfaceType,
        'defenderProcessesToExclude': Collection,
        'defenderScanDirection': defenderRealtimeScanDirection,
        'defenderScanMaxCpuPercentage': Edm.Int32,
        'defenderScanType': defenderScanType,
        'defenderScheduledQuickScanTime': Edm.TimeOfDay,
        'defenderScheduledScanDay': weeklySchedule,
        'defenderScheduledScanTime': Edm.TimeOfDay,
        'defenderScriptDownloadedPayloadExecution': defenderProtectionType,
        'defenderScriptDownloadedPayloadExecutionType': defenderAttackSurfaceType,
        'defenderScriptObfuscatedMacroCode': defenderProtectionType,
        'defenderScriptObfuscatedMacroCodeType': defenderAttackSurfaceType,
        'defenderSecurityCenterBlockExploitProtectionOverride': Edm.Boolean,
        'defenderSecurityCenterDisableAccountUI': Edm.Boolean,
        'defenderSecurityCenterDisableAppBrowserUI': Edm.Boolean,
        'defenderSecurityCenterDisableClearTpmUI': Edm.Boolean,
        'defenderSecurityCenterDisableFamilyUI': Edm.Boolean,
        'defenderSecurityCenterDisableHardwareUI': Edm.Boolean,
        'defenderSecurityCenterDisableHealthUI': Edm.Boolean,
        'defenderSecurityCenterDisableNetworkUI': Edm.Boolean,
        'defenderSecurityCenterDisableNotificationAreaUI': Edm.Boolean,
        'defenderSecurityCenterDisableRansomwareUI': Edm.Boolean,
        'defenderSecurityCenterDisableSecureBootUI': Edm.Boolean,
        'defenderSecurityCenterDisableTroubleshootingUI': Edm.Boolean,
        'defenderSecurityCenterDisableVirusUI': Edm.Boolean,
        'defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI': Edm.Boolean,
        'defenderSecurityCenterHelpEmail': Edm.String,
        'defenderSecurityCenterHelpPhone': Edm.String,
        'defenderSecurityCenterHelpURL': Edm.String,
        'defenderSecurityCenterITContactDisplay': defenderSecurityCenterITContactDisplayType,
        'defenderSecurityCenterNotificationsFromApp': defenderSecurityCenterNotificationsFromAppType,
        'defenderSecurityCenterOrganizationDisplayName': Edm.String,
        'defenderSignatureUpdateIntervalInHours': Edm.Int32,
        'defenderSubmitSamplesConsentType': defenderSubmitSamplesConsentType,
        'defenderUntrustedExecutable': defenderProtectionType,
        'defenderUntrustedExecutableType': defenderAttackSurfaceType,
        'defenderUntrustedUSBProcess': defenderProtectionType,
        'defenderUntrustedUSBProcessType': defenderAttackSurfaceType,
        'deviceGuardEnableSecureBootWithDMA': Edm.Boolean,
        'deviceGuardEnableVirtualizationBasedSecurity': Edm.Boolean,
        'deviceGuardLaunchSystemGuard': enablement,
        'deviceGuardLocalSystemAuthorityCredentialGuardSettings': deviceGuardLocalSystemAuthorityCredentialGuardType,
        'deviceGuardSecureBootWithDMA': secureBootWithDMAType,
        'dmaGuardDeviceEnumerationPolicy': dmaGuardDeviceEnumerationPolicyType,
        'firewallBlockStatefulFTP': Edm.Boolean,
        'firewallCertificateRevocationListCheckMethod': firewallCertificateRevocationListCheckMethodType,
        'firewallIdleTimeoutForSecurityAssociationInSeconds': Edm.Int32,
        'firewallIPSecExemptionsAllowDHCP': Edm.Boolean,
        'firewallIPSecExemptionsAllowICMP': Edm.Boolean,
        'firewallIPSecExemptionsAllowNeighborDiscovery': Edm.Boolean,
        'firewallIPSecExemptionsAllowRouterDiscovery': Edm.Boolean,
        'firewallIPSecExemptionsNone': Edm.Boolean,
        'firewallMergeKeyingModuleSettings': Edm.Boolean,
        'firewallPacketQueueingMethod': firewallPacketQueueingMethodType,
        'firewallPreSharedKeyEncodingMethod': firewallPreSharedKeyEncodingMethodType,
        'firewallProfileDomain': windowsFirewallNetworkProfile,
        'firewallProfilePrivate': windowsFirewallNetworkProfile,
        'firewallProfilePublic': windowsFirewallNetworkProfile,
        'firewallRules': Collection,
        'lanManagerAuthenticationLevel': lanManagerAuthenticationLevel,
        'lanManagerWorkstationDisableInsecureGuestLogons': Edm.Boolean,
        'localSecurityOptionsAdministratorAccountName': Edm.String,
        'localSecurityOptionsAdministratorElevationPromptBehavior': localSecurityOptionsAdministratorElevationPromptBehaviorType,
        'localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares': Edm.Boolean,
        'localSecurityOptionsAllowPKU2UAuthenticationRequests': Edm.Boolean,
        'localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager': Edm.String,
        'localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool': Edm.Boolean,
        'localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn': Edm.Boolean,
        'localSecurityOptionsAllowUIAccessApplicationElevation': Edm.Boolean,
        'localSecurityOptionsAllowUIAccessApplicationsForSecureLocations': Edm.Boolean,
        'localSecurityOptionsAllowUndockWithoutHavingToLogon': Edm.Boolean,
        'localSecurityOptionsBlockMicrosoftAccounts': Edm.Boolean,
        'localSecurityOptionsBlockRemoteLogonWithBlankPassword': Edm.Boolean,
        'localSecurityOptionsBlockRemoteOpticalDriveAccess': Edm.Boolean,
        'localSecurityOptionsBlockUsersInstallingPrinterDrivers': Edm.Boolean,
        'localSecurityOptionsClearVirtualMemoryPageFile': Edm.Boolean,
        'localSecurityOptionsClientDigitallySignCommunicationsAlways': Edm.Boolean,
        'localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers': Edm.Boolean,
        'localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation': Edm.Boolean,
        'localSecurityOptionsDisableAdministratorAccount': Edm.Boolean,
        'localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees': Edm.Boolean,
        'localSecurityOptionsDisableGuestAccount': Edm.Boolean,
        'localSecurityOptionsDisableServerDigitallySignCommunicationsAlways': Edm.Boolean,
        'localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees': Edm.Boolean,
        'localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts': Edm.Boolean,
        'localSecurityOptionsDoNotRequireCtrlAltDel': Edm.Boolean,
        'localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange': Edm.Boolean,
        'localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser': localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUserType,
        'localSecurityOptionsGuestAccountName': Edm.String,
        'localSecurityOptionsHideLastSignedInUser': Edm.Boolean,
        'localSecurityOptionsHideUsernameAtSignIn': Edm.Boolean,
        'localSecurityOptionsInformationDisplayedOnLockScreen': localSecurityOptionsInformationDisplayedOnLockScreenType,
        'localSecurityOptionsInformationShownOnLockScreen': localSecurityOptionsInformationShownOnLockScreenType,
        'localSecurityOptionsLogOnMessageText': Edm.String,
        'localSecurityOptionsLogOnMessageTitle': Edm.String,
        'localSecurityOptionsMachineInactivityLimit': Edm.Int32,
        'localSecurityOptionsMachineInactivityLimitInMinutes': Edm.Int32,
        'localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients': localSecurityOptionsMinimumSessionSecurity,
        'localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers': localSecurityOptionsMinimumSessionSecurity,
        'localSecurityOptionsOnlyElevateSignedExecutables': Edm.Boolean,
        'localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares': Edm.Boolean,
        'localSecurityOptionsSmartCardRemovalBehavior': localSecurityOptionsSmartCardRemovalBehaviorType,
        'localSecurityOptionsStandardUserElevationPromptBehavior': localSecurityOptionsStandardUserElevationPromptBehaviorType,
        'localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation': Edm.Boolean,
        'localSecurityOptionsUseAdminApprovalMode': Edm.Boolean,
        'localSecurityOptionsUseAdminApprovalModeForAdministrators': Edm.Boolean,
        'localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations': Edm.Boolean,
        'smartScreenBlockOverrideForFiles': Edm.Boolean,
        'smartScreenEnableInShell': Edm.Boolean,
        'userRightsAccessCredentialManagerAsTrustedCaller': deviceManagementUserRightsSetting,
        'userRightsActAsPartOfTheOperatingSystem': deviceManagementUserRightsSetting,
        'userRightsAllowAccessFromNetwork': deviceManagementUserRightsSetting,
        'userRightsBackupData': deviceManagementUserRightsSetting,
        'userRightsBlockAccessFromNetwork': deviceManagementUserRightsSetting,
        'userRightsChangeSystemTime': deviceManagementUserRightsSetting,
        'userRightsCreateGlobalObjects': deviceManagementUserRightsSetting,
        'userRightsCreatePageFile': deviceManagementUserRightsSetting,
        'userRightsCreatePermanentSharedObjects': deviceManagementUserRightsSetting,
        'userRightsCreateSymbolicLinks': deviceManagementUserRightsSetting,
        'userRightsCreateToken': deviceManagementUserRightsSetting,
        'userRightsDebugPrograms': deviceManagementUserRightsSetting,
        'userRightsDelegation': deviceManagementUserRightsSetting,
        'userRightsDenyLocalLogOn': deviceManagementUserRightsSetting,
        'userRightsGenerateSecurityAudits': deviceManagementUserRightsSetting,
        'userRightsImpersonateClient': deviceManagementUserRightsSetting,
        'userRightsIncreaseSchedulingPriority': deviceManagementUserRightsSetting,
        'userRightsLoadUnloadDrivers': deviceManagementUserRightsSetting,
        'userRightsLocalLogOn': deviceManagementUserRightsSetting,
        'userRightsLockMemory': deviceManagementUserRightsSetting,
        'userRightsManageAuditingAndSecurityLogs': deviceManagementUserRightsSetting,
        'userRightsManageVolumes': deviceManagementUserRightsSetting,
        'userRightsModifyFirmwareEnvironment': deviceManagementUserRightsSetting,
        'userRightsModifyObjectLabels': deviceManagementUserRightsSetting,
        'userRightsProfileSingleProcess': deviceManagementUserRightsSetting,
        'userRightsRemoteDesktopServicesLogOn': deviceManagementUserRightsSetting,
        'userRightsRemoteShutdown': deviceManagementUserRightsSetting,
        'userRightsRestoreData': deviceManagementUserRightsSetting,
        'userRightsTakeOwnership': deviceManagementUserRightsSetting,
        'windowsDefenderTamperProtection': windowsDefenderTamperProtectionOptions,
        'xboxServicesAccessoryManagementServiceStartupMode': serviceStartType,
        'xboxServicesEnableXboxGameSaveTask': Edm.Boolean,
        'xboxServicesLiveAuthManagerServiceStartupMode': serviceStartType,
        'xboxServicesLiveGameSaveServiceStartupMode': serviceStartType,
        'xboxServicesLiveNetworkingServiceStartupMode': serviceStartType,
    }
    rels = [

    ]


class windows10EnterpriseModernAppManagementConfiguration(deviceConfiguration):
    props = {
        'uninstallBuiltInApps': Edm.Boolean,
    }
    rels = [

    ]


class windows10GeneralConfiguration(deviceConfiguration):
    props = {
        'accountsBlockAddingNonMicrosoftAccountEmail': Edm.Boolean,
        'activateAppsWithVoice': enablement,
        'antiTheftModeBlocked': Edm.Boolean,
        'appManagementMSIAllowUserControlOverInstall': Edm.Boolean,
        'appManagementMSIAlwaysInstallWithElevatedPrivileges': Edm.Boolean,
        'appManagementPackageFamilyNamesToLaunchAfterLogOn': Collection,
        'appsAllowTrustedAppsSideloading': stateManagementSetting,
        'appsBlockWindowsStoreOriginatedApps': Edm.Boolean,
        'authenticationAllowSecondaryDevice': Edm.Boolean,
        'authenticationPreferredAzureADTenantDomainName': Edm.String,
        'authenticationWebSignIn': enablement,
        'bluetoothAllowedServices': Collection,
        'bluetoothBlockAdvertising': Edm.Boolean,
        'bluetoothBlockDiscoverableMode': Edm.Boolean,
        'bluetoothBlocked': Edm.Boolean,
        'bluetoothBlockPrePairing': Edm.Boolean,
        'bluetoothBlockPromptedProximalConnections': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'cellularBlockDataWhenRoaming': Edm.Boolean,
        'cellularBlockVpn': Edm.Boolean,
        'cellularBlockVpnWhenRoaming': Edm.Boolean,
        'cellularData': configurationUsage,
        'certificatesBlockManualRootCertificateInstallation': Edm.Boolean,
        'configureTimeZone': Edm.String,
        'connectedDevicesServiceBlocked': Edm.Boolean,
        'copyPasteBlocked': Edm.Boolean,
        'cortanaBlocked': Edm.Boolean,
        'cryptographyAllowFipsAlgorithmPolicy': Edm.Boolean,
        'dataProtectionBlockDirectMemoryAccess': Edm.Boolean,
        'defenderBlockEndUserAccess': Edm.Boolean,
        'defenderBlockOnAccessProtection': Edm.Boolean,
        'defenderCloudBlockLevel': defenderCloudBlockLevelType,
        'defenderCloudExtendedTimeout': Edm.Int32,
        'defenderCloudExtendedTimeoutInSeconds': Edm.Int32,
        'defenderDaysBeforeDeletingQuarantinedMalware': Edm.Int32,
        'defenderDetectedMalwareActions': defenderDetectedMalwareActions,
        'defenderDisableCatchupFullScan': Edm.Boolean,
        'defenderDisableCatchupQuickScan': Edm.Boolean,
        'defenderFileExtensionsToExclude': Collection,
        'defenderFilesAndFoldersToExclude': Collection,
        'defenderMonitorFileActivity': defenderMonitorFileActivity,
        'defenderPotentiallyUnwantedAppAction': defenderPotentiallyUnwantedAppAction,
        'defenderPotentiallyUnwantedAppActionSetting': defenderProtectionType,
        'defenderProcessesToExclude': Collection,
        'defenderPromptForSampleSubmission': defenderPromptForSampleSubmission,
        'defenderRequireBehaviorMonitoring': Edm.Boolean,
        'defenderRequireCloudProtection': Edm.Boolean,
        'defenderRequireNetworkInspectionSystem': Edm.Boolean,
        'defenderRequireRealTimeMonitoring': Edm.Boolean,
        'defenderScanArchiveFiles': Edm.Boolean,
        'defenderScanDownloads': Edm.Boolean,
        'defenderScanIncomingMail': Edm.Boolean,
        'defenderScanMappedNetworkDrivesDuringFullScan': Edm.Boolean,
        'defenderScanMaxCpu': Edm.Int32,
        'defenderScanNetworkFiles': Edm.Boolean,
        'defenderScanRemovableDrivesDuringFullScan': Edm.Boolean,
        'defenderScanScriptsLoadedInInternetExplorer': Edm.Boolean,
        'defenderScanType': defenderScanType,
        'defenderScheduledQuickScanTime': Edm.TimeOfDay,
        'defenderScheduledScanTime': Edm.TimeOfDay,
        'defenderScheduleScanEnableLowCpuPriority': Edm.Boolean,
        'defenderSignatureUpdateIntervalInHours': Edm.Int32,
        'defenderSubmitSamplesConsentType': defenderSubmitSamplesConsentType,
        'defenderSystemScanSchedule': weeklySchedule,
        'developerUnlockSetting': stateManagementSetting,
        'deviceManagementBlockFactoryResetOnMobile': Edm.Boolean,
        'deviceManagementBlockManualUnenroll': Edm.Boolean,
        'diagnosticsDataSubmissionMode': diagnosticDataSubmissionMode,
        'displayAppListWithGdiDPIScalingTurnedOff': Collection,
        'displayAppListWithGdiDPIScalingTurnedOn': Collection,
        'edgeAllowStartPagesModification': Edm.Boolean,
        'edgeBlockAccessToAboutFlags': Edm.Boolean,
        'edgeBlockAddressBarDropdown': Edm.Boolean,
        'edgeBlockAutofill': Edm.Boolean,
        'edgeBlockCompatibilityList': Edm.Boolean,
        'edgeBlockDeveloperTools': Edm.Boolean,
        'edgeBlocked': Edm.Boolean,
        'edgeBlockEditFavorites': Edm.Boolean,
        'edgeBlockExtensions': Edm.Boolean,
        'edgeBlockFullScreenMode': Edm.Boolean,
        'edgeBlockInPrivateBrowsing': Edm.Boolean,
        'edgeBlockJavaScript': Edm.Boolean,
        'edgeBlockLiveTileDataCollection': Edm.Boolean,
        'edgeBlockPasswordManager': Edm.Boolean,
        'edgeBlockPopups': Edm.Boolean,
        'edgeBlockPrelaunch': Edm.Boolean,
        'edgeBlockPrinting': Edm.Boolean,
        'edgeBlockSavingHistory': Edm.Boolean,
        'edgeBlockSearchEngineCustomization': Edm.Boolean,
        'edgeBlockSearchSuggestions': Edm.Boolean,
        'edgeBlockSendingDoNotTrackHeader': Edm.Boolean,
        'edgeBlockSendingIntranetTrafficToInternetExplorer': Edm.Boolean,
        'edgeBlockSideloadingExtensions': Edm.Boolean,
        'edgeBlockTabPreloading': Edm.Boolean,
        'edgeBlockWebContentOnNewTabPage': Edm.Boolean,
        'edgeClearBrowsingDataOnExit': Edm.Boolean,
        'edgeCookiePolicy': edgeCookiePolicy,
        'edgeDisableFirstRunPage': Edm.Boolean,
        'edgeEnterpriseModeSiteListLocation': Edm.String,
        'edgeFavoritesBarVisibility': visibilitySetting,
        'edgeFavoritesListLocation': Edm.String,
        'edgeFirstRunUrl': Edm.String,
        'edgeHomeButtonConfiguration': edgeHomeButtonConfiguration,
        'edgeHomeButtonConfigurationEnabled': Edm.Boolean,
        'edgeHomepageUrls': Collection,
        'edgeKioskModeRestriction': edgeKioskModeRestrictionType,
        'edgeKioskResetAfterIdleTimeInMinutes': Edm.Int32,
        'edgeNewTabPageURL': Edm.String,
        'edgeOpensWith': edgeOpenOptions,
        'edgePreventCertificateErrorOverride': Edm.Boolean,
        'edgeRequiredExtensionPackageFamilyNames': Collection,
        'edgeRequireSmartScreen': Edm.Boolean,
        'edgeSearchEngine': edgeSearchEngineBase,
        'edgeSendIntranetTrafficToInternetExplorer': Edm.Boolean,
        'edgeShowMessageWhenOpeningInternetExplorerSites': internetExplorerMessageSetting,
        'edgeSyncFavoritesWithInternetExplorer': Edm.Boolean,
        'edgeTelemetryForMicrosoft365Analytics': edgeTelemetryMode,
        'enableAutomaticRedeployment': Edm.Boolean,
        'energySaverOnBatteryThresholdPercentage': Edm.Int32,
        'energySaverPluggedInThresholdPercentage': Edm.Int32,
        'enterpriseCloudPrintDiscoveryEndPoint': Edm.String,
        'enterpriseCloudPrintDiscoveryMaxLimit': Edm.Int32,
        'enterpriseCloudPrintMopriaDiscoveryResourceIdentifier': Edm.String,
        'enterpriseCloudPrintOAuthAuthority': Edm.String,
        'enterpriseCloudPrintOAuthClientIdentifier': Edm.String,
        'enterpriseCloudPrintResourceIdentifier': Edm.String,
        'experienceBlockDeviceDiscovery': Edm.Boolean,
        'experienceBlockErrorDialogWhenNoSIM': Edm.Boolean,
        'experienceBlockTaskSwitcher': Edm.Boolean,
        'experienceDoNotSyncBrowserSettings': browserSyncSetting,
        'findMyFiles': enablement,
        'gameDvrBlocked': Edm.Boolean,
        'inkWorkspaceAccess': inkAccessSetting,
        'inkWorkspaceAccessState': stateManagementSetting,
        'inkWorkspaceBlockSuggestedApps': Edm.Boolean,
        'internetSharingBlocked': Edm.Boolean,
        'locationServicesBlocked': Edm.Boolean,
        'lockScreenActivateAppsWithVoice': enablement,
        'lockScreenAllowTimeoutConfiguration': Edm.Boolean,
        'lockScreenBlockActionCenterNotifications': Edm.Boolean,
        'lockScreenBlockCortana': Edm.Boolean,
        'lockScreenBlockToastNotifications': Edm.Boolean,
        'lockScreenTimeoutInSeconds': Edm.Int32,
        'logonBlockFastUserSwitching': Edm.Boolean,
        'messagingBlockMMS': Edm.Boolean,
        'messagingBlockRichCommunicationServices': Edm.Boolean,
        'messagingBlockSync': Edm.Boolean,
        'microsoftAccountBlocked': Edm.Boolean,
        'microsoftAccountBlockSettingsSync': Edm.Boolean,
        'microsoftAccountSignInAssistantSettings': signInAssistantOptions,
        'networkProxyApplySettingsDeviceWide': Edm.Boolean,
        'networkProxyAutomaticConfigurationUrl': Edm.String,
        'networkProxyDisableAutoDetect': Edm.Boolean,
        'networkProxyServer': windows10NetworkProxyServer,
        'nfcBlocked': Edm.Boolean,
        'oneDriveDisableFileSync': Edm.Boolean,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumAgeInDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'passwordRequireWhenResumeFromIdleState': Edm.Boolean,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'personalizationDesktopImageUrl': Edm.String,
        'personalizationLockScreenImageUrl': Edm.String,
        'powerButtonActionOnBattery': powerActionType,
        'powerButtonActionPluggedIn': powerActionType,
        'powerHybridSleepOnBattery': enablement,
        'powerHybridSleepPluggedIn': enablement,
        'powerLidCloseActionOnBattery': powerActionType,
        'powerLidCloseActionPluggedIn': powerActionType,
        'powerSleepButtonActionOnBattery': powerActionType,
        'powerSleepButtonActionPluggedIn': powerActionType,
        'printerBlockAddition': Edm.Boolean,
        'printerDefaultName': Edm.String,
        'printerNames': Collection,
        'privacyAdvertisingId': stateManagementSetting,
        'privacyAutoAcceptPairingAndConsentPrompts': Edm.Boolean,
        'privacyBlockActivityFeed': Edm.Boolean,
        'privacyBlockInputPersonalization': Edm.Boolean,
        'privacyBlockPublishUserActivities': Edm.Boolean,
        'privacyDisableLaunchExperience': Edm.Boolean,
        'resetProtectionModeBlocked': Edm.Boolean,
        'safeSearchFilter': safeSearchFilterType,
        'screenCaptureBlocked': Edm.Boolean,
        'searchBlockDiacritics': Edm.Boolean,
        'searchBlockWebResults': Edm.Boolean,
        'searchDisableAutoLanguageDetection': Edm.Boolean,
        'searchDisableIndexerBackoff': Edm.Boolean,
        'searchDisableIndexingEncryptedItems': Edm.Boolean,
        'searchDisableIndexingRemovableDrive': Edm.Boolean,
        'searchDisableLocation': Edm.Boolean,
        'searchDisableUseLocation': Edm.Boolean,
        'searchEnableAutomaticIndexSizeManangement': Edm.Boolean,
        'searchEnableRemoteQueries': Edm.Boolean,
        'securityBlockAzureADJoinedDevicesAutoEncryption': Edm.Boolean,
        'settingsBlockAccountsPage': Edm.Boolean,
        'settingsBlockAddProvisioningPackage': Edm.Boolean,
        'settingsBlockAppsPage': Edm.Boolean,
        'settingsBlockChangeLanguage': Edm.Boolean,
        'settingsBlockChangePowerSleep': Edm.Boolean,
        'settingsBlockChangeRegion': Edm.Boolean,
        'settingsBlockChangeSystemTime': Edm.Boolean,
        'settingsBlockDevicesPage': Edm.Boolean,
        'settingsBlockEaseOfAccessPage': Edm.Boolean,
        'settingsBlockEditDeviceName': Edm.Boolean,
        'settingsBlockGamingPage': Edm.Boolean,
        'settingsBlockNetworkInternetPage': Edm.Boolean,
        'settingsBlockPersonalizationPage': Edm.Boolean,
        'settingsBlockPrivacyPage': Edm.Boolean,
        'settingsBlockRemoveProvisioningPackage': Edm.Boolean,
        'settingsBlockSettingsApp': Edm.Boolean,
        'settingsBlockSystemPage': Edm.Boolean,
        'settingsBlockTimeLanguagePage': Edm.Boolean,
        'settingsBlockUpdateSecurityPage': Edm.Boolean,
        'sharedUserAppDataAllowed': Edm.Boolean,
        'smartScreenAppInstallControl': appInstallControlType,
        'smartScreenBlockPromptOverride': Edm.Boolean,
        'smartScreenBlockPromptOverrideForFiles': Edm.Boolean,
        'smartScreenEnableAppInstallControl': Edm.Boolean,
        'startBlockUnpinningAppsFromTaskbar': Edm.Boolean,
        'startMenuAppListVisibility': windowsStartMenuAppListVisibilityType,
        'startMenuHideChangeAccountSettings': Edm.Boolean,
        'startMenuHideFrequentlyUsedApps': Edm.Boolean,
        'startMenuHideHibernate': Edm.Boolean,
        'startMenuHideLock': Edm.Boolean,
        'startMenuHidePowerButton': Edm.Boolean,
        'startMenuHideRecentJumpLists': Edm.Boolean,
        'startMenuHideRecentlyAddedApps': Edm.Boolean,
        'startMenuHideRestartOptions': Edm.Boolean,
        'startMenuHideShutDown': Edm.Boolean,
        'startMenuHideSignOut': Edm.Boolean,
        'startMenuHideSleep': Edm.Boolean,
        'startMenuHideSwitchAccount': Edm.Boolean,
        'startMenuHideUserTile': Edm.Boolean,
        'startMenuLayoutEdgeAssetsXml': Edm.Binary,
        'startMenuLayoutXml': Edm.Binary,
        'startMenuMode': windowsStartMenuModeType,
        'startMenuPinnedFolderDocuments': visibilitySetting,
        'startMenuPinnedFolderDownloads': visibilitySetting,
        'startMenuPinnedFolderFileExplorer': visibilitySetting,
        'startMenuPinnedFolderHomeGroup': visibilitySetting,
        'startMenuPinnedFolderMusic': visibilitySetting,
        'startMenuPinnedFolderNetwork': visibilitySetting,
        'startMenuPinnedFolderPersonalFolder': visibilitySetting,
        'startMenuPinnedFolderPictures': visibilitySetting,
        'startMenuPinnedFolderSettings': visibilitySetting,
        'startMenuPinnedFolderVideos': visibilitySetting,
        'storageBlockRemovableStorage': Edm.Boolean,
        'storageRequireMobileDeviceEncryption': Edm.Boolean,
        'storageRestrictAppDataToSystemVolume': Edm.Boolean,
        'storageRestrictAppInstallToSystemVolume': Edm.Boolean,
        'systemTelemetryProxyServer': Edm.String,
        'taskManagerBlockEndTask': Edm.Boolean,
        'tenantLockdownRequireNetworkDuringOutOfBoxExperience': Edm.Boolean,
        'uninstallBuiltInApps': Edm.Boolean,
        'usbBlocked': Edm.Boolean,
        'voiceRecordingBlocked': Edm.Boolean,
        'webRtcBlockLocalhostIpAddress': Edm.Boolean,
        'wiFiBlockAutomaticConnectHotspots': Edm.Boolean,
        'wiFiBlocked': Edm.Boolean,
        'wiFiBlockManualConfiguration': Edm.Boolean,
        'wiFiScanInterval': Edm.Int32,
        'windows10AppsForceUpdateSchedule': windows10AppsForceUpdateSchedule,
        'windowsSpotlightBlockConsumerSpecificFeatures': Edm.Boolean,
        'windowsSpotlightBlocked': Edm.Boolean,
        'windowsSpotlightBlockOnActionCenter': Edm.Boolean,
        'windowsSpotlightBlockTailoredExperiences': Edm.Boolean,
        'windowsSpotlightBlockThirdPartyNotifications': Edm.Boolean,
        'windowsSpotlightBlockWelcomeExperience': Edm.Boolean,
        'windowsSpotlightBlockWindowsTips': Edm.Boolean,
        'windowsSpotlightConfigureOnLockScreen': windowsSpotlightEnablementSettings,
        'windowsStoreBlockAutoUpdate': Edm.Boolean,
        'windowsStoreBlocked': Edm.Boolean,
        'windowsStoreEnablePrivateStoreOnly': Edm.Boolean,
        'wirelessDisplayBlockProjectionToThisDevice': Edm.Boolean,
        'wirelessDisplayBlockUserInputFromReceiver': Edm.Boolean,
        'wirelessDisplayRequirePinForPairing': Edm.Boolean,
    }
    rels = [
        'privacyAccessControls',
    ]


class windows10ImportedPFXCertificateProfile(windowsCertificateProfileBase):
    props = {
        'intendedPurpose': intendedPurpose,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class windows10MobileCompliancePolicy(deviceCompliancePolicy):
    props = {
        'activeFirewallRequired': Edm.Boolean,
        'bitLockerEnabled': Edm.Boolean,
        'codeIntegrityEnabled': Edm.Boolean,
        'earlyLaunchAntiMalwareDriverEnabled': Edm.Boolean,
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'passwordRequireToUnlockFromIdle': Edm.Boolean,
        'secureBootEnabled': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
        'validOperatingSystemBuildRanges': Collection,
    }
    rels = [

    ]


class windows10NetworkBoundaryConfiguration(deviceConfiguration):
    props = {
        'windowsNetworkIsolationPolicy': windowsNetworkIsolationPolicy,
    }
    rels = [

    ]


class windows10PFXImportCertificateProfile(deviceConfiguration):
    props = {
        'keyStorageProvider': keyStorageProviderOption,
    }
    rels = [

    ]


class windows10PkcsCertificateProfile(windows10CertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'certificateTemplateName': Edm.String,
        'certificationAuthority': Edm.String,
        'certificationAuthorityName': Edm.String,
        'customSubjectAlternativeNames': Collection,
        'extendedKeyUsages': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class windows10SecureAssessmentConfiguration(deviceConfiguration):
    props = {
        'allowPrinting': Edm.Boolean,
        'allowScreenCapture': Edm.Boolean,
        'allowTextSuggestion': Edm.Boolean,
        'assessmentAppUserModelId': Edm.String,
        'configurationAccount': Edm.String,
        'configurationAccountType': secureAssessmentAccountType,
        'launchUri': Edm.String,
        'localGuestAccountName': Edm.String,
    }
    rels = [

    ]


class windows10TeamGeneralConfiguration(deviceConfiguration):
    props = {
        'azureOperationalInsightsBlockTelemetry': Edm.Boolean,
        'azureOperationalInsightsWorkspaceId': Edm.String,
        'azureOperationalInsightsWorkspaceKey': Edm.String,
        'connectAppBlockAutoLaunch': Edm.Boolean,
        'maintenanceWindowBlocked': Edm.Boolean,
        'maintenanceWindowDurationInHours': Edm.Int32,
        'maintenanceWindowStartTime': Edm.TimeOfDay,
        'miracastBlocked': Edm.Boolean,
        'miracastChannel': miracastChannel,
        'miracastRequirePin': Edm.Boolean,
        'settingsBlockMyMeetingsAndFiles': Edm.Boolean,
        'settingsBlockSessionResume': Edm.Boolean,
        'settingsBlockSigninSuggestions': Edm.Boolean,
        'settingsDefaultVolume': Edm.Int32,
        'settingsScreenTimeoutInMinutes': Edm.Int32,
        'settingsSessionTimeoutInMinutes': Edm.Int32,
        'settingsSleepTimeoutInMinutes': Edm.Int32,
        'welcomeScreenBackgroundImageUrl': Edm.String,
        'welcomeScreenBlockAutomaticWakeUp': Edm.Boolean,
        'welcomeScreenMeetingInformation': welcomeScreenMeetingInformation,
    }
    rels = [

    ]


class windowsVpnConfiguration(deviceConfiguration):
    props = {
        'connectionName': Edm.String,
        'customXml': Edm.Binary,
        'servers': Collection,
    }
    rels = [

    ]


class windows10VpnConfiguration(windowsVpnConfiguration):
    props = {
        'associatedApps': Collection,
        'authenticationMethod': windows10VpnAuthenticationMethod,
        'connectionType': windows10VpnConnectionType,
        'cryptographySuite': cryptographySuite,
        'dnsRules': Collection,
        'dnsSuffixes': Collection,
        'eapXml': Edm.Binary,
        'enableAlwaysOn': Edm.Boolean,
        'enableConditionalAccess': Edm.Boolean,
        'enableDeviceTunnel': Edm.Boolean,
        'enableDnsRegistration': Edm.Boolean,
        'enableSingleSignOnWithAlternateCertificate': Edm.Boolean,
        'enableSplitTunneling': Edm.Boolean,
        'microsoftTunnelSiteId': Edm.String,
        'onlyAssociatedAppsCanUseConnection': Edm.Boolean,
        'profileTarget': windows10VpnProfileTarget,
        'proxyServer': windows10VpnProxyServer,
        'rememberUserCredentials': Edm.Boolean,
        'routes': Collection,
        'singleSignOnEku': extendedKeyUsage,
        'singleSignOnIssuerHash': Edm.String,
        'trafficRules': Collection,
        'trustedNetworkDomains': Collection,
        'windowsInformationProtectionDomain': Edm.String,
    }
    rels = [
        'identityCertificate',
    ]


class windows81CertificateProfileBase(windowsCertificateProfileBase):
    props = {
        'customSubjectAlternativeNames': Collection,
        'extendedKeyUsages': Collection,
    }
    rels = [

    ]


class windows81CompliancePolicy(deviceCompliancePolicy):
    props = {
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'storageRequireEncryption': Edm.Boolean,
    }
    rels = [

    ]


class windows81GeneralConfiguration(deviceConfiguration):
    props = {
        'accountsBlockAddingNonMicrosoftAccountEmail': Edm.Boolean,
        'applyOnlyToWindows81': Edm.Boolean,
        'browserBlockAutofill': Edm.Boolean,
        'browserBlockAutomaticDetectionOfIntranetSites': Edm.Boolean,
        'browserBlockEnterpriseModeAccess': Edm.Boolean,
        'browserBlockJavaScript': Edm.Boolean,
        'browserBlockPlugins': Edm.Boolean,
        'browserBlockPopups': Edm.Boolean,
        'browserBlockSendingDoNotTrackHeader': Edm.Boolean,
        'browserBlockSingleWordEntryOnIntranetSites': Edm.Boolean,
        'browserEnterpriseModeSiteListLocation': Edm.String,
        'browserInternetSecurityLevel': internetSiteSecurityLevel,
        'browserIntranetSecurityLevel': siteSecurityLevel,
        'browserLoggingReportLocation': Edm.String,
        'browserRequireFirewall': Edm.Boolean,
        'browserRequireFraudWarning': Edm.Boolean,
        'browserRequireHighSecurityForRestrictedSites': Edm.Boolean,
        'browserRequireSmartScreen': Edm.Boolean,
        'browserTrustedSitesSecurityLevel': siteSecurityLevel,
        'cellularBlockDataRoaming': Edm.Boolean,
        'diagnosticsBlockDataSubmission': Edm.Boolean,
        'minimumAutoInstallClassification': updateClassification,
        'passwordBlockPicturePasswordAndPin': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequiredType': requiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'storageRequireDeviceEncryption': Edm.Boolean,
        'updatesMinimumAutoInstallClassification': updateClassification,
        'updatesRequireAutomaticUpdates': Edm.Boolean,
        'userAccountControlSettings': windowsUserAccountControlSettings,
        'workFoldersUrl': Edm.String,
    }
    rels = [

    ]


class windows81SCEPCertificateProfile(windows81CertificateProfileBase):
    props = {
        'certificateStore': certificateStore,
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
        'rootCertificate',
    ]


class windows81TrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'destinationStore': certificateDestinationStore,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class windows81VpnConfiguration(windowsVpnConfiguration):
    props = {
        'applyOnlyToWindows81': Edm.Boolean,
        'connectionType': windowsVpnConnectionType,
        'enableSplitTunneling': Edm.Boolean,
        'loginGroupOrDomain': Edm.String,
        'proxyServer': windows81VpnProxyServer,
    }
    rels = [

    ]


class windows81WifiImportConfiguration(deviceConfiguration):
    props = {
        'payload': Edm.Binary,
        'payloadFileName': Edm.String,
        'profileName': Edm.String,
    }
    rels = [

    ]


class windowsDefenderAdvancedThreatProtectionConfiguration(deviceConfiguration):
    props = {
        'advancedThreatProtectionAutoPopulateOnboardingBlob': Edm.Boolean,
        'advancedThreatProtectionOffboardingBlob': Edm.String,
        'advancedThreatProtectionOffboardingFilename': Edm.String,
        'advancedThreatProtectionOnboardingBlob': Edm.String,
        'advancedThreatProtectionOnboardingFilename': Edm.String,
        'allowSampleSharing': Edm.Boolean,
        'enableExpeditedTelemetryReporting': Edm.Boolean,
    }
    rels = [

    ]


class windowsDeliveryOptimizationConfiguration(deviceConfiguration):
    props = {
        'backgroundDownloadFromHttpDelayInSeconds': Edm.Int64,
        'bandwidthMode': deliveryOptimizationBandwidth,
        'cacheServerBackgroundDownloadFallbackToHttpDelayInSeconds': Edm.Int32,
        'cacheServerForegroundDownloadFallbackToHttpDelayInSeconds': Edm.Int32,
        'cacheServerHostNames': Collection,
        'deliveryOptimizationMode': windowsDeliveryOptimizationMode,
        'foregroundDownloadFromHttpDelayInSeconds': Edm.Int64,
        'groupIdSource': deliveryOptimizationGroupIdSource,
        'maximumCacheAgeInDays': Edm.Int32,
        'maximumCacheSize': deliveryOptimizationMaxCacheSize,
        'minimumBatteryPercentageAllowedToUpload': Edm.Int32,
        'minimumDiskSizeAllowedToPeerInGigabytes': Edm.Int32,
        'minimumFileSizeToCacheInMegabytes': Edm.Int32,
        'minimumRamAllowedToPeerInGigabytes': Edm.Int32,
        'modifyCacheLocation': Edm.String,
        'restrictPeerSelectionBy': deliveryOptimizationRestrictPeerSelectionByOptions,
        'vpnPeerCaching': enablement,
    }
    rels = [

    ]


class windowsDomainJoinConfiguration(deviceConfiguration):
    props = {
        'activeDirectoryDomainName': Edm.String,
        'computerNameStaticPrefix': Edm.String,
        'computerNameSuffixRandomCharCount': Edm.Int32,
        'organizationalUnit': Edm.String,
    }
    rels = [
        'networkAccessConfigurations',
    ]


class windowsHealthMonitoringConfiguration(deviceConfiguration):
    props = {
        'allowDeviceHealthMonitoring': enablement,
        'configDeviceHealthMonitoringCustomScope': Edm.String,
        'configDeviceHealthMonitoringScope': windowsHealthMonitoringScope,
    }
    rels = [

    ]


class windowsIdentityProtectionConfiguration(deviceConfiguration):
    props = {
        'enhancedAntiSpoofingForFacialFeaturesEnabled': Edm.Boolean,
        'pinExpirationInDays': Edm.Int32,
        'pinLowercaseCharactersUsage': configurationUsage,
        'pinMaximumLength': Edm.Int32,
        'pinMinimumLength': Edm.Int32,
        'pinPreviousBlockCount': Edm.Int32,
        'pinRecoveryEnabled': Edm.Boolean,
        'pinSpecialCharactersUsage': configurationUsage,
        'pinUppercaseCharactersUsage': configurationUsage,
        'securityDeviceRequired': Edm.Boolean,
        'unlockWithBiometricsEnabled': Edm.Boolean,
        'useCertificatesForOnPremisesAuthEnabled': Edm.Boolean,
        'useSecurityKeyForSignin': Edm.Boolean,
        'windowsHelloForBusinessBlocked': Edm.Boolean,
    }
    rels = [

    ]


class windowsKioskConfiguration(deviceConfiguration):
    props = {
        'edgeKioskEnablePublicBrowsing': Edm.Boolean,
        'kioskBrowserBlockedUrlExceptions': Collection,
        'kioskBrowserBlockedURLs': Collection,
        'kioskBrowserDefaultUrl': Edm.String,
        'kioskBrowserEnableEndSessionButton': Edm.Boolean,
        'kioskBrowserEnableHomeButton': Edm.Boolean,
        'kioskBrowserEnableNavigationButtons': Edm.Boolean,
        'kioskBrowserRestartOnIdleTimeInMinutes': Edm.Int32,
        'kioskProfiles': Collection,
        'windowsKioskForceUpdateSchedule': windowsKioskForceUpdateSchedule,
    }
    rels = [

    ]


class windowsPhone81CertificateProfileBase(deviceConfiguration):
    props = {
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'keyStorageProvider': keyStorageProviderOption,
        'renewalThresholdPercentage': Edm.Int32,
        'subjectAlternativeNameType': subjectAlternativeNameType,
        'subjectNameFormat': subjectNameFormat,
    }
    rels = [

    ]


class windowsPhone81CompliancePolicy(deviceCompliancePolicy):
    props = {
        'osMaximumVersion': Edm.String,
        'osMinimumVersion': Edm.String,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeLock': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'storageRequireEncryption': Edm.Boolean,
    }
    rels = [

    ]


class windowsPhone81CustomConfiguration(deviceConfiguration):
    props = {
        'omaSettings': Collection,
    }
    rels = [

    ]


class windowsPhone81GeneralConfiguration(deviceConfiguration):
    props = {
        'applyOnlyToWindowsPhone81': Edm.Boolean,
        'appsBlockCopyPaste': Edm.Boolean,
        'bluetoothBlocked': Edm.Boolean,
        'cameraBlocked': Edm.Boolean,
        'cellularBlockWifiTethering': Edm.Boolean,
        'compliantAppListType': appListType,
        'compliantAppsList': Collection,
        'diagnosticDataBlockSubmission': Edm.Boolean,
        'emailBlockAddingAccounts': Edm.Boolean,
        'locationServicesBlocked': Edm.Boolean,
        'microsoftAccountBlocked': Edm.Boolean,
        'nfcBlocked': Edm.Boolean,
        'passwordBlockSimple': Edm.Boolean,
        'passwordExpirationDays': Edm.Int32,
        'passwordMinimumCharacterSetCount': Edm.Int32,
        'passwordMinimumLength': Edm.Int32,
        'passwordMinutesOfInactivityBeforeScreenTimeout': Edm.Int32,
        'passwordPreviousPasswordBlockCount': Edm.Int32,
        'passwordRequired': Edm.Boolean,
        'passwordRequiredType': requiredPasswordType,
        'passwordSignInFailureCountBeforeFactoryReset': Edm.Int32,
        'screenCaptureBlocked': Edm.Boolean,
        'storageBlockRemovableStorage': Edm.Boolean,
        'storageRequireEncryption': Edm.Boolean,
        'webBrowserBlocked': Edm.Boolean,
        'wifiBlockAutomaticConnectHotspots': Edm.Boolean,
        'wifiBlocked': Edm.Boolean,
        'wifiBlockHotspotReporting': Edm.Boolean,
        'windowsStoreBlocked': Edm.Boolean,
    }
    rels = [

    ]


class windowsPhone81ImportedPFXCertificateProfile(windowsCertificateProfileBase):
    props = {
        'intendedPurpose': intendedPurpose,
    }
    rels = [
        'managedDeviceCertificateStates',
    ]


class windowsPhone81SCEPCertificateProfile(windowsPhone81CertificateProfileBase):
    props = {
        'hashAlgorithm': hashAlgorithms,
        'keySize': keySize,
        'keyUsage': keyUsages,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormatString': Edm.String,
        'subjectNameFormatString': Edm.String,
    }
    rels = [
        'managedDeviceCertificateStates',
        'rootCertificate',
    ]


class windowsPhone81TrustedRootCertificate(deviceConfiguration):
    props = {
        'certFileName': Edm.String,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class windowsPhone81VpnConfiguration(windows81VpnConfiguration):
    props = {
        'authenticationMethod': vpnAuthenticationMethod,
        'bypassVpnOnCompanyWifi': Edm.Boolean,
        'bypassVpnOnHomeWifi': Edm.Boolean,
        'dnsSuffixSearchList': Collection,
        'rememberUserCredentials': Edm.Boolean,
    }
    rels = [
        'identityCertificate',
    ]


class windowsPhoneEASEmailProfileConfiguration(easEmailProfileConfigurationBase):
    props = {
        'accountName': Edm.String,
        'applyOnlyToWindowsPhone81': Edm.Boolean,
        'durationOfEmailToSync': emailSyncDuration,
        'emailAddressSource': userEmailSource,
        'emailSyncSchedule': emailSyncSchedule,
        'hostName': Edm.String,
        'requireSsl': Edm.Boolean,
        'syncCalendar': Edm.Boolean,
        'syncContacts': Edm.Boolean,
        'syncTasks': Edm.Boolean,
    }
    rels = [

    ]


class windowsUpdateForBusinessConfiguration(deviceConfiguration):
    props = {
        'allowWindows11Upgrade': Edm.Boolean,
        'automaticUpdateMode': automaticUpdateMode,
        'autoRestartNotificationDismissal': autoRestartNotificationDismissalMethod,
        'businessReadyUpdatesOnly': windowsUpdateType,
        'deadlineForFeatureUpdatesInDays': Edm.Int32,
        'deadlineForQualityUpdatesInDays': Edm.Int32,
        'deadlineGracePeriodInDays': Edm.Int32,
        'deliveryOptimizationMode': windowsDeliveryOptimizationMode,
        'driversExcluded': Edm.Boolean,
        'engagedRestartDeadlineInDays': Edm.Int32,
        'engagedRestartSnoozeScheduleInDays': Edm.Int32,
        'engagedRestartTransitionScheduleInDays': Edm.Int32,
        'featureUpdatesDeferralPeriodInDays': Edm.Int32,
        'featureUpdatesPaused': Edm.Boolean,
        'featureUpdatesPauseExpiryDateTime': Edm.DateTimeOffset,
        'featureUpdatesPauseStartDate': Edm.Date,
        'featureUpdatesRollbackStartDateTime': Edm.DateTimeOffset,
        'featureUpdatesRollbackWindowInDays': Edm.Int32,
        'featureUpdatesWillBeRolledBack': Edm.Boolean,
        'installationSchedule': windowsUpdateInstallScheduleType,
        'microsoftUpdateServiceAllowed': Edm.Boolean,
        'postponeRebootUntilAfterDeadline': Edm.Boolean,
        'prereleaseFeatures': prereleaseFeatures,
        'qualityUpdatesDeferralPeriodInDays': Edm.Int32,
        'qualityUpdatesPaused': Edm.Boolean,
        'qualityUpdatesPauseExpiryDateTime': Edm.DateTimeOffset,
        'qualityUpdatesPauseStartDate': Edm.Date,
        'qualityUpdatesRollbackStartDateTime': Edm.DateTimeOffset,
        'qualityUpdatesWillBeRolledBack': Edm.Boolean,
        'scheduleImminentRestartWarningInMinutes': Edm.Int32,
        'scheduleRestartWarningInHours': Edm.Int32,
        'skipChecksBeforeRestart': Edm.Boolean,
        'updateNotificationLevel': windowsUpdateNotificationDisplayOption,
        'updateWeeks': windowsUpdateForBusinessUpdateWeeks,
        'userPauseAccess': enablement,
        'userWindowsUpdateScanAccess': enablement,
    }
    rels = [

    ]


class windowsWifiConfiguration(deviceConfiguration):
    props = {
        'connectAutomatically': Edm.Boolean,
        'connectToPreferredNetwork': Edm.Boolean,
        'connectWhenNetworkNameIsHidden': Edm.Boolean,
        'forceFIPSCompliance': Edm.Boolean,
        'meteredConnectionLimit': meteredConnectionLimitType,
        'networkName': Edm.String,
        'preSharedKey': Edm.String,
        'proxyAutomaticConfigurationUrl': Edm.String,
        'proxyManualAddress': Edm.String,
        'proxyManualPort': Edm.Int32,
        'proxySetting': wiFiProxySetting,
        'ssid': Edm.String,
        'wifiSecurityType': wiFiSecurityType,
    }
    rels = [

    ]


class windowsWifiEnterpriseEAPConfiguration(windowsWifiConfiguration):
    props = {
        'authenticationMethod': wiFiAuthenticationMethod,
        'authenticationPeriodInSeconds': Edm.Int32,
        'authenticationRetryDelayPeriodInSeconds': Edm.Int32,
        'authenticationType': wifiAuthenticationType,
        'cacheCredentials': Edm.Boolean,
        'disableUserPromptForServerValidation': Edm.Boolean,
        'eapolStartPeriodInSeconds': Edm.Int32,
        'eapType': eapType,
        'enablePairwiseMasterKeyCaching': Edm.Boolean,
        'enablePreAuthentication': Edm.Boolean,
        'innerAuthenticationProtocolForEAPTTLS': nonEapAuthenticationMethodForEapTtlsType,
        'maximumAuthenticationFailures': Edm.Int32,
        'maximumAuthenticationTimeoutInSeconds': Edm.Int32,
        'maximumEAPOLStartMessages': Edm.Int32,
        'maximumNumberOfPairwiseMasterKeysInCache': Edm.Int32,
        'maximumPairwiseMasterKeyCacheTimeInMinutes': Edm.Int32,
        'maximumPreAuthenticationAttempts': Edm.Int32,
        'networkSingleSignOn': networkSingleSignOnType,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'performServerValidation': Edm.Boolean,
        'promptForAdditionalAuthenticationCredentials': Edm.Boolean,
        'requireCryptographicBinding': Edm.Boolean,
        'trustedServerCertificateNames': Collection,
        'userBasedVirtualLan': Edm.Boolean,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForClientValidation',
        'rootCertificatesForServerValidation',
    ]


class windowsWiredNetworkConfiguration(deviceConfiguration):
    props = {
        'authenticationBlockPeriodInMinutes': Edm.Int32,
        'authenticationMethod': wiredNetworkAuthenticationMethod,
        'authenticationPeriodInSeconds': Edm.Int32,
        'authenticationRetryDelayPeriodInSeconds': Edm.Int32,
        'authenticationType': wiredNetworkAuthenticationType,
        'cacheCredentials': Edm.Boolean,
        'disableUserPromptForServerValidation': Edm.Boolean,
        'eapolStartPeriodInSeconds': Edm.Int32,
        'eapType': eapType,
        'enforce8021X': Edm.Boolean,
        'forceFIPSCompliance': Edm.Boolean,
        'innerAuthenticationProtocolForEAPTTLS': nonEapAuthenticationMethodForEapTtlsType,
        'maximumAuthenticationFailures': Edm.Int32,
        'maximumEAPOLStartMessages': Edm.Int32,
        'outerIdentityPrivacyTemporaryValue': Edm.String,
        'performServerValidation': Edm.Boolean,
        'requireCryptographicBinding': Edm.Boolean,
        'secondaryAuthenticationMethod': wiredNetworkAuthenticationMethod,
        'trustedServerCertificateNames': Collection,
    }
    rels = [
        'identityCertificateForClientAuthentication',
        'rootCertificateForClientValidation',
        'rootCertificatesForServerValidation',
        'secondaryIdentityCertificateForClientAuthentication',
        'secondaryRootCertificateForClientValidation',
    ]


class deviceManagementConfigurationChoiceSettingDefinition(deviceManagementConfigurationSettingDefinition):
    props = {
        'defaultOptionId': Edm.String,
        'options': Collection,
    }
    rels = [

    ]


class deviceManagementConfigurationChoiceSettingCollectionDefinition(deviceManagementConfigurationChoiceSettingDefinition):
    props = {
        'maximumCount': Edm.Int32,
        'minimumCount': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementConfigurationRedirectSettingDefinition(deviceManagementConfigurationSettingDefinition):
    props = {
        'deepLink': Edm.String,
        'redirectMessage': Edm.String,
        'redirectReason': Edm.String,
    }
    rels = [

    ]


class deviceManagementConfigurationSettingGroupDefinition(deviceManagementConfigurationSettingDefinition):
    props = {
        'childIds': Collection,
        'dependedOnBy': Collection,
        'dependentOn': Collection,
    }
    rels = [

    ]


class deviceManagementConfigurationSettingGroupCollectionDefinition(deviceManagementConfigurationSettingGroupDefinition):
    props = {
        'maximumCount': Edm.Int32,
        'minimumCount': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementConfigurationSimpleSettingDefinition(deviceManagementConfigurationSettingDefinition):
    props = {
        'defaultValue': deviceManagementConfigurationSettingValue,
        'dependedOnBy': Collection,
        'dependentOn': Collection,
        'valueDefinition': deviceManagementConfigurationSettingValueDefinition,
    }
    rels = [

    ]


class deviceManagementConfigurationSimpleSettingCollectionDefinition(deviceManagementConfigurationSimpleSettingDefinition):
    props = {
        'maximumCount': Edm.Int32,
        'minimumCount': Edm.Int32,
    }
    rels = [

    ]


class deviceComanagementAuthorityConfiguration(deviceEnrollmentConfiguration):
    props = {
        'configurationManagerAgentCommandLineArgument': Edm.String,
        'installConfigurationManagerAgent': Edm.Boolean,
        'managedDeviceAuthority': Edm.Int32,
    }
    rels = [

    ]


class deviceEnrollmentLimitConfiguration(deviceEnrollmentConfiguration):
    props = {
        'limit': Edm.Int32,
    }
    rels = [

    ]


class deviceEnrollmentNotificationConfiguration(deviceEnrollmentConfiguration):
    props = {
        'brandingOptions': enrollmentNotificationBrandingOptions,
        'defaultLocale': Edm.String,
        'notificationMessageTemplateId': Edm.Guid,
        'notificationTemplates': Collection,
        'platformType': enrollmentRestrictionPlatformType,
        'templateType': enrollmentNotificationTemplateType,
    }
    rels = [

    ]


class deviceEnrollmentPlatformRestrictionConfiguration(deviceEnrollmentConfiguration):
    props = {
        'platformRestriction': deviceEnrollmentPlatformRestriction,
        'platformType': enrollmentRestrictionPlatformType,
    }
    rels = [

    ]


class deviceEnrollmentPlatformRestrictionsConfiguration(deviceEnrollmentConfiguration):
    props = {
        'androidForWorkRestriction': deviceEnrollmentPlatformRestriction,
        'androidRestriction': deviceEnrollmentPlatformRestriction,
        'iosRestriction': deviceEnrollmentPlatformRestriction,
        'macOSRestriction': deviceEnrollmentPlatformRestriction,
        'macRestriction': deviceEnrollmentPlatformRestriction,
        'tvosRestriction': deviceEnrollmentPlatformRestriction,
        'visionOSRestriction': deviceEnrollmentPlatformRestriction,
        'windowsHomeSkuRestriction': deviceEnrollmentPlatformRestriction,
        'windowsMobileRestriction': deviceEnrollmentPlatformRestriction,
        'windowsRestriction': deviceEnrollmentPlatformRestriction,
    }
    rels = [

    ]


class deviceEnrollmentWindowsHelloForBusinessConfiguration(deviceEnrollmentConfiguration):
    props = {
        'enhancedBiometricsState': enablement,
        'enhancedSignInSecurity': Edm.Int32,
        'pinExpirationInDays': Edm.Int32,
        'pinLowercaseCharactersUsage': windowsHelloForBusinessPinUsage,
        'pinMaximumLength': Edm.Int32,
        'pinMinimumLength': Edm.Int32,
        'pinPreviousBlockCount': Edm.Int32,
        'pinSpecialCharactersUsage': windowsHelloForBusinessPinUsage,
        'pinUppercaseCharactersUsage': windowsHelloForBusinessPinUsage,
        'remotePassportEnabled': Edm.Boolean,
        'securityDeviceRequired': Edm.Boolean,
        'securityKeyForSignIn': enablement,
        'state': enablement,
        'unlockWithBiometricsEnabled': Edm.Boolean,
    }
    rels = [

    ]


class windows10EnrollmentCompletionPageConfiguration(deviceEnrollmentConfiguration):
    props = {
        'allowDeviceResetOnInstallFailure': Edm.Boolean,
        'allowDeviceUseOnInstallFailure': Edm.Boolean,
        'allowLogCollectionOnInstallFailure': Edm.Boolean,
        'allowNonBlockingAppInstallation': Edm.Boolean,
        'blockDeviceSetupRetryByUser': Edm.Boolean,
        'customErrorMessage': Edm.String,
        'disableUserStatusTrackingAfterFirstUser': Edm.Boolean,
        'installProgressTimeoutInMinutes': Edm.Int32,
        'installQualityUpdates': Edm.Boolean,
        'selectedMobileAppIds': Collection,
        'showInstallationProgress': Edm.Boolean,
        'trackInstallProgressForAutopilotOnly': Edm.Boolean,
    }
    rels = [

    ]


class deviceManagementAbstractComplexSettingDefinition(deviceManagementSettingDefinition):
    props = {
        'implementations': Collection,
    }
    rels = [

    ]


class deviceManagementAbstractComplexSettingInstance(deviceManagementSettingInstance):
    props = {
        'implementationId': Edm.String,
    }
    rels = [
        'value',
    ]


class deviceManagementBooleanSettingInstance(deviceManagementSettingInstance):
    props = {
        'value': Edm.Boolean,
    }
    rels = [

    ]


class deviceManagementCollectionSettingDefinition(deviceManagementSettingDefinition):
    props = {
        'elementDefinitionId': Edm.String,
    }
    rels = [

    ]


class deviceManagementCollectionSettingInstance(deviceManagementSettingInstance):
    props = {

    }
    rels = [
        'value',
    ]


class deviceManagementComplexSettingDefinition(deviceManagementSettingDefinition):
    props = {
        'propertyDefinitionIds': Collection,
    }
    rels = [

    ]


class deviceManagementComplexSettingInstance(deviceManagementSettingInstance):
    props = {

    }
    rels = [
        'value',
    ]


class deviceManagementIntegerSettingInstance(deviceManagementSettingInstance):
    props = {
        'value': Edm.Int32,
    }
    rels = [

    ]


class deviceManagementIntentSettingCategory(deviceManagementSettingCategory):
    props = {

    }
    rels = [
        'settings',
    ]


class deviceManagementStringSettingInstance(deviceManagementSettingInstance):
    props = {
        'value': Edm.String,
    }
    rels = [

    ]


class deviceManagementTemplateSettingCategory(deviceManagementSettingCategory):
    props = {

    }
    rels = [
        'recommendedSettings',
    ]


class securityBaselineCategoryStateSummary(securityBaselineStateSummary):
    props = {
        'displayName': Edm.String,
    }
    rels = [

    ]


class securityBaselineTemplate(deviceManagementTemplate):
    props = {

    }
    rels = [
        'categoryDeviceStateSummaries',
        'deviceStates',
        'deviceStateSummary',
    ]


class windowsManagedDevice(managedDevice):
    props = {

    }
    rels = [

    ]


class windows10XCertificateProfile(deviceManagementResourceAccessProfileBase):
    props = {

    }
    rels = [

    ]


class windows10XSCEPCertificateProfile(windows10XCertificateProfile):
    props = {
        'certificateStore': certificateStore,
        'certificateValidityPeriodScale': certificateValidityPeriodScale,
        'certificateValidityPeriodValue': Edm.Int32,
        'extendedKeyUsages': Collection,
        'hashAlgorithm': Collection,
        'keySize': keySize,
        'keyStorageProvider': keyStorageProviderOption,
        'keyUsage': keyUsages,
        'renewalThresholdPercentage': Edm.Int32,
        'rootCertificateId': Edm.Guid,
        'scepServerUrls': Collection,
        'subjectAlternativeNameFormats': Collection,
        'subjectNameFormatString': Edm.String,
    }
    rels = [

    ]


class windows10XTrustedRootCertificate(deviceManagementResourceAccessProfileBase):
    props = {
        'certFileName': Edm.String,
        'destinationStore': certificateDestinationStore,
        'trustedRootCertificate': Edm.Binary,
    }
    rels = [

    ]


class windows10XVpnConfiguration(deviceManagementResourceAccessProfileBase):
    props = {
        'authenticationCertificateId': Edm.Guid,
        'customXml': Edm.Binary,
        'customXmlFileName': Edm.String,
    }
    rels = [

    ]


class windows10XWifiConfiguration(deviceManagementResourceAccessProfileBase):
    props = {
        'authenticationCertificateId': Edm.Guid,
        'customXml': Edm.Binary,
        'customXmlFileName': Edm.String,
    }
    rels = [

    ]


class activeDirectoryWindowsAutopilotDeploymentProfile(windowsAutopilotDeploymentProfile):
    props = {
        'hybridAzureADJoinSkipConnectivityCheck': Edm.Boolean,
    }
    rels = [
        'domainJoinConfiguration',
    ]


class azureADWindowsAutopilotDeploymentProfile(windowsAutopilotDeploymentProfile):
    props = {

    }
    rels = [

    ]


class depEnrollmentBaseProfile(enrollmentProfile):
    props = {
        'appleIdDisabled': Edm.Boolean,
        'applePayDisabled': Edm.Boolean,
        'configurationWebUrl': Edm.Boolean,
        'deviceNameTemplate': Edm.String,
        'diagnosticsDisabled': Edm.Boolean,
        'displayToneSetupDisabled': Edm.Boolean,
        'enabledSkipKeys': Collection,
        'enrollmentTimeAzureAdGroupIds': Collection,
        'isDefault': Edm.Boolean,
        'isMandatory': Edm.Boolean,
        'locationDisabled': Edm.Boolean,
        'privacyPaneDisabled': Edm.Boolean,
        'profileRemovalDisabled': Edm.Boolean,
        'restoreBlocked': Edm.Boolean,
        'screenTimeScreenDisabled': Edm.Boolean,
        'siriDisabled': Edm.Boolean,
        'supervisedModeEnabled': Edm.Boolean,
        'supportDepartment': Edm.String,
        'supportPhoneNumber': Edm.String,
        'termsAndConditionsDisabled': Edm.Boolean,
        'touchIdDisabled': Edm.Boolean,
        'waitForDeviceConfiguredConfirmation': Edm.Boolean,
    }
    rels = [

    ]


class depEnrollmentProfile(enrollmentProfile):
    props = {
        'appleIdDisabled': Edm.Boolean,
        'applePayDisabled': Edm.Boolean,
        'awaitDeviceConfiguredConfirmation': Edm.Boolean,
        'diagnosticsDisabled': Edm.Boolean,
        'enableSharedIPad': Edm.Boolean,
        'isDefault': Edm.Boolean,
        'isMandatory': Edm.Boolean,
        'iTunesPairingMode': iTunesPairingMode,
        'locationDisabled': Edm.Boolean,
        'macOSFileVaultDisabled': Edm.Boolean,
        'macOSRegistrationDisabled': Edm.Boolean,
        'managementCertificates': Collection,
        'passCodeDisabled': Edm.Boolean,
        'profileRemovalDisabled': Edm.Boolean,
        'restoreBlocked': Edm.Boolean,
        'restoreFromAndroidDisabled': Edm.Boolean,
        'sharedIPadMaximumUserCount': Edm.Int32,
        'siriDisabled': Edm.Boolean,
        'supervisedModeEnabled': Edm.Boolean,
        'supportDepartment': Edm.String,
        'supportPhoneNumber': Edm.String,
        'termsAndConditionsDisabled': Edm.Boolean,
        'touchIdDisabled': Edm.Boolean,
        'zoomDisabled': Edm.Boolean,
    }
    rels = [

    ]


class depIOSEnrollmentProfile(depEnrollmentBaseProfile):
    props = {
        'appearanceScreenDisabled': Edm.Boolean,
        'awaitDeviceConfiguredConfirmation': Edm.Boolean,
        'carrierActivationUrl': Edm.String,
        'companyPortalVppTokenId': Edm.String,
        'deviceToDeviceMigrationDisabled': Edm.Boolean,
        'enableSharedIPad': Edm.Boolean,
        'enableSingleAppEnrollmentMode': Edm.Boolean,
        'expressLanguageScreenDisabled': Edm.Boolean,
        'forceTemporarySession': Edm.Boolean,
        'homeButtonScreenDisabled': Edm.Boolean,
        'iMessageAndFaceTimeScreenDisabled': Edm.Boolean,
        'iTunesPairingMode': iTunesPairingMode,
        'managementCertificates': Collection,
        'onBoardingScreenDisabled': Edm.Boolean,
        'passCodeDisabled': Edm.Boolean,
        'passcodeLockGracePeriodInSeconds': Edm.Int32,
        'preferredLanguageScreenDisabled': Edm.Boolean,
        'restoreCompletedScreenDisabled': Edm.Boolean,
        'restoreFromAndroidDisabled': Edm.Boolean,
        'sharedIPadMaximumUserCount': Edm.Int32,
        'simSetupScreenDisabled': Edm.Boolean,
        'softwareUpdateScreenDisabled': Edm.Boolean,
        'temporarySessionTimeoutInSeconds': Edm.Int32,
        'updateCompleteScreenDisabled': Edm.Boolean,
        'userlessSharedAadModeEnabled': Edm.Boolean,
        'userSessionTimeoutInSeconds': Edm.Int32,
        'watchMigrationScreenDisabled': Edm.Boolean,
        'welcomeScreenDisabled': Edm.Boolean,
        'zoomDisabled': Edm.Boolean,
    }
    rels = [

    ]


class depMacOSEnrollmentProfile(depEnrollmentBaseProfile):
    props = {
        'accessibilityScreenDisabled': Edm.Boolean,
        'adminAccountFullName': Edm.String,
        'adminAccountPassword': Edm.String,
        'adminAccountUserName': Edm.String,
        'autoAdvanceSetupEnabled': Edm.Boolean,
        'autoUnlockWithWatchDisabled': Edm.Boolean,
        'chooseYourLockScreenDisabled': Edm.Boolean,
        'dontAutoPopulatePrimaryAccountInfo': Edm.Boolean,
        'enableRestrictEditing': Edm.Boolean,
        'fileVaultDisabled': Edm.Boolean,
        'hideAdminAccount': Edm.Boolean,
        'iCloudDiagnosticsDisabled': Edm.Boolean,
        'iCloudStorageDisabled': Edm.Boolean,
        'passCodeDisabled': Edm.Boolean,
        'primaryAccountFullName': Edm.String,
        'primaryAccountUserName': Edm.String,
        'registrationDisabled': Edm.Boolean,
        'requestRequiresNetworkTether': Edm.Boolean,
        'setPrimarySetupAccountAsRegularUser': Edm.Boolean,
        'skipPrimarySetupAccountCreation': Edm.Boolean,
        'zoomDisabled': Edm.Boolean,
    }
    rels = [

    ]


class depTvOSEnrollmentProfile(enrollmentProfile):
    props = {

    }
    rels = [

    ]


class depVisionOSEnrollmentProfile(enrollmentProfile):
    props = {

    }
    rels = [

    ]


class importedAppleDeviceIdentityResult(importedAppleDeviceIdentity):
    props = {
        'status': Edm.Boolean,
    }
    rels = [

    ]


class importedDeviceIdentityResult(importedDeviceIdentity):
    props = {
        'status': Edm.Boolean,
    }
    rels = [

    ]


class groupPolicyUploadedPresentation(groupPolicyPresentation):
    props = {

    }
    rels = [

    ]


class groupPolicyPresentationCheckBox(groupPolicyUploadedPresentation):
    props = {
        'defaultChecked': Edm.Boolean,
    }
    rels = [

    ]


class groupPolicyPresentationComboBox(groupPolicyUploadedPresentation):
    props = {
        'defaultValue': Edm.String,
        'maxLength': Edm.Int64,
        'required': Edm.Boolean,
        'suggestions': Collection,
    }
    rels = [

    ]


class groupPolicyPresentationDecimalTextBox(groupPolicyUploadedPresentation):
    props = {
        'defaultValue': Edm.Int64,
        'maxValue': Edm.Int64,
        'minValue': Edm.Int64,
        'required': Edm.Boolean,
        'spin': Edm.Boolean,
        'spinStep': Edm.Int64,
    }
    rels = [

    ]


class groupPolicyPresentationDropdownList(groupPolicyUploadedPresentation):
    props = {
        'defaultItem': groupPolicyPresentationDropdownListItem,
        'items': Collection,
        'required': Edm.Boolean,
    }
    rels = [

    ]


class groupPolicyPresentationListBox(groupPolicyUploadedPresentation):
    props = {
        'explicitValue': Edm.Boolean,
        'valuePrefix': Edm.String,
    }
    rels = [

    ]


class groupPolicyPresentationLongDecimalTextBox(groupPolicyUploadedPresentation):
    props = {
        'defaultValue': Edm.Int64,
        'maxValue': Edm.Int64,
        'minValue': Edm.Int64,
        'required': Edm.Boolean,
        'spin': Edm.Boolean,
        'spinStep': Edm.Int64,
    }
    rels = [

    ]


class groupPolicyPresentationMultiTextBox(groupPolicyUploadedPresentation):
    props = {
        'maxLength': Edm.Int64,
        'maxStrings': Edm.Int64,
        'required': Edm.Boolean,
    }
    rels = [

    ]


class groupPolicyPresentationText(groupPolicyUploadedPresentation):
    props = {

    }
    rels = [

    ]


class groupPolicyPresentationTextBox(groupPolicyUploadedPresentation):
    props = {
        'defaultValue': Edm.String,
        'maxLength': Edm.Int64,
        'required': Edm.Boolean,
    }
    rels = [

    ]


class groupPolicyPresentationValueBoolean(groupPolicyPresentationValue):
    props = {
        'value': Edm.Boolean,
    }
    rels = [

    ]


class groupPolicyPresentationValueDecimal(groupPolicyPresentationValue):
    props = {
        'value': Edm.Int64,
    }
    rels = [

    ]


class groupPolicyPresentationValueList(groupPolicyPresentationValue):
    props = {
        'values': Collection,
    }
    rels = [

    ]


class groupPolicyPresentationValueLongDecimal(groupPolicyPresentationValue):
    props = {
        'value': Edm.Int64,
    }
    rels = [

    ]


class groupPolicyPresentationValueMultiText(groupPolicyPresentationValue):
    props = {
        'values': Collection,
    }
    rels = [

    ]


class groupPolicyPresentationValueText(groupPolicyPresentationValue):
    props = {
        'value': Edm.String,
    }
    rels = [

    ]


class androidManagedAppRegistration(managedAppRegistration):
    props = {
        'patchVersion': Edm.String,
    }
    rels = [

    ]


class iosManagedAppRegistration(managedAppRegistration):
    props = {

    }
    rels = [

    ]


class managedAppStatusRaw(managedAppStatus):
    props = {
        'content': Json,
    }
    rels = [

    ]


class windowsManagedAppRegistration(managedAppRegistration):
    props = {

    }
    rels = [

    ]


class appVulnerabilityTask(deviceAppManagementTask):
    props = {
        'appName': Edm.String,
        'appPublisher': Edm.String,
        'appVersion': Edm.String,
        'insights': Edm.String,
        'managedDeviceCount': Edm.Int32,
        'mitigationType': appVulnerabilityTaskMitigationType,
        'mobileAppCount': Edm.Int32,
        'remediation': Edm.String,
    }
    rels = [
        'managedDevices',
        'mobileApps',
    ]


class securityConfigurationTask(deviceAppManagementTask):
    props = {
        'applicablePlatform': endpointSecurityConfigurationApplicablePlatform,
        'endpointSecurityPolicy': endpointSecurityConfigurationType,
        'endpointSecurityPolicyProfile': endpointSecurityConfigurationProfileType,
        'insights': Edm.String,
        'intendedSettings': Collection,
        'managedDeviceCount': Edm.Int32,
    }
    rels = [
        'managedDevices',
    ]


class unmanagedDeviceDiscoveryTask(deviceAppManagementTask):
    props = {
        'unmanagedDevices': Collection,
    }
    rels = [

    ]


class deviceAndAppManagementRoleDefinition(roleDefinition):
    props = {

    }
    rels = [

    ]


class appleVppTokenTroubleshootingEvent(deviceManagementTroubleshootingEvent):
    props = {
        'tokenId': Edm.String,
    }
    rels = [

    ]


class enrollmentTroubleshootingEvent(deviceManagementTroubleshootingEvent):
    props = {
        'deviceId': Edm.String,
        'enrollmentType': deviceEnrollmentType,
        'failureCategory': deviceEnrollmentFailureReason,
        'failureReason': Edm.String,
        'managedDeviceIdentifier': Edm.String,
        'operatingSystem': Edm.String,
        'osVersion': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class windowsFeatureUpdateCatalogItem(windowsUpdateCatalogItem):
    props = {
        'version': Edm.String,
    }
    rels = [

    ]


class windowsQualityUpdateCatalogItem(windowsUpdateCatalogItem):
    props = {
        'classification': windowsQualityUpdateCategory,
        'isExpeditable': Edm.Boolean,
        'kbArticleId': Edm.String,
        'productRevisions': Collection,
        'qualityUpdateCadence': windowsQualityUpdateCadence,
    }
    rels = [

    ]


class serviceHealthIssue(serviceAnnouncementBase):
    props = {
        'classification': serviceHealthClassificationType,
        'feature': Edm.String,
        'featureGroup': Edm.String,
        'impactDescription': Edm.String,
        'isResolved': Edm.Boolean,
        'origin': serviceHealthOrigin,
        'posts': Collection,
        'service': Edm.String,
        'status': serviceHealthStatus,
    }
    rels = [

    ]


class serviceUpdateMessage(serviceAnnouncementBase):
    props = {
        'actionRequiredByDateTime': Edm.DateTimeOffset,
        'attachmentsArchive': Edm.Stream,
        'body': itemBody,
        'category': serviceUpdateCategory,
        'hasAttachments': Edm.Boolean,
        'isMajorChange': Edm.Boolean,
        'services': Collection,
        'severity': serviceUpdateSeverity,
        'tags': Collection,
        'viewPoint': serviceUpdateMessageViewpoint,
    }
    rels = [
        'attachments',
    ]


class awsAuthorizationSystem(authorizationSystem):
    props = {
        'associatedIdentities': awsAssociatedIdentities,
    }
    rels = [
        'actions',
        'policies',
        'resources',
        'services',
    ]


class awsAuthorizationSystemTypeAction(authorizationSystemTypeAction):
    props = {

    }
    rels = [
        'service',
    ]


class awsAuthorizationSystemResource(authorizationSystemResource):
    props = {

    }
    rels = [
        'service',
    ]


class azureAuthorizationSystem(authorizationSystem):
    props = {
        'associatedIdentities': azureAssociatedIdentities,
    }
    rels = [
        'actions',
        'resources',
        'roleDefinitions',
        'services',
    ]


class azureAuthorizationSystemTypeAction(authorizationSystemTypeAction):
    props = {

    }
    rels = [
        'service',
    ]


class azureAuthorizationSystemResource(authorizationSystemResource):
    props = {

    }
    rels = [
        'service',
    ]


class gcpAuthorizationSystem(authorizationSystem):
    props = {
        'associatedIdentities': gcpAssociatedIdentities,
    }
    rels = [
        'actions',
        'resources',
        'roles',
        'services',
    ]


class gcpAuthorizationSystemTypeAction(authorizationSystemTypeAction):
    props = {

    }
    rels = [
        'service',
    ]


class gcpAuthorizationSystemResource(authorizationSystemResource):
    props = {

    }
    rels = [
        'service',
    ]


class awsIdentity(authorizationSystemIdentity):
    props = {

    }
    rels = [

    ]


class awsRole(awsIdentity):
    props = {
        'roleType': awsRoleType,
        'trustEntityType': awsRoleTrustEntityType,
    }
    rels = [

    ]


class awsUser(awsIdentity):
    props = {

    }
    rels = [
        'assumableRoles',
    ]


class azureIdentity(authorizationSystemIdentity):
    props = {

    }
    rels = [

    ]


class azureManagedIdentity(azureIdentity):
    props = {

    }
    rels = [

    ]


class azureServicePrincipal(azureIdentity):
    props = {

    }
    rels = [

    ]


class azureUser(azureIdentity):
    props = {

    }
    rels = [

    ]


class gcpIdentity(authorizationSystemIdentity):
    props = {

    }
    rels = [

    ]


class gcpServiceAccount(gcpIdentity):
    props = {

    }
    rels = [

    ]


class gcpUser(gcpIdentity):
    props = {

    }
    rels = [

    ]


class awsAccessKey(awsIdentity):
    props = {

    }
    rels = [
        'owner',
    ]


class awsEc2Instance(awsIdentity):
    props = {

    }
    rels = [
        'resource',
    ]


class awsGroup(awsIdentity):
    props = {

    }
    rels = [

    ]


class awsLambda(awsIdentity):
    props = {

    }
    rels = [
        'resource',
    ]


class azureGroup(azureIdentity):
    props = {

    }
    rels = [

    ]


class azureServerlessFunction(azureIdentity):
    props = {

    }
    rels = [
        'resource',
    ]


class gcpCloudFunction(gcpIdentity):
    props = {

    }
    rels = [
        'resource',
    ]


class gcpGroup(gcpIdentity):
    props = {

    }
    rels = [

    ]


class awsExternalSystemAccessFinding(finding):
    props = {
        'accessMethods': externalSystemAccessMethods,
        'systemWithAccess': authorizationSystemInfo,
        'trustedIdentityCount': Edm.Int32,
        'trustsAllIdentities': Edm.Boolean,
    }
    rels = [
        'affectedSystem',
    ]


class awsExternalSystemAccessRoleFinding(finding):
    props = {
        'accessibleSystemIds': Collection,
        'permissionsCreepIndex': permissionsCreepIndex,
    }
    rels = [
        'role',
    ]


class awsIdentityAccessManagementKeyAgeFinding(finding):
    props = {
        'actionSummary': actionSummary,
        'awsAccessKeyDetails': awsAccessKeyDetails,
        'permissionsCreepIndex': permissionsCreepIndex,
        'status': iamStatus,
    }
    rels = [
        'accessKey',
    ]


class awsIdentityAccessManagementKeyUsageFinding(finding):
    props = {
        'actionSummary': actionSummary,
        'awsAccessKeyDetails': awsAccessKeyDetails,
        'permissionsCreepIndex': permissionsCreepIndex,
        'status': iamStatus,
    }
    rels = [
        'accessKey',
    ]


class awsSecretInformationAccessFinding(finding):
    props = {
        'identityDetails': identityDetails,
        'permissionsCreepIndex': permissionsCreepIndex,
        'secretInformationWebServices': awsSecretInformationWebServices,
    }
    rels = [
        'identity',
    ]


class awsSecurityToolAdministrationFinding(finding):
    props = {
        'identityDetails': identityDetails,
        'permissionsCreepIndex': permissionsCreepIndex,
        'securityTools': awsSecurityToolWebServices,
    }
    rels = [
        'identity',
    ]


class encryptedAwsStorageBucketFinding(finding):
    props = {
        'accessibility': awsAccessType,
    }
    rels = [
        'storageBucket',
    ]


class encryptedAzureStorageAccountFinding(finding):
    props = {
        'encryptionManagedBy': azureEncryption,
    }
    rels = [
        'storageAccount',
    ]


class encryptedGcpStorageBucketFinding(finding):
    props = {
        'accessibility': gcpAccessType,
        'encryptionManagedBy': gcpEncryption,
    }
    rels = [
        'storageBucket',
    ]


class externallyAccessibleAwsStorageBucketFinding(finding):
    props = {
        'accessibility': awsAccessType,
        'accountsWithAccess': accountsWithAccess,
    }
    rels = [
        'storageBucket',
    ]


class externallyAccessibleAzureBlobContainerFinding(finding):
    props = {
        'accessibility': azureAccessType,
        'encryptionManagedBy': azureEncryption,
    }
    rels = [
        'storageAccount',
    ]


class externallyAccessibleGcpStorageBucketFinding(finding):
    props = {
        'accessibility': gcpAccessType,
        'encryptionManagedBy': gcpEncryption,
    }
    rels = [
        'storageBucket',
    ]


class identityFinding(finding):
    props = {
        'actionSummary': actionSummary,
        'identityDetails': identityDetails,
        'permissionsCreepIndex': permissionsCreepIndex,
    }
    rels = [
        'identity',
    ]


class inactiveAwsResourceFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class inactiveAwsRoleFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class inactiveAzureServicePrincipalFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class inactiveGcpServiceAccountFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class inactiveGroupFinding(finding):
    props = {
        'actionSummary': actionSummary,
        'permissionsCreepIndex': permissionsCreepIndex,
    }
    rels = [
        'group',
    ]


class inactiveServerlessFunctionFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class inactiveUserFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class openAwsSecurityGroupFinding(finding):
    props = {
        'inboundPorts': inboundPorts,
        'totalStorageBucketCount': Edm.Int32,
    }
    rels = [
        'assignedComputeInstancesDetails',
        'securityGroup',
    ]


class openNetworkAzureSecurityGroupFinding(finding):
    props = {
        'inboundPorts': inboundPorts,
    }
    rels = [
        'securityGroup',
        'virtualMachines',
    ]


class overprovisionedAwsResourceFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class overprovisionedAwsRoleFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class overprovisionedAzureServicePrincipalFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class overprovisionedGcpServiceAccountFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class overprovisionedServerlessFunctionFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class overprovisionedUserFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class privilegeEscalationFinding(finding):
    props = {
        'identityDetails': identityDetails,
        'permissionsCreepIndex': permissionsCreepIndex,
    }
    rels = [
        'identity',
        'privilegeEscalationDetails',
    ]


class privilegeEscalationAwsResourceFinding(privilegeEscalationFinding):
    props = {

    }
    rels = [

    ]


class privilegeEscalationAwsRoleFinding(privilegeEscalationFinding):
    props = {

    }
    rels = [

    ]


class privilegeEscalationGcpServiceAccountFinding(privilegeEscalationFinding):
    props = {

    }
    rels = [

    ]


class privilegeEscalationUserFinding(privilegeEscalationFinding):
    props = {

    }
    rels = [

    ]


class secretInformationAccessAwsResourceFinding(awsSecretInformationAccessFinding):
    props = {

    }
    rels = [

    ]


class secretInformationAccessAwsRoleFinding(awsSecretInformationAccessFinding):
    props = {

    }
    rels = [

    ]


class secretInformationAccessAwsServerlessFunctionFinding(awsSecretInformationAccessFinding):
    props = {

    }
    rels = [

    ]


class secretInformationAccessAwsUserFinding(awsSecretInformationAccessFinding):
    props = {

    }
    rels = [

    ]


class securityToolAwsResourceAdministratorFinding(awsSecurityToolAdministrationFinding):
    props = {

    }
    rels = [

    ]


class securityToolAwsRoleAdministratorFinding(awsSecurityToolAdministrationFinding):
    props = {

    }
    rels = [

    ]


class securityToolAwsServerlessFunctionAdministratorFinding(awsSecurityToolAdministrationFinding):
    props = {

    }
    rels = [

    ]


class securityToolAwsUserAdministratorFinding(awsSecurityToolAdministrationFinding):
    props = {

    }
    rels = [

    ]


class superAwsResourceFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class superAwsRoleFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class superAzureServicePrincipalFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class superGcpServiceAccountFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class superServerlessFunctionFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class superUserFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class unenforcedMfaAwsUserFinding(identityFinding):
    props = {

    }
    rels = [

    ]


class virtualMachineWithAwsStorageBucketAccessFinding(finding):
    props = {
        'accessibleCount': Edm.Int32,
        'bucketCount': Edm.Int32,
        'permissionsCreepIndex': permissionsCreepIndex,
    }
    rels = [
        'ec2Instance',
        'role',
    ]


class sharedWithChannelTeamInfo(teamInfo):
    props = {
        'isHostTeam': Edm.Boolean,
    }
    rels = [
        'allowedMembers',
    ]


class plannerBucket(plannerDelta):
    props = {
        'archivalInfo': plannerArchivalInfo,
        'creationSource': plannerBucketCreation,
        'isArchived': Edm.Boolean,
        'name': Edm.String,
        'orderHint': Edm.String,
        'planId': Edm.String,
    }
    rels = [
        'tasks',
    ]


class plannerPlan(plannerDelta):
    props = {
        'archivalInfo': plannerArchivalInfo,
        'container': plannerPlanContainer,
        'contexts': plannerPlanContextCollection,
        'createdBy': identitySet,
        'createdDateTime': Edm.DateTimeOffset,
        'creationSource': plannerPlanCreation,
        'isArchived': Edm.Boolean,
        'owner': Edm.String,
        'sharedWithContainers': Collection,
        'title': Edm.String,
    }
    rels = [
        'buckets',
        'details',
        'tasks',
    ]


class plannerAssignedToTaskBoardTaskFormat(plannerDelta):
    props = {
        'orderHintsByAssignee': plannerOrderHintsByAssignee,
        'unassignedOrderHint': Edm.String,
    }
    rels = [

    ]


class plannerBucketTaskBoardTaskFormat(plannerDelta):
    props = {
        'orderHint': Edm.String,
    }
    rels = [

    ]


class plannerPlanDetails(plannerDelta):
    props = {
        'categoryDescriptions': plannerCategoryDescriptions,
        'contextDetails': plannerPlanContextDetailsCollection,
        'sharedWith': plannerUserIds,
    }
    rels = [

    ]


class plannerProgressTaskBoardTaskFormat(plannerDelta):
    props = {
        'orderHint': Edm.String,
    }
    rels = [

    ]


class plannerTaskDetails(plannerDelta):
    props = {
        'approvalAttachment': plannerBaseApprovalAttachment,
        'checklist': plannerChecklistItems,
        'completionRequirements': plannerTaskCompletionRequirementDetails,
        'description': Edm.String,
        'forms': plannerFormsDictionary,
        'notes': itemBody,
        'previewType': plannerPreviewType,
        'references': plannerExternalReferences,
    }
    rels = [

    ]


class onenoteEntitySchemaObjectModel(onenoteEntityBaseModel):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class onenoteEntityHierarchyModel(onenoteEntitySchemaObjectModel):
    props = {
        'createdBy': identitySet,
        'displayName': Edm.String,
        'lastModifiedBy': identitySet,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class notebook(onenoteEntityHierarchyModel):
    props = {
        'isDefault': Edm.Boolean,
        'isShared': Edm.Boolean,
        'links': notebookLinks,
        'sectionGroupsUrl': Edm.String,
        'sectionsUrl': Edm.String,
        'userRole': onenoteUserRole,
    }
    rels = [
        'sectionGroups',
        'sections',
    ]


class sectionGroup(onenoteEntityHierarchyModel):
    props = {
        'sectionGroupsUrl': Edm.String,
        'sectionsUrl': Edm.String,
    }
    rels = [
        'parentNotebook',
        'parentSectionGroup',
        'sectionGroups',
        'sections',
    ]


class onenoteSection(onenoteEntityHierarchyModel):
    props = {
        'isDefault': Edm.Boolean,
        'links': sectionLinks,
        'pagesUrl': Edm.String,
    }
    rels = [
        'pages',
        'parentNotebook',
        'parentSectionGroup',
    ]


class onenoteOperation(operation):
    props = {
        'error': onenoteOperationError,
        'percentComplete': Edm.String,
        'resourceId': Edm.String,
        'resourceLocation': Edm.String,
    }
    rels = [

    ]


class onenotePage(onenoteEntitySchemaObjectModel):
    props = {
        'content': Edm.Stream,
        'contentUrl': Edm.String,
        'createdByAppId': Edm.String,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'level': Edm.Int32,
        'links': pageLinks,
        'order': Edm.Int32,
        'title': Edm.String,
        'userTags': Collection,
    }
    rels = [
        'parentNotebook',
        'parentSection',
    ]


class onenoteResource(onenoteEntityBaseModel):
    props = {
        'content': Edm.Stream,
        'contentUrl': Edm.String,
    }
    rels = [

    ]


class resellerDelegatedAdminRelationship(delegatedAdminRelationship):
    props = {
        'indirectProviderTenantId': Edm.String,
        'isPartnerConsentPending': Edm.Boolean,
    }
    rels = [

    ]


class educationalActivity(itemFacet):
    props = {
        'completionMonthYear': Edm.Date,
        'endMonthYear': Edm.Date,
        'institution': institutionData,
        'program': educationalActivityDetail,
        'startMonthYear': Edm.Date,
    }
    rels = [

    ]


class itemAddress(itemFacet):
    props = {
        'detail': physicalAddress,
        'displayName': Edm.String,
        'geoCoordinates': geoCoordinates,
    }
    rels = [

    ]


class itemEmail(itemFacet):
    props = {
        'address': Edm.String,
        'displayName': Edm.String,
        'type': emailType,
    }
    rels = [

    ]


class itemPatent(itemFacet):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'isPending': Edm.Boolean,
        'issuedDate': Edm.Date,
        'issuingAuthority': Edm.String,
        'number': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class itemPhone(itemFacet):
    props = {
        'displayName': Edm.String,
        'number': Edm.String,
        'type': phoneType,
    }
    rels = [

    ]


class itemPublication(itemFacet):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'publishedDate': Edm.Date,
        'publisher': Edm.String,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class languageProficiency(itemFacet):
    props = {
        'displayName': Edm.String,
        'proficiency': languageProficiencyLevel,
        'reading': languageProficiencyLevel,
        'spoken': languageProficiencyLevel,
        'tag': Edm.String,
        'thumbnailUrl': Edm.String,
        'written': languageProficiencyLevel,
    }
    rels = [

    ]


class personAnnotation(itemFacet):
    props = {
        'detail': itemBody,
        'displayName': Edm.String,
        'thumbnailUrl': Edm.String,
    }
    rels = [

    ]


class personAnnualEvent(itemFacet):
    props = {
        'date': Edm.Date,
        'displayName': Edm.String,
        'type': personAnnualEventType,
    }
    rels = [

    ]


class personAward(itemFacet):
    props = {
        'description': Edm.String,
        'displayName': Edm.String,
        'issuedDate': Edm.Date,
        'issuingAuthority': Edm.String,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class personCertification(itemFacet):
    props = {
        'certificationId': Edm.String,
        'description': Edm.String,
        'displayName': Edm.String,
        'endDate': Edm.Date,
        'issuedDate': Edm.Date,
        'issuingAuthority': Edm.String,
        'issuingCompany': Edm.String,
        'startDate': Edm.Date,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class personExtension(extension):
    props = {

    }
    rels = [

    ]


class personInterest(itemFacet):
    props = {
        'categories': Collection,
        'collaborationTags': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class personName(itemFacet):
    props = {
        'displayName': Edm.String,
        'first': Edm.String,
        'initials': Edm.String,
        'languageTag': Edm.String,
        'last': Edm.String,
        'maiden': Edm.String,
        'middle': Edm.String,
        'nickname': Edm.String,
        'pronunciation': personNamePronounciation,
        'suffix': Edm.String,
        'title': Edm.String,
    }
    rels = [

    ]


class personResponsibility(itemFacet):
    props = {
        'collaborationTags': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class personWebsite(itemFacet):
    props = {
        'categories': Collection,
        'description': Edm.String,
        'displayName': Edm.String,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class userAccountInformation(itemFacet):
    props = {
        'ageGroup': Edm.String,
        'countryCode': Edm.String,
        'preferredLanguageTag': localeInfo,
        'userPrincipalName': Edm.String,
    }
    rels = [

    ]


class workPosition(itemFacet):
    props = {
        'categories': Collection,
        'colleagues': Collection,
        'detail': positionDetail,
        'isCurrent': Edm.Boolean,
        'manager': relatedPerson,
    }
    rels = [

    ]


class projectParticipation(itemFacet):
    props = {
        'categories': Collection,
        'client': companyDetail,
        'collaborationTags': Collection,
        'colleagues': Collection,
        'detail': positionDetail,
        'displayName': Edm.String,
        'sponsors': Collection,
        'thumbnailUrl': Edm.String,
    }
    rels = [

    ]


class skillProficiency(itemFacet):
    props = {
        'categories': Collection,
        'collaborationTags': Collection,
        'displayName': Edm.String,
        'proficiency': skillProficiencyLevel,
        'thumbnailUrl': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class webAccount(itemFacet):
    props = {
        'description': Edm.String,
        'service': serviceInformation,
        'statusMessage': Edm.String,
        'thumbnailUrl': Edm.String,
        'userId': Edm.String,
        'webUrl': Edm.String,
    }
    rels = [

    ]


class invalidLicenseAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {

    }
    rels = [

    ]


class invalidLicenseAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'tenantLicenseStatus': Edm.String,
    }
    rels = [

    ]


class noMfaOnRoleActivationAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {

    }
    rels = [

    ]


class noMfaOnRoleActivationAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'roleDisplayName': Edm.String,
        'roleTemplateId': Edm.String,
    }
    rels = [

    ]


class redundantAssignmentAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {
        'duration': Edm.Duration,
    }
    rels = [

    ]


class redundantAssignmentAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'assigneeDisplayName': Edm.String,
        'assigneeId': Edm.String,
        'assigneeUserPrincipalName': Edm.String,
        'lastActivationDateTime': Edm.DateTimeOffset,
        'roleDefinitionId': Edm.String,
        'roleDisplayName': Edm.String,
        'roleTemplateId': Edm.String,
    }
    rels = [

    ]


class rolesAssignedOutsidePrivilegedIdentityManagementAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {

    }
    rels = [

    ]


class rolesAssignedOutsidePrivilegedIdentityManagementAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'assigneeDisplayName': Edm.String,
        'assigneeId': Edm.String,
        'assigneeUserPrincipalName': Edm.String,
        'assignmentCreatedDateTime': Edm.DateTimeOffset,
        'roleDefinitionId': Edm.String,
        'roleDisplayName': Edm.String,
        'roleTemplateId': Edm.String,
    }
    rels = [

    ]


class sequentialActivationRenewalsAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {
        'sequentialActivationCounterThreshold': Edm.Int32,
        'timeIntervalBetweenActivations': Edm.Duration,
    }
    rels = [

    ]


class sequentialActivationRenewalsAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'activationCount': Edm.Int32,
        'assigneeDisplayName': Edm.String,
        'assigneeId': Edm.String,
        'assigneeUserPrincipalName': Edm.String,
        'roleDefinitionId': Edm.String,
        'roleDisplayName': Edm.String,
        'roleTemplateId': Edm.String,
        'sequenceEndDateTime': Edm.DateTimeOffset,
        'sequenceStartDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class staleSignInAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {
        'duration': Edm.Duration,
    }
    rels = [

    ]


class staleSignInAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'assigneeDisplayName': Edm.String,
        'assigneeId': Edm.String,
        'assigneeUserPrincipalName': Edm.String,
        'assignmentCreatedDateTime': Edm.DateTimeOffset,
        'lastSignInDateTime': Edm.DateTimeOffset,
        'roleDefinitionId': Edm.String,
        'roleDisplayName': Edm.String,
        'roleTemplateId': Edm.String,
    }
    rels = [

    ]


class tooManyGlobalAdminsAssignedToTenantAlertConfiguration(unifiedRoleManagementAlertConfiguration):
    props = {
        'globalAdminCountThreshold': Edm.Int32,
        'percentageOfGlobalAdminsOutOfRolesThreshold': Edm.Int32,
    }
    rels = [

    ]


class tooManyGlobalAdminsAssignedToTenantAlertIncident(unifiedRoleManagementAlertIncident):
    props = {
        'assigneeDisplayName': Edm.String,
        'assigneeId': Edm.String,
        'assigneeUserPrincipalName': Edm.String,
    }
    rels = [

    ]


class unifiedRoleManagementPolicyApprovalRule(unifiedRoleManagementPolicyRule):
    props = {
        'setting': approvalSettings,
    }
    rels = [

    ]


class unifiedRoleManagementPolicyAuthenticationContextRule(unifiedRoleManagementPolicyRule):
    props = {
        'claimValue': Edm.String,
        'isEnabled': Edm.Boolean,
    }
    rels = [

    ]


class unifiedRoleManagementPolicyEnablementRule(unifiedRoleManagementPolicyRule):
    props = {
        'enabledRules': Collection,
    }
    rels = [

    ]


class unifiedRoleManagementPolicyExpirationRule(unifiedRoleManagementPolicyRule):
    props = {
        'isExpirationRequired': Edm.Boolean,
        'maximumDuration': Edm.Duration,
    }
    rels = [

    ]


class unifiedRoleManagementPolicyNotificationRule(unifiedRoleManagementPolicyRule):
    props = {
        'isDefaultRecipientsEnabled': Edm.Boolean,
        'notificationLevel': Edm.String,
        'notificationRecipients': Collection,
        'notificationType': Edm.String,
        'recipientType': Edm.String,
    }
    rels = [

    ]


class printerShare(printerBase):
    props = {
        'allowAllUsers': Edm.Boolean,
        'createdDateTime': Edm.DateTimeOffset,
        'viewPoint': printerShareViewpoint,
    }
    rels = [
        'allowedGroups',
        'allowedUsers',
        'printer',
    ]


class printer(printerBase):
    props = {
        'acceptingJobs': Edm.Boolean,
        'hasPhysicalDevice': Edm.Boolean,
        'isShared': Edm.Boolean,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'registeredDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'connectors',
        'share',
        'shares',
        'taskTriggers',
    ]


class printerCreateOperation(printOperation):
    props = {
        'certificate': Edm.String,
    }
    rels = [
        'printer',
    ]


class attackSimulationOperation(longRunningOperation):
    props = {
        'percentageCompleted': Edm.Int32,
        'tenantId': Edm.String,
        'type': attackSimulationOperationType,
    }
    rels = [

    ]


class addLargeGalleryViewOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class cancelMediaProcessingOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class emergencyCallEvent(callEvent):
    props = {
        'callerInfo': emergencyCallerInfo,
        'emergencyNumberDialed': Edm.String,
        'policyName': Edm.String,
    }
    rels = [

    ]


class externalMeetingRegistrant(meetingRegistrantBase):
    props = {
        'tenantId': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class externalMeetingRegistration(meetingRegistrationBase):
    props = {

    }
    rels = [

    ]


class inviteParticipantsOperation(commsOperation):
    props = {
        'participants': Collection,
    }
    rels = [

    ]


class meetingRegistrant(meetingRegistrantBase):
    props = {
        'customQuestionAnswers': Collection,
        'email': Edm.String,
        'firstName': Edm.String,
        'lastName': Edm.String,
        'registrationDateTime': Edm.DateTimeOffset,
        'status': meetingRegistrantStatus,
    }
    rels = [

    ]


class muteParticipantOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class muteParticipantsOperation(commsOperation):
    props = {
        'participants': Collection,
    }
    rels = [

    ]


class playPromptOperation(commsOperation):
    props = {
        'completionReason': playPromptCompletionReason,
    }
    rels = [

    ]


class recordOperation(commsOperation):
    props = {
        'completionReason': recordCompletionReason,
        'recordingAccessToken': Edm.String,
        'recordingLocation': Edm.String,
    }
    rels = [

    ]


class sendDtmfTonesOperation(commsOperation):
    props = {
        'completionReason': sendDtmfCompletionReason,
    }
    rels = [

    ]


class startHoldMusicOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class startRecordingOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class startTranscriptionOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class stopHoldMusicOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class stopRecordingOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class stopTranscriptionOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class subscribeToToneOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class unmuteParticipantOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class updateRecordingStatusOperation(commsOperation):
    props = {

    }
    rels = [

    ]


class virtualEventWebinar(virtualEvent):
    props = {
        'audience': meetingAudience,
        'coOrganizers': Collection,
    }
    rels = [
        'registrationConfiguration',
        'registrations',
    ]


class virtualEventSession(onlineMeetingBase):
    props = {
        'endDateTime': dateTimeTimeZone,
        'startDateTime': dateTimeTimeZone,
    }
    rels = [
        'presenters',
        'registrations',
    ]


class virtualEventRegistrationCustomQuestion(virtualEventRegistrationQuestionBase):
    props = {
        'answerChoices': Collection,
        'answerInputType': virtualEventRegistrationQuestionAnswerInputType,
    }
    rels = [

    ]


class virtualEventRegistrationPredefinedQuestion(virtualEventRegistrationQuestionBase):
    props = {
        'label': virtualEventRegistrationPredefinedQuestionLabel,
    }
    rels = [

    ]


class virtualEventTownhall(virtualEvent):
    props = {
        'audience': meetingAudience,
        'coOrganizers': Collection,
        'invitedAttendees': Collection,
        'isInviteOnly': Edm.Boolean,
    }
    rels = [

    ]


class virtualEventWebinarRegistrationConfiguration(virtualEventRegistrationConfiguration):
    props = {
        'isManualApprovalEnabled': Edm.Boolean,
        'isWaitlistEnabled': Edm.Boolean,
    }
    rels = [

    ]


class emailAuthenticationMethod(authenticationMethod):
    props = {
        'emailAddress': Edm.String,
    }
    rels = [

    ]


class fido2AuthenticationMethod(authenticationMethod):
    props = {
        'aaGuid': Edm.String,
        'attestationCertificates': Collection,
        'attestationLevel': attestationLevel,
        'displayName': Edm.String,
        'model': Edm.String,
        'publicKeyCredential': webauthnPublicKeyCredential,
    }
    rels = [

    ]


class hardwareOathAuthenticationMethod(authenticationMethod):
    props = {

    }
    rels = [
        'device',
    ]


class microsoftAuthenticatorAuthenticationMethod(authenticationMethod):
    props = {
        'clientAppName': microsoftAuthenticatorAuthenticationMethodClientAppName,
        'deviceTag': Edm.String,
        'displayName': Edm.String,
        'phoneAppVersion': Edm.String,
    }
    rels = [
        'device',
    ]


class passwordlessMicrosoftAuthenticatorAuthenticationMethod(authenticationMethod):
    props = {
        'creationDateTime': Edm.DateTimeOffset,
        'displayName': Edm.String,
    }
    rels = [
        'device',
    ]


class passwordAuthenticationMethod(authenticationMethod):
    props = {
        'password': Edm.String,
    }
    rels = [

    ]


class phoneAuthenticationMethod(authenticationMethod):
    props = {
        'phoneNumber': Edm.String,
        'phoneType': authenticationPhoneType,
        'smsSignInState': authenticationMethodSignInState,
    }
    rels = [

    ]


class platformCredentialAuthenticationMethod(authenticationMethod):
    props = {
        'displayName': Edm.String,
        'keyStrength': authenticationMethodKeyStrength,
        'platform': authenticationMethodPlatform,
    }
    rels = [
        'device',
    ]


class softwareOathAuthenticationMethod(authenticationMethod):
    props = {
        'secretKey': Edm.String,
    }
    rels = [

    ]


class temporaryAccessPassAuthenticationMethod(authenticationMethod):
    props = {
        'isUsableOnce': Edm.Boolean,
        'lifetimeInMinutes': Edm.Int32,
        'startDateTime': Edm.DateTimeOffset,
        'temporaryAccessPass': Edm.String,
    }
    rels = [

    ]


class windowsHelloForBusinessAuthenticationMethod(authenticationMethod):
    props = {
        'displayName': Edm.String,
        'keyStrength': authenticationMethodKeyStrength,
    }
    rels = [
        'device',
    ]


class hardwareOathTokenAuthenticationMethodDevice(authenticationMethodDevice):
    props = {
        'assignedTo': identity,
        'hashFunction': hardwareOathTokenHashFunction,
        'manufacturer': Edm.String,
        'model': Edm.String,
        'secretKey': Edm.String,
        'serialNumber': Edm.String,
        'status': hardwareOathTokenStatus,
        'timeIntervalInSeconds': Edm.Int32,
    }
    rels = [
        'assignTo',
    ]


class aadUserConversationMember(conversationMember):
    props = {
        'email': Edm.String,
        'tenantId': Edm.String,
        'userId': Edm.String,
    }
    rels = [
        'user',
    ]


class anonymousGuestConversationMember(conversationMember):
    props = {
        'anonymousGuestId': Edm.String,
    }
    rels = [

    ]


class associatedTeamInfo(teamInfo):
    props = {

    }
    rels = [

    ]


class azureCommunicationServicesUserConversationMember(conversationMember):
    props = {
        'azureCommunicationServicesId': Edm.String,
    }
    rels = [

    ]


class chatMessageHostedContent(teamworkHostedContent):
    props = {

    }
    rels = [

    ]


class microsoftAccountUserConversationMember(conversationMember):
    props = {
        'userId': Edm.String,
    }
    rels = [

    ]


class skypeForBusinessUserConversationMember(conversationMember):
    props = {
        'tenantId': Edm.String,
        'userId': Edm.String,
    }
    rels = [

    ]


class skypeUserConversationMember(conversationMember):
    props = {
        'skypeId': Edm.String,
    }
    rels = [

    ]


class workforceIntegration(changeTrackedEntity):
    props = {
        'apiVersion': Edm.Int32,
        'displayName': Edm.String,
        'eligibilityFilteringEnabledEntities': eligibilityFilteringEnabledEntities,
        'encryption': workforceIntegrationEncryption,
        'isActive': Edm.Boolean,
        'supportedEntities': workforceIntegrationSupportedEntities,
        'supports': workforceIntegrationSupportedEntities,
        'url': Edm.String,
    }
    rels = [

    ]


class userScopeTeamsAppInstallation(teamsAppInstallation):
    props = {

    }
    rels = [
        'chat',
    ]


class dayNote(changeTrackedEntity):
    props = {
        'dayNoteDate': Edm.Date,
        'draftDayNote': itemBody,
        'sharedDayNote': itemBody,
    }
    rels = [

    ]


class scheduleChangeRequest(changeTrackedEntity):
    props = {
        'assignedTo': scheduleChangeRequestActor,
        'managerActionDateTime': Edm.DateTimeOffset,
        'managerActionMessage': Edm.String,
        'managerUserId': Edm.String,
        'senderDateTime': Edm.DateTimeOffset,
        'senderMessage': Edm.String,
        'senderUserId': Edm.String,
        'state': scheduleChangeState,
    }
    rels = [

    ]


class offerShiftRequest(scheduleChangeRequest):
    props = {
        'recipientActionDateTime': Edm.DateTimeOffset,
        'recipientActionMessage': Edm.String,
        'recipientUserId': Edm.String,
        'senderShiftId': Edm.String,
    }
    rels = [

    ]


class openShift(changeTrackedEntity):
    props = {
        'draftOpenShift': openShiftItem,
        'isStagedForDeletion': Edm.Boolean,
        'schedulingGroupId': Edm.String,
        'schedulingGroupInfo': schedulingGroupInfo,
        'sharedOpenShift': openShiftItem,
        'teamInfo': shiftsTeamInfo,
    }
    rels = [

    ]


class openShiftChangeRequest(scheduleChangeRequest):
    props = {
        'openShiftId': Edm.String,
    }
    rels = [

    ]


class schedulingGroup(changeTrackedEntity):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'isActive': Edm.Boolean,
        'userIds': Collection,
    }
    rels = [

    ]


class shift(changeTrackedEntity):
    props = {
        'draftShift': shiftItem,
        'isStagedForDeletion': Edm.Boolean,
        'schedulingGroupId': Edm.String,
        'schedulingGroupInfo': schedulingGroupInfo,
        'sharedShift': shiftItem,
        'teamInfo': shiftsTeamInfo,
        'userId': Edm.String,
        'userInfo': shiftsUserInfo,
    }
    rels = [

    ]


class swapShiftsChangeRequest(offerShiftRequest):
    props = {
        'recipientShiftId': Edm.String,
    }
    rels = [

    ]


class timeCard(changeTrackedEntity):
    props = {
        'breaks': Collection,
        'clockInEvent': timeCardEvent,
        'clockOutEvent': timeCardEvent,
        'confirmedBy': confirmedBy,
        'notes': itemBody,
        'originalEntry': timeCardEntry,
        'state': timeCardState,
        'userId': Edm.String,
    }
    rels = [

    ]


class timeOffReason(changeTrackedEntity):
    props = {
        'code': Edm.String,
        'displayName': Edm.String,
        'iconType': timeOffReasonIconType,
        'isActive': Edm.Boolean,
    }
    rels = [

    ]


class timeOffRequest(scheduleChangeRequest):
    props = {
        'endDateTime': Edm.DateTimeOffset,
        'startDateTime': Edm.DateTimeOffset,
        'timeOffReasonId': Edm.String,
    }
    rels = [

    ]


class timeOff(changeTrackedEntity):
    props = {
        'draftTimeOff': timeOffItem,
        'isStagedForDeletion': Edm.Boolean,
        'sharedTimeOff': timeOffItem,
        'teamInfo': shiftsTeamInfo,
        'userId': Edm.String,
        'userInfo': shiftsUserInfo,
    }
    rels = [

    ]


class emailFileAssessmentRequest(threatAssessmentRequest):
    props = {
        'contentData': Edm.String,
        'destinationRoutingReason': mailDestinationRoutingReason,
        'recipientEmail': Edm.String,
    }
    rels = [

    ]


class fileAssessmentRequest(threatAssessmentRequest):
    props = {
        'contentData': Edm.String,
        'fileName': Edm.String,
    }
    rels = [

    ]


class mailAssessmentRequest(threatAssessmentRequest):
    props = {
        'destinationRoutingReason': mailDestinationRoutingReason,
        'messageUri': Edm.String,
        'recipientEmail': Edm.String,
    }
    rels = [

    ]


class urlAssessmentRequest(threatAssessmentRequest):
    props = {
        'url': Edm.String,
    }
    rels = [

    ]


class taskFileAttachment(attachmentBase):
    props = {
        'contentBytes': Edm.Binary,
    }
    rels = [

    ]


class serviceStorageQuotaBreakdown(storageQuotaBreakdown):
    props = {

    }
    rels = [

    ]


class goalsExportJob(longRunningOperation):
    props = {
        'content': Edm.Stream,
        'expirationDateTime': Edm.DateTimeOffset,
        'explorerViewId': Edm.String,
        'goalsOrganizationId': Edm.String,
    }
    rels = [

    ]


class learningAssignment(learningCourseActivity):
    props = {
        'assignedDateTime': Edm.DateTimeOffset,
        'assignerUserId': Edm.String,
        'assignmentType': assignmentType,
        'dueDateTime': dateTimeTimeZone,
        'notes': itemBody,
    }
    rels = [

    ]


class learningSelfInitiatedCourse(learningCourseActivity):
    props = {
        'startedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class networkaccess_filteringPolicy(networkaccess_policy):
    props = {
        'action': Collection, #extnamespace: networkaccess_filteringPolicyAction,
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class networkaccess_filteringProfile(networkaccess_profile):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'priority': Edm.Int64,
    }
    rels = [
        'conditionalAccessPolicies',
    ]


class networkaccess_forwardingPolicy(networkaccess_policy):
    props = {
        'trafficForwardingType': Collection, #extnamespace: networkaccess_trafficForwardingType,
    }
    rels = [

    ]


class networkaccess_forwardingProfile(networkaccess_profile):
    props = {
        'associations': Collection,
        'priority': Edm.Int32,
        'trafficForwardingType': Collection, #extnamespace: networkaccess_trafficForwardingType,
    }
    rels = [
        'servicePrincipal',
    ]


class networkaccess_filteringPolicyLink(networkaccess_policyLink):
    props = {
        'createdDateTime': Edm.DateTimeOffset,
        'lastModifiedDateTime': Edm.DateTimeOffset,
        'loggingState': Collection, #extnamespace: networkaccess_status,
        'priority': Edm.Int64,
    }
    rels = [

    ]


class networkaccess_filteringRule(networkaccess_policyRule):
    props = {
        'destinations': Collection,
        'ruleType': Collection, #extnamespace: networkaccess_networkDestinationType,
    }
    rels = [

    ]


class networkaccess_forwardingPolicyLink(networkaccess_policyLink):
    props = {

    }
    rels = [

    ]


class networkaccess_forwardingRule(networkaccess_policyRule):
    props = {
        'action': Collection, #extnamespace: networkaccess_forwardingRuleAction,
        'destinations': Collection,
        'ruleType': Collection, #extnamespace: networkaccess_networkDestinationType,
    }
    rels = [

    ]


class networkaccess_fqdnFilteringRule(networkaccess_filteringRule):
    props = {

    }
    rels = [

    ]


class networkaccess_internetAccessForwardingRule(networkaccess_forwardingRule):
    props = {
        'ports': Collection,
        'protocol': Collection, #extnamespace: networkaccess_networkingProtocol,
    }
    rels = [

    ]


class networkaccess_m365ForwardingRule(networkaccess_forwardingRule):
    props = {
        'category': Collection, #extnamespace: networkaccess_forwardingCategory,
        'ports': Collection,
        'protocol': Collection, #extnamespace: networkaccess_networkingProtocol,
    }
    rels = [

    ]


class networkaccess_privateAccessForwardingRule(networkaccess_forwardingRule):
    props = {

    }
    rels = [

    ]


class networkaccess_webCategoryFilteringRule(networkaccess_filteringRule):
    props = {

    }
    rels = [

    ]


class ediscovery_addToReviewSetOperation(ediscovery_caseOperation):
    props = {

    }
    rels = [
        'reviewSet',
        'sourceCollection',
    ]


class ediscovery_custodian(ediscovery_dataSourceContainer):
    props = {
        'acknowledgedDateTime': Edm.DateTimeOffset,
        'applyHoldToSources': Edm.Boolean,
        'email': Edm.String,
    }
    rels = [
        'siteSources',
        'unifiedGroupSources',
        'userSources',
    ]


class ediscovery_noncustodialDataSource(ediscovery_dataSourceContainer):
    props = {
        'applyHoldToSource': Edm.Boolean,
    }
    rels = [
        'dataSource',
    ]


class ediscovery_caseExportOperation(ediscovery_caseOperation):
    props = {
        'azureBlobContainer': Edm.String,
        'azureBlobToken': Edm.String,
        'description': Edm.String,
        'exportOptions': Collection, #extnamespace: ediscovery_exportOptions,
        'exportStructure': Collection, #extnamespace: ediscovery_exportFileStructure,
        'outputFolderId': Edm.String,
        'outputName': Edm.String,
    }
    rels = [
        'reviewSet',
    ]


class ediscovery_caseHoldOperation(ediscovery_caseOperation):
    props = {

    }
    rels = [

    ]


class ediscovery_caseIndexOperation(ediscovery_caseOperation):
    props = {

    }
    rels = [

    ]


class ediscovery_siteSource(ediscovery_dataSource):
    props = {

    }
    rels = [
        'site',
    ]


class ediscovery_unifiedGroupSource(ediscovery_dataSource):
    props = {
        'includedSources': Collection, #extnamespace: ediscovery_sourceType,
    }
    rels = [
        'group',
    ]


class ediscovery_userSource(ediscovery_dataSource):
    props = {
        'email': Edm.String,
        'includedSources': Collection, #extnamespace: ediscovery_sourceType,
        'siteWebUrl': Edm.String,
    }
    rels = [

    ]


class ediscovery_estimateStatisticsOperation(ediscovery_caseOperation):
    props = {
        'indexedItemCount': Edm.Int64,
        'indexedItemsSize': Edm.Int64,
        'mailboxCount': Edm.Int32,
        'siteCount': Edm.Int32,
        'unindexedItemCount': Edm.Int64,
        'unindexedItemsSize': Edm.Int64,
    }
    rels = [
        'sourceCollection',
    ]


class ediscovery_purgeDataOperation(ediscovery_caseOperation):
    props = {

    }
    rels = [

    ]


class ediscovery_tagOperation(ediscovery_caseOperation):
    props = {

    }
    rels = [

    ]


class security_ediscoveryCase(security_case):
    props = {
        'closedBy': identitySet,
        'closedDateTime': Edm.DateTimeOffset,
        'externalId': Edm.String,
    }
    rels = [
        'custodians',
        'legalHolds',
        'noncustodialDataSources',
        'operations',
        'reviewSets',
        'searches',
        'settings',
        'tags',
    ]


class security_ediscoveryAddToReviewSetOperation(security_caseOperation):
    props = {
        'additionalDataOptions': Collection, #extnamespace: security_additionalDataOptions,
        'cloudAttachmentVersion': Collection, #extnamespace: security_cloudAttachmentVersion,
        'documentVersion': Collection, #extnamespace: security_documentVersion,
        'itemsToInclude': Collection, #extnamespace: security_itemsToInclude,
    }
    rels = [
        'reviewSet',
        'search',
    ]


class security_ediscoveryReviewSet(security_dataSet):
    props = {

    }
    rels = [
        'files',
        'queries',
    ]


class security_ediscoverySearch(security_search):
    props = {
        'dataSourceScopes': Collection, #extnamespace: security_dataSourceScopes,
    }
    rels = [
        'additionalSources',
        'addToReviewSetOperation',
        'custodianSources',
        'lastEstimateStatisticsOperation',
        'noncustodialSources',
    ]


class security_ediscoveryCustodian(security_dataSourceContainer):
    props = {
        'acknowledgedDateTime': Edm.DateTimeOffset,
        'email': Edm.String,
    }
    rels = [
        'lastIndexOperation',
        'siteSources',
        'unifiedGroupSources',
        'userSources',
    ]


class security_ediscoveryHoldPolicy(security_policyBase):
    props = {
        'contentQuery': Edm.String,
        'errors': Collection,
        'isEnabled': Edm.Boolean,
    }
    rels = [
        'siteSources',
        'userSources',
    ]


class security_ediscoveryNoncustodialDataSource(security_dataSourceContainer):
    props = {

    }
    rels = [
        'dataSource',
        'lastIndexOperation',
    ]


class security_ediscoveryReviewTag(security_tag):
    props = {
        'childSelectability': Collection, #extnamespace: security_childSelectability,
    }
    rels = [
        'childTags',
        'parent',
    ]


class security_ediscoveryIndexOperation(security_caseOperation):
    props = {

    }
    rels = [

    ]


class security_siteSource(security_dataSource):
    props = {

    }
    rels = [
        'site',
    ]


class security_unifiedGroupSource(security_dataSource):
    props = {
        'includedSources': Collection, #extnamespace: security_sourceType,
    }
    rels = [
        'group',
    ]


class security_userSource(security_dataSource):
    props = {
        'email': Edm.String,
        'includedSources': Collection, #extnamespace: security_sourceType,
        'siteWebUrl': Edm.String,
    }
    rels = [

    ]


class security_ediscoveryEstimateOperation(security_caseOperation):
    props = {
        'indexedItemCount': Edm.Int64,
        'indexedItemsSize': Edm.Int64,
        'mailboxCount': Edm.Int32,
        'siteCount': Edm.Int32,
        'statisticsOptions': Collection, #extnamespace: security_statisticsOptions,
        'unindexedItemCount': Edm.Int64,
        'unindexedItemsSize': Edm.Int64,
    }
    rels = [
        'search',
    ]


class security_ediscoveryExportOperation(security_caseOperation):
    props = {
        'azureBlobContainer': Edm.String,
        'azureBlobToken': Edm.String,
        'description': Edm.String,
        'exportFileMetadata': Collection,
        'exportOptions': Collection, #extnamespace: security_exportOptions,
        'exportStructure': Collection, #extnamespace: security_exportFileStructure,
        'outputFolderId': Edm.String,
        'outputName': Edm.String,
    }
    rels = [
        'reviewSet',
        'reviewSetQuery',
    ]


class security_ediscoveryReviewSetQuery(security_search):
    props = {

    }
    rels = [

    ]


class security_ediscoveryFile(security_file):
    props = {

    }
    rels = [
        'custodian',
        'tags',
    ]


class security_ediscoveryHoldOperation(security_caseOperation):
    props = {

    }
    rels = [

    ]


class security_ediscoveryPurgeDataOperation(security_caseOperation):
    props = {

    }
    rels = [

    ]


class security_ediscoverySearchExportOperation(security_caseOperation):
    props = {
        'additionalOptions': Collection, #extnamespace: security_additionalOptions,
        'cloudAttachmentVersion': Collection, #extnamespace: security_cloudAttachmentVersion,
        'description': Edm.String,
        'displayName': Edm.String,
        'documentVersion': Collection, #extnamespace: security_documentVersion,
        'exportCriteria': Collection, #extnamespace: security_exportCriteria,
        'exportFileMetadata': Collection,
        'exportFormat': Collection, #extnamespace: security_exportFormat,
        'exportLocation': Collection, #extnamespace: security_exportLocation,
        'exportSingleItems': Edm.Boolean,
    }
    rels = [
        'search',
    ]


class security_ediscoveryTagOperation(security_caseOperation):
    props = {

    }
    rels = [

    ]


class security_endpointDiscoveredCloudAppDetail(security_discoveredCloudAppDetail):
    props = {
        'deviceCount': Edm.Int64,
    }
    rels = [
        'devices',
    ]


class security_detectionRule(security_protectionRule):
    props = {
        'detectionAction': Collection, #extnamespace: security_detectionAction,
        'detectorId': Edm.String,
        'lastRunDetails': Collection, #extnamespace: security_runDetails,
        'queryCondition': Collection, #extnamespace: security_queryCondition,
        'schedule': Collection, #extnamespace: security_ruleSchedule,
    }
    rels = [

    ]


class security_authorityTemplate(security_filePlanDescriptorTemplate):
    props = {

    }
    rels = [

    ]


class security_categoryTemplate(security_filePlanDescriptorTemplate):
    props = {

    }
    rels = [
        'subcategories',
    ]


class security_subcategoryTemplate(security_filePlanDescriptorTemplate):
    props = {

    }
    rels = [

    ]


class security_citationTemplate(security_filePlanDescriptorTemplate):
    props = {
        'citationJurisdiction': Edm.String,
        'citationUrl': Edm.String,
    }
    rels = [

    ]


class security_departmentTemplate(security_filePlanDescriptorTemplate):
    props = {

    }
    rels = [

    ]


class security_filePlanReferenceTemplate(security_filePlanDescriptorTemplate):
    props = {

    }
    rels = [

    ]


class security_emailThreatSubmission(security_threatSubmission):
    props = {
        'attackSimulationInfo': Collection, #extnamespace: security_attackSimulationInfo,
        'internetMessageId': Edm.String,
        'originalCategory': Collection, #extnamespace: security_submissionCategory,
        'receivedDateTime': Edm.DateTimeOffset,
        'recipientEmailAddress': Edm.String,
        'sender': Edm.String,
        'senderIP': Edm.String,
        'subject': Edm.String,
        'tenantAllowOrBlockListAction': Collection, #extnamespace: security_tenantAllowOrBlockListAction,
    }
    rels = [

    ]


class security_emailContentThreatSubmission(security_emailThreatSubmission):
    props = {
        'fileContent': Edm.String,
    }
    rels = [

    ]


class security_emailUrlThreatSubmission(security_emailThreatSubmission):
    props = {
        'messageUrl': Edm.String,
    }
    rels = [

    ]


class security_fileThreatSubmission(security_threatSubmission):
    props = {
        'fileName': Edm.String,
    }
    rels = [

    ]


class security_fileContentThreatSubmission(security_fileThreatSubmission):
    props = {
        'fileContent': Edm.String,
    }
    rels = [

    ]


class security_fileUrlThreatSubmission(security_fileThreatSubmission):
    props = {
        'fileUrl': Edm.String,
    }
    rels = [

    ]


class security_urlThreatSubmission(security_threatSubmission):
    props = {
        'webUrl': Edm.String,
    }
    rels = [

    ]


class security_hostComponent(security_artifact):
    props = {
        'category': Edm.String,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
        'version': Edm.String,
    }
    rels = [
        'host',
    ]


class security_host(security_artifact):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'childHostPairs',
        'components',
        'cookies',
        'hostPairs',
        'parentHostPairs',
        'passiveDns',
        'passiveDnsReverse',
        'ports',
        'reputation',
        'sslCertificates',
        'subdomains',
        'trackers',
        'whois',
    ]


class security_articleIndicator(security_indicator):
    props = {

    }
    rels = [

    ]


class security_hostCookie(security_artifact):
    props = {
        'domain': Edm.String,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'name': Edm.String,
    }
    rels = [
        'host',
    ]


class security_passiveDnsRecord(security_artifact):
    props = {
        'collectedDateTime': Edm.DateTimeOffset,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'recordType': Edm.String,
    }
    rels = [
        'artifact',
        'parentHost',
    ]


class security_hostSslCertificate(security_artifact):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'ports': Collection,
    }
    rels = [
        'host',
        'sslCertificate',
    ]


class security_hostTracker(security_artifact):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'kind': Edm.String,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'value': Edm.String,
    }
    rels = [
        'host',
    ]


class security_whoisRecord(security_whoisBaseRecord):
    props = {

    }
    rels = [
        'history',
    ]


class security_hostname(security_host):
    props = {
        'registrant': Edm.String,
        'registrar': Edm.String,
    }
    rels = [

    ]


class security_sslCertificate(security_artifact):
    props = {
        'expirationDateTime': Edm.DateTimeOffset,
        'fingerprint': Edm.String,
        'firstSeenDateTime': Edm.DateTimeOffset,
        'issueDateTime': Edm.DateTimeOffset,
        'issuer': Collection, #extnamespace: security_sslCertificateEntity,
        'lastSeenDateTime': Edm.DateTimeOffset,
        'serialNumber': Edm.String,
        'sha1': Edm.String,
        'subject': Collection, #extnamespace: security_sslCertificateEntity,
    }
    rels = [
        'relatedHosts',
    ]


class security_intelligenceProfileIndicator(security_indicator):
    props = {
        'firstSeenDateTime': Edm.DateTimeOffset,
        'lastSeenDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class security_ipAddress(security_host):
    props = {
        'autonomousSystem': Collection, #extnamespace: security_autonomousSystem,
        'countryOrRegion': Edm.String,
        'hostingProvider': Edm.String,
        'netblock': Edm.String,
    }
    rels = [

    ]


class security_whoisHistoryRecord(security_whoisBaseRecord):
    props = {

    }
    rels = [

    ]


class security_unclassifiedArtifact(security_artifact):
    props = {
        'kind': Edm.String,
        'value': Edm.String,
    }
    rels = [

    ]


class callRecords_organizer(callRecords_participantBase):
    props = {

    }
    rels = [

    ]


class callRecords_participant(callRecords_participantBase):
    props = {

    }
    rels = [

    ]


class industryData_administrativeUnitProvisioningFlow(industryData_provisioningFlow):
    props = {
        'creationOptions': Collection, #extnamespace: industryData_adminUnitCreationOptions,
    }
    rels = [

    ]


class industryData_apiDataConnector(industryData_industryDataConnector):
    props = {
        'apiFormat': Collection, #extnamespace: industryData_apiFormat,
        'baseUrl': Edm.String,
        'credential': Collection, #extnamespace: industryData_credential,
    }
    rels = [

    ]


class industryData_fileDataConnector(industryData_industryDataConnector):
    props = {

    }
    rels = [

    ]


class industryData_azureDataLakeConnector(industryData_fileDataConnector):
    props = {
        'fileFormat': Collection, #extnamespace: industryData_fileFormatReferenceValue,
    }
    rels = [

    ]


class industryData_classGroupProvisioningFlow(industryData_provisioningFlow):
    props = {
        'configuration': Collection, #extnamespace: industryData_classGroupConfiguration,
    }
    rels = [

    ]


class industryData_validateOperation(longRunningOperation):
    props = {
        'errors': Collection,
        'warnings': Collection,
    }
    rels = [

    ]


class industryData_fileValidateOperation(industryData_validateOperation):
    props = {
        'validatedFiles': Collection,
    }
    rels = [

    ]


class industryData_inboundFlow(industryData_industryDataActivity):
    props = {
        'dataDomain': Collection, #extnamespace: industryData_inboundDomain,
        'effectiveDateTime': Edm.DateTimeOffset,
        'expirationDateTime': Edm.DateTimeOffset,
    }
    rels = [
        'dataConnector',
        'year',
    ]


class industryData_inboundApiFlow(industryData_inboundFlow):
    props = {

    }
    rels = [

    ]


class industryData_inboundFileFlow(industryData_inboundFlow):
    props = {

    }
    rels = [

    ]


class industryData_inboundFlowActivity(industryData_industryDataRunActivity):
    props = {

    }
    rels = [

    ]


class industryData_oneRosterApiDataConnector(industryData_apiDataConnector):
    props = {
        'apiVersion': Edm.String,
        'isContactsEnabled': Edm.Boolean,
        'isDemographicsEnabled': Edm.Boolean,
        'isFlagsEnabled': Edm.Boolean,
    }
    rels = [

    ]


class industryData_outboundFlowActivity(industryData_industryDataRunActivity):
    props = {

    }
    rels = [

    ]


class industryData_securityGroupProvisioningFlow(industryData_provisioningFlow):
    props = {
        'creationOptions': Collection, #extnamespace: industryData_securityGroupCreationOptions,
    }
    rels = [

    ]


class industryData_userProvisioningFlow(industryData_provisioningFlow):
    props = {
        'createUnmatchedUsers': Edm.Boolean,
        'creationOptions': Collection, #extnamespace: industryData_userCreationOptions,
        'managementOptions': Collection, #extnamespace: industryData_userManagementOptions,
    }
    rels = [

    ]


class partners_billing_exportSuccessOperation(partners_billing_operation):
    props = {

    }
    rels = [
        'resourceLocation',
    ]


class partners_billing_failedOperation(partners_billing_operation):
    props = {
        'error': publicError,
    }
    rels = [

    ]


class partners_billing_runningOperation(partners_billing_operation):
    props = {

    }
    rels = [

    ]


class partner_security_adminsMfaEnforcedSecurityRequirement(partner_security_securityRequirement):
    props = {
        'adminsRequiredNotUsingMfaCount': Edm.Int64,
        'legacyPerUserMfaStatus': Collection, #extnamespace: partner_security_policyStatus,
        'mfaConditionalAccessPolicyStatus': Collection, #extnamespace: partner_security_policyStatus,
        'mfaEnabledAdminsCount': Edm.Int64,
        'mfaEnabledUsersCount': Edm.Int64,
        'securityDefaultsStatus': Collection, #extnamespace: partner_security_policyStatus,
        'totalAdminsCount': Edm.Int64,
        'totalUsersCount': Edm.Int64,
        'usersRequiredNotUsingMfaCount': Edm.Int64,
    }
    rels = [

    ]


class partner_security_customersMfaEnforcedSecurityRequirement(partner_security_securityRequirement):
    props = {
        'compliantTenantCount': Edm.Int64,
        'totalTenantCount': Edm.Int64,
    }
    rels = [

    ]


class partner_security_customersSpendingBudgetSecurityRequirement(partner_security_securityRequirement):
    props = {
        'customersWithSpendBudgetCount': Edm.Int64,
        'totalCustomersCount': Edm.Int64,
    }
    rels = [

    ]


class partner_security_responseTimeSecurityRequirement(partner_security_securityRequirement):
    props = {
        'averageResponseTimeInHours': Edm.Single,
    }
    rels = [

    ]


class search_acronym(search_searchAnswer):
    props = {
        'standsFor': Edm.String,
        'state': Collection, #extnamespace: search_answerState,
    }
    rels = [

    ]


class search_bookmark(search_searchAnswer):
    props = {
        'availabilityEndDateTime': Edm.DateTimeOffset,
        'availabilityStartDateTime': Edm.DateTimeOffset,
        'categories': Collection,
        'groupIds': Collection,
        'isSuggested': Edm.Boolean,
        'keywords': Collection, #extnamespace: search_answerKeyword,
        'languageTags': Collection,
        'platforms': Collection,
        'powerAppIds': Collection,
        'state': Collection, #extnamespace: search_answerState,
        'targetedVariations': Collection,
    }
    rels = [

    ]


class search_qna(search_searchAnswer):
    props = {
        'availabilityEndDateTime': Edm.DateTimeOffset,
        'availabilityStartDateTime': Edm.DateTimeOffset,
        'groupIds': Collection,
        'isSuggested': Edm.Boolean,
        'keywords': Collection, #extnamespace: search_answerKeyword,
        'languageTags': Collection,
        'platforms': Collection,
        'state': Collection, #extnamespace: search_answerState,
        'targetedVariations': Collection,
    }
    rels = [

    ]


class externalConnectors_externalActivityResult(externalConnectors_externalActivity):
    props = {
        'error': publicError,
    }
    rels = [

    ]


class windowsUpdates_azureADDevice(windowsUpdates_updatableAsset):
    props = {
        'enrollment': Collection, #extnamespace: windowsUpdates_updateManagementEnrollment,
        'errors': Collection,
    }
    rels = [

    ]


class windowsUpdates_contentApproval(windowsUpdates_complianceChange):
    props = {
        'content': Collection, #extnamespace: windowsUpdates_deployableContent,
        'deploymentSettings': Collection, #extnamespace: windowsUpdates_deploymentSettings,
    }
    rels = [
        'deployments',
    ]


class windowsUpdates_softwareUpdateCatalogEntry(windowsUpdates_catalogEntry):
    props = {

    }
    rels = [

    ]


class windowsUpdates_driverUpdateCatalogEntry(windowsUpdates_softwareUpdateCatalogEntry):
    props = {
        'description': Edm.String,
        'driverClass': Edm.String,
        'manufacturer': Edm.String,
        'provider': Edm.String,
        'setupInformationFile': Edm.String,
        'version': Edm.String,
        'versionDateTime': Edm.DateTimeOffset,
    }
    rels = [

    ]


class windowsUpdates_featureUpdateCatalogEntry(windowsUpdates_softwareUpdateCatalogEntry):
    props = {
        'buildNumber': Edm.String,
        'version': Edm.String,
    }
    rels = [

    ]


class windowsUpdates_operationalInsightsConnection(windowsUpdates_resourceConnection):
    props = {
        'azureResourceGroupName': Edm.String,
        'azureSubscriptionId': Edm.String,
        'workspaceName': Edm.String,
    }
    rels = [

    ]


class windowsUpdates_qualityUpdateCatalogEntry(windowsUpdates_softwareUpdateCatalogEntry):
    props = {
        'catalogName': Edm.String,
        'cveSeverityInformation': Collection, #extnamespace: windowsUpdates_qualityUpdateCveSeverityInformation,
        'isExpeditable': Edm.Boolean,
        'qualityUpdateCadence': Collection, #extnamespace: windowsUpdates_qualityUpdateCadence,
        'qualityUpdateClassification': Collection, #extnamespace: windowsUpdates_qualityUpdateClassification,
        'shortName': Edm.String,
    }
    rels = [
        'productRevisions',
    ]


class windowsUpdates_updatableAssetGroup(windowsUpdates_updatableAsset):
    props = {

    }
    rels = [
        'members',
    ]

