import { Injectable } from '@angular/core';
import { HttpClient, HttpParams } from '@angular/common/http';
import { environment } from '../../environments/environment'
import {
  Router, Resolve,
  RouterStateSnapshot,
  ActivatedRouteSnapshot
}                                 from '@angular/router';
import { Observable, of, EMPTY }  from 'rxjs';
import { mergeMap, take }         from 'rxjs/operators';

export interface GroupsItem {
  displayName: string;
  description: string;
  createdDateTime: string;
  dirSyncEnabled: string;
  objectId: string;
  objectType: string;
  mail: string;
  isPublic: boolean;
  isAssignableToRole: boolean;
  membershipRule: string;
  groupTypes: string[];
  memberOf: GroupsItem[];
  memberGroups: GroupsItem[];
  memberUsers: UsersItem[];
  memberDevices: DevicesItem[];
  memberServicePrincipals: ServicePrincipalsItem[];
  memberOfRole: DirectoryRolesItem[];
  ownerUsers: UsersItem[];
  ownerServicePrincipals: ServicePrincipalsItem[];
  pimRoleAssignments: PIMRoleAssignment[];
}

export interface AdministrativeUnitsItem {
  displayName: string;
  description: string;
  objectId: string;
  objectType: string;
  membershipRule: string;
  memberUsers: UsersItem[];
  memberDevices: DevicesItem[];
  memberGroups: GroupsItem[];
}

export interface DirectoryRolesItem {
  description: string;
  displayName: string;
  objectId: string;
  roleTemplateId: string;
  memberUsers: UsersItem[];
  memberServicePrincipals: ServicePrincipalsItem[];
  memberGroups: GroupsItem[];
}

export interface RoleAssignmentsItem {
  type: string;
  scope: string[];
  scopeIds: string[];
  scopeNames: string[];
  scopeTypes: string[];
  principal: (UsersItem | ServicePrincipalsItem | GroupsItem)[];
}

export interface RoleDefinitionsItem {
  description: string;
  displayName: string;
  objectId: string;
  templateId: string;
  isBuiltIn: boolean;
  assignments: RoleAssignmentsItem[];
}

export interface ApplicationsItem {
  objectId: string;
  displayName: string;
  appId: string;
  availableToOtherTenants: boolean;
  oauth2AllowIdTokenImplicitFlow: boolean;
  oauth2AllowImplicitFlow: boolean;
  appRoles: object[];
  replyUrls: object[];
  homepage: string;
  publisherName: string;
  oauth2Permissions: object[];
  publisherDomain: boolean;
  publicClient: boolean;
  appMetadata: appMetadata;
  ownerUsers: UsersItem[];
  ownerServicePrincipals: ServicePrincipalsItem[];
}

export interface UsersItem {
  userPrincipalName: string;
  objectType: string;
  objectId: string;
  displayName: string;
  mobile: string;
  jobTitle: string;
  lastPasswordChangeDateTime: string;
  department: string;
  mail: string;
  dirSyncEnabled: boolean;
  accountEnabled: boolean;
  memberOf: GroupsItem[];
  memberOfRole: DirectoryRolesItem[];
  ownedServicePrincipals: ServicePrincipalsItem[];
  ownedDevices: DevicesItem[];
  ownedGroups: GroupsItem[];
  ownedApplications: ApplicationsItem[];
  strongAuthenticationDetail: object;
  userType: string;
  searchableDeviceKey: object;
  pimRoleAssignments: PIMRoleAssignment[];
}

export interface appMetadata {
  data: any[];
  version: number;
}

export interface MfaItem {
  objectId: string;
  displayName: string;
  mfamethods: number;
  perusermfa: string;
  has_app: boolean;
  has_phonenr: boolean;
  has_fido: boolean;
  accountEnabled: boolean;
  strongAuthenticationDetail: object;
}

export interface OAuth2PermissionsItem {
  type: string;
  userid: string;
  userdisplayname: string;
  targetapplication: string;
  targetspobjectid: string;
  sourceapplication: string;
  sourcespobjectid: string;
  expiry: string;
  scope: string;
}

export interface ServicePrincipalsItem {
  objectId: string;
  objectType: string;
  displayName: string;
  appDisplayName: string;
  appOwnerTenantId: string;
  appRoleAssignmentRequired: boolean;
  publisherName: string;
  appId: string;
  appMetadata: appMetadata;
  replyUrls: object[];
  appRoles: object[];
  microsoftFirstParty: boolean;
  accountEnabled: boolean;
  isDirSyncEnabled: boolean;
  oauth2Permissions: object[];
  passwordCredentials: object;
  keyCredentials: object;
  servicePrincipalType: string;
  ownerUsers: UsersItem[];
  ownerServicePrincipals: ServicePrincipalsItem[];
  memberOfRole: DirectoryRolesItem[];
  memberOf: GroupsItem[];
  appRolesAssignedTo: object[];
  appRolesAssigned: object[];
}

export interface TenantDetail {
  objectId: string;
  displayName: string;
  dirSyncEnabled: boolean;
  verifiedDomains: object[];

}

export interface PolicyScopeItem {
  objectId: string;
  objectType: string;
  displayName: string;
}

export interface PolicyScope {
  include: PolicyScopeItem[];
  exclude: PolicyScopeItem[];
}

export interface PolicyItem {
  objectId: string;
  displayName: string;
  policyDetail: object;
  policyScope: PolicyScope;
}

export interface NetworkLocationItem {
  displayName: string;
  trusted: boolean;
  appliesToUnknownCountry: boolean;
  ipRanges: string[];
  categories: string[];
  countryCodes: string[]
}

export interface NetworkLocationList {
  [s: string]: NetworkLocationItem;
}

export interface DirectorySetting {
  displayName: string;
  id: string;
  templateId: string;
  values: { name: string, value: string }[];

}

export interface TenantStats {
  countUsers: number;
  countGroups: number;
  countApplications: number;
  countServicePrincipals: number;
  countDevices: number;
  countAdministrativeUnits: number;
}

export interface AppRolesItem {
  pname: string;
  ptype: string;
  objid: string;
  app: string;
  value: string;
  desc: string;
  spid: string;
}

export interface DevicesItem {
  objectId: string;
  accountEnabled: boolean;
  bitLockerKey: object[];
  deviceCategory: string;
  deviceId: string;
  deviceKey: object;
  deviceManufacturer: string;
  deviceManagementAppId: string;
  deviceMetadata: string;
  deviceModel: string;
  deviceObjectVersion: number;
  deviceOSType: string;
  deviceOSVersion: string;
  deviceOwnership: string;
  devicePhysicalIds: object;
  deviceSystemMetadata: object;
  deviceTrustType: string;
  dirSyncEnabled: boolean;
  displayName: string;
  domainName: string;
  owner: UsersItem[];
}

export interface AuthorizationPolicy {
  id: string;
  allowInvitesFrom: string;
  allowedToSignUpEmailBasedSubscriptions: boolean;
  allowedToUseSSPR: boolean;
  allowEmailVerifiedUsersToJoinOrganization: boolean;
  blockMsolPowerShell: boolean;
  defaultUserRolePermissions: object;
  displayName: string;
  description: string;
  enabledPreviewFeatures: object;
  guestUserRoleId: string;
  permissionGrantPolicyIdsAssignedToDefaultUserRole: string[];
}

export interface UsersList {
  items: UsersItem[];
  count: number;
}

export interface GroupsList {
  items: GroupsItem[];
  count: number;
}

export interface DevicesList {
  items: DevicesItem[];
  count: number;
}

// Pagination interface as contributed by Richard Gomez (rgmz)
export interface PaginationParams {
  page: number;
  pageSize: number;
  sortColumn?: string;
  sortDirection?: string;
  search?: string;
}

/*
  PIM interfaces
*/
export interface PIMLifeCycleRule {
  ruleIdentifier: string;
  setting: string; // JSON string containing rule-specific settings
}

export interface PIMLifeCycleManagement {
  caller: 'Admin' | 'EndUser';
  level: 'Eligible' | 'Member';
  operation: string;
  value: PIMLifeCycleRule[];
}

export interface PIMRoleSettingsV2 {
  id: string;
  isDefault: boolean;
  lastUpdatedBy: string | null;
  lastUpdatedDateTime: string | null;
  lifeCycleManagement: PIMLifeCycleManagement[];
}

export interface PIMRoleDefinition {
  displayName: string;
  externalId: string;
  id: string;
  templateId: string;
  type: string | null;
  roleSettingsv2?: PIMRoleSettingsV2[];
  roleAssignments?: PIMRoleAssignment[];
}

export interface PIMResource {
  displayName: string;
  externalId: string;
  id: string;
  managedAt: string | null;
  onboardDateTime: string | null;
  originTenantId: string | null;
  registeredDateTime: string | null;
  registeredRoot: string | null;
  status: string;
  type: string; // 'Directory', 'Security', etc.
  roleDefinitions?: PIMRoleDefinition[];
  roleSettingsv2?: PIMRoleSettingsV2[];
  roleAssignments?: PIMRoleAssignment[];
}

export interface PIMRoleAssignment {
  assignmentState: 'Eligible' | 'Active';
  condition: string | null;
  conditionDescription: string | null;
  conditionVersion: string | null;
  endDateTime: string | null;
  externalId: string;
  id: string;
  isPermanent: boolean;
  linkedEligibleRoleAssignmentId: string | null;
  memberType: string;
  resource: PIMResource;
  resourceId: string;
  roleDefinition?: PIMRoleDefinition;
  roleDefinitionId: string;
  scopedResourceId: string | null;
  startDateTime: string | null;
  status: string;
  subjectGroup: any[];
  subjectId: string;
  subjectServicePrincipal: any[];
  subjectUser: string[];
}

/*
  Identity Governance interfaces
*/
export interface AccessPackageResourceRole {
  description: string | null;
  displayName: string;
  id: string;
  originId: string;
  originSystem: string;
  roleType: string | null;
}

export interface AccessPackageResourceScope {
  description: string;
  displayName: string;
  id: string;
  isRootScope: boolean;
  originId: string;
  originSystem: string;
  roleOriginId: string | null;
  url: string | null;
}

export interface AccessPackageResourceRoleScope {
  createdBy: string;
  createdByString: string;
  createdDateTime: string;
  id: string;
  modifiedBy: string;
  modifiedDateTime: string;
  role: AccessPackageResourceRole[];
  scope: AccessPackageResourceScope[];
}

export interface AccessPackageDetails {
  catalogId: string;
  createdBy: string;
  createdByString: string;
  createdDateTime: string;
  description: string;
  displayName: string;
  id: string;
  isHidden: boolean;
  isRoleScopesVisible: boolean;
  lastModifiedByString: string;
  lastModifiedDateTime: string;
  modifiedBy: string;
  modifiedDateTime: string;
  resourceRoleScopes: AccessPackageResourceRoleScope[];
}

export interface AccessPackageApprovalStage {
  approvalStageTimeOutInDays?: number;
  approverInformationVisibility?: string;
  durationBeforeAutomaticDenial?: string;
  durationBeforeEscalation?: string;
  isApproverJustificationRequired: boolean;
  isEscalationEnabled: boolean;
  primaryApprovers: any[];
  fallbackPrimaryApprovers: any[];
  escalationApprovers: any[];
  fallbackEscalationApprovers: any[];
}

export interface AccessPackageApprovalSettings {
  isApprovalRequiredForAdd?: boolean;
  isApprovalRequired?: boolean;
  isApprovalRequiredForUpdate: boolean;
  isRequestorJustificationRequired: boolean;
  approvalMode?: string;
  stages?: AccessPackageApprovalStage[];
  approvalStages?: AccessPackageApprovalStage[];
}

export interface AccessPackagePolicy {
  accessPackage: AccessPackageDetails;
  approvalSettings?: AccessPackageApprovalSettings;
  requestApprovalSettings?: AccessPackageApprovalSettings;
  allowedTargetScope: string;
  canExtend: boolean;
  createdDateTime: string;
  description: string;
  displayName: string;
  durationInDays: number;
  expiration: {
    duration: string;
    endDateTime: string | null;
    type: string;
  };
  id: string;
  modifiedDateTime: string;
  policyAssignmentType: string;
}

/*
  Azure related interfaces
*/

export interface AzureRolePermission {
  actions: string[];
  notActions: string[];
}

export interface AzureRoleDefinition {
  created_on: string;
  description: string;
  id: string;
  name: string;
  permissions: AzureRolePermission[];
  role_name: string;
  role_type: string;
  type: string;
}

export interface AzureRoleAssignment {
  condition: string | null;
  condition_version: string | null;
  created_on: string;
  delegated_managed_identity_resource_id: string | null;
  description: string | null;
  id: string;
  name: string;
  principal_id: string;
  principal_type: string;
  role: AzureRoleDefinition;
  scope: string;
  type: string;
}

export interface AzureScopeInfo {
  type: 'Root' | 'ManagementGroup' | 'Subscription' | 'ResourceGroup' | 'Resource';
  displayName: string;
  subscriptionId?: string;
  resourceGroup?: string;
  resourceProvider?: string;
  resourceType?: string;
  resourceName?: string;
}

/*
  NHI & Agent 365 interfaces
*/
export interface NhiSummary {
  totalNhIs: number;
  totalAgents: number;
  totalAutonomousAgents: number;
  totalManagedIdentities: number;
  totalSystemManagedIdentities: number;
  totalUserAssignedManagedIdentities: number;
  totalWorkloadApps: number;
  totalFirstPartyMicrosoftNhIs?: number;
  totalFederatedCredentials: number | null;
  federatedCredentialsCollected?: boolean;
  agentMetadataCollected?: boolean;
  federatedCredentialsCollectionStatus?: 'collected' | 'skipped' | 'failed' | 'uncollected' | string;
  agentMetadataCollectionStatus?: 'collected' | 'skipped' | 'failed' | 'uncollected' | string;
  federatedCredentialsCollectionDetail?: string | null;
  agentMetadataCollectionDetail?: string | null;
  severityBreakdown?: NhiSeverityBreakdown;
  topFindings?: NhiFindingItem[];
  dataGaps?: string[];
  tier0PrivilegedNhIs: number;
  ownerlessNhIs: number;
  criticalFindingsCount: number;
  highFindingsCount: number;
  mediumFindingsCount: number;
  lowFindingsCount: number;
  informationalFindingsCount: number;
  collectionStatus: 'collected' | 'derived_from_legacy_db' | string;
  federatedCredentialsTablePresent?: boolean;
  agentMetadataTablePresent?: boolean;
}

export interface NhiSeverityBreakdown {
  Critical: number;
  High: number;
  Medium: number;
  Low: number;
  Informational: number;
}

export interface NhiAgentItem {
  objectId: string;
  appId: string;
  applicationObjectId?: string | null;
  displayName: string;
  agentCategory: string;
  executionMode: string;
  blueprintId?: string | null;
  m365Scopes: string[];
  graphAppRoles: string[];
  oauth2Scopes: string[];
  tier0Roles: string[];
  directoryRoles: string[];
  azureRoles: string[];
  pimRoles?: string[];
  ownersCount: number | null;
  ownerNames: string[];
  hasSecrets: boolean;
  hasCerts: boolean;
  federatedCredentialsCount: number | null;
  sponsorUserIds?: string[];
  sponsorNames?: string[];
  sponsorsCount?: number;
  unresolvedSponsors?: string[];
  mcpTools?: string[];
  accountEnabled: boolean;
  riskLevel: string;
  severityWeight: number;
  riskReasons: string[];
}

export interface NhiWorkloadItem {
  objectId: string;
  appId: string;
  applicationObjectId?: string | null;
  displayName: string;
  nhiType: 'FirstPartyMicrosoft' | string;
  nhiCategory?: string;
  servicePrincipalType: string;
  managedIdentityResourceId?: string | null;
  accountEnabled: boolean;
  secretsCount: number;
  certsCount: number;
  federatedCredentialsCount: number | null;
  maxExpiryDays?: number | null;
  directoryRoles?: string[];
  pimRoles?: string[];
  azureRoles?: string[];
  graphAppRoles?: string[];
  tier0Roles?: string[];
  expiredCredentialsCount: number;
  longLivedCredentialsCount: number;
  credentialSummary: string;
  privilegedRoles: string[];
  m365Scopes: string[];
  ownersCount: number | null;
  ownerNames: string[];
  riskLevel: string;
  severityWeight: number;
  riskReasons: string[];
}

export interface FederatedCredentialItem {
  id: string;
  applicationObjectId: string;
  applicationDisplayName: string;
  appId: string;
  name: string;
  issuer: string;
  subject: string;
  description?: string | null;
  audiences: string[];
  claimsMatchingExpression?: any;
  riskLevel: string;
  severityWeight: number;
  riskReasons: string[];
}

export interface NhiFindingItem {
  id: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Informational' | string;
  severityWeight: number;
  category: string;
  principalObjectId: string;
  principalType: 'ServicePrincipal' | 'Application' | string;
  principalName: string;
  appId?: string | null;
  title: string;
  detail: string;
  recommendation: string;
  evidence?: any;
}

export interface ServicePrincipalNhiDetail {
  objectId: string;
  appId?: string;
  displayName?: string;
  isAgent: boolean;
  agent?: NhiAgentItem | null;
  workload?: NhiWorkloadItem | null;
  federatedCredentials: FederatedCredentialItem[];
  findings: NhiFindingItem[];
  collectionStatus?: 'collected' | 'derived_from_legacy_db' | string;
  agentMetadataCollected?: boolean;
  agentMetadataCollectionDetail?: string | null;
}

@Injectable({
  providedIn: 'root'
})
export class DatabaseService {
  defaultPage = 1;
  defaultPageSize = 50;

  constructor(private http: HttpClient) { }

  public getUsers():  Observable<UsersItem[]> {
      return this.http.get<UsersItem[]>(environment.apibase + 'users');
  }

  public getUsersPaged(pagination?: PaginationParams):  Observable<UsersList> {
      return this.http.get<UsersList>(environment.apibase + 'paged/users',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getUser(id: string | null):  Observable<UsersItem> {
      return this.http.get<UsersItem>(environment.apibase + 'users/'+ id);
  }

  public getUserPolicies(id: string | null):  Observable<PolicyItem[]> {
      return this.http.get<PolicyItem[]>(environment.apibase + 'users/'+ id+'/policies');
  }

  public getUserPIMassignments(id: string | null):  Observable<PIMRoleAssignment[]> {
      return this.http.get<PIMRoleAssignment[]>(environment.apibase + 'users/'+ id +'/pimassignments');
  }

  public getUserAccessPackages(id: string | null):  Observable<AccessPackagePolicy[]> {
      return this.http.get<AccessPackagePolicy[]>(environment.apibase + 'users/'+ id +'/accesspackages');
  }

  public getUserAzureRoleAssignments(id: string | null):  Observable<AzureRoleAssignment[]> {
      return this.http.get<AzureRoleAssignment[]>(environment.apibase + 'users/'+ id +'/azroleassignments');
  }

  public getNetworkLocations():  Observable<NetworkLocationList> {
      return this.http.get<NetworkLocationList>(environment.apibase + 'policies/locations');
  }

  public getDevices():  Observable<DevicesItem[]> {
      return this.http.get<DevicesItem[]>(environment.apibase + 'devices');
  }

  public getDevicesPaged(pagination?: PaginationParams):  Observable<DevicesList> {
      return this.http.get<DevicesList>(environment.apibase + 'paged/devices',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getDevice(id: string | null):  Observable<DevicesItem> {
      return this.http.get<DevicesItem>(environment.apibase + 'devices/'+ id);
  }

  public getGroups():  Observable<GroupsItem[]> {
      return this.http.get<GroupsItem[]>(environment.apibase + 'groups');
  }

  public getGroupsPaged(pagination?: PaginationParams):  Observable<GroupsList> {
      return this.http.get<GroupsList>(environment.apibase + 'paged/groups',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getGroup(id: string | null):  Observable<GroupsItem> {
      return this.http.get<GroupsItem>(environment.apibase + 'groups/'+ id);
  }

  public getGroupPIMResource(id: string | null):  Observable<PIMResource> {
      return this.http.get<PIMResource>(environment.apibase + 'groups/'+ id+'/pimresource');
  }

  public getGroupAzureRoleAssignments(id: string | null):  Observable<AzureRoleAssignment[]> {
      return this.http.get<AzureRoleAssignment[]>(environment.apibase + 'groups/'+ id +'/azroleassignments');
  }

  public getGroupResolve(id: string | null):  Observable<GroupsItem> {
      return this.http.get<GroupsItem>(environment.apibase + 'groupresolve/'+ id);
  }

  public getAdministrativeUnits():  Observable<AdministrativeUnitsItem[]> {
      return this.http.get<AdministrativeUnitsItem[]>(environment.apibase + 'administrativeunits');
  }

  public getAdministrativeUnit(id: string | null):  Observable<AdministrativeUnitsItem> {
      return this.http.get<AdministrativeUnitsItem>(environment.apibase + 'administrativeunits/'+ id);
  }

  public getServicePrincipals():  Observable<ServicePrincipalsItem[]> {
      return this.http.get<ServicePrincipalsItem[]>(environment.apibase + 'serviceprincipals');
  }

  public getServicePrincipal(id: string | null):  Observable<ServicePrincipalsItem> {
      return this.http.get<ServicePrincipalsItem>(environment.apibase + 'serviceprincipals/'+ id);
  }

  public getServicePrincipalAzureRoleAssignments(id: string | null):  Observable<AzureRoleAssignment[]> {
      return this.http.get<AzureRoleAssignment[]>(environment.apibase + 'serviceprincipals/'+ id +'/azroleassignments');
  }

  public getServicePrincipalByAppId(id: string | null):  Observable<ServicePrincipalsItem> {
      return this.http.get<ServicePrincipalsItem>(environment.apibase + 'serviceprincipals-by-appid/'+ id);
  }

  public getApplicationByAppId(id: string | null):  Observable<ApplicationsItem> {
      return this.http.get<ApplicationsItem>(environment.apibase + 'applications-by-appid/'+ id);
  }

  public getApplications():  Observable<ApplicationsItem[]> {
      return this.http.get<ApplicationsItem[]>(environment.apibase + 'applications');
  }

  public getApplication(id: string | null):  Observable<ApplicationsItem> {
      return this.http.get<ApplicationsItem>(environment.apibase + 'applications/'+ id);
  }

  public getDirectoryRoles():  Observable<DirectoryRolesItem[]> {
      return this.http.get<DirectoryRolesItem[]>(environment.apibase + 'directoryroles');
  }

  public getRoleDefinitions():  Observable<RoleDefinitionsItem[]> {
      return this.http.get<RoleDefinitionsItem[]>(environment.apibase + 'roledefinitions');
  }

  public getTenantStats():  Observable<TenantStats> {
      return this.http.get<TenantStats>(environment.apibase + 'stats');
  }

  public getTenantDetail():  Observable<TenantDetail> {
      return this.http.get<TenantDetail>(environment.apibase + 'tenantdetails');
  }

  public getDirectorySetting():  Observable<DirectorySetting> {
      return this.http.get<DirectorySetting>(environment.apibase + 'directorysettings');
  }

  public getAuthorizationPolicies(): Observable<AuthorizationPolicy[]> {
      return this.http.get<AuthorizationPolicy[]>(environment.apibase + 'authorizationpolicies');
  }

  public getAppRoles():  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles');
  }

  public getAppRolesByResource(spid: string | null):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles_by_resource/' + spid);
  }

  public getAppRolesByPrincipal(pid: string | null):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles_by_principal/' + pid);
  }

  public getMfa():  Observable<MfaItem[]> {
      return this.http.get<MfaItem[]>(environment.apibase + 'mfa');
  }

  public getOAuth2Permissions():  Observable<OAuth2PermissionsItem[]> {
      return this.http.get<OAuth2PermissionsItem[]>(environment.apibase + 'oauth2permissions');
  }

  public getNhiSummary(): Observable<NhiSummary> {
      return this.http.get<NhiSummary>(environment.apibase + 'nhi/summary');
  }

  public getNhiAgents(): Observable<NhiAgentItem[]> {
      return this.http.get<NhiAgentItem[]>(environment.apibase + 'nhi/agents');
  }

  public getNhiWorkloads(): Observable<NhiWorkloadItem[]> {
      return this.http.get<NhiWorkloadItem[]>(environment.apibase + 'nhi/workloads');
  }

  public getNhiFederatedCredentials(): Observable<FederatedCredentialItem[]> {
      return this.http.get<FederatedCredentialItem[]>(environment.apibase + 'nhi/federatedcredentials');
  }

  public getNhiFindings(): Observable<NhiFindingItem[]> {
      return this.http.get<NhiFindingItem[]>(environment.apibase + 'nhi/findings');
  }

  public getApplicationFederatedCredentials(id: string | null): Observable<FederatedCredentialItem[]> {
      return this.http.get<FederatedCredentialItem[]>(environment.apibase + 'applications/' + id + '/federatedcredentials');
  }

  public getServicePrincipalNhi(id: string | null): Observable<ServicePrincipalNhiDetail> {
      return this.http.get<ServicePrincipalNhiDetail>(environment.apibase + 'serviceprincipals/' + id + '/nhi');
  }

  // Pagination parsing as contributed by Richard Gomez (rgmz)
  private toHttpParams(params?: PaginationParams): HttpParams {
    let httpParams = new HttpParams();
    httpParams = httpParams.set('page', params?.page || this.defaultPage);
    httpParams = httpParams.set('limit', params?.pageSize || this.defaultPageSize);
    if (params?.sortColumn) {
      httpParams = httpParams.set('sortColumn', params.sortColumn);
    }
    if (params?.sortDirection) {
      httpParams = httpParams.set('sortDirection', params.sortDirection);
    }
    if (params?.search) {
      httpParams = httpParams.set('search', params.search);
    }
    return httpParams;
  }
}

@Injectable({
  providedIn: 'root',
})
export class UsersResolveService implements Resolve<UsersItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<UsersItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getUser(id).pipe(
      mergeMap(user => {
        if (user) {
          return of(user);
        } else { // id not found
          this.router.navigate(['/users']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class DevicesResolveService implements Resolve<DevicesItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<DevicesItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getDevice(id).pipe(
      mergeMap(device => {
        if (device) {
          return of(device);
        } else { // id not found
          this.router.navigate(['/users']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class GroupsResolveService implements Resolve<GroupsItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<GroupsItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getGroup(id).pipe(
      mergeMap(group => {
        if (group) {
          return of(group);
        } else { // id not found
          this.router.navigate(['/groups']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class AdministrativeUnitsResolveService implements Resolve<AdministrativeUnitsItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<AdministrativeUnitsItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getAdministrativeUnit(id).pipe(
      mergeMap(administrativeunit => {
        if (administrativeunit) {
          return of(administrativeunit);
        } else { // id not found
          this.router.navigate(['/administrativeunits']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class ApplicationsResolveService implements Resolve<ApplicationsItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<ApplicationsItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getApplication(id).pipe(
      mergeMap(application => {
        if (application) {
          return of(application);
        } else { // id not found
          this.router.navigate(['/groups']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class ServicePrincipalsResolveService implements Resolve<ServicePrincipalsItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<ServicePrincipalsItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getServicePrincipal(id).pipe(
      mergeMap(serviceprincipal => {
        if (serviceprincipal) {
          return of(serviceprincipal);
        } else { // id not found
          this.router.navigate(['/serviceprincipals']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class ServicePrincipalsByAppIdResolveService implements Resolve<ServicePrincipalsItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<ServicePrincipalsItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getServicePrincipalByAppId(id).pipe(
      mergeMap(serviceprincipal => {
        if (serviceprincipal) {
          this.router.navigate(['/serviceprincipals', serviceprincipal.objectId]);
          return EMPTY;
        } else { // id not found
          this.router.navigate(['/serviceprincipals']);
          return EMPTY;
        }
      })
    );
  }
}

@Injectable({
  providedIn: 'root',
})
export class ApplicationsByAppIdResolveService implements Resolve<ApplicationsItem> {
  constructor(private dbservice: DatabaseService, private router: Router) {}

  resolve(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Observable<ApplicationsItem> | Observable<never> {
    let id = route.paramMap.get('id');

    return this.dbservice.getApplicationByAppId(id).pipe(
      mergeMap(application => {
        if (application) {
          this.router.navigate(['/applications', application.objectId]);
          return EMPTY;
        } else { // id not found
          this.router.navigate(['/applications']);
          return EMPTY;
        }
      })
    );
  }
}
