import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { environment } from '../../environments/environment'
import {
  Router, Resolve,
  RouterStateSnapshot,
  ActivatedRouteSnapshot
}                                 from '@angular/router';
import { Observable, of, EMPTY }  from 'rxjs';
import { mergeMap, take }         from 'rxjs/operators';

export interface AdministrativeUnitsItem {
  description: string;
  displayName: string;
  id: string;
  memberDevices: DevicesItem[];
  memberGroups: GroupsItem[];
  memberUsers: UsersItem[];
  membershipRule: string;
}

export interface AppRolesItem {
  app: string;
  desc: string;
  objid: string;
  pname: string;
  ptype: string;
  spid: string;
  value: string;
}

export interface spa {
  redirectUris: object[];
}

export interface web {
  redirectUris: object[];
  homePageUrl: string;
  implicitGrantSettings: object[];
  logoutUrl: string;
  redirectorUriSettings: object[];
}

export interface api {
  knownClientApplications: object[];
  oauth2PermissionScopes: object[];
  preAuthorizedApplications: object[];
}

export interface ApplicationsItem {
  api: api;
  appId: string;
  appMetadata: appMetadata;
  appRoles: object[];
  displayName: string;
  id: string;
  keyCredentials: object[];
  ownerServicePrincipals: ServicePrincipalsItem[];
  ownerUsers: UsersItem[];
  passwordCredentials: object[];
  publicClient: boolean;
  publisherDomain: boolean;
  spa: spa;
  web: web;
  signInAudience: string;
  notes: string;
  tags: object[];
  nativeAuthenticationApisEnabled: boolean;
  isFallbackPublicClient: boolean;
  requestSignatureVerification: boolean;
}

export interface AuthorizationPolicy {
  allowEmailVerifiedUsersToJoinOrganization: boolean;
  allowInvitesFrom: string;
  allowedToSignUpEmailBasedSubscriptions: boolean;
  allowedToUseSSPR: boolean;
  blockMsolPowerShell: boolean;
  defaultUserRolePermissions: object;
  description: string;
  displayName: string;
  guestUserRoleId: string;
  id: string;
}

export interface DevicesItem {
  accountEnabled: boolean;
  deviceCategory: string;
  deviceId: string;
  manufacturer: string;
  model: string;
  deviceVersion: number;
  operatingSystem: string;
  operatingSystemVersion: string;
  deviceOwnership: string;
  physicalIds: object;
  trustType: string;
  onPremisesSyncEnabled: boolean;
  displayName: string;
  domainName: string;
  id: string;
  isCompliant: boolean;
  isManaged: boolean;
  isRooted: boolean;
  owner: UsersItem[];
}

export interface DirectoryRolesItem {
  description: string;
  displayName: string;
  id: string;
  memberGroups: GroupsItem[];
  memberServicePrincipals: ServicePrincipalsItem[];
  memberUsers: UsersItem[];
  roleTemplateId: string;
  roleDisabled: boolean;
}

export interface DirectorySetting {
  displayName: string;
  id: string;
  templateId: string;
  values: { name: string, value: string }[];
}

export interface GroupsItem {
  createdDateTime: string;
  description: string;
  displayName: string;
  groupTypes: string[];
  id: string;
  isAssignableToRole: boolean;
  isPublic: boolean;
  mail: string;
  memberDevices: DevicesItem[];
  memberGroups: GroupsItem[];
  memberOf: GroupsItem[];
  memberOfRole: DirectoryRolesItem[];
  memberServicePrincipals: ServicePrincipalsItem[];
  memberUsers: UsersItem[];
  membershipRule: string;
  onPremisesSyncEnabled: string;
  onPremisesDomainName: string;
  onPremisesNetBiosName: string;
  onPremisesSamAccountName: string;
  onPremisesSecurityIdentifier: string;
  ownerServicePrincipals: ServicePrincipalsItem[];
  ownerUsers: UsersItem[];
  }

export interface MfaItem {
  displayName: string;
  has_app: boolean;
  has_fido: boolean;
  has_phonenr: boolean;
  id: string;
  mfamethods: number;
  isAdmin: boolean;
  isMfaRegistered: boolean;
  isSsprRegistered: boolean;
  isSsprEnabled: boolean;
  isSsprCapable: boolean;
  isMfaCapable: boolean;
  isPasswordlessCapable: boolean;
  methodsRegistered: object;
  systemPreferredAuthenticationMethods: object; 
  userPreferredMethodForSecondaryAuthentication: string;
}

export interface OAuth2PermissionsItem {
  // expiry: string;
  // scope: string;
  // sourceapplication: string;
  // sourcespid: string;
  // targetapplication: string;
  // targetspid: string;
  // type: string;
  // userdisplayname: string;
  // userid: string;
  clientId: string;
  consentType: string;
  id: string;
  principalId: string;
  resourceId: string;
  scope: string;
}

export interface RoleAssignmentsItem {
  principal: (UsersItem | ServicePrincipalsItem | GroupsItem)[];
  scope: string[];
  scopeIds: string[];
  scopeNames: string[];
  scopeTypes: string[];
  type: string;
}

export interface RoleDefinitionsItem {
  assignments: RoleAssignmentsItem[];
  description: string;
  displayName: string;
  id: string;
  isBuiltIn: boolean;
  templateId: string;
}

export interface ServicePrincipalsItem {
  accountEnabled: boolean;
  appDisplayName: string;
  appId: string;
  appOwnerOrganizationId: string;
  appRoleAssignmentRequired: boolean;
  appRoles: object[];
  appRolesAssigned: object[];
  appRolesAssignedTo: object[];
  displayName: string;
  description: string;
  id: string;
  isDirSyncEnabled: boolean;
  keyCredentials: object;
  memberOf: GroupsItem[];
  memberOfRole: DirectoryRolesItem[];
  oauth2PermissionScopes: object[];
  ownerServicePrincipals: ServicePrincipalsItem[];
  ownerUsers: UsersItem[];
  passwordCredentials: object;
  replyUrls: object[];
  servicePrincipalType: string;
}

export interface TenantDetail {
  onPremisesSyncEnabled: boolean;
  displayName: string;
  id: string;
  verifiedDomains: object[];
}

export interface TenantStats {
  countAdministrativeUnits: number;
  countApplications: number;
  countDevices: number;
  countGroups: number;
  countServicePrincipals: number;
  countUsers: number;
}

export interface UsersItem {
  businessPhones: object[];
  displayName: string;
  givenName: string;
  id: string;
  jobTitle: string;
  mail: string;
  mobilePhone: string;
  officeLocation: string;
  onPremisesSyncEnabled: boolean;
  preferredLanguage: string;
  surname: string;
  userPrincipalName: string;
  memberOf: GroupsItem[];
  memberOfRole: DirectoryRolesItem[];
  ownedApplications: ApplicationsItem[];
  ownedDevices: DevicesItem[];
  ownedGroups: GroupsItem[];
  ownedServicePrincipals: ServicePrincipalsItem[];
  // strongAuthenticationDetail: object;
  has_app: boolean;
  has_fido: boolean;
  has_phonenr: boolean;
  mfamethods: number;
  isAdmin: boolean;
  isMfaRegistered: boolean;
  isSsprRegistered: boolean;
  isSsprEnabled: boolean;
  isSsprCapable: boolean;
  isMfaCapable: boolean;
  isPasswordlessCapable: boolean;
  methodsRegistered: object;
  systemPreferredAuthenticationMethods: object; 
  userPreferredMethodForSecondaryAuthentication: string;
}


export interface appMetadata {
  data: object[];
  version: number;
}


@Injectable({
  providedIn: 'root'
})
export class DatabaseService {

  constructor(private http: HttpClient) { }

  public getUsers():  Observable<UsersItem[]> {
      return this.http.get<UsersItem[]>(environment.apibase + 'users');
  }

  public getUser(id):  Observable<UsersItem> {
      return this.http.get<UsersItem>(environment.apibase + 'users/'+ id);
  }

  public getDevices():  Observable<DevicesItem[]> {
      return this.http.get<DevicesItem[]>(environment.apibase + 'devices');
  }

  public getDevice(id):  Observable<DevicesItem> {
      return this.http.get<DevicesItem>(environment.apibase + 'devices/'+ id);
  }

  public getGroups():  Observable<GroupsItem[]> {
      return this.http.get<GroupsItem[]>(environment.apibase + 'groups');
  }

  public getGroup(id):  Observable<GroupsItem> {
      return this.http.get<GroupsItem>(environment.apibase + 'groups/'+ id);
  }

  public getAdministrativeUnits():  Observable<AdministrativeUnitsItem[]> {
      return this.http.get<AdministrativeUnitsItem[]>(environment.apibase + 'administrativeunits');
  }

  public getAdministrativeUnit(id):  Observable<AdministrativeUnitsItem> {
      return this.http.get<AdministrativeUnitsItem>(environment.apibase + 'administrativeunits/'+ id);
  }

  public getServicePrincipals():  Observable<ServicePrincipalsItem[]> {
      return this.http.get<ServicePrincipalsItem[]>(environment.apibase + 'serviceprincipals');
  }

  public getServicePrincipal(id):  Observable<ServicePrincipalsItem> {
      return this.http.get<ServicePrincipalsItem>(environment.apibase + 'serviceprincipals/'+ id);
  }

  public getServicePrincipalByAppId(id):  Observable<ServicePrincipalsItem> {
      return this.http.get<ServicePrincipalsItem>(environment.apibase + 'serviceprincipals-by-appid/'+ id);
  }

  public getApplications():  Observable<ApplicationsItem[]> {
      return this.http.get<ApplicationsItem[]>(environment.apibase + 'applications');
  }

  public getApplication(id):  Observable<ApplicationsItem> {
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

  public getAppRolesByResource(spid):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles_by_resource/' + spid);
  }

  public getAppRolesByPrincipal(pid):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles_by_principal/' + pid);
  }

  public getMfa():  Observable<MfaItem[]> {
      return this.http.get<MfaItem[]>(environment.apibase + 'mfa');
  }

  public getOAuth2Permissions():  Observable<OAuth2PermissionsItem[]> {
      return this.http.get<OAuth2PermissionsItem[]>(environment.apibase + 'oauth2permissions');
  }
}

// Janky use of type guards dynamically generate links at runtime within roletable.component.html
export function isUsersItem(obj: any): obj is UsersItem {
  return (obj as UsersItem).businessPhones !== undefined;
}

export function isGroupsItem(obj: any): obj is GroupsItem {
  return (obj as GroupsItem).groupTypes !== undefined;
}

export function isServicePrincipalsItem(obj: any): obj is ServicePrincipalsItem {
  return (obj as ServicePrincipalsItem).servicePrincipalType !== undefined;
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
          this.router.navigate(['/serviceprincipals', serviceprincipal.id]);
          return EMPTY;
        } else { // id not found
          this.router.navigate(['/serviceprincipals']);
          return EMPTY;
        }
      })
    );
  }
}
