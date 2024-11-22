import { Injectable } from '@angular/core';
import {HttpClient, HttpParams} from '@angular/common/http';
import { environment } from '../../environments/environment';
import {
  Router, Resolve,
  RouterStateSnapshot,
  ActivatedRouteSnapshot, Params
} from '@angular/router';
import { Observable, of, EMPTY }  from 'rxjs';
import { mergeMap, take }         from 'rxjs/operators';
import {SortDirection} from '@angular/material/sort';

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
}

export interface appMetadata {
  data: object[];
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

export interface PaginationParams {
  page: number;
  pageSize: number;
  sortField?: string;
  sortDirection?: SortDirection;
  contains?: string;
}

@Injectable({
  providedIn: 'root'
})
export class DatabaseService {
  defaultPage = 1;
  defaultPageSize = 50;

  constructor(private http: HttpClient) { }

  public getUsers(pagination?: PaginationParams): Observable<UsersItem[]> {
      return this.http.get<UsersItem[]>(environment.apibase + 'users', {
        params: this.toHttpParams(pagination)
      });
  }

  public getUser(id):  Observable<UsersItem> {
      return this.http.get<UsersItem>(environment.apibase + 'users/'+ id);
  }

  public getDevices(pagination?: PaginationParams):  Observable<DevicesItem[]> {
      return this.http.get<DevicesItem[]>(environment.apibase + 'devices',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getDevice(id):  Observable<DevicesItem> {
      return this.http.get<DevicesItem>(environment.apibase + 'devices/'+ id);
  }

  public getGroups(pagination?: PaginationParams):  Observable<GroupsItem[]> {
      return this.http.get<GroupsItem[]>(environment.apibase + 'groups',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getGroup(id):  Observable<GroupsItem> {
      return this.http.get<GroupsItem>(environment.apibase + 'groups/'+ id);
  }

  public getAdministrativeUnits(pagination?: PaginationParams):  Observable<AdministrativeUnitsItem[]> {
      return this.http.get<AdministrativeUnitsItem[]>(environment.apibase + 'administrativeunits',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getAdministrativeUnit(id):  Observable<AdministrativeUnitsItem> {
      return this.http.get<AdministrativeUnitsItem>(environment.apibase + 'administrativeunits/'+ id);
  }

  public getServicePrincipals(pagination?: PaginationParams):  Observable<ServicePrincipalsItem[]> {
      return this.http.get<ServicePrincipalsItem[]>(environment.apibase + 'serviceprincipals',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getServicePrincipal(id):  Observable<ServicePrincipalsItem> {
      return this.http.get<ServicePrincipalsItem>(environment.apibase + 'serviceprincipals/'+ id);
  }

  public getServicePrincipalByAppId(id):  Observable<ServicePrincipalsItem> {
      return this.http.get<ServicePrincipalsItem>(environment.apibase + 'serviceprincipals-by-appid/'+ id);
  }

  public getApplications(pagination?: PaginationParams):  Observable<ApplicationsItem[]> {
      return this.http.get<ApplicationsItem[]>(environment.apibase + 'applications',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getApplication(id):  Observable<ApplicationsItem> {
      return this.http.get<ApplicationsItem>(environment.apibase + 'applications/'+ id);
  }

  public getDirectoryRoles(pagination?: PaginationParams):  Observable<DirectoryRolesItem[]> {
      return this.http.get<DirectoryRolesItem[]>(environment.apibase + 'directoryroles',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getRoleDefinitions(pagination?: PaginationParams):  Observable<RoleDefinitionsItem[]> {
      return this.http.get<RoleDefinitionsItem[]>(environment.apibase + 'roledefinitions',
        { params: this.toHttpParams(pagination) }
      );
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

  public getAuthorizationPolicies(pagination?: PaginationParams): Observable<AuthorizationPolicy[]> {
      return this.http.get<AuthorizationPolicy[]>(environment.apibase + 'authorizationpolicies',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getAppRoles(pagination?: PaginationParams):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getAppRolesByResource(spid):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles_by_resource/' + spid);
  }

  public getAppRolesByPrincipal(pid):  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles_by_principal/' + pid);
  }

  public getMfa(pagination?: PaginationParams):  Observable<MfaItem[]> {
      return this.http.get<MfaItem[]>(environment.apibase + 'mfa',
        { params: this.toHttpParams(pagination) }
      );
  }

  public getOAuth2Permissions(pagination?: PaginationParams):  Observable<OAuth2PermissionsItem[]> {
      return this.http.get<OAuth2PermissionsItem[]>(environment.apibase + 'oauth2permissions',
        { params: this.toHttpParams(pagination) }
      );
  }

  toHttpParams(params?: PaginationParams): HttpParams {
    let httpParams = new HttpParams();
    httpParams = httpParams.set('page', params?.page || this.defaultPage);
    httpParams = httpParams.set('per_page', params?.pageSize || this.defaultPageSize);
    if (params?.sortField) {
      httpParams = httpParams.set('sort', params.sortField);
    }
    if (params?.sortDirection) {
      httpParams = httpParams.set('direction', params.sortDirection);
    }
    if (params?.contains) {
      httpParams = httpParams.set('contains', params.contains);
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
