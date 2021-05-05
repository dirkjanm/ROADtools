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

export interface GroupsItem {
  displayName: string;
  description: string;
  createdDateTime: string;
  dirSyncEnabled: string;
  objectId: string;
  objectType: string;
  mail: string;
  isPublic: boolean;
  membershipRule: string;
  memberOf: GroupsItem[];
  memberUsers: UsersItem[];
  memberServicePrincipals: ServicePrincipalsItem[];
  memberOfRole: DirectoryRolesItem[];
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
  ownedApplications: ApplicationsItem[];
  strongAuthenticationDetail: object;
}

export interface appMetadata {
  data: object[];
  version: number;
}

export interface MfaItem {
  objectId: string;
  displayName: string;
  mfamethods: number;
  perusermfa: boolean;
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
}

export interface TenantDetail {
  objectId: string;
  displayName: string;
  dirSyncEnabled: boolean;
  verifiedDomains: object[];

}

export interface TenantStats {
  countUsers: number;
  countGroups: number;
  countApplications: number;
  countServicePrincipals: number;
  countDevices: number;
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

  public getTenantStats():  Observable<TenantStats> {
      return this.http.get<TenantStats>(environment.apibase + 'stats');
  }

  public getTenantDetail():  Observable<TenantDetail> {
      return this.http.get<TenantDetail>(environment.apibase + 'tenantdetails');
  }

  public getAppRoles():  Observable<AppRolesItem[]> {
      return this.http.get<AppRolesItem[]>(environment.apibase + 'approles');
  }

  public getMfa():  Observable<MfaItem[]> {
      return this.http.get<MfaItem[]>(environment.apibase + 'mfa');
  }

  public getOAuth2Permissions():  Observable<OAuth2PermissionsItem[]> {
      return this.http.get<OAuth2PermissionsItem[]>(environment.apibase + 'oauth2permissions');
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

