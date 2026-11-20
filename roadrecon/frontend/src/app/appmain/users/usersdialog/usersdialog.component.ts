import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { UtilitiesService } from '../../utils.service';
import { UsersItem, DatabaseService, PolicyItem, NetworkLocationItem, NetworkLocationList, PIMRoleDefinition, PIMRoleAssignment, AccessPackagePolicy, AccessPackageDetails, AzureRoleAssignment, AzureScopeInfo } from '../../aadobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatChipsModule } from '@angular/material/chips';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatSort } from '@angular/material/sort';
import { MatProgressSpinnerModule } from '@angular/material/progress-spinner';
import { Location } from '@angular/common';
import { LocalStorageService } from 'ngx-webstorage';
import { forkJoin, of } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Component({
  standalone: false,
  template: ''
})
export class UsersdialogInitComponent implements OnInit {
  user!: UsersItem;
  myurl: string;
  showPortalLink: boolean;
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    public dialog: MatDialog,
    private location: Location,
    private localSt:LocalStorageService
  ) {
    this.myurl = this.router.url;
    this.showPortalLink = this.localSt.retrieve('portallinks');
  }

  ngOnInit() {
    this.route.data
      .subscribe((data: any) => {
        const dialogRef = this.dialog.open(UsersdialogComponent,{
          data: {
            user: data.user,
            showPortalLink: this.showPortalLink
          }
        });
        dialogRef.afterClosed().subscribe(result => {
          if(this.router.url == this.myurl){
            this.location.back();
          }

        });
      });
  }

}

@Component({
  standalone: false,
  selector: 'app-usersdialog',
  templateUrl: './usersdialog.component.html',
  styleUrls: ['./usersdialog.component.less'],
  providers: [DatabaseService]
})
export class UsersdialogComponent {
  public displayedColumnsGroups: string[] = ['displayName', 'description', 'isAssignableToRole']
  public displayedColumnsRoles: string[] = ['displayName', 'description']
  public displayedColumnsServicePrincipals: string[] = ['displayName', 'publisherName', 'microsoftFirstParty', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];
  public displayedColumnsDevices: string[] = ['displayName', 'deviceManufacturer', 'accountEnabled', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'isManaged', 'isRooted'];
  public displayedColumnsApplications: string[] = ['displayName', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];
  public displayedColumnsPolicies: string[] = ['displayName', 'policyScope', 'details'];
  public displayedColumnsPim: string[] = ['resourceType', 'resourceAndRole', 'assignmentState', 'approval', 'duration'];
  public displayedColumnsAccessPackage: string[] = ['packageName', 'resources', 'approval', 'duration'];
  public displayedColumnsAzureRole: string[] = ['role', 'scopeType', 'scopeDetails'];

  public showPortalLink: boolean;
  public user: UsersItem;
  public policies!: PolicyItem[];
  public policyLocations!: NetworkLocationList;
  public PIMgroupAssignments: PIMRoleAssignment[] = [];
  public accessPackages: AccessPackagePolicy[] = [];
  public azureRoleAssignments: AzureRoleAssignment[] = [];
  public resolvedResources: Map<string, string> = new Map(); // Cache for resolved resource names
  public isLoadingResources: boolean = false;
  public blueteam: boolean = false;
  @ViewChild(MatSort, {static: true}) sort!: MatSort;
  constructor(
    private service: DatabaseService,
    public dialogRef: MatDialogRef<UsersdialogComponent>,
    public utils: UtilitiesService,
    private localSt:LocalStorageService,
    @Inject(MAT_DIALOG_DATA) public data: {user: UsersItem, showPortalLink: boolean}
  ) {
    this.user = data.user;
    this.showPortalLink = data.showPortalLink;
    this.blueteam = this.localSt.retrieve('blueteam');
    this.service.getUserPolicies(this.user.objectId).subscribe((data: PolicyItem[]) => this.policies = data);
    this.service.getNetworkLocations().subscribe((data: NetworkLocationList) => this.policyLocations = data);
    this.service.getUserPIMassignments(this.user.objectId).subscribe((data: PIMRoleAssignment[]) => this.PIMgroupAssignments = data);
    this.service.getUserAzureRoleAssignments(this.user.objectId).subscribe((data: AzureRoleAssignment[]) => this.azureRoleAssignments = data);
    this.service.getUserAccessPackages(this.user.objectId).subscribe((data: AccessPackagePolicy[]) => {
      this.accessPackages = data;
      this.resolveAccessPackageResourceNames();
    });
  }

  public resolveAccessPackageResourceNames(): void {
    this.isLoadingResources = true;
    const observables: any[] = [];

    // Collect all unique originIds that need to be resolved
    const resourcesToResolve: { originId: string; originSystem: string }[] = [];

    this.accessPackages.forEach(policy => {
      if (policy.accessPackage.resourceRoleScopes) {
        policy.accessPackage.resourceRoleScopes.forEach(roleScope => {
          const scope = roleScope.scope && roleScope.scope.length > 0 ? roleScope.scope[0] : null;
          if (scope && (scope.originSystem === 'AadGroup' || scope.originSystem === 'AadApplication')) {
            // Check if we haven't already added this resource
            if (!resourcesToResolve.some(r => r.originId === scope.originId && r.originSystem === scope.originSystem)) {
              resourcesToResolve.push({
                originId: scope.originId,
                originSystem: scope.originSystem
              });
            }
          }
        });
      }
    });

    // Create observables to fetch each resource
    resourcesToResolve.forEach(resource => {
      if (resource.originSystem === 'AadGroup') {
        observables.push(
          this.service.getGroupResolve(resource.originId).pipe(
            catchError(err => {
              console.warn(`Failed to fetch group ${resource.originId}:`, err);
              return of(null);
            })
          )
        );
      } else if (resource.originSystem === 'AadApplication') {
        observables.push(
          this.service.getServicePrincipal(resource.originId).pipe(
            catchError(err => {
              console.warn(`Failed to fetch service principal ${resource.originId}:`, err);
              return of(null);
            })
          )
        );
      }
    });

    // Execute all API calls in parallel
    if (observables.length > 0) {
      forkJoin(observables).subscribe(
        (results: any[]) => {
          // Store resolved names in the cache
          results.forEach((result, index) => {
            if (result && result.displayName) {
              const resource = resourcesToResolve[index];
              this.resolvedResources.set(resource.originId, result.displayName);
            }
          });
          this.isLoadingResources = false;
        },
        (error) => {
          console.error('Error resolving resource names:', error);
          this.isLoadingResources = false;
        }
      );
    } else {
      this.isLoadingResources = false;
    }
  }

  /**
   * Gets a formatted list of resources from an access package with resolved names
   * @param accessPackage The access package details
   * @returns Array of resource descriptions
   */
  public getAccessPackageResources(accessPackage: AccessPackageDetails): string[] {
    if (!accessPackage.resourceRoleScopes || accessPackage.resourceRoleScopes.length === 0) {
      return [];
    }

    return accessPackage.resourceRoleScopes.map(roleScope => {
      const role = roleScope.role && roleScope.role.length > 0 ? roleScope.role[0] : null;
      const scope = roleScope.scope && roleScope.scope.length > 0 ? roleScope.scope[0] : null;

      if (!role || !scope) {
        return 'Unknown resource';
      }

      // Format based on origin system
      switch (scope.originSystem) {
        case 'AadGroup':
          const groupName = this.resolvedResources.get(scope.originId) || 'Loading...';
          return `Group: ${groupName} (${role.displayName})`;

        case 'AadApplication':
          const appName = this.resolvedResources.get(scope.originId) || 'Loading...';
          return `Application: ${appName} (${role.displayName})`;

        case 'SharePointOnline':
          // Extract site name from originId if it's a URL
          let siteName = scope.originId;
          try {
            const url = new URL(scope.originId);
            siteName = url.pathname.split('/').filter(p => p).pop() || siteName;
          } catch (e) {
            // Not a URL, use as-is
          }
          return `SharePoint Site: ${siteName} (${role.displayName})`;

        default:
          return `${scope.originSystem}: ${role.displayName}`;
      }
    });
  }

  public requiresRoleApproval(roleDefinition: PIMRoleDefinition | null | undefined): boolean | null {
    return roleDefinition ? this.utils.requiresApproval(roleDefinition) : null;
  }
}
