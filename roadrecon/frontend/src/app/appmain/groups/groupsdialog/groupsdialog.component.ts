import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { GroupsItem, DatabaseService, PIMResource, PIMRoleDefinition, PIMRoleAssignment, AccessPackagePolicy, AccessPackageDetails, AzureRoleAssignment, AzureScopeInfo } from '../../aadobjects.service'
import { UtilitiesService } from '../../utils.service';
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
import { LocalStorageService } from 'ngx-webstorage';
@Component({
  standalone: false,
  template: ''
})
export class GroupsdialogInitComponent implements OnInit {
  group!: GroupsItem;
  myurl: string;
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    public dialog: MatDialog,
    private location: Location
  ) {
    this.myurl = this.router.url;
  }

  ngOnInit() {
    this.route.data
      .subscribe((data: any) => {
        const dialogRef = this.dialog.open(GroupsdialogComponent, {
          data: data.group
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
  selector: 'app-groupsdialog',
  templateUrl: './groupsdialog.component.html',
  styleUrls: ['./groupsdialog.component.less'],
  providers: [DatabaseService]
})
export class GroupsdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description'];
  public displayedColumnsUsers: string[] = ['displayName', 'userPrincipalName', 'userType'];
  public displayedColumnsServicePrincipal: string[] = ['displayName', 'servicePrincipalType'];
  public displayedColumnsOwners: string[] = ['displayName', 'userPrincipalName'];
  public displayedColumnsDevices: string[] = ['displayName', 'deviceModel', 'deviceOSType', 'deviceTrustType'];
  public displayedColumnsRoles: string[] = ['displayName', 'description'];
  public pimMemberColumns: string[] = ['subject', 'duration', 'status'];
  public pimOwnerColumns: string[] = ['subject', 'duration', 'status'];
  public showPortalLink: boolean;
  public displayedColumnsPim: string[] = ['resourceType', 'resourceAndRole', 'assignmentState', 'approval', 'duration'];
  public displayedColumnsAccessPackage: string[] = ['packageName', 'resources', 'approval', 'duration'];
  public displayedColumnsAzureRole: string[] = ['role', 'scopeType', 'scopeDetails'];
  public pimGroupDetails: PIMResource | null = null;
  public azureRoleAssignments: AzureRoleAssignment[] = [];
  public blueteam: boolean = false;

  @ViewChild(MatSort, {static: true}) sort!: MatSort;
  constructor(
    private service: DatabaseService,
    public dialogRef: MatDialogRef<GroupsdialogComponent>,
    public utils: UtilitiesService,
    @Inject(MAT_DIALOG_DATA) public group: GroupsItem,
    private localSt: LocalStorageService
  ) {
    this.showPortalLink = this.localSt.retrieve('portallinks');
    this.service.getGroupPIMResource(this.group.objectId).subscribe((data: PIMResource) => this.pimGroupDetails = data);
    this.service.getGroupAzureRoleAssignments(this.group.objectId).subscribe((data: AzureRoleAssignment[]) => this.azureRoleAssignments = data);
    this.blueteam = this.localSt.retrieve('blueteam');
  }
  getAssignmentSubject(assignment: PIMRoleAssignment): { subject: any; type: 'User' | 'Group' | 'ServicePrincipal' } | null {
    if (assignment.subjectUser && assignment.subjectUser.length > 0) {
      return { subject: assignment.subjectUser[0], type: 'User' };
    }
    if (assignment.subjectGroup && assignment.subjectGroup.length > 0) {
      return { subject: assignment.subjectGroup[0], type: 'Group' };
    }
    if (assignment.subjectServicePrincipal && assignment.subjectServicePrincipal.length > 0) {
      return { subject: assignment.subjectServicePrincipal[0], type: 'ServicePrincipal' };
    }
    return null;
  }

  getEligibleAssignments(roleDefinition: PIMRoleDefinition | null | undefined): PIMRoleAssignment[] {
    return (roleDefinition?.roleAssignments || []).filter(a => a.assignmentState === 'Eligible');
  }

  getActiveAssignments(roleDefinition: PIMRoleDefinition | null | undefined): PIMRoleAssignment[] {
    return (roleDefinition?.roleAssignments || []).filter(a => a.assignmentState === 'Active');
  }

  // Reuse existing utility function directly
  requiresGroupRoleApproval(roleDefinition: PIMRoleDefinition | null | undefined): boolean | null {
    return roleDefinition ? this.utils.requiresApproval(roleDefinition) : null;
  }

  formatSubjectDisplay(subject: any, type?: 'User' | 'Group' | 'ServicePrincipal'): string {
    if (!subject) {
      return 'Unknown';
    }

    const displayName = subject.displayName || 'Unknown';

    switch (type) {
      case 'User':
        return subject.userPrincipalName ? `${displayName} (${subject.userPrincipalName})` : displayName;
      case 'Group':
        return displayName;
      case 'ServicePrincipal':
        return subject.appId ? `${displayName} (${subject.appId})` : displayName;
      default:
        return displayName;
    }
  }

  getRoleDefinition(roleName: string): PIMRoleDefinition | null {
    if (!this.pimGroupDetails || !this.pimGroupDetails.roleDefinitions) {
      return null;
    }
    return this.pimGroupDetails.roleDefinitions.find(r => r.displayName === roleName) || null;
  }

  formatDateTime(date: string | null | undefined): string | null {
    return this.utils.formatDateTime(date);
  }
}
