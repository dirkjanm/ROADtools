import { Component, OnInit, Inject } from '@angular/core';
import { DatabaseService, TenantDetail, DirectorySetting, TenantStats, AuthorizationPolicy } from '../aadobjects.service'
import {MatDialog, MatDialogRef, MAT_DIALOG_DATA} from '@angular/material/dialog';

@Component({
  selector: 'app-index',
  templateUrl: './index.component.html',
  styleUrls: ['./index.component.less'],
  providers: [DatabaseService]
})
export class IndexComponent implements OnInit {
  public tenantdetails: TenantDetail;
  public directorysettings: DirectorySetting;
  public tenantstats: TenantStats;
  public authorizationPolicy: AuthorizationPolicy;
  public hasSelfConsentPolicy: boolean = false;
  public displayedColumns: string[] = ['name', 'type', 'capabilities', 'properties']
  constructor(private service: DatabaseService, public dialog: MatDialog) {  }

  ngOnInit(): void {
    this.service.getTenantDetail().subscribe((data: TenantDetail) => this.tenantdetails = data);
    this.service.getDirectorySetting().subscribe((data: DirectorySetting) => this.directorysettings = data);
    this.service.getTenantStats().subscribe((data: TenantStats) => this.tenantstats = data);
    this.service.getAuthorizationPolicies().subscribe((data: AuthorizationPolicy[]) => {
      if(data.length > 0){
        this.authorizationPolicy = data[0];
        data[0].permissionGrantPolicyIdsAssignedToDefaultUserRole.forEach((value: string) => {
          // Check this explicitly because of the new elements here
          if (value.indexOf("ManagePermissionGrantsForSelf") != -1){
            this.hasSelfConsentPolicy = true;
          }
        });
      }
    });
  }

  showDetails(): void {
    const dialogRef = this.dialog.open(DetailDialog, {
      data: this.tenantdetails
    });

  }
}

@Component({
  template: `<h1 mat-dialog-title>Tenant details</h1>
             <mat-dialog-content><p appJsonFormat [json]="details"></p>
             </mat-dialog-content>`,
})
export class DetailDialog {

  constructor(
    public dialogRef: MatDialogRef<DetailDialog>,
    @Inject(MAT_DIALOG_DATA) public details: TenantDetail) {}

}
