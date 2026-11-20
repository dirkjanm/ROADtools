import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ServicePrincipalsItem, AppRolesItem, DatabaseService, TenantDetail, AzureRoleAssignment, AzureScopeInfo, ServicePrincipalNhiDetail } from '../../aadobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { UtilitiesService } from '../../utils.service';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
@Component({
  standalone: false,
  template: ''
})
export class ServicePrincipalsdialogInitComponent implements OnInit {
  sp!: ServicePrincipalsItem;
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
        const dialogRef = this.dialog.open(ServicePrincipalsdialogComponent, {
          data: data.sp
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
  selector: 'app-serviceprincipalsdialog',
  templateUrl: './serviceprincipalsdialog.component.html',
  styleUrls: ['./serviceprincipalsdialog.component.less'],
  providers: [DatabaseService]
})
export class ServicePrincipalsdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description'];
  public displayedColumnsOwners: string[] = ['displayName', 'userPrincipalName'];
  public displayedColumnsAppRoles: string[] = ['value','displayName', 'description', 'id', 'allowedMemberTypes'];
  public displayedColumnsOAuth2: string[] = ['value', 'userConsentDisplayName','userConsentDescription', 'adminConsentDisplayName', 'adminConsentDescription', 'id', 'type'];
  public displayedColumnsAppRolesAssigned: string[] =  ['pname', 'ptype', 'value', 'desc'];
  public displayedColumnsAppRolesAssignedTo: string[] =  ['pname', 'ptype', 'value', 'app', 'desc'];
  public displayedColumnsAccessPackage: string[] = ['packageName', 'resources', 'approval', 'duration'];
  public displayedColumnsAzureRole: string[] = ['role', 'scopeType', 'scopeDetails'];
  public displayedColumnsNhiFindings: string[] = ['severity', 'category', 'title', 'detail', 'recommendation'];
  public metadata: any[] = [];
  public approlesgiven: AppRolesItem[] = [];
  public approlesgivento: AppRolesItem[] = [];
  public tenantdetails!: TenantDetail;
  public azureRoleAssignments: AzureRoleAssignment[] = [];
  public nhiDetail: ServicePrincipalNhiDetail | null = null;
  @ViewChild(MatSort, {static: true}) sort!: MatSort;
  constructor(
    public dialogRef: MatDialogRef<ServicePrincipalsdialogComponent>,
    private service: DatabaseService,
    public utils: UtilitiesService,
    @Inject(MAT_DIALOG_DATA) public sp: ServicePrincipalsItem
  ) {
    if (sp.appMetadata && sp.appMetadata.data.length > 0){
      for( let metadata of (sp.appMetadata.data as any[])){
        let out: any = {}
        let innerdata: string;
        let jsondata: object;
        try {
          innerdata = atob(metadata['value'])
          try {
            jsondata = JSON.parse(innerdata);
            out['value'] = jsondata;
            out['isJSON'] = true;
          }
          catch(error){
            out['value'] = innerdata;
            out['isJSON'] = false;
          }
        }
        catch(error) {
          innerdata = metadata['value'];
          out['value'] = innerdata;
          out['isJSON'] = false;
        }
        out['key'] = metadata['key'];
        this.metadata.push(out);
      }
    }
    if (sp.appRolesAssigned && sp.appRolesAssigned.length > 0){
      this.service.getAppRolesByResource(sp.objectId).subscribe((data: AppRolesItem[]) => this.approlesgiven.push(...data));
    }
    if (sp.appRolesAssignedTo && sp.appRolesAssignedTo.length > 0){
      this.service.getAppRolesByPrincipal(sp.objectId).subscribe((data: AppRolesItem[]) => this.approlesgivento.push(...data));
    }
    this.service.getTenantDetail().subscribe((data: TenantDetail) => this.tenantdetails = data);
    this.service.getServicePrincipalAzureRoleAssignments(this.sp.objectId).subscribe((data: AzureRoleAssignment[]) => this.azureRoleAssignments = data);
    this.service.getServicePrincipalNhi(this.sp.objectId).subscribe(
      (data: ServicePrincipalNhiDetail) => {
        this.nhiDetail = data;
      },
      () => {
        this.nhiDetail = null;
      }
    );

  }
}
