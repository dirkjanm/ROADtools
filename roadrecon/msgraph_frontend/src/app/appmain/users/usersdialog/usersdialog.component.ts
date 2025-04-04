import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { UsersItem } from '../../msgraphobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
@Component({
  template: ''
})
export class UsersdialogInitComponent implements OnInit {
  user: UsersItem;
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
      .subscribe((data: { user: UsersItem }) => {
        const dialogRef = this.dialog.open(UsersdialogComponent, {
          data: data.user
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
  selector: 'app-usersdialog',
  templateUrl: './usersdialog.component.html',
  styleUrls: ['./usersdialog.component.less']
})
export class UsersdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description']
  public displayedColumnsServicePrincipals: string[] = ['displayName', 'accountEnabled', 'servicePrincipalType', 'appOwnerOrganizationId','passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];
  public displayedColumnsDevices: string[] = ['displayName', 'manufacturer', 'accountEnabled', 'model', 'operatingSystem', 'operatingSystemVersion', 'trustType', 'isCompliant', 'isManaged', 'isRooted', 'onPremisesSyncEnabled'];
  // TO DO: Add in new properties such as api, spa and web - api has oauth2permissions which has been removed from here for now
  public displayedColumnsApplications: string[] = ['displayName', 'passwordCredentials', 'keyCredentials', 'appRoles'];

  @ViewChild(MatSort, {static: true}) sort: MatSort;
  constructor(
    public dialogRef: MatDialogRef<UsersdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public user: UsersItem
  ) { }

}
