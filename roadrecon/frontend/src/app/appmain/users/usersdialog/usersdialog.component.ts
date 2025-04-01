import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { UsersItem } from '../../aadobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
import { LocalStorageService } from 'ngx-webstorage';

@Component({
  template: ''
})
export class UsersdialogInitComponent implements OnInit {
  user: UsersItem;
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
      .subscribe((data: { user: UsersItem }) => {
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
  selector: 'app-usersdialog',
  templateUrl: './usersdialog.component.html',
  styleUrls: ['./usersdialog.component.less']
})
export class UsersdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description']
  public displayedColumnsServicePrincipals: string[] = ['displayName', 'publisherName', 'microsoftFirstParty', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];
  public displayedColumnsDevices: string[] = ['displayName', 'deviceManufacturer', 'accountEnabled', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'isManaged', 'isRooted'];
  public displayedColumnsApplications: string[] = ['displayName', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];
  public showPortalLink: boolean;
  public user: UsersItem;
  @ViewChild(MatSort, {static: true}) sort: MatSort;
  constructor(
    public dialogRef: MatDialogRef<UsersdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: {user: UsersItem, showPortalLink: boolean}
  ) {
    this.user = data.user;
    this.showPortalLink = data.showPortalLink;
  }

}
