import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { UsersItem } from '../../aadobjects.service'
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
  public displayedColumnsServicePrincipals: string[] = ['displayName', 'publisherName', 'microsoftFirstParty', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];
  public displayedColumnsDevices: string[] = ['displayName', 'deviceManufacturer', 'accountEnabled', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'isManaged', 'isRooted'];
  public displayedColumnsApplications: string[] = ['displayName', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions'];

  @ViewChild(MatSort, {static: true}) sort: MatSort;
  constructor(
    public dialogRef: MatDialogRef<UsersdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public user: UsersItem
  ) { }

}
