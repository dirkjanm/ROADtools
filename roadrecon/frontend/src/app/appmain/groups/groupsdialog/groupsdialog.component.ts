import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { GroupsItem } from '../../aadobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
import { LocalStorageService } from 'ngx-webstorage';
@Component({
  template: ''
})
export class GroupsdialogInitComponent implements OnInit {
  user: GroupsItem;
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
      .subscribe((data: { user: GroupsItem }) => {
        const dialogRef = this.dialog.open(GroupsdialogComponent, {
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
  selector: 'app-groupsdialog',
  templateUrl: './groupsdialog.component.html',
  styleUrls: ['./groupsdialog.component.less']
})
export class GroupsdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description']
  public displayedColumnsUsers: string[] = ['displayName', 'userPrincipalName', 'userType']
  public displayedColumnsServicePrincipal: string[] = ['displayName', 'servicePrincipalType']
  public displayedColumnsOwners: string[] = ['displayName', 'userPrincipalName']
  public displayedColumnsDevices: string[] = ['displayName', 'deviceModel', 'deviceOSType', 'deviceTrustType'];
  public showPortalLink: boolean;

  @ViewChild(MatSort, {static: true}) sort: MatSort;
  constructor(
    public dialogRef: MatDialogRef<GroupsdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public group: GroupsItem,
    private localSt: LocalStorageService
  ) {
    this.showPortalLink = this.localSt.retrieve('portallinks');
  }

}
