import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { GroupsItem } from '../../aadobjects.service';
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
  showPortalLink: boolean;

  constructor(
    private route: ActivatedRoute,
    private router: Router,
    public dialog: MatDialog,
    private location: Location,
    private localSt: LocalStorageService
  ) {
    this.myurl = this.router.url;
    this.showPortalLink = this.localSt.retrieve('portallinks');
  }

  ngOnInit() {
    this.route.data
      .subscribe((data: { user: GroupsItem }) => {
        const dialogRef = this.dialog.open(GroupsdialogComponent, {
          data: {
            group: data.user,
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
  public group: GroupsItem;

  @ViewChild(MatSort, { static: true }) sort: MatSort;

  constructor(
    public dialogRef: MatDialogRef<GroupsdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public data: { group: GroupsItem, showPortalLink: boolean }
  ) {
    this.group = data.group;
    this.showPortalLink = data.showPortalLink;
  }
}
