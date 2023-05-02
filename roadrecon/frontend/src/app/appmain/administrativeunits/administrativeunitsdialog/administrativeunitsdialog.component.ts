import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AdministrativeUnitsItem } from '../../aadobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
@Component({
  template: ''
})
export class AdministrativeUnitsdialogInitComponent implements OnInit {
  user: AdministrativeUnitsItem;
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
      .subscribe((data: { user: AdministrativeUnitsItem }) => {
        const dialogRef = this.dialog.open(AdministrativeUnitsdialogComponent, {
          data: data.user
        });
        dialogRef.afterClosed().subscribe(result => {
          console.log(this.router.url);
          console.log(this.myurl);
          if(this.router.url == this.myurl){
            this.location.back();
          }

        });
      });
  }

}

@Component({
  selector: 'app-administrativeunitsdialog',
  templateUrl: './administrativeunitsdialog.component.html',
  styleUrls: ['./administrativeunitsdialog.component.less']
})
export class AdministrativeUnitsdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description']
  public displayedColumnsUsers: string[] = ['displayName', 'description', 'userType']
  public displayedColumnsServicePrincipal: string[] = ['displayName']
  public displayedColumnsOwners: string[] = ['displayName', 'userPrincipalName']
  public displayedColumnsDevices: string[] = ['displayName', 'deviceModel', 'deviceOSType', 'deviceTrustType'];

  @ViewChild(MatSort, {static: true}) sort: MatSort;
  constructor(
    public dialogRef: MatDialogRef<AdministrativeUnitsdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public administrativeUnit: AdministrativeUnitsItem
  ) { }

}
