import { Component, OnInit, Inject, ViewChild } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { ApplicationsItem, appMetadata } from '../../aadobjects.service'
import { MatDialog, MatDialogRef, MAT_DIALOG_DATA } from '@angular/material/dialog';
import { MatSort } from '@angular/material/sort';
import { Location } from '@angular/common';
@Component({
  template: ''
})
export class ApplicationsdialogInitComponent implements OnInit {
  application: ApplicationsItem;
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
      .subscribe((data: { application: ApplicationsItem }) => {
        const dialogRef = this.dialog.open(ApplicationsdialogComponent, {
          data: data.application
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
  selector: 'app-applicationsdialog',
  templateUrl: './applicationsdialog.component.html',
  styleUrls: ['./applicationsdialog.component.less']
})
export class ApplicationsdialogComponent {
  public displayedColumns: string[] = ['displayName', 'description']
  public displayedColumnsOwners: string[] = ['displayName', 'userPrincipalName']
  public displayedColumnsAppRoles: string[] = ['value','displayName', 'description', 'id', 'allowedMemberTypes']
  public displayedColumnsOAuth2: string[] = ['value', 'userConsentDisplayName','userConsentDescription', 'adminConsentDisplayName', 'adminConsentDescription', 'id', 'type']
  public metadata: object[] = [];
  @ViewChild(MatSort, {static: true}) sort: MatSort;
  constructor(
    public dialogRef: MatDialogRef<ApplicationsdialogComponent>,
    @Inject(MAT_DIALOG_DATA) public application: ApplicationsItem
  ) {
    if (application.appMetadata && application.appMetadata.data.length > 0){
      for( let metadata of application.appMetadata.data){
        let out = {}
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
        console.log(out);
        this.metadata.push(out);
      }
    }
  }
}
