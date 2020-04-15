import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { RolesDataSource } from './roles-datasource';
import { DatabaseService, OAuth2PermissionsItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-roles',
  templateUrl: './oauth2permissions.component.html',
  styleUrls: ['./oauth2permissions.component.less'],
  providers: [DatabaseService]
})
export class Oauth2permissionsComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<OAuth2PermissionsItem>;
  dataSource: MatTableDataSource<OAuth2PermissionsItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['type', 'userdisplayname', 'sourceapplication', 'targetapplication', 'scope', 'expiry'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getOAuth2Permissions().subscribe((data: OAuth2PermissionsItem[]) => this.dataSource.data = data);
  }

  ngAfterViewInit() {
    this.dataSource.sort = this.sort;
    this.dataSource.paginator = this.paginator;
    this.table.dataSource = this.dataSource;
  }

  applyFilter(filterValue: string) {
    filterValue = filterValue.trim(); // Remove whitespace
    filterValue = filterValue.toLowerCase(); // Datasource defaults to lowercase matches
    this.dataSource.filter = filterValue;
  }
}
