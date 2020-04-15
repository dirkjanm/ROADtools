import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { ApplicationsDataSource } from './applications-datasource';
import { DatabaseService, ApplicationsItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-applications',
  templateUrl: './applications.component.html',
  styleUrls: ['./applications.component.less'],
  providers: [DatabaseService]
})
export class ApplicationsComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<ApplicationsItem>;
  dataSource: MatTableDataSource<ApplicationsItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'availableToOtherTenants', 'homepage', 'publicClient', 'oauth2AllowImplicitFlow', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions', 'ownerUsers'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getApplications().subscribe((data: ApplicationsItem[]) => this.dataSource.data = data);
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
