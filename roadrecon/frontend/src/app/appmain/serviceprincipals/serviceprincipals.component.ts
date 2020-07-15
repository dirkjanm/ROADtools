import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { ServicePrincipalsDataSource } from './serviceprincipals-datasource';
import { DatabaseService, ServicePrincipalsItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-serviceprincipals',
  templateUrl: './serviceprincipals.component.html',
  styleUrls: ['./serviceprincipals.component.less'],
  providers: [DatabaseService]
})
export class ServicePrincipalsComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<ServicePrincipalsItem>;
  dataSource: MatTableDataSource<ServicePrincipalsItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'servicePrincipalType', 'publisherName', 'microsoftFirstParty', 'passwordCredentials', 'keyCredentials', 'appRoles', 'oauth2Permissions', 'owner'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getServicePrincipals().subscribe((data: ServicePrincipalsItem[]) => this.dataSource.data = data);
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
