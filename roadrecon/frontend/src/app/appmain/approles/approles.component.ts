import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { RolesDataSource } from './roles-datasource';
import { DatabaseService, AppRolesItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-roles',
  templateUrl: './approles.component.html',
  styleUrls: ['./approles.component.less'],
  providers: [DatabaseService]
})
export class AppRolesComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<AppRolesItem>;
  dataSource: MatTableDataSource<AppRolesItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['pname', 'ptype', 'app', 'value', 'desc'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getAppRoles().subscribe((data: AppRolesItem[]) => this.dataSource.data = data);
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
