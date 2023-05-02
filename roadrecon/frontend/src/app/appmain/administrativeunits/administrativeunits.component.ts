import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { AdministrativeUnitsDataSource } from './administrativeunits-datasource';
import { DatabaseService, AdministrativeUnitsItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-administrativeunits',
  templateUrl: './administrativeunits.component.html',
  styleUrls: ['./administrativeunits.component.less'],
  providers: [DatabaseService]
})
export class AdministrativeUnitsComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<AdministrativeUnitsItem>;
  dataSource: MatTableDataSource<AdministrativeUnitsItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'description', 'membershipRule'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getAdministrativeUnits().subscribe((data: AdministrativeUnitsItem[]) => this.dataSource.data = data);
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
