import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
import { DatabaseService, DevicesItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-devices',
  templateUrl: './devices.component.html',
  styleUrls: ['./devices.component.less'],
  providers: [DatabaseService]
})
export class DevicesComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<DevicesItem>;
  dataSource: MatTableDataSource<DevicesItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'deviceManufacturer', 'accountEnabled', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'isManaged', 'isRooted'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getDevices().subscribe((data: DevicesItem[]) => this.dataSource.data = data);
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
