import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
import {DatabaseService, DevicesItem, UsersItem} from '../aadobjects.service';
import {FormControl} from '@angular/forms';
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
  readonly filterControl = new FormControl('');
  dataSource: MatTableDataSource<DevicesItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'deviceManufacturer', 'accountEnabled', 'deviceModel', 'deviceOSType', 'deviceOSVersion', 'deviceTrustType', 'isCompliant', 'isManaged', 'isRooted'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.loadData();
  }

  ngAfterViewInit() {
    this.dataSource.sort = this.sort;
    this.dataSource.paginator = this.paginator;
    this.table.dataSource = this.dataSource;

    this.filterControl.valueChanges.subscribe(() => this.loadData());
    this.sort.sortChange.subscribe(() => {
      this.paginator.pageIndex = 0; // Reset to first page on sort change
      this.loadData();
    });
    this.paginator.page.subscribe(() => this.loadData());
  }

  loadData() {
    let filterValue = this.filterControl.value;
    if (filterValue) {
      filterValue = filterValue.trim().toLowerCase();
    }
    this.service.getDevices(
      {
        page: this.paginator?.pageIndex,
        pageSize: this.paginator?.pageSize,
        sortField: this.sort?.active,
        sortDirection: this.sort?.direction,
        contains: filterValue,
      }
    ).subscribe((data: DevicesItem[]) => this.dataSource.data = data);
  }
}
