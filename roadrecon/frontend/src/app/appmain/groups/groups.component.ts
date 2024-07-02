import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { GroupsDataSource } from './groups-datasource';
import {DatabaseService, DevicesItem, GroupsItem} from '../aadobjects.service';
import {FormControl} from '@angular/forms';
// import
@Component({
  selector: 'app-groups',
  templateUrl: './groups.component.html',
  styleUrls: ['./groups.component.less'],
  providers: [DatabaseService]
})
export class GroupsComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<GroupsItem>;
  readonly filterControl = new FormControl('');
  dataSource: MatTableDataSource<GroupsItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'description', 'groupTypes', 'dirSyncEnabled', 'mail', 'isPublic', 'isAssignableToRole', 'membershipRule'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.loadData();
  }

  ngAfterViewInit() {
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
    this.service.getGroups(
      {
        page: this.paginator?.pageIndex,
        pageSize: this.paginator?.pageSize,
        sortField: this.sort?.active,
        sortDirection: this.sort?.direction,
        contains: filterValue,
      }
    ).subscribe((data: GroupsItem[]) => this.dataSource.data = data);
  }
}
