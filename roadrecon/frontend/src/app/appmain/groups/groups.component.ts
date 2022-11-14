import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { GroupsDataSource } from './groups-datasource';
import { DatabaseService, GroupsItem } from '../aadobjects.service'
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
  dataSource: MatTableDataSource<GroupsItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'description', 'groupTypes', 'dirSyncEnabled', 'mail', 'isPublic', 'isAssignableToRole', 'membershipRule'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getGroups().subscribe((data: GroupsItem[]) => this.dataSource.data = data);
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
