import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator, PageEvent } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
import { DatabaseService, GroupsItem, GroupsList } from '../aadobjects.service'
import { LocalStorageService } from 'ngx-webstorage';

@Component({
  standalone: false,
  selector: 'app-groups',
  templateUrl: './groups.component.html',
  styleUrls: ['./groups.component.less'],
  providers: [DatabaseService]
})
export class GroupsComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatTable) table!: MatTable<GroupsItem>;
  dataSource!: MatTableDataSource<GroupsItem>;
  totalRecords: number = 0;
  pageIndex: number = 0;
  ssp: boolean = false;
  searchfilter: string = '';

  constructor(private service: DatabaseService, private localSt:LocalStorageService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'description', 'groupTypes', 'dirSyncEnabled', 'mail', 'isPublic', 'isAssignableToRole', 'membershipRule'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.ssp = this.localSt.retrieve('paging');
    if(!this.ssp){
      this.service.getGroups().subscribe((data: GroupsItem[]) => {
        this.dataSource.data = data;
        this.totalRecords = data.length;
      });
    }else{
      this.loadData(1);
    }
  }

  loadData(page: number = 1) {
    this.service.getGroupsPaged({
        page: page,
        pageSize: this.paginator?.pageSize,
        sortColumn: this.sort?.active,
        sortDirection: this.sort?.direction,
        search: this.searchfilter,
      }).subscribe((data: GroupsList) => {
      this.dataSource.data = data.items;
      this.totalRecords = data.count;
      this.pageIndex = page - 1;
    });
  }

  onPageChange(event: PageEvent): void {
    if(this.ssp) this.loadData(event.pageIndex + 1);
  }

  ngAfterViewInit() {
    this.sort.sortChange.subscribe(() => {
      this.paginator.pageIndex = 0; // Reset to first page on sort change
      this.loadData(1);
    });
    // Connect paginator only when paging is not used
    if (!this.ssp){
      this.dataSource.paginator = this.paginator;
      this.dataSource.sort = this.sort;
    }
    this.table.dataSource = this.dataSource;
    this.dataSource.sortingDataAccessor = (data: any, sortHeaderId: string): string => {
      if (typeof data[sortHeaderId] === 'string') {
        return data[sortHeaderId].toLocaleLowerCase();
      }
      return data[sortHeaderId];
    };
  }

  applyFilter(filterValue: string) {
    if(this.ssp){
      filterValue = filterValue.trim().toLowerCase(); // Datasource defaults to lowercase matches
      this.searchfilter = filterValue;
      this.loadData(1);
    }else{
      filterValue = filterValue.trim().toLowerCase(); // Datasource defaults to lowercase matches
      this.dataSource.filter = filterValue;
    }
  }
}
