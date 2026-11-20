import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator, PageEvent } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
import { DatabaseService, UsersItem, UsersList } from '../aadobjects.service'
import { LocalStorageService } from 'ngx-webstorage';

@Component({
  standalone: false,
  selector: 'app-users',
  templateUrl: './users.component.html',
  styleUrls: ['./users.component.less'],
  providers: [DatabaseService]
})
export class UsersComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator!: MatPaginator;
  @ViewChild(MatSort) sort!: MatSort;
  @ViewChild(MatTable) table!: MatTable<UsersItem>;
  dataSource!: MatTableDataSource<UsersItem>;
  totalRecords: number = 0;
  pageIndex: number = 0;
  ssp: boolean = false;
  searchfilter: string = '';

  constructor(private service: DatabaseService, private localSt:LocalStorageService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'userPrincipalName', 'accountEnabled',  'mail', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'userType'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.ssp = this.localSt.retrieve('paging');
    if(!this.ssp){
      this.service.getUsers().subscribe((data: UsersItem[]) => {
        this.dataSource.data = data;
        this.totalRecords = data.length;
      });
    }else{
      this.loadData(1);
    }
    this.localSt.observe('mfa')
      .subscribe((value) => {
        this.updateMfaColumn(value);
      });
    this.updateMfaColumn(this.localSt.retrieve('mfa'));
  }

  loadData(page: number = 1) {
    this.service.getUsersPaged({
        page: page,
        pageSize: this.paginator?.pageSize,
        sortColumn: this.sort?.active,
        sortDirection: this.sort?.direction,
        search: this.searchfilter,
      }).subscribe((data: UsersList) => {
      this.dataSource.data = data.items;
      this.totalRecords = data.count;
      this.pageIndex = page - 1;
    });
  }

  onPageChange(event: PageEvent): void {
    if(this.ssp) this.loadData(event.pageIndex + 1);
  }

  updateMfaColumn(value: any) {
    if(value){
      if(!this.displayedColumns.includes('strongAuthenticationDetail')){
        this.displayedColumns.push('strongAuthenticationDetail')
      }
    }else{
      if(this.displayedColumns.includes('strongAuthenticationDetail')){
        this.displayedColumns.splice(this.displayedColumns.indexOf('strongAuthenticationDetail'), 1)
      }
    }
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
