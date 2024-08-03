import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { UsersDataSource } from './users-datasource';
import { DatabaseService, UsersItem } from '../aadobjects.service';
import { LocalStorageService } from 'ngx-webstorage';
import {MatInput} from '@angular/material/input';
import {FormControl} from '@angular/forms';
// import
@Component({
  selector: 'app-users',
  templateUrl: './users.component.html',
  styleUrls: ['./users.component.less'],
  providers: [DatabaseService]
})
export class UsersComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<UsersItem>;
  readonly filterControl = new FormControl('');
  dataSource: MatTableDataSource<UsersItem>;

  constructor(private service: DatabaseService, private localSt:LocalStorageService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'userPrincipalName', 'accountEnabled',  'mail', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'userType'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.loadData();
    this.localSt.observe('mfa')
      .subscribe((value) => {
        this.updateMfaColumn(value);
      });
    this.updateMfaColumn(this.localSt.retrieve('mfa'));
  }

  updateMfaColumn(value) {
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
    this.dataSource.sort = this.sort;
    this.dataSource.paginator = this.paginator;
    this.table.dataSource = this.dataSource;

    this.filterControl.valueChanges.subscribe(() => {
      this.loadData();
    });
    this.sort.sortChange.subscribe(() => {
      this.paginator.pageIndex = 0; // Reset to first page on sort change
      this.loadData();
    });

    this.paginator.page.subscribe(() => {
      this.loadData();
    });
  }

  loadData() {
    let filterValue = this.filterControl.value;
    if (filterValue) {
      filterValue = filterValue.trim().toLowerCase();
    }
    this.service.getUsers(
      {
        page: this.paginator?.pageIndex,
        pageSize: this.paginator?.pageSize,
        sortField: this.sort?.active,
        sortDirection: this.sort?.direction,
        contains: filterValue,
      }
    ).subscribe((data: UsersItem[]) => this.dataSource.data = data);
  }

  loadData() {
    this.service.getUsers(this.paginator?.pageIndex, this.paginator?.pageSize, this.sort?.active, this.sort?.direction)
      .subscribe((data: UsersItem[]) => this.dataSource.data = data);
  }
}
