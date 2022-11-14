import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { UsersDataSource } from './users-datasource';
import { DatabaseService, UsersItem } from '../aadobjects.service'
import { LocalStorageService } from 'ngx-webstorage';
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
  dataSource: MatTableDataSource<UsersItem>;

  constructor(private service: DatabaseService, private localSt:LocalStorageService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'userPrincipalName', 'accountEnabled',  'mail', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled', 'userType'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getUsers().subscribe((data: UsersItem[]) => this.dataSource.data = data);
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
  }

  applyFilter(filterValue: string) {
    filterValue = filterValue.trim(); // Remove whitespace
    filterValue = filterValue.toLowerCase(); // Datasource defaults to lowercase matches
    this.dataSource.filter = filterValue;
  }
}
