import { AfterViewInit, Component, OnInit, ViewChild, Input } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
import { DirectoryRolesItem, UsersItem, ServicePrincipalsItem } from '../aadobjects.service'
import { LocalStorageService } from 'ngx-webstorage';

// import
@Component({
  selector: 'role-table',
  templateUrl: './roletable.component.html',
  styleUrls: ['./roletable.component.less'],
})
export class RoletableComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<ServicePrincipalsItem | UsersItem>;
  @Input() role: DirectoryRolesItem;
  dataSource: MatTableDataSource<ServicePrincipalsItem | UsersItem>;

  constructor(private localSt:LocalStorageService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'objectType', 'userPrincipalName', 'dirSyncEnabled', 'accountEnabled'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    let roleMembers = Array<ServicePrincipalsItem | UsersItem>();
    roleMembers = roleMembers.concat(this.role.memberUsers);
    roleMembers = roleMembers.concat(this.role.memberServicePrincipals);
    this.dataSource.data = roleMembers;
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
