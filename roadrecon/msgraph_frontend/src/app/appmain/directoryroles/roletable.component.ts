import { AfterViewInit, Component, OnInit, ViewChild, Input } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
import { RoleDefinitionsItem, RoleAssignmentsItem } from '../msgraphobjects.service'
import { LocalStorageService } from 'ngx-webstorage';
import { isUsersItem, isGroupsItem, isServicePrincipalsItem} from '../msgraphobjects.service';
import { UsersItem, GroupsItem, ServicePrincipalsItem} from '../msgraphobjects.service';

// import
@Component({
  selector: 'role-table',
  templateUrl: './roletable.component.html',
  styleUrls: ['./roletable.component.less'],
})
export class RoletableComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<RoleAssignmentsItem>;
  @Input() role: RoleDefinitionsItem;
  dataSource: MatTableDataSource<RoleAssignmentsItem>;

  constructor(private localSt:LocalStorageService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'scope', 'type', 'userPrincipalName', 'onPremisesSyncEnabled','objType'];

 

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.dataSource.data = this.role.assignments;
    this.localSt.observe('mfa')
      .subscribe((value) => {
        this.updateMfaColumn(value);
      });
    this.updateMfaColumn(this.localSt.retrieve('mfa'));
  }


  determineObjectType(obj: UsersItem | GroupsItem | ServicePrincipalsItem): string {
    if (isUsersItem(obj)) {
      return "User";
    } 
    else if (isGroupsItem(obj)) {
      return "Group";
    } 
    else if (isServicePrincipalsItem(obj)) {
      return "ServicePrincipal";
    } 
    else {
      console.log('Unknown object type.');
      return "unknown";
    }
  }
  

  updateMfaColumn(value) {
    const columnsToAddOrRemove: string[] = ['methodsRegistered'];//['isMfaRegistered','has_app','has_phonenr','has_fido','isSsprRegistered','isSsprEnabled','isSsprCapable','isMfaCapable','isPasswordlessCapable','methodsRegistered','systemPreferredAuthenticationMethods','userPreferredMethodForSecondaryAuthentication'];

    if (value) {
      // Add columns if not already present
      columnsToAddOrRemove.forEach(column => {
          if (!this.displayedColumns.includes(column)) {
              this.displayedColumns.push(column);
          }
      });
  } else {
      // Remove columns if present
      this.displayedColumns = this.displayedColumns.filter(column => !columnsToAddOrRemove.includes(column));
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
