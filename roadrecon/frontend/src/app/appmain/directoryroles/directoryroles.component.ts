import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { filter } from 'rxjs/operators';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { DirectoryRolesDataSource } from './directoryroles-datasource';
import { DatabaseService, RoleDefinitionsItem, UsersItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-directoryroles',
  templateUrl: './directoryroles.component.html',
  styleUrls: ['./directoryroles.component.less'],
  providers: [DatabaseService]
})
export class DirectoryRolesComponent implements OnInit {
  roles: RoleDefinitionsItem[];

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'name', 'mail', 'department', 'lastPasswordChangeDateTime', 'jobTitle', 'mobile', 'dirSyncEnabled'];

  ngOnInit() {
    this.service.getRoleDefinitions().subscribe((data: RoleDefinitionsItem[]) => {
      this.roles = data.filter((role: RoleDefinitionsItem) => role.assignments.length > 0)
    });
  }
}
