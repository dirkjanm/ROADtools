import { AfterViewInit, Component, OnInit, ViewChild } from '@angular/core';
import { MatPaginator } from '@angular/material/paginator';
import { MatSort } from '@angular/material/sort';
import { MatTable, MatTableDataSource } from '@angular/material/table';
// import { UsersDataSource } from './users-datasource';
import { DatabaseService, MfaItem } from '../aadobjects.service'
// import
@Component({
  selector: 'app-mfa',
  templateUrl: './mfa.component.html',
  styleUrls: ['./mfa.component.less'],
  providers: [DatabaseService]
})
export class MfaComponent implements AfterViewInit, OnInit {
  @ViewChild(MatPaginator) paginator: MatPaginator;
  @ViewChild(MatSort) sort: MatSort;
  @ViewChild(MatTable) table: MatTable<MfaItem>;
  dataSource: MatTableDataSource<MfaItem>;

  constructor(private service: DatabaseService) {  }

  /** Columns displayed in the table. Columns IDs can be added, removed, or reordered. */
  displayedColumns = ['displayName', 'userPrincipalName', 'accountEnabled', 'perusermfa', 'mfamethods', 'has_fido', 'has_app', 'has_phonenr', 'strongAuthenticationDetail'];

  ngOnInit() {
    this.dataSource = new MatTableDataSource();
    this.service.getMfa().subscribe((data: MfaItem[]) => this.dataSource.data = data);

  }

  ngAfterViewInit() {
    this.dataSource.sort = this.sort;
    this.dataSource.paginator = this.paginator;
    this.table.dataSource = this.dataSource;
    this.dataSource.sortingDataAccessor = (item, property) => {
      switch (property) {
        case 'mfamethods': {
          return item['strongAuthenticationDetail']['methods'].length;
        }

        case 'strongAuthenticationDetail': {
          return item['strongAuthenticationDetail']['methods'].length;
        }
        default: {
          return item[property];
        }
      }
    };
  }

  applyFilter(filterValue: string) {
    filterValue = filterValue.trim(); // Remove whitespace
    filterValue = filterValue.toLowerCase(); // Datasource defaults to lowercase matches
    this.dataSource.filter = filterValue;
  }
}
