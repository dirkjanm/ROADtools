import { Component, OnInit } from '@angular/core';
import { MatTableDataSource } from '@angular/material/table';
import {
  DatabaseService,
  NhiSummary,
  NhiAgentItem,
  NhiWorkloadItem,
  FederatedCredentialItem,
  NhiFindingItem,
} from '../aadobjects.service';

@Component({
  standalone: false,
  selector: 'app-nhi',
  templateUrl: './nhi.component.html',
  styleUrls: ['./nhi.component.less'],
  providers: [DatabaseService],
})
export class NhiComponent implements OnInit {
  summary: NhiSummary | null = null;
  findingsDataSource = new MatTableDataSource<NhiFindingItem>([]);
  agentsDataSource = new MatTableDataSource<NhiAgentItem>([]);
  workloadsDataSource = new MatTableDataSource<NhiWorkloadItem>([]);
  ficsDataSource = new MatTableDataSource<FederatedCredentialItem>([]);

  findingsColumns: string[] = [
    'severity',
    'category',
    'principalName',
    'title',
    'detail',
    'recommendation',
  ];
  agentsColumns: string[] = [
    'displayName',
    'agentCategory',
    'executionMode',
    'm365Scopes',
    'tier0Roles',
    'ownersCount',
    'riskLevel',
  ];
  workloadsColumns: string[] = [
    'displayName',
    'nhiType',
    'managedIdentityResourceId',
    'credentialSummary',
    'privilegedRoles',
    'ownersCount',
    'riskLevel',
  ];
  ficsColumns: string[] = [
    'applicationDisplayName',
    'name',
    'issuer',
    'subject',
    'audiences',
    'riskLevel',
    'riskReasons',
  ];

  constructor(private service: DatabaseService) {}

  ngOnInit(): void {
    this.findingsDataSource.filterPredicate = (data: NhiFindingItem, filter: string) =>
      JSON.stringify(data).toLowerCase().includes(filter);
    this.agentsDataSource.filterPredicate = (data: NhiAgentItem, filter: string) =>
      JSON.stringify(data).toLowerCase().includes(filter);
    this.workloadsDataSource.filterPredicate = (data: NhiWorkloadItem, filter: string) =>
      JSON.stringify(data).toLowerCase().includes(filter);
    this.ficsDataSource.filterPredicate = (data: FederatedCredentialItem, filter: string) =>
      JSON.stringify(data).toLowerCase().includes(filter);

    this.service.getNhiSummary().subscribe((s) => (this.summary = s));
    this.service.getNhiFindings().subscribe((d) => (this.findingsDataSource.data = d || []));
    this.service.getNhiAgents().subscribe((d) => (this.agentsDataSource.data = d || []));
    this.service.getNhiWorkloads().subscribe((d) => (this.workloadsDataSource.data = d || []));
    this.service
      .getNhiFederatedCredentials()
      .subscribe((d) => (this.ficsDataSource.data = d || []));
  }

  applyFilter(filterValue: string): void {
    const normalized = (filterValue || '').trim().toLowerCase();
    this.findingsDataSource.filter = normalized;
    this.agentsDataSource.filter = normalized;
    this.workloadsDataSource.filter = normalized;
    this.ficsDataSource.filter = normalized;
  }

  getPrincipalRoute(row: NhiFindingItem): string[] {
    if (row.principalType === 'Application') {
      return ['/applications', row.principalObjectId];
    }
    return ['/serviceprincipals', row.principalObjectId];
  }
}
