import { Component, OnInit, ViewChild } from '@angular/core';
import { Observable } from 'rxjs';
import { MatTableDataSource } from '@angular/material/table';
import { MatSort } from '@angular/material/sort';
import { MatPaginator } from '@angular/material/paginator';
import {
  DatabaseService,
  NhiSummary,
  NhiAgentItem,
  NhiWorkloadItem,
  FederatedCredentialItem,
  NhiFindingItem,
} from '../aadobjects.service';

const SEVERITY_ORDER: string[] = ['Critical', 'High', 'Medium', 'Low', 'Informational'];

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

  readonly severityOrder = SEVERITY_ORDER;
  readonly pageSizeOptions = [25, 50, 100, 500];

  // Loading / error state. pending counts outstanding requests.
  pending = 0;
  errors: string[] = [];

  // Lowercase search blob per row, computed once when data loads.
  private searchBlobs = new WeakMap<object, string>();

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
    'ownerNames',
    'sponsorNames',
    'ownersCount',
    'federatedCredentialsCount',
    'riskLevel',
  ];
  workloadsColumns: string[] = [
    'displayName',
    'nhiType',
    'managedIdentityResourceId',
    'credentialSummary',
    'federatedCredentialsCount',
    'maxExpiryDays',
    'roleSplit',
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

  // Tables live inside lazily-rendered mat-tabs, so wire sort/paginator via setters.
  @ViewChild('findingsSort') set findingsSort(s: MatSort | undefined) {
    if (s) { this.findingsDataSource.sort = s; }
  }
  @ViewChild('agentsSort') set agentsSort(s: MatSort | undefined) {
    if (s) { this.agentsDataSource.sort = s; }
  }
  @ViewChild('workloadsSort') set workloadsSort(s: MatSort | undefined) {
    if (s) { this.workloadsDataSource.sort = s; }
  }
  @ViewChild('ficsSort') set ficsSort(s: MatSort | undefined) {
    if (s) { this.ficsDataSource.sort = s; }
  }
  @ViewChild('findingsPaginator') set findingsPaginator(p: MatPaginator | undefined) {
    if (p) { this.findingsDataSource.paginator = p; }
  }
  @ViewChild('agentsPaginator') set agentsPaginator(p: MatPaginator | undefined) {
    if (p) { this.agentsDataSource.paginator = p; }
  }
  @ViewChild('workloadsPaginator') set workloadsPaginator(p: MatPaginator | undefined) {
    if (p) { this.workloadsDataSource.paginator = p; }
  }
  @ViewChild('ficsPaginator') set ficsPaginator(p: MatPaginator | undefined) {
    if (p) { this.ficsDataSource.paginator = p; }
  }

  constructor(private service: DatabaseService) {}

  ngOnInit(): void {
    const predicate = (data: object, filter: string): boolean =>
      (this.searchBlobs.get(data) || '').includes(filter);
    const accessor = (data: any, column: string): string | number => this.sortValue(data, column);

    this.findingsDataSource.filterPredicate = predicate;
    this.agentsDataSource.filterPredicate = predicate;
    this.workloadsDataSource.filterPredicate = predicate;
    this.ficsDataSource.filterPredicate = predicate;
    this.findingsDataSource.sortingDataAccessor = accessor;
    this.agentsDataSource.sortingDataAccessor = accessor;
    this.workloadsDataSource.sortingDataAccessor = accessor;
    this.ficsDataSource.sortingDataAccessor = accessor;

    this.load('summary', this.service.getNhiSummary(), (s) => (this.summary = s));
    this.load('findings', this.service.getNhiFindings(), (d) =>
      (this.findingsDataSource.data = this.withBlobs(d)));
    this.load('agents', this.service.getNhiAgents(), (d) =>
      (this.agentsDataSource.data = this.withBlobs(d)));
    this.load('workloads', this.service.getNhiWorkloads(), (d) =>
      (this.workloadsDataSource.data = this.withBlobs(d)));
    this.load('federated credentials', this.service.getNhiFederatedCredentials(), (d) =>
      (this.ficsDataSource.data = this.withBlobs(d)));
  }

  get loading(): boolean {
    return this.pending > 0;
  }

  private load<T>(
    what: string,
    source: Observable<T>,
    assign: (v: T) => void
  ): void {
    this.pending++;
    source.subscribe({
      next: (v: T) => {
        assign(v);
        this.pending--;
      },
      error: (e: any) => {
        this.pending--;
        const status = e && e.status ? ' (HTTP ' + e.status + ')' : '';
        this.errors = [...this.errors, 'Failed to load NHI ' + what + status + '.'];
      },
    });
  }

  private withBlobs<T extends object>(rows: T[] | null | undefined): T[] {
    const list = rows || [];
    for (const row of list) {
      this.searchBlobs.set(row, JSON.stringify(row).toLowerCase());
    }
    return list;
  }

  private sortValue(data: any, column: string): string | number {
    if (column === 'severity' || column === 'riskLevel') {
      return data.severityWeight ?? 0;
    }
    if (column === 'roleSplit') {
      return (data.privilegedRoles || []).join(', ').toLowerCase();
    }
    const v = data[column];
    if (v === null || v === undefined) { return -1; }
    if (Array.isArray(v)) { return v.join(', ').toLowerCase(); }
    if (typeof v === 'number') { return v; }
    return String(v).toLowerCase();
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

  readonly noMatchMessage = 'No rows match your search';

  /** True only when data exists, a filter is active, and it matches nothing. */
  noMatches(ds: MatTableDataSource<any>): boolean {
    return !this.loading && ds.data.length > 0 && !!ds.filter && ds.filteredData.length === 0;
  }

  /** Labelled role groups for the workloads tab; empty groups are omitted. */
  roleGroups(row: NhiWorkloadItem): { label: string; roles: string[] }[] {
    return [
      { label: 'Entra', roles: row.directoryRoles || [] },
      { label: 'PIM', roles: row.pimRoles || [] },
      { label: 'Azure', roles: row.azureRoles || [] },
      { label: 'Graph app', roles: row.graphAppRoles || [] },
      { label: 'Tier-0', roles: row.tier0Roles || [] },
    ].filter((g) => g.roles.length > 0);
  }

  /** null/undefined renders as 'n/a', never 0. */
  fmt(value: number | null | undefined): string {
    return value === null || value === undefined ? 'n/a' : String(value);
  }

  /** FIC KPI: 'n/a' unless collected; '0 collected' only when collected and empty. */
  ficKpi(): string {
    const s = this.summary;
    if (!s || s.totalFederatedCredentials === null || s.totalFederatedCredentials === undefined) {
      return 'n/a';
    }
    if (!s.federatedCredentialsCollected) {
      return 'n/a';
    }
    return s.totalFederatedCredentials === 0 ? '0 collected' : String(s.totalFederatedCredentials);
  }

  get showStatusBanner(): boolean {
    const s = this.summary;
    return !!s && (s.collectionStatus !== 'collected' || !s.federatedCredentialsCollected);
  }

  severityCount(sev: string): number {
    const s = this.summary;
    if (!s) { return 0; }
    if (s.severityBreakdown) {
      return (s.severityBreakdown as any)[sev] ?? 0;
    }
    const fallback: { [k: string]: number } = {
      Critical: s.criticalFindingsCount,
      High: s.highFindingsCount,
      Medium: s.mediumFindingsCount,
      Low: s.lowFindingsCount,
      Informational: s.informationalFindingsCount,
    };
    return fallback[sev] ?? 0;
  }

  sevClass(level: string | null | undefined): string {
    return 'risk-' + (level || 'informational').toLowerCase();
  }

  /** Empty-state text for the federated credentials tab. */
  get ficEmptyMessage(): string {
    const s = this.summary;
    if (s && s.federatedCredentialsCollected) {
      return 'Federated credentials were collected: 0 collected.';
    }
    return 'Federated credentials were not collected, so this is unknown rather than zero.'
      + (s && s.federatedCredentialsCollectionDetail ? ' ' + s.federatedCredentialsCollectionDetail : '');
  }
}
