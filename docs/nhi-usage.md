# NHI and Agent 365 in ROADrecon

ROADrecon collects non-human identities, agent metadata and federated identity credentials alongside its normal directory gather. The GUI reads the resulting database offline.

## Gather

Use a ROADrecon AAD Graph token with a refresh token to collect both the normal directory data and Microsoft Graph NHI data:

```text
roadrecon gather --nhi -f .roadtools_auth -d roadrecon.db
```

`--nhi` exchanges the refresh token for a Microsoft Graph token during the NHI phase. `--autotoken` also enables this exchange. `--skip-nhi` skips both NHI sources and takes precedence over `--nhi`. Without a usable Microsoft Graph token or exchange, the normal gather continues and records both NHI sources as `skipped`; heuristic agent classification can still use collected service principals.

The normal gather CLI requires an AAD Graph audience access token. A Microsoft Graph audience access token supplied directly is rejected before the NHI phase unless `--autotoken` can exchange it for the normal gather. Keep token files private and do not commit them.

## Authenticating with roadtx

`roadtx` obtains the token file that `gather` reads. The default file is `.roadtools_auth` in the current directory; it holds both an access token and a refresh token. `gather --nhi` needs that refresh token to exchange for a Microsoft Graph token — an access token obtained on its own (for example via `az`) cannot provide it.

```text
roadtx gettokens -t <tenant-id> --device-code -r https://graph.windows.net -f .roadtools_auth
roadtx describe -f .roadtools_auth
roadrecon gather -f .roadtools_auth -d roadrecon.db --nhi
```

Omit `-u`/`--username` when using `--device-code`: a supplied username/password takes priority over the device-code flow. `-r https://graph.windows.net` is the default audience and the one `gather` accepts for the normal directory phase. `roadtx describe` confirms `aud` and `tenantId` before gathering.

To avoid writing a token file at all, pipe the two commands:

```text
roadtx gettokens -t <tenant-id> --device-code -r https://graph.windows.net --tokens-stdout |
  python -m roadtools.roadrecon.gather --tokens-stdin -d roadrecon.db --nhi
```

Use the version from this checkout. An older installed `roadrecon` command can lack the `--nhi` flag and the `/api/nhi/*` routes and will return 404s for the NHI endpoints. Set `PYTHONPATH` to the local `roadlib/roadtools` and `roadrecon/roadtools` directories and run `python -m roadtools.roadrecon.gather` / `python -m roadtools.roadrecon.gui`, or install the local packages in editable mode.

`.roadtools_auth` is gitignored, but a refresh token is a reusable credential: keep it private, never commit or share it, and only authenticate to a tenant you are authorized to test.

## GUI and API

Start the GUI with the same database, then open `/nhi`:

```text
roadrecon gui -d roadrecon.db
```

The **NHI & Agent 365** page has Overview & Risk Findings, Agent 365 & AI Agents, Managed Identities & Workloads, and Federated Credentials tabs. Application dialogs show FICs and NHI risk. Service principal dialogs show agent and NHI posture.

The read-only JSON endpoints are:

| Endpoint | Data |
|---|---|
| `/api/nhi/summary` | Counts, collection status, data gaps and top findings |
| `/api/nhi/agents` | Agent principals and risk |
| `/api/nhi/workloads` | Managed identities and workload apps |
| `/api/nhi/federatedcredentials` | Collected FICs and risk |
| `/api/nhi/findings` | All NHI findings |
| `/api/applications/<id>/federatedcredentials` | One application's collected FICs |
| `/api/serviceprincipals/<id>/nhi` | One service principal's NHI posture |

## Reading collection status

`collectionStatus` describes FIC collection only. Check `federatedCredentialsCollectionStatus` and `agentMetadataCollectionStatus` in `/api/nhi/summary` for each source, and read `dataGaps` before treating counts as complete. `collected` with zero items is a confirmed zero; `skipped`, `failed` and `uncollected` mean the source is unknown. A failed source can leave older rows in the database, but those rows are excluded from the FIC report.

`totalFederatedCredentials` and per-principal `federatedCredentialsCount` are `null` when FIC collection is unknown, rather than zero. Agent metadata gaps mean the displayed agents may only be those identified heuristically. Findings are sorted by severity; `Informational` is reserved and currently never emitted.
