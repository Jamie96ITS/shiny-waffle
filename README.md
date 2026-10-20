# Cloudflare DNS CSV Sync

Create, update, or delete DNS records in one Cloudflare zone from a CSV file. The CSV must have `record_type`, `name`, and `target` columns. `type` is also accepted as an alias for `record_type`. Optional columns are `ttl`, `priority`, and `disabled`.

Set `disabled` to `true` to delete the matching DNS record; `false` or an empty value leaves it enabled. The value is case-insensitive. A disabled row still requires the record type, name, and target so the sync can identify the record. Deletions are shown without being applied when using `--dry-run`.

Supported record types are `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, and `TXT`. Each MX row requires a numeric `priority` from 0 to 65535; multiple MX rows can share a name. TTL is optional and accepts `1` for automatic TTL or a value from 60 to 86400 seconds. If omitted, existing records keep their current TTL and new records use automatic TTL.

Both sync programs check for a TXT record named `_dnsweaver.<record-name>` before reconciling an existing record. If found, they skip that record set, including disabled-row deletions, and report that DNSWeaver manages it. They also skip existing CNAME records whose target ends in `.cfargotunnel.com` (case-insensitive, with an optional trailing dot), reporting that Cloudflare Tunnels manages the name.

Credentials can come from environment variables or the default `.cloudflare-dns-sync.json` file. The JSON file uses `api_token` and `zone_id` keys; environment variables take precedence. A different file can be selected with `--config`. Cloudflare DNS record requests use the zone ID and do not require an account ID. The API token must have Zone DNS Read and Zone DNS Edit permissions and be scoped to the selected zone. If a request returns HTTP 403, verify those permissions, the token's zone resource scope, and that `zone_id` identifies the intended zone.

For example, create `.cloudflare-dns-sync.json` using the structure in [cloudflare-dns-sync.example.json](cloudflare-dns-sync.example.json), then preview the changes:

```sh
python main.py dns_records.example.csv --dry-run
```

Alternatively, set `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID` in the environment. Remove `--dry-run` to apply changes. The token needs permission to read and edit DNS records for the selected zone. `requirements.txt` contains the Python dependencies.

## Technitium DNS

Use `technitium_sync.py` with the same CSV file. Credentials and server settings can be stored in `.technitium-dns-sync.json` using the structure in [technitium-dns-sync.example.json](technitium-dns-sync.example.json), or supplied through `TECHNITIUM_BASE_URL`, `TECHNITIUM_API_TOKEN`, and `TECHNITIUM_ZONE`. Environment variables override config values. Optional `node` in the config selects a cluster node.

Preview changes with:

```sh
python technitium_sync.py dns_records.example.csv --dry-run
```

Use `--config PATH` to select a different JSON config file. The Technitium API uses its server default TTL for new records when CSV TTL is blank or `1`; for updates, TTL `1` requests the API's documented default of 3600 seconds. An omitted TTL preserves the existing record's TTL.

## GitHub Actions

An example workflow is provided at [.github/workflows/dns-sync.yml.example](.github/workflows/dns-sync.yml.example). Rename it to `.github/workflows/dns-sync.yml` to activate it. It syncs on pushes to `main` that change `dns_records.csv`; manual runs let you choose the provider and default to dry-run.

Add the provider credentials as GitHub Actions repository secrets: `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID`, or `TECHNITIUM_BASE_URL`, `TECHNITIUM_API_TOKEN`, and `TECHNITIUM_ZONE`. For manual runs, the `DNS_PROVIDER` repository variable can set the default provider for push-triggered runs; it defaults to Cloudflare. Set `DNS_CSV_PATH` to change the CSV location, and update the workflow's `paths` filter to match it. A hosted runner must be able to reach the Technitium API; use a self-hosted runner for a private DNS server.
