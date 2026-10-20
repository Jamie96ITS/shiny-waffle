# Cloudflare DNS CSV Sync

Create or update DNS records in one Cloudflare zone from a CSV file. The CSV must have `record_type`, `name`, and `target` columns. `type` is also accepted as an alias for `record_type`. Optional columns are `ttl` and `priority`.

Supported record types are `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, and `TXT`. Each MX row requires a numeric `priority` from 0 to 65535; multiple MX rows can share a name. TTL is optional and accepts `1` for automatic TTL or a value from 60 to 86400 seconds. If omitted, existing records keep their current TTL and new records use automatic TTL.

Credentials can come from environment variables or the default `.cloudflare-dns-sync.json` file. The JSON file uses `api_token` and `zone_id` keys; environment variables take precedence. A different file can be selected with `--config`.

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
