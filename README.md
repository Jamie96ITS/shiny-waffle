# Cloudflare DNS CSV Sync

Create or update DNS records in one Cloudflare zone from a CSV file. The CSV must have `record_type`, `name`, and `target` columns. `type` is also accepted as an alias for `record_type`. Optional columns are `ttl` and `priority`.

Supported record types are `A`, `AAAA`, `CNAME`, `MX`, `NS`, `PTR`, and `TXT`. Each MX row requires a numeric `priority` from 0 to 65535; multiple MX rows can share a name. TTL is optional and accepts `1` for automatic TTL or a value from 60 to 86400 seconds. If omitted, existing records keep their current TTL and new records use automatic TTL.

Credentials can come from environment variables or the default `.cloudflare-dns-sync.json` file. The JSON file uses `api_token` and `zone_id` keys; environment variables take precedence. A different file can be selected with `--config`.

For example, create `.cloudflare-dns-sync.json` using the structure in [cloudflare-dns-sync.example.json](cloudflare-dns-sync.example.json), then preview the changes:

```sh
python main.py dns_records.example.csv --dry-run
```

Alternatively, set `CLOUDFLARE_API_TOKEN` and `CLOUDFLARE_ZONE_ID` in the environment. Remove `--dry-run` to apply changes. The token needs permission to read and edit DNS records for the selected zone. `requirements.txt` contains the Python dependencies.
