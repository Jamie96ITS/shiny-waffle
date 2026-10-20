"""Create or update Cloudflare DNS records from a CSV file."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable

from cloudflare import Cloudflare, PermissionDeniedError
from dns_sync_common import (
	DNSRecord,
	dns_names_equal,
	dnsweaver_marker_name,
	conflicting_record_types,
	is_cloudflare_tunnel_target,
	load_records,
	parse_report_types,
	print_record_report,
	record_is_disabled,
	validate_cname_address_conflicts,
)


def sync_records(
	records: Iterable[DNSRecord],
	client: Cloudflare,
	zone_id: str,
	dry_run: bool = False,
) -> None:
	records = list(records)
	validate_cname_address_conflicts(records)
	groups: dict[tuple[str, str], list[DNSRecord]] = {}
	for desired in records:
		groups.setdefault((desired.record_type, desired.name), []).append(desired)

	ordered_groups = sorted(
		groups.items(),
		key=lambda item: any(not record.disabled for record in item[1]),
	)
	for (record_type, name), desired_records in ordered_groups:
		existing = list(client.dns.records.list(zone_id=zone_id, name=name, type=record_type))
		if record_type == "CNAME" and any(
			is_cloudflare_tunnel_target(record.content) for record in existing
		):
			print(f"SKIP {record_type} {name}: Cloudflare Tunnels manages this name")
			continue
		if existing:
			marker_name = dnsweaver_marker_name(name)
			markers = client.dns.records.list(zone_id=zone_id, name=marker_name, type="TXT")
			if any(dns_names_equal(marker.name, marker_name) for marker in markers):
				print(f"SKIP {record_type} {name}: DNSWeaver manages this record (TXT {marker_name})")
				continue

		enabled_records = [record for record in desired_records if not record.disabled]
		conflict_types = conflicting_record_types(record_type)
		if enabled_records and conflict_types:
			for current in client.dns.records.list(zone_id=zone_id, name=name):
				if (
					current.type in conflict_types
					and dns_names_equal(current.name, name)
					and not record_is_disabled(records, current.type, current.name, current.content)
				):
					raise ValueError(
						f"Cannot sync {record_type} record for {name!r}: existing "
						f"{current.type} record conflicts with CNAME/A/AAAA record rules. "
						f"Disable the conflicting record in the CSV first."
					)

		available = existing.copy()
		matches: dict[int, object] = {}
		for desired in (record for record in desired_records if record.disabled):
			current = next(
				(
					record
					for record in available
					if record.content == desired.target
					and (record_type != "MX" or record.priority == desired.priority)
				),
				None,
			)
			if current is None:
				print(f"NOT FOUND {record_type} {name} -> {desired.target} (disabled)")
				continue
			print(f"DELETE {record_type} {name} -> {desired.target}")
			available.remove(current)
			if not dry_run:
				client.dns.records.delete(current.id, zone_id=zone_id)

		records_to_reconcile = available.copy()

		for index, desired in enumerate(enabled_records):
			current = next(
				(
					record
					for record in available
					if record.content == desired.target
					and (record_type != "MX" or record.priority == desired.priority)
				),
				None,
			)
			if current is not None:
				matches[index] = current
				available.remove(current)

		if record_type not in {"MX", "TXT"} and len(records_to_reconcile) > 1 and enabled_records:
			if not any(record.content == enabled_records[0].target for record in records_to_reconcile):
				raise ValueError(
					f"Multiple {record_type} records exist for {name!r}, "
					"and none match the CSV target; resolve the duplicates manually"
				)

		for index, desired in enumerate(enabled_records):
			current = matches.get(index)
			if current is None and available:
				if record_type == "MX":
					current = next(
						(record for record in available if record.priority == desired.priority),
						available[0],
					)
				else:
					current = available[0]
				available.remove(current)

			if current is not None:
				target_ttl = desired.ttl if desired.ttl is not None else current.ttl
				target_priority = desired.priority if record_type == "MX" else None
				if current.content == desired.target and current.ttl == target_ttl and (
					record_type != "MX" or current.priority == target_priority
				) and (desired.proxied is None or current.proxied == desired.proxied):
					print(f"UNCHANGED {record_type} {name} -> {desired.target}")
					continue

				changes = []
				if current.content != desired.target:
					changes.append(f"target {current.content} -> {desired.target}")
				if current.ttl != target_ttl:
					changes.append(f"TTL {current.ttl} -> {target_ttl}")
				if record_type == "MX" and current.priority != target_priority:
					changes.append(f"priority {current.priority} -> {target_priority}")
				if desired.proxied is not None and current.proxied != desired.proxied:
					changes.append(f"proxied {current.proxied} -> {desired.proxied}")
				print(f"UPDATE {record_type} {name}: {', '.join(changes)}")
				if not dry_run:
					update_params = {
						"zone_id": zone_id,
						"name": current.name,
						"type": current.type,
						"ttl": target_ttl,
						"content": desired.target,
					}
					if record_type == "MX":
						update_params["priority"] = desired.priority
					if desired.proxied is not None:
						update_params["proxied"] = desired.proxied
					client.dns.records.edit(current.id, **update_params)
				continue

			print(f"CREATE {record_type} {name} -> {desired.target}")
			if not dry_run:
				create_params = {
					"zone_id": zone_id,
					"name": name,
					"type": record_type,
					"ttl": desired.ttl if desired.ttl is not None else 1,
					"content": desired.target,
				}
				if record_type == "MX":
					create_params["priority"] = desired.priority
				if desired.proxied is not None:
					create_params["proxied"] = desired.proxied
				client.dns.records.create(**create_params)


def report_records(
	records: list[DNSRecord],
	client: Cloudflare,
	zone_id: str,
	record_types: frozenset[str] | None,
) -> None:
	existing = list(client.dns.records.list(zone_id=zone_id))
	print_record_report(
		records,
		[
			(
				record.type,
				record.name,
				record.content,
				record.ttl,
				getattr(record, "priority", None),
				getattr(record, "proxied", None),
			)
			for record in existing
		],
		record_types,
	)


def load_credentials(config_path: Path) -> tuple[str | None, str | None]:
	config = {}
	if config_path.exists():
		try:
			with config_path.open(encoding="utf-8") as config_file:
				config = json.load(config_file)
		except json.JSONDecodeError as error:
			raise ValueError(f"config file {config_path} must contain valid JSON") from error
		if not isinstance(config, dict):
			raise ValueError(f"config file {config_path} must contain a JSON object")
		for key in ("api_token", "zone_id"):
			if key in config and not isinstance(config[key], str):
				raise ValueError(f"config value {key!r} in {config_path} must be a string")

	api_token = os.environ.get("CLOUDFLARE_API_TOKEN") or config.get("api_token")
	zone_id = os.environ.get("CLOUDFLARE_ZONE_ID") or config.get("zone_id")	
	return api_token, zone_id


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("csv_file", type=Path, help="CSV with record_type, name, target, and optional ttl/priority columns")
	parser.add_argument("--dry-run", action="store_true", help="Show planned changes without creating or updating records")
	parser.add_argument(
		"--report",
		nargs="?",
		const="all",
		default=None,
		metavar="ALL|TYPE,...",
		help="Report existing records without syncing; use all types by default or select types (e.g. A,AAAA)",
	)
	parser.add_argument(
		"--config",
		type=Path,
		default=Path(".cloudflare-dns-sync.json"),
		help="JSON credentials file (default: .cloudflare-dns-sync.json)",
	)
	args = parser.parse_args()
	try:
		report_types = parse_report_types(args.report) if args.report is not None else None
	except ValueError as error:
		parser.error(str(error))

	try:
		api_token, zone_id = load_credentials(args.config)
	except (OSError, ValueError) as error:
		parser.error(str(error))
	if not api_token or not zone_id:
		parser.error(
			"provide api_token and zone_id in the config file or set "
			"CLOUDFLARE_API_TOKEN and CLOUDFLARE_ZONE_ID"
		)

	try:
		records = load_records(args.csv_file)
		if not records and args.report is None:
			raise ValueError("CSV contains no DNS records")
		client = Cloudflare(api_token=api_token)
		if args.report is not None:
			report_records(records, client, zone_id, report_types)
			return 0
		sync_records(records, client, zone_id, args.dry_run)
	except (OSError, ValueError) as error:
		print(f"Error: {error}", file=sys.stderr)
		return 1
	except PermissionDeniedError as error:
		print(
			"Cloudflare API returned HTTP 403 (permission denied). Check that the API token "
			"has Zone DNS Read and Zone DNS Edit permissions for the zone identified by "
			"CLOUDFLARE_ZONE_ID. DNS record requests do not require an account ID.\n"
			f"Cloudflare response: {error}",
			file=sys.stderr,
		)
		return 1
	except Exception as error:
		print(f"Cloudflare API error: {error}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
