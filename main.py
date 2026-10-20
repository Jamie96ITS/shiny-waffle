"""Create or update Cloudflare DNS records from a CSV file."""

import argparse
import csv
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cloudflare import Cloudflare


SUPPORTED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"}


@dataclass(frozen=True)
class DNSRecord:
	record_type: str
	name: str
	target: str
	ttl: int | None = None
	priority: int | None = None


def load_records(csv_path: Path) -> list[DNSRecord]:
	"""Read and validate DNS records before making any API calls."""
	with csv_path.open(newline="", encoding="utf-8-sig") as csv_file:
		reader = csv.DictReader(csv_file)
		if reader.fieldnames is None:
			raise ValueError("CSV file is empty or missing a header row")

		headers = {
			(header or "").strip().lower().replace(" ", "_"): header
			for header in reader.fieldnames
		}
		type_header = headers.get("record_type") or headers.get("type")
		name_header = headers.get("name")
		target_header = headers.get("target")
		ttl_header = headers.get("ttl")
		priority_header = headers.get("priority")
		if not all((type_header, name_header, target_header)):
			raise ValueError("CSV must contain record_type (or type), name, and target columns")

		records: list[DNSRecord] = []
		seen: set[tuple[str, ...]] = set()
		for row_number, row in enumerate(reader, start=2):
			record_type = (row.get(type_header) or "").strip().upper()
			name = (row.get(name_header) or "").strip()
			target = (row.get(target_header) or "").strip()
			ttl_value = (row.get(ttl_header) or "").strip() if ttl_header else ""
			priority_value = (row.get(priority_header) or "").strip() if priority_header else ""
			if not record_type or not name or not target:
				raise ValueError(f"CSV row {row_number}: record type, name, and target are required")
			if record_type not in SUPPORTED_RECORD_TYPES:
				supported = ", ".join(sorted(SUPPORTED_RECORD_TYPES))
				raise ValueError(f"CSV row {row_number}: unsupported record type {record_type!r}; use {supported}")

			ttl = None
			if ttl_value:
				try:
					ttl = int(ttl_value)
				except ValueError as error:
					raise ValueError(f"CSV row {row_number}: TTL must be an integer") from error
				if ttl != 1 and not 60 <= ttl <= 86400:
					raise ValueError(f"CSV row {row_number}: TTL must be 1 (automatic) or between 60 and 86400")

			priority = None
			if record_type == "MX":
				if not priority_value:
					raise ValueError(f"CSV row {row_number}: MX records require a priority")
				try:
					priority = int(priority_value)
				except ValueError as error:
					raise ValueError(f"CSV row {row_number}: MX priority must be an integer") from error
				if not 0 <= priority <= 65535:
					raise ValueError(f"CSV row {row_number}: MX priority must be between 0 and 65535")
			elif priority_value:
				raise ValueError(f"CSV row {row_number}: priority is only supported for MX records")

			key = (record_type, name.lower())
			if record_type == "MX":
				key += (target.lower(), str(priority))
			if key in seen:
				duplicate_detail = "duplicate MX target and priority" if record_type == "MX" else f"duplicate {record_type} record for {name!r}"
				raise ValueError(f"CSV row {row_number}: {duplicate_detail}")
			seen.add(key)
			records.append(DNSRecord(record_type, name, target, ttl, priority))

	return records


def sync_records(
	records: Iterable[DNSRecord],
	client: Cloudflare,
	zone_id: str,
	dry_run: bool = False,
) -> None:
	groups: dict[tuple[str, str], list[DNSRecord]] = {}
	for desired in records:
		groups.setdefault((desired.record_type, desired.name), []).append(desired)

	for (record_type, name), desired_records in groups.items():
		existing = list(client.dns.records.list(zone_id=zone_id, name=name, type=record_type))
		available = existing.copy()
		matches: dict[int, object] = {}

		for index, desired in enumerate(desired_records):
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

		if record_type != "MX" and len(existing) > 1:
			if not any(record.content == desired_records[0].target for record in existing):
				raise ValueError(
					f"Multiple {record_type} records exist for {name!r}, "
					"and none match the CSV target; resolve the duplicates manually"
				)

		for index, desired in enumerate(desired_records):
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
				):
					print(f"UNCHANGED {record_type} {name} -> {desired.target}")
					continue

				changes = []
				if current.content != desired.target:
					changes.append(f"target {current.content} -> {desired.target}")
				if current.ttl != target_ttl:
					changes.append(f"TTL {current.ttl} -> {target_ttl}")
				if record_type == "MX" and current.priority != target_priority:
					changes.append(f"priority {current.priority} -> {target_priority}")
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
				client.dns.records.create(**create_params)


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
		"--config",
		type=Path,
		default=Path(".cloudflare-dns-sync.json"),
		help="JSON credentials file (default: .cloudflare-dns-sync.json)",
	)
	args = parser.parse_args()

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
		if not records:
			raise ValueError("CSV contains no DNS records")
		sync_records(records, Cloudflare(api_token=api_token), zone_id, args.dry_run)
	except (OSError, ValueError) as error:
		print(f"Error: {error}", file=sys.stderr)
		return 1
	except Exception as error:
		print(f"Cloudflare API error: {error}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
