"""Create or update Technitium DNS records from the shared CSV format."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from technitiumdns import Client
from technitiumdns.models.zones import DnsRecord

from dns_sync_common import DNSRecord, dns_names_equal, dnsweaver_marker_name, load_records


TARGET_FIELDS = {
	"A": "ipAddress",
	"AAAA": "ipAddress",
	"CNAME": "cname",
	"MX": "exchange",
	"NS": "nameServer",
	"PTR": "ptrName",
	"TXT": "text",
}


def record_target(record: DnsRecord, record_type: str) -> str | None:
	return record.r_data.get(TARGET_FIELDS[record_type])


def update_fields(record: DnsRecord, desired: DNSRecord) -> dict[str, Any]:
	current_target = record_target(record, desired.record_type)
	if current_target is None:
		raise ValueError(
			f"Cannot read {desired.record_type} target for {record.name!r} "
			"from Technitium record data"
		)

	if desired.record_type in {"A", "AAAA"}:
		return {"ipAddress": current_target, "newIpAddress": desired.target}
	if desired.record_type == "CNAME":
		return {"cname": desired.target}
	if desired.record_type == "MX":
		preference = record.r_data.get("preference")
		if preference is None:
			raise ValueError(f"Cannot read MX preference for {record.name!r} from Technitium record data")
		return {
			"exchange": current_target,
			"newExchange": desired.target,
			"preference": preference,
			"newPreference": desired.priority,
		}
	if desired.record_type == "NS":
		return {"nameServer": current_target, "newNameServer": desired.target}
	if desired.record_type == "PTR":
		return {"ptrName": current_target, "newPtrName": desired.target}
	return {"text": current_target, "newText": desired.target}


def create_fields(desired: DNSRecord) -> dict[str, Any]:
	if desired.record_type in {"A", "AAAA"}:
		return {"ipAddress": desired.target}
	if desired.record_type == "CNAME":
		return {"cname": desired.target}
	if desired.record_type == "MX":
		return {"exchange": desired.target, "preference": desired.priority}
	if desired.record_type == "NS":
		return {"nameServer": desired.target}
	if desired.record_type == "PTR":
		return {"ptrName": desired.target}
	return {"text": desired.target}


def sync_records(
	records: Iterable[DNSRecord],
	client: Client,
	zone: str,
	dry_run: bool = False,
) -> None:
	groups: dict[tuple[str, str], list[DNSRecord]] = {}
	for desired in records:
		groups.setdefault((desired.record_type, desired.name), []).append(desired)

	for (record_type, name), desired_records in groups.items():
		existing = [
			record
			for record in client.zones.get_records(domain=name, zone=zone)
			if record.type == record_type and record.name.rstrip(".").lower() == name.rstrip(".").lower()
		]
		if existing:
			marker_name = dnsweaver_marker_name(name)
			markers = client.zones.get_records(domain=marker_name, zone=zone)
			if any(
				record.type == "TXT" and dns_names_equal(record.name, marker_name)
				for record in markers
			):
				print(f"SKIP {record_type} {name}: DNSWeaver manages this record (TXT {marker_name})")
				continue

		available = existing.copy()
		matches: dict[int, DnsRecord] = {}

		for index, desired in enumerate(desired_records):
			current = next(
				(
					record
					for record in available
					if record_target(record, record_type) == desired.target
					and (record_type != "MX" or record.r_data.get("preference") == desired.priority)
				),
				None,
			)
			if current is not None:
				matches[index] = current
				available.remove(current)

		if record_type != "MX" and len(existing) > 1:
			if not any(record_target(record, record_type) == desired_records[0].target for record in existing):
				raise ValueError(
					f"Multiple {record_type} records exist for {name!r}, "
					"and none match the CSV target; resolve the duplicates manually"
				)

		for index, desired in enumerate(desired_records):
			current = matches.get(index)
			if current is None and available:
				if record_type == "MX":
					current = next(
						(record for record in available if record.r_data.get("preference") == desired.priority),
						available[0],
					)
				else:
					current = available[0]
				available.remove(current)

			if current is not None:
				target_ttl = current.ttl if desired.ttl is None else 3600 if desired.ttl == 1 else desired.ttl
				current_target = record_target(current, record_type)
				target_priority = desired.priority if record_type == "MX" else None
				if current_target == desired.target and current.ttl == target_ttl and (
					record_type != "MX" or current.r_data.get("preference") == target_priority
				):
					print(f"UNCHANGED {record_type} {name} -> {desired.target}")
					continue

				changes = []
				if current_target != desired.target:
					changes.append(f"target {current_target} -> {desired.target}")
				if current.ttl != target_ttl:
					changes.append(f"TTL {current.ttl} -> {target_ttl}")
				if record_type == "MX" and current.r_data.get("preference") != target_priority:
					changes.append(f"priority {current.r_data.get('preference')} -> {target_priority}")
				print(f"UPDATE {record_type} {name}: {', '.join(changes)}")
				if not dry_run:
					client.zones.update_record(
						domain=current.name,
						zone=zone,
						type=record_type,
						ttl=target_ttl,
						extra=update_fields(current, desired),
					)
				continue

			print(f"CREATE {record_type} {name} -> {desired.target}")
			if not dry_run:
				client.zones.add_record(
					domain=name,
					zone=zone,
					type=record_type,
					ttl=None if desired.ttl in (None, 1) else desired.ttl,
					extra=create_fields(desired),
				)


def load_config(config_path: Path) -> dict[str, str | None]:
	config: dict[str, Any] = {}
	if config_path.exists():
		try:
			with config_path.open(encoding="utf-8") as config_file:
				config = json.load(config_file)
		except json.JSONDecodeError as error:
			raise ValueError(f"config file {config_path} must contain valid JSON") from error
		if not isinstance(config, dict):
			raise ValueError(f"config file {config_path} must contain a JSON object")

	settings = {
		"base_url": os.environ.get("TECHNITIUM_BASE_URL") or config.get("base_url"),
		"token": os.environ.get("TECHNITIUM_API_TOKEN") or config.get("token"),
		"zone": os.environ.get("TECHNITIUM_ZONE") or config.get("zone"),
		"node": os.environ.get("TECHNITIUM_NODE") or config.get("node"),
	}
	for key, value in settings.items():
		if value is not None and not isinstance(value, str):
			raise ValueError(f"config value {key!r} in {config_path} must be a string")
	return settings


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__)
	parser.add_argument("csv_file", type=Path, help="CSV with record_type, name, target, and optional ttl/priority columns")
	parser.add_argument("--dry-run", action="store_true", help="Show planned changes without writing to Technitium")
	parser.add_argument(
		"--config",
		type=Path,
		default=Path(".technitium-dns-sync.json"),
		help="JSON credentials file (default: .technitium-dns-sync.json)",
	)
	args = parser.parse_args()

	try:
		settings = load_config(args.config)
	except (OSError, ValueError) as error:
		parser.error(str(error))
	missing = [key for key in ("base_url", "token", "zone") if not settings[key]]
	if missing:
		parser.error(
			"provide base_url, token, and zone in the config file or set "
			"TECHNITIUM_BASE_URL, TECHNITIUM_API_TOKEN, and TECHNITIUM_ZONE"
		)

	try:
		records = load_records(args.csv_file)
		if not records:
			raise ValueError("CSV contains no DNS records")
		with Client(
			settings["base_url"],
			token=settings["token"],
			node=settings["node"],
		) as client:
			sync_records(records, client, settings["zone"], args.dry_run)
	except (OSError, ValueError) as error:
		print(f"Error: {error}", file=sys.stderr)
		return 1
	except Exception as error:
		print(f"Technitium API error: {error}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())