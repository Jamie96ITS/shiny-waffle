"""Shared CSV parsing for DNS synchronization scripts."""

import csv
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"}
REPORT_RECORD_TYPES = SUPPORTED_RECORD_TYPES | {
	"CAA",
	"CERT",
	"DNSKEY",
	"DS",
	"HTTPS",
	"LOC",
	"NAPTR",
	"OPENPGPKEY",
	"SMIMEA",
	"SRV",
	"SSHFP",
	"SVCB",
	"TLSA",
	"URI",
}


def dnsweaver_marker_name(name: str) -> str:
	return f"_dnsweaver.{name.rstrip('.')}"


def dns_names_equal(first: str, second: str) -> bool:
	return first.rstrip(".").casefold() == second.rstrip(".").casefold()


def is_cloudflare_tunnel_target(target: str | None) -> bool:
	return target is not None and target.rstrip(".").casefold().endswith(".cfargotunnel.com")


def conflicting_record_types(record_type: str) -> set[str]:
	if record_type == "CNAME":
		return {"A", "AAAA"}
	if record_type in {"A", "AAAA"}:
		return {"CNAME"}
	return set()


def validate_cname_address_conflicts(records: list["DNSRecord"]) -> None:
	active_types_by_name: dict[str, set[str]] = {}
	names_by_key: dict[str, str] = {}
	for record in records:
		if record.disabled or record.record_type not in {"A", "AAAA", "CNAME"}:
			continue
		name_key = record.name.rstrip(".").casefold()
		active_types_by_name.setdefault(name_key, set()).add(record.record_type)
		names_by_key[name_key] = record.name

	for name_key, record_types in active_types_by_name.items():
		if "CNAME" in record_types and record_types.intersection({"A", "AAAA"}):
			address_types = ", ".join(sorted(record_types.intersection({"A", "AAAA"})))
			raise ValueError(
				f"Conflicting DNS records for {names_by_key[name_key]!r}: "
				f"CNAME cannot coexist with {address_types}"
			)


def record_is_disabled(
	records: list["DNSRecord"],
	record_type: str,
	name: str,
	target: str,
) -> bool:
	return any(
		record.disabled
		and record.record_type == record_type
		and dns_names_equal(record.name, name)
		and record.target.casefold() == target.casefold()
		for record in records
	)


def parse_report_types(value: str) -> frozenset[str] | None:
	if not value or value.casefold() == "all":
		return None

	record_types = {record_type.strip().upper() for record_type in value.split(",")}
	if "" in record_types:
		raise ValueError("report record types must be comma-separated without empty entries")
	unsupported = record_types - REPORT_RECORD_TYPES
	if unsupported:
		supported = ", ".join(sorted(REPORT_RECORD_TYPES))
		raise ValueError(
			f"unsupported report record type {', '.join(sorted(unsupported))!r}; use {supported}"
		)
	return frozenset(record_types)


def dns_record_key(
	record_type: str,
	name: str,
	target: str,
	priority: int | None = None,
) -> tuple[str, str, str, int | None]:
	normalized_target = target.casefold()
	if record_type in {"CNAME", "MX", "NS", "PTR"}:
		normalized_target = normalized_target.rstrip(".")
	return record_type.upper(), name.rstrip(".").casefold(), normalized_target, priority


def print_record_report(
	csv_records: list[DNSRecord],
	server_records: list[tuple[str, str, str, int | None, int | None, bool | None]],
	record_types: frozenset[str] | None,
) -> None:
	csv_keys = {
		dns_record_key(record.record_type, record.name, record.target, record.priority)
		for record in csv_records
		if record_types is None or record.record_type in record_types
	}
	in_csv: list[tuple[str, str, str, int | None, int | None, bool | None]] = []
	server_only: list[tuple[str, str, str, int | None, int | None, bool | None]] = []
	for record in server_records:
		record_type, name, target, _, priority, _ = record
		record_type = record_type.upper()
		if record_types is not None and record_type not in record_types:
			continue
		key = dns_record_key(record_type, name, target, priority)
		(in_csv if key in csv_keys else server_only).append(record)

	def print_section(
		title: str,
		records: list[tuple[str, str, str, int | None, int | None, bool | None]],
	) -> None:
		print(f"{title}:")
		if not records:
			print("  (none)")
			return
		for record_type, name, target, ttl, priority, proxied in sorted(
			records,
			key=lambda item: (item[0], item[1].casefold(), item[2].casefold(), item[4] or -1),
		):
			details = []
			if ttl is not None:
				details.append(f"TTL={ttl}")
			if priority is not None:
				details.append(f"priority={priority}")
			if proxied is not None:
				details.append(f"proxied={str(proxied).lower()}")
			suffix = f" ({', '.join(details)})" if details else ""
			print(f"  {record_type} {name} -> {target}{suffix}")

	print_section("Records also in CSV", in_csv)
	print_section("Records only on server", server_only)


@dataclass(frozen=True)
class DNSRecord:
	record_type: str
	name: str
	target: str
	ttl: int | None = None
	priority: int | None = None
	disabled: bool = False
	proxied: bool | None = None


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
		disabled_header = headers.get("disabled")
		proxied_header = headers.get("proxied")
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
			disabled_value = (row.get(disabled_header) or "").strip().casefold() if disabled_header else ""
			proxied_value = (row.get(proxied_header) or "").strip().casefold() if proxied_header else ""
			if not record_type or not name or not target:
				raise ValueError(f"CSV row {row_number}: record type, name, and target are required")
			if record_type not in SUPPORTED_RECORD_TYPES:
				supported = ", ".join(sorted(SUPPORTED_RECORD_TYPES))
				raise ValueError(f"CSV row {row_number}: unsupported record type {record_type!r}; use {supported}")
			if disabled_value not in {"", "true", "false"}:
				raise ValueError(f"CSV row {row_number}: disabled must be true, false, or empty")
			disabled = disabled_value == "true"
			if proxied_value not in {"", "true", "false"}:
				raise ValueError(f"CSV row {row_number}: proxied must be true, false, or empty")
			proxied = None if not proxied_value else proxied_value == "true"
			if proxied and record_type not in {"A", "AAAA", "CNAME"}:
				raise ValueError(f"CSV row {row_number}: proxied is only supported for A, AAAA, and CNAME records")

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
			records.append(DNSRecord(record_type, name, target, ttl, priority, disabled, proxied))

	validate_cname_address_conflicts(records)
	return records