"""Shared CSV parsing for DNS synchronization scripts."""

import csv
from dataclasses import dataclass
from pathlib import Path


SUPPORTED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "NS", "PTR", "TXT"}


def dnsweaver_marker_name(name: str) -> str:
	return f"_dnsweaver.{name.rstrip('.')}"


def dns_names_equal(first: str, second: str) -> bool:
	return first.rstrip(".").casefold() == second.rstrip(".").casefold()


@dataclass(frozen=True)
class DNSRecord:
	record_type: str
	name: str
	target: str
	ttl: int | None = None
	priority: int | None = None
	disabled: bool = False


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
			if not record_type or not name or not target:
				raise ValueError(f"CSV row {row_number}: record type, name, and target are required")
			if record_type not in SUPPORTED_RECORD_TYPES:
				supported = ", ".join(sorted(SUPPORTED_RECORD_TYPES))
				raise ValueError(f"CSV row {row_number}: unsupported record type {record_type!r}; use {supported}")
			if disabled_value not in {"", "true", "false"}:
				raise ValueError(f"CSV row {row_number}: disabled must be true, false, or empty")
			disabled = disabled_value == "true"

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
			records.append(DNSRecord(record_type, name, target, ttl, priority, disabled))

	return records