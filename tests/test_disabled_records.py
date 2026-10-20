import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

from cloudflare_sync import sync_records as sync_cloudflare_records
from dns_sync_common import DNSRecord, load_records
from technitium_sync import sync_records as sync_technitium_records


class DisabledRecordTests(unittest.TestCase):
	def test_load_records_parses_disabled_values(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target,disabled\n"
				"A,one.example.com,192.0.2.1,true\n"
				"A,two.example.com,192.0.2.2,FALSE\n"
				"A,three.example.com,192.0.2.3,\n",
				encoding="utf-8",
			)

			records = load_records(csv_path)

		self.assertEqual([record.disabled for record in records], [True, False, False])

	def test_load_records_rejects_unknown_disabled_value(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target,disabled\n"
				"A,one.example.com,192.0.2.1,yes\n",
				encoding="utf-8",
			)

			with self.assertRaisesRegex(ValueError, "disabled must be true, false, or empty"):
				load_records(csv_path)

	def test_load_records_defaults_disabled_to_false_when_column_is_missing(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target\n"
				"A,one.example.com,192.0.2.1\n",
				encoding="utf-8",
			)

			records = load_records(csv_path)

		self.assertFalse(records[0].disabled)

	def test_cloudflare_deletes_disabled_record(self) -> None:
		record = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="A",
			content="192.0.2.1",
			priority=None,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[record] if kwargs["name"] == record.name else []
		)

		sync_cloudflare_records(
			[DNSRecord("A", record.name, record.content, disabled=True)],
			client,
			"zone-id",
		)

		client.dns.records.delete.assert_called_once_with("record-id", zone_id="zone-id")

	def test_technitium_deletes_disabled_record(self) -> None:
		record = SimpleNamespace(
			name="one.example.com",
			type="A",
			r_data={"ipAddress": "192.0.2.1"},
		)
		client = Mock()
		client.zones.get_records.side_effect = lambda **kwargs: (
			[record] if kwargs["domain"] == record.name else []
		)

		sync_technitium_records(
			[DNSRecord("A", record.name, "192.0.2.1", disabled=True)],
			client,
			"zone",
		)

		client.zones.delete_record.assert_called_once_with(
			domain="one.example.com",
			zone="zone",
			type="A",
		)

	def test_dry_run_does_not_delete_disabled_record(self) -> None:
		record = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="A",
			content="192.0.2.1",
			priority=None,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[record] if kwargs["name"] == record.name else []
		)

		sync_cloudflare_records(
			[DNSRecord("A", record.name, record.content, disabled=True)],
			client,
			"zone-id",
			dry_run=True,
		)

		client.dns.records.delete.assert_not_called()


if __name__ == "__main__":
	unittest.main()
