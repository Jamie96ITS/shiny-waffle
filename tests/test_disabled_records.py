import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call

from cloudflare.types.dns import ARecord
from cloudflare_sync import sync_records as sync_cloudflare_records
from dns_sync_common import (
	DNSRecord,
	is_cloudflare_tunnel_target,
	load_records,
	parse_report_types,
)
from technitium_sync import (
	report_records as report_technitium_records,
	sync_records as sync_technitium_records,
)
from cloudflare_sync import report_records as report_cloudflare_records


class DisabledRecordTests(unittest.TestCase):
	def test_parse_report_types_defaults_empty_and_all_to_supported_types(self) -> None:
		self.assertIsNone(parse_report_types(""))
		self.assertIsNone(parse_report_types("all"))
		self.assertIsNone(parse_report_types("ALL"))

	def test_parse_report_types_parses_comma_separated_types(self) -> None:
		self.assertEqual(parse_report_types(" a,AAAA,CAA "), frozenset({"A", "AAAA", "CAA"}))

	def test_parse_report_types_rejects_invalid_values(self) -> None:
		for value in ("A,,AAAA", "A,UNKNOWN"):
			with self.subTest(value=value), self.assertRaises(ValueError):
				parse_report_types(value)

	def test_cloudflare_report_separates_csv_matches_from_server_only(self) -> None:
		existing = [
			ARecord(
				name="www.example.com.",
				ttl=300,
				type="A",
				content="192.0.2.1",
				proxied=True,
			),
			SimpleNamespace(
				type="AAAA",
				name="www.example.com",
				content="2001:db8::1",
				ttl=300,
				priority=None,
				proxied=False,
			),
			SimpleNamespace(
				type="CAA",
				name="www.example.com",
				content='0 issue "letsencrypt.org"',
				ttl=300,
				priority=0,
				proxied=None,
			),
			SimpleNamespace(
				type="TXT",
				name="_dnsweaver.www.example.com",
				content="",
				ttl=300,
				priority=None,
				proxied=False,
			),
			SimpleNamespace(
				type="CNAME",
				name="tunnel.example.com",
				content="012345.cfargotunnel.com.",
				ttl=300,
				priority=None,
				proxied=True,
			),
		]
		client = Mock()
		client.dns.records.list.return_value = existing
		output = io.StringIO()

		with contextlib.redirect_stdout(output):
			report_cloudflare_records(
				[DNSRecord("A", "WWW.example.com", "192.0.2.1")],
				client,
				"zone-id",
				None,
			)

		self.assertIn("Records also in CSV:", output.getvalue())
		self.assertIn("A www.example.com. -> 192.0.2.1", output.getvalue())
		self.assertIn("Records only on server:", output.getvalue())
		self.assertIn("AAAA www.example.com -> 2001:db8::1", output.getvalue())
		self.assertIn('CAA www.example.com -> 0 issue "letsencrypt.org"', output.getvalue())
		self.assertIn("A www.example.com. -> 192.0.2.1 (TTL=300.0, proxied=true) [managed by DNSWeaver]", output.getvalue())
		self.assertIn(
			"CNAME tunnel.example.com -> 012345.cfargotunnel.com. "
			"(TTL=300, proxied=true) [managed by Cloudflare Tunnels]",
			output.getvalue(),
		)

	def test_technitium_report_filters_types_without_syncing(self) -> None:
		existing = [
			SimpleNamespace(
				type="A",
				name="www.example.com",
				r_data={"ipAddress": "192.0.2.1"},
				ttl=300,
			),
			SimpleNamespace(
				type="AAAA",
				name="www.example.com",
				r_data={"ipAddress": "2001:db8::1"},
				ttl=300,
			),
		]
		client = Mock()
		client.zones.get_records.return_value = existing
		output = io.StringIO()

		with contextlib.redirect_stdout(output):
			report_technitium_records(
				[DNSRecord("A", "www.example.com", "192.0.2.1")],
				client,
				"zone",
				frozenset({"A"}),
			)

		client.zones.get_records.assert_called_once_with(domain="zone", zone="zone", list_zone=True)
		self.assertIn("A www.example.com -> 192.0.2.1", output.getvalue())
		self.assertNotIn("AAAA", output.getvalue())
		client.zones.add_record.assert_not_called()
		client.zones.update_record.assert_not_called()
		client.zones.delete_record.assert_not_called()

	def test_technitium_report_formats_soa_records(self) -> None:
		soa = SimpleNamespace(
			type="SOA",
			name="example.com",
			r_data={
				"primaryNameServer": "ns1.example.com",
				"responsiblePerson": "hostmaster.example.com",
				"serial": 2026102001,
			},
			ttl=3600,
		)
		client = Mock()
		client.zones.get_records.return_value = [soa]
		output = io.StringIO()

		with contextlib.redirect_stdout(output):
			report_technitium_records([], client, "example.com", None)

		self.assertIn("SOA example.com ->", output.getvalue())
		self.assertIn('"primaryNameServer": "ns1.example.com"', output.getvalue())
		self.assertIn('"serial": 2026102001', output.getvalue())

	def test_technitium_report_marks_dnsweaver_owned_records(self) -> None:
		records = [
			SimpleNamespace(
				type="A",
				name="www.example.com",
				r_data={"ipAddress": "192.0.2.1"},
				ttl=300,
			),
			SimpleNamespace(
				type="TXT",
				name="_dnsweaver.www.example.com",
				r_data={"text": "marker"},
				ttl=300,
			),
			SimpleNamespace(
				type="CNAME",
				name="tunnel.example.com",
				r_data={"cname": "012345.cfargotunnel.com"},
				ttl=300,
			),
		]
		client = Mock()
		client.zones.get_records.return_value = records
		output = io.StringIO()

		with contextlib.redirect_stdout(output):
			report_technitium_records([], client, "example.com", frozenset({"A", "CNAME"}))

		self.assertIn("A www.example.com -> 192.0.2.1 (TTL=300) [managed by DNSWeaver]", output.getvalue())
		self.assertIn(
			"CNAME tunnel.example.com -> 012345.cfargotunnel.com "
			"(TTL=300) [managed by Cloudflare Tunnels]",
			output.getvalue(),
		)

	def test_load_records_parses_proxied_values(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target,proxied\n"
				"A,one.example.com,192.0.2.1,true\n"
				"AAAA,two.example.com,2001:db8::1,FALSE\n"
				"CNAME,three.example.com,target.example.com,\n",
				encoding="utf-8",
			)

			records = load_records(csv_path)

		self.assertEqual([record.proxied for record in records], [True, False, None])

	def test_load_records_rejects_invalid_proxied_value(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target,proxied\n"
				"A,one.example.com,192.0.2.1,yes\n",
				encoding="utf-8",
			)

			with self.assertRaisesRegex(ValueError, "proxied must be true, false, or empty"):
				load_records(csv_path)

	def test_load_records_rejects_proxied_non_proxyable_record(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target,proxied\n"
				"TXT,example.com,token,true\n",
				encoding="utf-8",
			)

			with self.assertRaisesRegex(ValueError, "proxied is only supported for A, AAAA, and CNAME"):
				load_records(csv_path)

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

	def test_cloudflare_skips_cloudflare_tunnel_cname(self) -> None:
		record = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="CNAME",
			content="abc123.CFARGOtunnel.com.",
			priority=None,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[record] if kwargs["name"] == record.name else []
		)

		sync_cloudflare_records(
			[DNSRecord("CNAME", record.name, "new-target.example.com")],
			client,
			"zone-id",
		)

		client.dns.records.edit.assert_not_called()
		client.dns.records.delete.assert_not_called()
		client.dns.records.create.assert_not_called()

	def test_technitium_skips_disabled_cloudflare_tunnel_cname(self) -> None:
		record = SimpleNamespace(
			name="one.example.com",
			type="CNAME",
			r_data={"cname": "abc123.cfargotunnel.com"},
		)
		client = Mock()
		client.zones.get_records.side_effect = lambda **kwargs: (
			[record] if kwargs["domain"] == record.name else []
		)

		sync_technitium_records(
			[DNSRecord("CNAME", record.name, "abc123.cfargotunnel.com", disabled=True)],
			client,
			"zone",
		)

		client.zones.update_record.assert_not_called()
		client.zones.delete_record.assert_not_called()
		client.zones.add_record.assert_not_called()

	def test_cloudflare_tunnel_suffix_requires_a_subdomain(self) -> None:
		self.assertTrue(is_cloudflare_tunnel_target("tunnel.cfargotunnel.com"))
		self.assertTrue(is_cloudflare_tunnel_target("tunnel.cfargotunnel.com."))
		self.assertFalse(is_cloudflare_tunnel_target("cfargotunnel.com"))
		self.assertFalse(is_cloudflare_tunnel_target("tunnel.cfargotunnel.com.example"))
		self.assertFalse(is_cloudflare_tunnel_target(None))

	def test_cloudflare_updates_proxied_flag(self) -> None:
		record = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="A",
			content="192.0.2.1",
			priority=None,
			proxied=False,
			ttl=1,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[record] if kwargs["name"] == record.name else []
		)

		sync_cloudflare_records(
			[DNSRecord("A", record.name, record.content, proxied=True)],
			client,
			"zone-id",
		)

		client.dns.records.edit.assert_called_once_with(
			"record-id",
			zone_id="zone-id",
			name="one.example.com",
			type="A",
			ttl=1,
			content="192.0.2.1",
			proxied=True,
		)

	def test_cloudflare_dry_run_does_not_edit_updated_record(self) -> None:
		record = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="A",
			content="192.0.2.1",
			priority=None,
			proxied=False,
			ttl=1,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[record] if kwargs["name"] == record.name else []
		)

		sync_cloudflare_records(
			[DNSRecord("A", record.name, "192.0.2.2", proxied=True)],
			client,
			"zone-id",
			dry_run=True,
		)

		client.dns.records.edit.assert_not_called()

	def test_cloudflare_preserves_proxied_flag_when_unspecified(self) -> None:
		record = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="A",
			content="192.0.2.1",
			priority=None,
			proxied=True,
			ttl=1,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[record] if kwargs["name"] == record.name else []
		)

		sync_cloudflare_records(
			[DNSRecord("A", record.name, record.content)],
			client,
			"zone-id",
		)

		client.dns.records.edit.assert_not_called()
		client.dns.records.create.assert_not_called()

	def test_cloudflare_creates_with_explicit_proxied_flag(self) -> None:
		client = Mock()
		client.dns.records.list.return_value = []

		sync_cloudflare_records(
			[DNSRecord("A", "one.example.com", "192.0.2.1", proxied=True)],
			client,
			"zone-id",
		)

		client.dns.records.create.assert_called_once_with(
			zone_id="zone-id",
			name="one.example.com",
			type="A",
			ttl=1,
			content="192.0.2.1",
			proxied=True,
		)

	def test_load_records_rejects_active_cname_and_address_record_conflict(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target\n"
				"A,WWW.example.com,192.0.2.1\n"
				"CNAME,www.example.com.,target.example.com\n",
				encoding="utf-8",
			)

			with self.assertRaisesRegex(ValueError, "CNAME cannot coexist with A"):
				load_records(csv_path)

	def test_load_records_allows_multiple_txt_values_at_same_name(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target\n"
				"TXT,example.com,first-value\n"
				"TXT,example.com,second-value\n",
				encoding="utf-8",
			)

			records = load_records(csv_path)

		self.assertEqual([record.target for record in records], ["first-value", "second-value"])

	def test_load_records_still_rejects_duplicate_txt_value(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target\n"
				"TXT,example.com,same-value\n"
				"TXT,example.com,same-value\n",
				encoding="utf-8",
			)

			with self.assertRaisesRegex(ValueError, "duplicate TXT record"):
				load_records(csv_path)

	def test_cloudflare_creates_multiple_txt_records_at_same_name(self) -> None:
		client = Mock()
		client.dns.records.list.return_value = []

		sync_cloudflare_records(
			[
				DNSRecord("TXT", "example.com", "first-value"),
				DNSRecord("TXT", "example.com", "second-value"),
			],
			client,
			"zone-id",
		)

		self.assertEqual(client.dns.records.create.call_count, 2)
		self.assertEqual(
			[call.kwargs["content"] for call in client.dns.records.create.call_args_list],
			["first-value", "second-value"],
		)

	def test_technitium_creates_multiple_txt_records_at_same_name(self) -> None:
		client = Mock()
		client.zones.get_records.return_value = []

		sync_technitium_records(
			[
				DNSRecord("TXT", "example.com", "first-value"),
				DNSRecord("TXT", "example.com", "second-value"),
			],
			client,
			"example.com",
		)

		self.assertEqual(client.zones.add_record.call_count, 2)
		self.assertEqual(
			[
				call.kwargs["extra"]["text"]
				for call in client.zones.add_record.call_args_list
			],
			["first-value", "second-value"],
		)

	def test_load_records_allows_conflicting_record_marked_disabled(self) -> None:
		with tempfile.TemporaryDirectory() as directory:
			csv_path = Path(directory) / "records.csv"
			csv_path.write_text(
				"record_type,name,target,disabled\n"
				"A,www.example.com,192.0.2.1,true\n"
				"CNAME,www.example.com,target.example.com,false\n",
				encoding="utf-8",
			)

			records = load_records(csv_path)

		self.assertEqual(len(records), 2)

	def test_cloudflare_rejects_existing_conflicting_cname(self) -> None:
		existing = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="CNAME",
			content="target.example.com",
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[existing] if kwargs["name"] == existing.name and kwargs.get("type") in (None, "CNAME") else []
		)

		with self.assertRaisesRegex(ValueError, "existing CNAME record conflicts"):
			sync_cloudflare_records(
				[DNSRecord("A", existing.name, "192.0.2.1")],
				client,
				"zone-id",
			)

		client.dns.records.create.assert_not_called()

	def test_technitium_rejects_existing_conflicting_address_record(self) -> None:
		existing = SimpleNamespace(
			name="one.example.com",
			type="AAAA",
			r_data={"ipAddress": "2001:db8::1"},
		)
		client = Mock()
		client.zones.get_records.return_value = [existing]

		with self.assertRaisesRegex(ValueError, "existing AAAA record conflicts"):
			sync_technitium_records(
				[DNSRecord("CNAME", existing.name, "target.example.com")],
				client,
				"zone",
			)

		client.zones.add_record.assert_not_called()

	def test_cloudflare_processes_disabled_conflict_before_enabled_row(self) -> None:
		existing = SimpleNamespace(
			id="record-id",
			name="one.example.com",
			type="A",
			content="192.0.2.1",
			priority=None,
			ttl=1,
			proxied=False,
		)
		client = Mock()
		client.dns.records.list.side_effect = lambda **kwargs: (
			[existing]
			if kwargs["name"] == existing.name and kwargs.get("type") in (None, "A")
			else []
		)

		sync_cloudflare_records(
			[
				DNSRecord("CNAME", existing.name, "target.example.com"),
				DNSRecord("A", existing.name, existing.content, disabled=True),
			],
			client,
			"zone-id",
		)

		calls = client.mock_calls
		delete_call = call.dns.records.delete("record-id", zone_id="zone-id")
		create_call = call.dns.records.create(
			zone_id="zone-id",
			name="one.example.com",
			type="CNAME",
			ttl=1,
			content="target.example.com",
		)
		self.assertLess(calls.index(delete_call), calls.index(create_call))


if __name__ == "__main__":
	unittest.main()
