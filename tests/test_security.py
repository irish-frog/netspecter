import importlib.util
import json
import os
import re
import tempfile
import unittest
from pathlib import Path


SOURCE_DIR = Path(__file__).resolve().parents[1]


class WebSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tempdir = tempfile.TemporaryDirectory()
        cls.original_env = {
            key: os.environ.get(key)
            for key in (
                "NETSPECTER_INSTALL_ROOT",
                "NETSPECTER_CONFIG_ROOT",
                "NETSPECTER_DATA_ROOT",
                "NETSPECTER_APP_ROOT",
            )
        }
        root = Path(cls.tempdir.name)
        os.environ["NETSPECTER_INSTALL_ROOT"] = str(root / "install")
        os.environ["NETSPECTER_CONFIG_ROOT"] = str(root / "config")
        os.environ["NETSPECTER_DATA_ROOT"] = str(root / "data")
        os.environ["NETSPECTER_APP_ROOT"] = str(SOURCE_DIR)

        spec = importlib.util.spec_from_file_location("netspecter_test_app", SOURCE_DIR / "app.py")
        cls.module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.module)
        cls.module.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        for key, value in cls.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        cls.tempdir.cleanup()

    def setUp(self):
        self.client = self.module.app.test_client()

    def csrf_from(self, path="/setup-admin"):
        page = self.client.get(path)
        match = re.search(r'name="_csrf_token" value="([^"]+)"', page.get_data(as_text=True))
        self.assertIsNotNone(match)
        return match.group(1)

    def test_post_without_csrf_token_is_rejected(self):
        response = self.client.post("/setup-admin", data={"password": "not-important"})
        self.assertEqual(400, response.status_code)

    def test_post_with_issued_csrf_token_reaches_handler(self):
        token = self.csrf_from()
        response = self.client.post(
            "/setup-admin",
            data={"_csrf_token": token, "password": "short", "confirm": "short"},
        )
        self.assertEqual(200, response.status_code)

    def test_mutating_action_routes_do_not_accept_get(self):
        source = (SOURCE_DIR / "app.py").read_text()
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        for path in ("/device/pause/<ip>", "/device/resume/<ip>", "/adguard/action"):
            self.assertNotIn("GET", rules[path])
            self.assertIn("POST", rules[path])
        self.assertIn("Block DNS", source)
        self.assertIn("Allow DNS", source)
        self.assertNotIn("Pause Internet", source)

    def test_range_picker_escapes_request_path(self):
        with self.module.app.test_request_context('/applications/" onmouseover="x'):
            html = self.module.time_picker()
        self.assertIn("/applications/&quot; onmouseover=&quot;x?range=1d", html)
        self.assertNotIn('href="/applications/" onmouseover="x', html)

    def test_browser_security_headers_are_set(self):
        response = self.client.get("/setup-admin")
        self.assertEqual("nosniff", response.headers["X-Content-Type-Options"])
        self.assertEqual("DENY", response.headers["X-Frame-Options"])
        self.assertEqual("strict-origin-when-cross-origin", response.headers["Referrer-Policy"])
        self.assertIn("frame-ancestors 'none'", response.headers["Content-Security-Policy"])

    def test_fresh_install_interval_matches_live_collection_intent(self):
        example = json.loads((SOURCE_DIR / "config.example.json").read_text())
        self.assertEqual(2, self.module.DEFAULT_CONFIG["collect_interval_seconds"])
        self.assertEqual(2, example["collect_interval_seconds"])

    def test_web_service_uses_gunicorn_wsgi_entrypoint(self):
        requirements = (SOURCE_DIR / "requirements.txt").read_text().splitlines()
        service = (SOURCE_DIR / "systemd" / "netspecter-web.service").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        source = (SOURCE_DIR / "app.py").read_text()
        gunicorn_config = (SOURCE_DIR / "gunicorn_config.py").read_text()
        self.assertIn("gunicorn", requirements)
        self.assertIn("gunicorn_config.py wsgi:application", service)
        self.assertIn('cp gunicorn_config.py "$INSTALL_DIR/gunicorn_config.py"', installer)
        self.assertIn('cp wsgi.py "$INSTALL_DIR/wsgi.py"', installer)
        self.assertIn('chmod 700 "$CONFIG_DIR" "$CONFIG_DIR/adguard" "$DATA_DIR"', installer)
        self.assertIn('chmod 600 "$CONFIG_DIR/config.json" "$DATA_DIR/netspecter.db" "$DATA_DIR/cache.json" "$DATA_DIR/oui_cache.json"', installer)
        self.assertNotIn("config = json.loads", gunicorn_config)
        self.assertIn('ROOT = Path(os.environ.get("NETSPECTER_APP_ROOT", str(INSTALL_ROOT)))', source)
        self.assertNotIn('"/root/netspecter"', source)

    def test_dashboard_panels_refresh_every_five_seconds(self):
        source = (SOURCE_DIR / "app.py").read_text()
        self.assertIn("setInterval(loadDashboardSummary, 5000);", source)
        self.assertIn("setInterval(loadDashboardTraffic, 5000);", source)
        self.assertNotIn("setInterval(loadDashboardSummary, 30000);", source)
        self.assertNotIn("setInterval(loadDashboardTraffic, 30000);", source)

    def test_estimated_app_traffic_has_storage_and_app_detail_output(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        self.module.init_db()
        con = self.module.connect_db()
        tables = {
            row[0]
            for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        }
        con.close()
        self.assertIn("estimated_app_traffic", tables)
        self.assertIn("remote_traffic_intervals", tables)
        self.assertIn("remote_ip_locations", tables)
        self.assertNotIn("<h2>Estimated App Traffic", source)
        self.assertIn("remember_estimated_app_targets", collector)
        self.assertIn("MONITORED_APP_DOMAIN_KEYS", collector)
        self.assertIn("MONITORED_APP_CATEGORIES", source)
        self.assertIn("Est. Download / Total", source)
        self.assertIn("Estimated data is measured from DNS-attributed delivery traffic for this monitored app.", source)

    def test_data_tables_offer_stable_sorting_without_live_rate_sorting(self):
        self.module.init_db()
        config = self.module.cfg()
        config["auth_enabled"] = False
        self.module.save_cfg(config)

        pages = {
            "/devices?sort=vendor&dir=asc": [
                '/devices?sort=name&dir=desc',
                '/devices?sort=last&dir=desc',
            ],
            "/traffic?sort=download&dir=asc": [
                "sort=download&dir=desc",
                "sort=total&dir=desc",
            ],
            "/applications?sort=app&dir=asc": [
                "sort=app&dir=desc",
                "sort=share&dir=desc",
            ],
            "/blocked-services?sort=service&dir=asc": [
                "sort=service&dir=desc",
                "sort=last&dir=desc",
            ],
            "/applications/YouTube?sort=estimated&dir=asc": [
                "sort=estimated&dir=desc",
                "sort=last&dir=desc",
            ],
        }
        for path, expected_links in pages.items():
            response = self.client.get(path)
            self.assertEqual(200, response.status_code, path)
            html = response.get_data(as_text=True)
            for link in expected_links:
                self.assertIn(link, html, path)

        devices_html = self.client.get("/devices").get_data(as_text=True)
        traffic_html = self.client.get("/traffic").get_data(as_text=True)
        self.assertNotIn("sort=live", devices_html)
        self.assertNotIn("sort=throughput", traffic_html)

    def test_stylesheet_url_changes_when_sidebar_watermark_css_changes(self):
        source = (SOURCE_DIR / "app.py").read_text()
        css = (SOURCE_DIR / "static" / "theme.css").read_text()
        self.assertIn("/static/theme.css?v=20260526m", source)
        self.assertIn('<div class="designer-credit">Designed by Gavin Reniers</div>\n  <img src="/static/netspecter-logo-sidebar.png" class="brand-logo">', source)
        self.assertIn("color: #2B4470;", css)
        self.assertNotIn("position: absolute;\n  left: 16px;\n  right: 16px;\n  bottom: 14px;\n  color: rgba(154, 167, 187, .55);", css)

    def test_speed_test_is_manual_post_action_and_installed(self):
        source = (SOURCE_DIR / "app.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        self.assertIn("/speed-test", rules)
        self.assertIn("POST", rules["/speed-test"])
        self.assertNotIn("GET", rules["/speed-test"])
        self.assertIn('["/usr/bin/speedtest", "--accept-license", "--accept-gdpr"]', source)
        self.assertIn('speedtest_env.setdefault("HOME", "/root")', source)
        self.assertIn('speedtest_env.setdefault("LC_ALL", "C.UTF-8")', source)
        self.assertIn("ookla/speedtest-cli/script.deb.sh", installer)
        self.assertIn("dpkg-query -W -f='${Status}' speedtest", installer)
        self.assertIn("speedtest", installer)

    def test_optional_unifi_discovery_and_scheduled_speed_history_ship_disabled(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        schedule = (SOURCE_DIR / "scheduled_speedtest.py").read_text()
        example = json.loads((SOURCE_DIR / "config.example.json").read_text())
        rules = {rule.rule: rule.methods for rule in self.module.app.url_map.iter_rules()}
        self.assertFalse(example["unifi_enabled"])
        self.assertFalse(example["unifi_skip_tls_verify"])
        self.assertEqual(0, example["scheduled_speedtests_per_day"])
        self.assertIn("unifi_api_key", self.module.SENSITIVE_CONFIG_KEYS)
        self.assertIn("/integrations", rules)
        self.assertIn("/speed-tests", rules)
        self.assertIn("def find_unifi_site(config):", source)
        self.assertIn("def unifi_verify_tls(config):", source)
        self.assertIn("def unifi_connector_bases(config):", source)
        self.assertIn("def unifi_json_response(result):", source)
        self.assertIn("UniFi OS firmware 5.0.3 or newer", source)
        self.assertIn("Connector URL corrected automatically.", source)
        self.assertIn("local UniFi gateway URL", source)
        self.assertIn("Find Site Automatically", source)
        self.assertIn("Allow self-signed certificate for local UniFi gateway", source)
        self.assertIn("refresh_unifi_clients", collector)
        self.assertIn("def unifi_verify_tls(config):", collector)
        self.assertIn("def unifi_connector_bases(config):", collector)
        self.assertIn('"X-API-Key": api_key', collector)
        self.assertIn("UNIFI_CLIENT_REFRESH_SECONDS = 300", collector)
        self.assertIn("CREATE TABLE IF NOT EXISTS speed_tests", source)
        self.assertIn("scheduled_speedtest.py", installer)
        self.assertIn("netspecter-speedtest.timer", installer)
        self.assertIn('if runs == 0:', schedule)

    def test_common_pages_do_not_block_on_public_ip_and_devices_batch_live_speeds(self):
        source = (SOURCE_DIR / "app.py").read_text()
        self.assertIn("def public_ip(refresh=True):", source)
        self.assertIn("Public IP: {public_ip(refresh=False)}", source)
        self.assertIn("def live_all_host_speeds():", source)
        self.assertIn("live_speeds = live_all_host_speeds()", source)

    def test_vendor_lookup_and_private_mac_guidance(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        self.assertIn("private_mac_address", source)
        self.assertIn("Private Wi-Fi Address / Randomized MAC", source)
        self.assertIn('"private / random mac"', source)
        self.assertIn('SYSTEM_OUI_PATH = Path("/usr/share/ieee-data/oui.txt")', collector)
        self.assertIn('return "Private / Random MAC"', collector)
        self.assertIn("ieee-data", installer)

    def test_adguard_client_names_fill_device_labels_without_overwriting_custom_names(self):
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        self.assertIn('f"{base}/control/clients"', collector)
        self.assertIn("ADGUARD_CLIENT_REFRESH_SECONDS = 300", collector)
        self.assertIn("def parse_adguard_client_names(payload):", collector)
        self.assertIn("remember_adguard_client_activity(client, ts)", collector)
        self.assertIn("CREATE TABLE IF NOT EXISTS device_overrides", collector)
        self.assertIn("WHERE ip=? AND (name IS NULL OR TRIM(name)='' OR name=ip)", collector)

    def test_removed_legacy_live_probe_is_not_shipped(self):
        source = (SOURCE_DIR / "app.py").read_text()
        installer = (SOURCE_DIR / "install.sh").read_text()
        self.assertNotIn("iftop_live_hosts", source)
        self.assertNotIn("iftop_iface", source)
        self.assertNotRegex(installer, r"\biftop\b")
        self.assertFalse((SOURCE_DIR / "static" / "netspecter-logo-wide.png").exists())

    def test_unsupported_legacy_config_keys_are_removed_on_load(self):
        legacy = self.module.DEFAULT_CONFIG.copy()
        legacy["old_unused_password"] = "not-needed"
        self.module.CONFIG_PATH.write_text(json.dumps(legacy))
        loaded = self.module.cfg()
        persisted = json.loads(self.module.CONFIG_PATH.read_text())
        self.assertNotIn("old_unused_password", loaded)
        self.assertNotIn("old_unused_password", persisted)

    def test_network_map_uses_cached_monitored_destination_locations(self):
        source = (SOURCE_DIR / "app.py").read_text()
        collector = (SOURCE_DIR / "live_packet_collector.py").read_text()
        css = (SOURCE_DIR / "static" / "theme.css").read_text()
        self.assertIn("Monitored App Destinations", source)
        self.assertIn('id="destinationMap"', source)
        self.assertIn("https://unpkg.com/leaflet@1.9.4", source)
        self.assertIn("https://tile.openstreetmap.org", source)
        self.assertNotIn("<h2>Active Devices</h2>", source)
        self.assertNotIn("<h2>Recently Seen / Stale</h2>", source)
        map_source = source[source.index("def network_map():"):source.index("def csv_response", source.index("def network_map():"))]
        self.assertNotIn("{time_picker()}", map_source)
        self.assertIn("compact-topology", map_source)
        self.assertIn("update_one_remote_location", collector)
        self.assertIn("GEOLOCATION_REFRESH_SECONDS = 3600", collector)
        self.assertIn("remote_traffic_intervals", collector)
        self.assertIn("#destinationMap", css)
        self.assertIn(".compact-topology", css)


if __name__ == "__main__":
    unittest.main()
