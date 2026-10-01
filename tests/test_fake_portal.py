"""Regression checks for the local captive-portal test fixture."""

from contextlib import ExitStack
from http.server import ThreadingHTTPServer
import http.client
import io
import socket
import sys
import threading
import unittest
from unittest import mock

import fake_portal


class FakePortalTest(unittest.TestCase):
    def available_port_pair(self):
        for _ in range(100):
            with ExitStack() as sockets:
                first = sockets.enter_context(socket.socket())
                first.bind(("127.0.0.1", 0))
                port = first.getsockname()[1]
                if port == 65535:
                    continue
                second = sockets.enter_context(socket.socket())
                try:
                    second.bind(("127.0.0.1", port + 1))
                except OSError:
                    continue
                return port
        self.fail("could not find two adjacent loopback ports")

    def test_two_stage_startup_does_not_require_reverse_dns(self):
        port = self.available_port_pair()
        servers = []

        def started(server, *args, **kwargs):
            servers.append(server)

        with (
            mock.patch("socket.getfqdn", side_effect=AssertionError("reverse DNS used")) as dns,
            mock.patch.object(ThreadingHTTPServer, "serve_forever", autospec=True,
                              side_effect=started),
            mock.patch("threading.Thread.start", autospec=True,
                       side_effect=lambda thread: thread.run()),
            mock.patch.object(sys, "argv", ["fake_portal.py", "--port", str(port),
                                           "--mode", "two-stage"]),
            mock.patch("sys.stderr", new_callable=io.StringIO),
            mock.patch.dict(fake_portal.state, fake_portal.state.copy(), clear=True),
        ):
            try:
                fake_portal.main()
                self.assertEqual({server.server_address for server in servers},
                                 {("127.0.0.1", port), ("127.0.0.1", port + 1)})
                for server in servers:
                    self.assertTrue(server.server_name)
                    self.assertEqual(server.server_port, server.server_address[1])
                dns.assert_not_called()
            finally:
                for server in servers:
                    server.server_close()

    def test_credential_redirect_logs_status_without_credentials(self):
        for status in (307, 308):
            with (
                self.subTest(status=status),
                mock.patch.dict(fake_portal.state, {}, clear=True),
                mock.patch("sys.stderr", new_callable=io.StringIO) as logs,
                fake_portal.LoopbackHTTPServer(("127.0.0.1", 0), fake_portal.Portal) as server,
            ):
                fake_portal.state["stage2_port"] = server.server_port
                worker = threading.Thread(target=server.serve_forever,
                                          kwargs={"poll_interval": 0.01}, daemon=True)
                worker.start()
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port,
                                                        timeout=2)
                try:
                    connection.request("GET", f"/test-credential-redirect?code={status}")
                    control_response = connection.getresponse()
                    self.assertEqual(control_response.status, 200)
                    control_response.read()
                    self.assertEqual(fake_portal.state["credential_redirect"], str(status))
                    connection.request("POST", "/stage2/auth",
                                       "userName=fixture-user&userPwd=fixture-secret")
                    response = connection.getresponse()
                    self.assertEqual(response.status, status)
                    response.read()
                finally:
                    connection.close()
                    server.shutdown()
                    worker.join(timeout=2)
                output = logs.getvalue()
                self.assertEqual(output.count(f"CREDENTIAL_REDIRECT {status}\n"), 1)
                self.assertNotIn("fixture-user", output)
                self.assertNotIn("fixture-secret", output)


if __name__ == "__main__":
    unittest.main()
