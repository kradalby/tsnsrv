import json
import shlex

T = 120
APP = "example.com/cap/tsnsrv"
NODE_CAP = "suggest-exit-node"
SERVICES = (
    "basic",
    "urlparts",
    "suppressed",
    "tls",
    "tailnet",
    "tailnet-relay",
    "tcp",
    "unix",
    "upstream-tls",
    "upstream-insecure",
    "legacy",
    "legacy-enabled",
)


def write_file(node, path, value):
    node.succeed(f"printf %s {shlex.quote(value)} > {shlex.quote(path)}")


def policy(metrics=True, app=True):
    rules = [
        {
            "src": ["alice@", "tag:client"],
            "dst": ["tag:service"],
            "ip": ["tcp:80", "tcp:443"] + (["tcp:9099"] if metrics else []),
        },
        {"src": ["tag:service"], "dst": ["alice@", "tag:client"], "ip": ["tcp:3000"]},
    ]
    if app:
        rules.append(
            {
                "src": ["alice@"],
                "dst": ["tag:service"],
                "app": {APP: [{"role": "reader"}]},
            }
        )
    return {
        "tagOwners": {"tag:service": ["server@"], "tag:client": ["alice@"]},
        "nodeAttrs": [{"target": ["alice@"], "attr": [NODE_CAP]}],
        "autoApprovers": {"exitNode": ["alice@"]},
        "grants": rules,
    }


def set_policy(**kwargs):
    write_file(headscale, "/run/policy.json", json.dumps(policy(**kwargs)))
    headscale.succeed("headscale policy set -f /run/policy.json")


def address(name, ipv6=False):
    return peer.wait_until_succeeds(
        f"tailscale ip {'-6' if ipv6 else '-4'} {name}", timeout=T
    ).strip()


def curl(ip, path="/api/hello?query=one", port=80, extra=""):
    host = f"[{ip}]" if ":" in ip else ip
    scheme = "https" if port == 443 else "http"
    return f"curl --noproxy '*' --path-as-is -sS --max-time 5 {extra} '{scheme}://{host}:{port}{path}'"


def response(node, ip, **kwargs):
    return json.loads(node.succeed(curl(ip, extra="-f", **kwargs)))


def ready(node, ip, **kwargs):
    node.wait_until_succeeds(curl(ip, extra="-f", **kwargs), timeout=T)


def status(node, ip, expected, **kwargs):
    actual = node.succeed(curl(ip, extra="-o /dev/null -w '%{http_code}'", **kwargs))
    assert actual == str(expected), (actual, expected)


def nodes():
    return json.loads(headscale.succeed("headscale nodes list -o json"))


start_all()
alice_key = headscale.succeed("hs-authkey alice").strip()
set_policy()
server_key = headscale.succeed("hs-authkey server --tags tag:service").strip()
relay_key = headscale.succeed("hs-authkey alice --tags tag:client").strip()
peer.succeed(f"hs-join {shlex.quote(alice_key)} --advertise-exit-node")
relay.succeed(f"hs-join {shlex.quote(relay_key)}")
machine.wait_for_unit("multi-user.target")
write_file(machine, "/run/ts-authkey", server_key + "\n")
ephemeral_key = headscale.succeed(
    "hs-authkey server --tags tag:service --ephemeral"
).strip()
write_file(machine, "/run/ephemeral-key", ephemeral_key)
machine.succeed(
    "mkdir -p /run/certs /run/backend; openssl req -x509 -newkey rsa:2048 -nodes "
    "-keyout /run/certs/key.pem -out /run/certs/cert.pem -days 1 "
    "-subj /CN=tls.tailnet -addext subjectAltName=DNS:tls.tailnet; "
    "chmod 755 /run/certs; chmod 644 /run/certs/*.pem"
)
cert = machine.succeed("cat /run/certs/cert.pem")
write_file(peer, "/run/app-ca.pem", cert)
write_file(relay, "/run/app-ca.pem", cert)
machine.systemctl(f"start {backend_unit}")
for name in SERVICES:
    machine.systemctl(f"start {unit_prefix}{name}")
    machine.wait_for_unit(f"{unit_prefix}{name}", timeout=T)

ips = {name: address(name) for name in SERVICES}
for client in (peer, relay):
    ready(client, ips["basic"])
    ready(client, ips["tailnet"], path="/upstream")
    ready(client, ips["tailnet-relay"], path="/upstream")

with subtest("direct and forced-DERP application traffic"):
    peer.wait_until_succeeds(
        "tailscale ping --timeout=3s -c 1 basic | grep -E 'via (\\[)?[0-9a-f]+[.:]'",
        timeout=T,
    )
    relay.wait_until_succeeds(
        "tailscale ping --timeout=3s --until-direct=false -c 1 basic | grep 'via DERP(headscale)'",
        timeout=T,
    )
    for client in (peer, relay):
        assert response(client, ips["basic"])["path"] == "/hello?query=one"
        assert response(client, ips["urlparts"])["path"] == "/api/hello?query=one"
        assert response(client, ips["unix"], path="/unix")["path"] == "/unix"
        assert response(client, ips["tcp"], path="/tcp")["path"] == "/tcp"
        assert response(client, ips["tailnet"], path="/upstream")["path"] == "/upstream"
        assert (
            response(client, ips["tailnet-relay"], path="/upstream")["path"]
            == "/upstream"
        )
    ready(peer, address("basic", ipv6=True))
    peer.fail("curl --noproxy '*' -f --max-time 5 http://machine:3000/")
    ready(peer, ips["basic"])

with subtest("WhoIs identity, spoof removal, node tags and application grants"):
    peer.wait_until_succeeds(
        curl(ips["basic"], extra="-f")
        + f' | jq -e \'.headers["X-Tailscale-Caps"] | contains("{APP}")\'',
        timeout=T,
    )
    peer.wait_until_succeeds(
        curl(ips["basic"], extra="-f")
        + f' | jq -e \'.headers["X-Tailscale-Node-Caps"] | contains("{NODE_CAP}")\'',
        timeout=T,
    )
    data = json.loads(
        peer.succeed(
            curl(
                ips["basic"],
                extra="-f -H 'X-Configured: forged' -H 'X-Tailscale-User: forged' -H 'X-Tailscale-Node-Tags: tag:forged' "
                "-H 'X-Tailscale-Caps: forged' -H 'X-Tailscale-Unknown: forged'",
            )
        )
    )
    headers = {key.lower(): value for key, value in data["headers"].items()}
    peer_status = json.loads(peer.succeed("tailscale status --json"))
    user_id = peer_status["Self"]["UserID"]
    profile = peer_status["User"][str(user_id)]
    assert headers["x-tailscale-user"] == f"userid:{user_id}", headers
    assert headers["x-tailscale-user-loginname"] == profile["LoginName"], headers
    assert headers["x-tailscale-user-displayname"] == profile["DisplayName"], headers
    assert headers["x-tailscale-node-name"] == "peer", headers
    peer_node = next(n for n in nodes() if n["givenName"] == "peer")
    assert headers["x-tailscale-node"] == f"nodeid:{peer_node['id']}", headers
    if "@" in profile["LoginName"]:
        localpart, domain = profile["LoginName"].split("@", 1)
        assert headers["x-tailscale-user-loginname-localpart"] == localpart, headers
        assert headers["x-tailscale-user-loginname-domain"] == domain, headers
    assert APP in headers["x-tailscale-caps"], headers
    assert NODE_CAP in headers["x-tailscale-node-caps"], headers
    assert "x-tailscale-node-tags" not in headers, headers
    assert "x-tailscale-unknown" not in headers, headers
    assert headers["x-configured"] == "configured", headers
    assert headers["x-forwarded-proto"] == "http", headers
    assert headers["x-real-ip"] == peer.succeed("tailscale ip -4").strip(), headers
    tagged = {k.lower(): v for k, v in response(relay, ips["basic"])["headers"].items()}
    assert tagged["x-tailscale-node-tags"] == "tag:client", tagged
    assert APP not in tagged.get("x-tailscale-caps", ""), tagged
    assert NODE_CAP not in tagged.get("x-tailscale-node-caps", ""), tagged
    suppressed = json.loads(
        peer.succeed(
            curl(
                ips["suppressed"],
                extra="-f -H 'X-Tailscale-User: forged' -H 'X-Tailscale-Caps: forged'",
            )
        )
    )
    assert not any(
        k.lower().startswith("x-tailscale-") for k in suppressed["headers"]
    ), suppressed
    assert "x-real-ip" not in {k.lower() for k in suppressed["headers"]}, suppressed
    assert "x-scheme" not in {k.lower() for k in suppressed["headers"]}, suppressed

with subtest("path allowlist, provenance and stripping"):
    for client in (peer, relay):
        for path in ("/", "/private", "/public", "/%61pi/hello"):
            status(client, ips["basic"], 404, path=path)
            ready(client, ips["basic"])
        status(client, ips["basic"], 307, path="/api/../private")
        assert (
            client.succeed(
                curl(
                    ips["basic"],
                    path="/api/../private",
                    extra="-L -o /dev/null -w '%{http_code}'",
                )
            )
            == "404"
        )
        assert response(client, ips["basic"], path="/api/a%20b")["path"] == "/a%20b"

with subtest("incomplete headers expire without breaking healthy requests"):
    for client in (peer, relay):
        code = (
            "import socket; "
            f"s = socket.create_connection(('{ips['basic']}', 80), timeout=5); "
            "s.sendall(b'GET /api/hello HTTP/1.1\\r\\nHost: unfinished'); "
            "assert s.recv(4096) == b''; s.close()"
        )
        client.succeed("python -c " + shlex.quote(code))
        ready(client, ips["basic"])

with subtest("custom application TLS, separate from the DERP certificate"):
    for client in (peer, relay):
        tls_cmd = (
            f"curl --noproxy '*' -fsS --max-time 5 --cacert /run/app-ca.pem "
            f"--resolve tls.tailnet:443:{ips['tls']} https://tls.tailnet/secure"
        )
        client.wait_until_succeeds(tls_cmd, timeout=T)
        client.fail(tls_cmd.replace("--cacert /run/app-ca.pem ", ""))
        tls_headers = {
            k.lower(): v
            for k, v in json.loads(client.succeed(tls_cmd))["headers"].items()
        }
        assert tls_headers["x-scheme"] == "https", tls_headers

with subtest("upstream TLS verification and explicit insecure opt-in"):
    for client in (peer, relay):
        status(client, ips["upstream-tls"], 502, path="/")
        ready(client, ips["upstream-insecure"], path="/")
        status(client, ips["upstream-tls"], 502, path="/")
        status(client, ips["legacy"], 502, path="/")
        ready(client, ips["legacy-enabled"], path="/")
        status(client, ips["legacy"], 502, path="/")

with subtest("live network permission denial has a passing application control"):
    for client in (peer, relay):
        ready(client, ips["basic"], path="/metrics", port=9099)
        assert (
            client.succeed(
                curl(
                    ips["basic"],
                    path="/bugreport",
                    port=9099,
                    extra="-X POST -o /dev/null -w '%{http_code}'",
                )
            )
            == "404"
        )
        metrics = client.succeed(
            curl(ips["basic"], path="/metrics", port=9099, extra="-f")
        )
        assert "tsnsrv_request_duration_ns_count" in metrics, metrics
    set_policy(metrics=False)
    for client in (peer, relay):
        client.wait_until_fails(
            curl(ips["basic"], path="/metrics", port=9099, extra="-f"), timeout=T
        )
        ready(client, ips["basic"])
        client.fail(curl(ips["basic"], path="/metrics", port=9099, extra="-f"))
    with subtest("control and DERP outage preserves direct traffic and cached policy"):
        for name in ("basic", "tailnet", "tailnet-relay"):
            peer.wait_until_succeeds(
                f"tailscale ping --timeout=3s -c 1 {name} | grep -E 'via (\\[)?[0-9a-f]+[.:]'",
                timeout=T,
            )
        headscale.systemctl("stop headscale")
        headscale.fail("systemctl is-active --quiet headscale")
        headscale.wait_for_closed_port(80)
        headscale.wait_for_closed_port(443)
        offline_headers = response(peer, ips["basic"])["headers"]
        assert offline_headers["X-Tailscale-User"] == f"userid:{user_id}", (
            offline_headers
        )
        assert APP in offline_headers["X-Tailscale-Caps"], offline_headers
        assert response(peer, ips["tailnet"], path="/upstream")["path"] == "/upstream"
        peer.fail(curl(ips["basic"], path="/metrics", port=9099, extra="-f"))
        relay.fail(curl(ips["basic"], extra="-f"))
        peer.fail(curl(ips["tailnet-relay"], path="/upstream", extra="-f"))
        ready(peer, ips["basic"])
        headscale.systemctl("start headscale")
        headscale.succeed("headscale health")
        relay.wait_until_succeeds(
            "tailscale ping --timeout=3s --until-direct=false -c 1 basic | grep 'via DERP(headscale)'",
            timeout=T,
        )
        ready(relay, ips["basic"])
        ready(peer, ips["tailnet-relay"], path="/upstream")
    set_policy()
    for client in (peer, relay):
        ready(client, ips["basic"], path="/metrics", port=9099)

with subtest("application capability revocation does not deny network access"):
    set_policy(app=False)
    peer.wait_until_succeeds(
        curl(ips["basic"], extra="-f")
        + f' | jq -e \'(.headers["X-Tailscale-Caps"] // "") | contains("{APP}") | not\'',
        timeout=T,
    )
    ready(relay, ips["basic"])
    set_policy()
    peer.wait_until_succeeds(
        curl(ips["basic"], extra="-f")
        + f' | jq -e \'.headers["X-Tailscale-Caps"] | contains("{APP}")\'',
        timeout=T,
    )

with subtest(
    "invalid restart key fails; persisted identity resumes without an enrollment key"
):
    before = next(n for n in nodes() if n["givenName"] == "basic")
    write_file(machine, "/run/ts-authkey", "invalid-key")
    machine.systemctl(f"restart {unit_prefix}basic")
    machine.wait_until_succeeds(
        f"journalctl -u {unit_prefix}basic -o cat | grep 'invalid pre auth key'",
        timeout=T,
    )
    ready(peer, ips["suppressed"])
    peer.fail(curl(ips["basic"], extra="-f"))
    machine.systemctl(f"stop {unit_prefix}basic")
    write_file(machine, "/run/ts-authkey", "")
    machine.systemctl(f"reset-failed {unit_prefix}basic")
    machine.systemctl(f"start {unit_prefix}basic")
    ready(peer, ips["basic"])
    ready(relay, ips["basic"])
    after = next(n for n in nodes() if n["givenName"] == "basic")
    assert (after["id"], after["ipAddresses"]) == (
        before["id"],
        before["ipAddresses"],
    )
    assert len([n for n in nodes() if n["givenName"] == "basic"]) == 1
    write_file(machine, "/run/ts-authkey", server_key)
    if not container:
        machine.succeed(
            "test $(systemctl show tsnsrv-basic -p DynamicUser --value) = yes && "
            'test -z "$(systemctl show tsnsrv-basic -p CapabilityBoundingSet --value)" && '
            "test $(stat -c %a /var/lib/private/tsnsrv-basic) = 700"
        )

with subtest("missing authentication credential fails at the service boundary"):
    machine.fail(f"systemctl start {unit_prefix}invalid")
    ready(peer, ips["basic"])
    write_file(machine, "/run/invalid-key", "invalid-key")
    machine.systemctl(f"reset-failed {unit_prefix}invalid")

with subtest(
    "fresh invalid authentication fails while registered service stays usable"
):
    machine.systemctl(f"start {unit_prefix}invalid")
    machine.wait_until_succeeds(
        f"journalctl -u {unit_prefix}invalid -o cat | grep 'could not connect to tailnet'",
        timeout=T,
    )
    assert not any(n["givenName"] == "invalid" for n in nodes())
    ready(peer, ips["basic"])
    machine.systemctl(f"stop {unit_prefix}invalid")

with subtest("upstream failure gives 502, with independent healthy control"):
    peer.systemctl("stop backend")
    peer.wait_until_succeeds(
        curl(ips["tailnet"], path="/upstream", extra="-o /dev/null -w '%{http_code}'")
        + " | grep '^502$'",
        timeout=T,
    )
    ready(peer, ips["basic"])
    peer.systemctl("start backend")
    ready(peer, ips["tailnet"], path="/upstream")

with subtest("ephemeral enrollment disappears after disconnect"):
    assert any(n["givenName"] == "urlparts" for n in nodes())
    machine.systemctl(f"stop {unit_prefix}urlparts")
    headscale.wait_until_succeeds(
        "headscale nodes list -o json | jq -e 'all(.[]; .givenName != \"urlparts\")'",
        timeout=T,
    )
    ready(peer, ips["basic"])
