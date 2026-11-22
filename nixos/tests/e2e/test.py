import json
import shlex

T = 120


def set_policy(metrics=True):
    policy = {
        "tagOwners": {"tag:service": ["server@"]},
        "grants": [
            {
                "src": ["alice@"],
                "dst": ["tag:service"],
                "ip": ["tcp:80"] + (["tcp:9099"] if metrics else []),
            }
        ],
    }
    headscale.succeed(f"printf %s {shlex.quote(json.dumps(policy))} > /run/policy.json")
    headscale.succeed("headscale policy set -f /run/policy.json")


def curl(name="basic", path="/api/hello?query=one", port=80, extra="-f"):
    return (
        f"curl --noproxy '*' --path-as-is -sS --max-time 5 {extra} "
        f"'http://{ips[name]}:{port}{path}'"
    )


def ready(client, **kwargs):
    return client.wait_until_succeeds(curl(**kwargs), timeout=T)


def nodes():
    return json.loads(headscale.succeed("headscale nodes list -o json"))


start_all()
key = headscale.succeed("hs-authkey alice").strip()
set_policy()
server_key = headscale.succeed("hs-authkey server --tags tag:service").strip()
for client in (peer, relay):
    client.succeed(f"hs-join {shlex.quote(key)}")
machine.wait_for_unit("multi-user.target")
machine.succeed("ip -4 route show default | grep 'dev eth1'")
machine.succeed(f"printf %s {shlex.quote(server_key)} > /run/ts-authkey")
machine.systemctl(f"start {backend_unit}")
for name in ("basic", "urlparts"):
    machine.systemctl(f"start {unit_prefix}{name}")
    machine.wait_for_unit(f"{unit_prefix}{name}", timeout=T)
ips = {
    name: peer.wait_until_succeeds(f"tailscale ip -4 {name}", timeout=T).strip()
    for name in ("basic", "urlparts")
}

with subtest("HTTP forwarding over direct UDP and embedded DERP"):
    peer.wait_until_succeeds(
        "tailscale ping --timeout=3s -c 1 basic | grep -E 'via (\\[)?[0-9a-f]+[.:]'",
        timeout=T,
    )
    relay.wait_until_succeeds(
        "tailscale ping --timeout=3s --until-direct=false -c 1 basic | grep 'via DERP(headscale)'",
        timeout=T,
    )
    for client in (peer, relay):
        assert json.loads(ready(client))["path"] == "/hello?query=one"
        assert (
            json.loads(ready(client, name="urlparts"))["path"] == "/api/hello?query=one"
        )
        assert json.loads(ready(client, path="/api/a%20b"))["path"] == "/a%20b"

with subtest("WhoIs identity replaces forged headers"):
    peer_status = json.loads(peer.succeed("tailscale status --json"))
    user_id = peer_status["Self"]["UserID"]
    profile = peer_status["User"][str(user_id)]
    for client in (peer, relay):
        data = json.loads(
            client.succeed(
                curl(
                    extra="-f -H 'X-Tailscale-User: forged' -H 'X-Tailscale-Unknown: forged'"
                )
            )
        )
        headers = {name.lower(): value for name, value in data["headers"].items()}
        assert headers["x-tailscale-user"] == f"userid:{user_id}", data
        assert headers["x-tailscale-user-loginname"] == profile["LoginName"], data
        assert "x-tailscale-unknown" not in headers, data

with subtest("tailnet allowlist rejects unmatched and Funnel-only paths"):
    for client in (peer, relay):
        for path in ("/", "/private", "/public"):
            status = client.succeed(
                curl(path=path, extra="-o /dev/null -w '%{http_code}'")
            )
            assert status == "404", (path, status)
        ready(client)

with subtest("live policy denies metrics while HTTP remains healthy"):
    for client in (peer, relay):
        ready(client, path="/metrics", port=9099)
    set_policy(metrics=False)
    for client in (peer, relay):
        client.wait_until_fails(curl(path="/metrics", port=9099), timeout=T)
        ready(client)
        client.fail(curl(path="/metrics", port=9099))

with subtest("control and DERP outage preserves established direct HTTP"):
    peer.wait_until_succeeds(
        "tailscale ping --timeout=3s -c 1 basic | grep -E 'via (\\[)?[0-9a-f]+[.:]'",
        timeout=T,
    )
    headscale.systemctl("stop headscale")
    headscale.wait_for_closed_port(80)
    headscale.wait_for_closed_port(443)
    data = json.loads(ready(peer))
    assert data["headers"]["X-Tailscale-User"] == f"userid:{user_id}", data
    peer.fail(curl(path="/metrics", port=9099))
    relay.fail(curl())
    headscale.systemctl("start headscale")
    headscale.succeed("headscale health")
    ready(relay)
    set_policy()
    for client in (peer, relay):
        ready(client, path="/metrics", port=9099)

with subtest("persisted node identity survives restart without an enrollment key"):
    before = next(node for node in nodes() if node["givenName"] == "basic")
    machine.succeed(": > /run/ts-authkey")
    machine.systemctl(f"restart {unit_prefix}basic")
    for client in (peer, relay):
        ready(client)
    after = next(node for node in nodes() if node["givenName"] == "basic")
    assert (after["id"], after["ipAddresses"]) == (before["id"], before["ipAddresses"])
    assert len([node for node in nodes() if node["givenName"] == "basic"]) == 1
