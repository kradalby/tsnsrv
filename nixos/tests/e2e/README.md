# Tailnet integration tests

Both checks use the project's package and NixOS module. The OCI check also uses
its published-image derivation and sidecar configuration. Headscale's exported
testkit supplies control, embedded DERP, users and keys; testkit-peer supplies
the two real tailscaled clients. Headscale retains its own nixpkgs/Go pin.

Run on Linux with KVM:

```sh
nix build '.#checks.x86_64-linux."e2e/systemd"' -L --no-link
nix build '.#checks.x86_64-linux."e2e/oci"' -L --no-link
```

The shared script checks:

- Actual HTTP forwarding through direct UDP and forced DERP, with transport
  evidence from tailscale ping, plus IPv6 ingress.
- Explicit destination URLs, composed URL parts, TCP destination override, Unix
  sockets, local upstreams and outbound tsnet dialing to direct and relay-only
  tailnet nodes.
- Real WhoIs user/node headers, tagged requesters, node capabilities and
  application grants. Forged X-Tailscale headers are removed. Suppression
  removes all identity headers, including forged ones. An approved exit
  advertisement supplies the peer-visible `suggest-exit-node` capability; this
  suite does not test exit-node routing.
- Application capabilities are forwarded as names, not payloads. They do not
  authorize HTTP operations in tsnsrv; the upstream application must enforce
  them. Live capability revocation leaves network access working.
- Live network grants allow HTTP while denying metrics. Each denial has an
  allowed HTTP control, and restoring policy restores metrics access.
- Tailnet-only and Funnel-only prefix provenance on the tailnet listener,
  prefix stripping/preservation, encoded paths and rejected paths.
- Custom application HTTPS certificates, both accepted with explicit trust and
  rejected without it. The testkit's DERP certificate is unrelated. Upstream
  TLS rejects the self-signed certificate unless explicitly configured insecure.
  Legacy RSA key-exchange ciphers require a separate explicit opt-in.
- Reusable preauth keys, file credentials, missing credentials, failed fresh
  enrollment, ephemeral-key enrollment and cleanup after disconnect, persistent
  identity/IP across restart without an enrollment key, explicit rejection of an
  invalid key even on restart, and a 502 when
  the upstream disappears while another proxy still works.
- Incomplete request headers expire; subsequent requests still succeed.
- Default-disabled bug-report endpoint and the real systemd DynamicUser,
  capability bounding set and state-directory permissions.

The test opts into `-disableNetworkNamespaces` because unprivileged tsnet
otherwise binds sockets to the VM's default user-network interface, bypassing
the route to the test VLAN. Production defaults and service sandboxing remain
unchanged. On a production host, use this option only when ordinary routing is
appropriate; Tailscale's interface binding normally prevents routing loops.

## Fixture limits

Public Funnel ingress, FunnelOnly exposure, automatic Tailscale HTTPS/ACME
certificates, OAuth client-secret exchange/key minting (including OAuth tag and
ephemeral permissions), and successful cloud bug-report uploads require
Tailscale cloud infrastructure. Headscale does not reproduce those services.
Offline prefix tests do not prove public Funnel behavior.

Headscale local users have no cloud profile picture, and do not exercise
cloud-specific identity providers. Tests check the actual local WhoIs profile.
The `-tag` CLI flag feeds OAuth key minting; ordinary preauth-key tags come from
Headscale's key, not that flag. Headscale's key-driven ephemeral expiry is tested;
cloud enrollment using only the tsnet ephemeral flag remains outside this fixture.
