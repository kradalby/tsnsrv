{
  pkgs,
  headscale,
  nixosModule,
}: let
  peer = {
    imports = [headscale.nixosModules.testkit-peer];
    environment.systemPackages = [pkgs.curl pkgs.jq pkgs.python3];
    networking.firewall.trustedInterfaces = ["tailscale0"];
    systemd.services.backend = {
      wantedBy = ["multi-user.target"];
      serviceConfig.ExecStart = "${pkgs.python3}/bin/python ${./backend.py} 0.0.0.0";
    };
  };
in {
  nodes = {
    headscale = {
      imports = [headscale.nixosModules.testkit];
      environment.systemPackages = [pkgs.jq];
      services.headscale.settings.node.ephemeral.inactivity_timeout = "70s";
    };
    peer = {
      imports = [peer];
      # Approved exit advertisements expose a peer-visible node capability.
      services.tailscale.useRoutingFeatures = "server";
    };
    relay = {
      imports = [peer];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
    machine = {
      imports = [nixosModule];
      virtualisation.memorySize = 2048;
      virtualisation.cores = 2;
      environment.systemPackages = [pkgs.openssl pkgs.jq];
      # tsnet chooses a random UDP port; allow direct traffic on the test LAN.
      networking.firewall.allowedUDPPortRanges = [
        {
          from = 1024;
          to = 65535;
        }
      ];
      services.tsnsrv = {
        enable = true;
        defaults = {
          loginServerUrl = "http://headscale";
          authKeyPath = "/run/ts-authkey";
          timeout = "30s";
          listenAddr = ":80";
          urlParts.host = "127.0.0.1";
          urlParts.port = 3000;
          extraArgs = ["-disableNetworkNamespaces"];
        };
      };
    };
  };
  services = {
    basic = {
      plaintext = true;
      toURL = "http://127.0.0.1:3000";
      prefixes = ["tailnet:/api" "funnel:/public"];
      readHeaderTimeout = "1s";
      upstreamHeaders.X-Configured = "configured";
    };
    urlparts = {
      plaintext = true;
      urlParts.port = 3000;
      prefixes = ["/api"];
      stripPrefix = false;
      ephemeral = true;
      authKeyPath = "/run/ephemeral-key";
    };
    suppressed = {
      plaintext = true;
      suppressWhois = true;
      toURL = "http://127.0.0.1:3000";
      suppressTailnetDialer = true;
      extraArgs = ["-disableNetworkNamespaces" "-recommendedProxyHeaders=false"];
    };
    tls = {
      listenAddr = ":443";
      certificateFile = "/run/certs/cert.pem";
      certificateKey = "/run/certs/key.pem";
      toURL = "http://127.0.0.1:3000";
    };
    tailnet = {
      plaintext = true;
      toURL = "http://peer.tailnet:3000";
    };
    tailnet-relay = {
      plaintext = true;
      toURL = "http://relay.tailnet:3000";
    };
    tcp = {
      plaintext = true;
      toURL = "http://unused.invalid";
      extraArgs = ["-disableNetworkNamespaces" "-upstreamTCPAddr=127.0.0.1:3000"];
    };
    unix = {
      plaintext = true;
      toURL = "http://unused.invalid";
      upstreamUnixAddr = "/run/backend/http.sock";
    };
    upstream-tls = {
      plaintext = true;
      toURL = "https://127.0.0.1:3001";
    };
    upstream-insecure = {
      plaintext = true;
      toURL = "https://127.0.0.1:3001";
      insecureHTTPS = true;
    };
    legacy = {
      plaintext = true;
      toURL = "https://127.0.0.1:3002";
      insecureHTTPS = true;
    };
    legacy-enabled = {
      plaintext = true;
      toURL = "https://127.0.0.1:3002";
      insecureHTTPS = true;
      upstreamAllowInsecureCiphers = true;
    };
    invalid = {
      plaintext = true;
      authKeyPath = "/run/invalid-key";
      timeout = "5s";
      toURL = "http://127.0.0.1:3000";
    };
  };
}
