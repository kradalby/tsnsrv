{
  pkgs,
  headscale,
  nixosModule,
}: {
  nodes = {
    headscale.imports = [headscale.nixosModules.testkit];
    peer = {
      imports = [headscale.nixosModules.testkit-peer];
      environment.systemPackages = [pkgs.curl pkgs.jq];
    };
    relay = {
      imports = [headscale.nixosModules.testkit-peer];
      environment.systemPackages = [pkgs.curl pkgs.jq];
      systemd.services.tailscaled.environment.TS_DEBUG_ALWAYS_USE_DERP = "1";
    };
    machine = {
      lib,
      nodes,
      ...
    }: {
      imports = [nixosModule];
      virtualisation.memorySize = 1024;
      virtualisation.cores = 2;
      # Unprivileged tsnet binds to the default-route interface, so use the test LAN.
      networking.interfaces.eth0.useDHCP = lib.mkForce false;
      networking.defaultGateway = {
        address = nodes.headscale.networking.primaryIPAddress;
        interface = "eth1";
      };
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
        };
      };
    };
  };
  services = {
    basic = {
      plaintext = true;
      toURL = "http://127.0.0.1:3000";
      prefixes = ["tailnet:/api" "funnel:/public"];
    };
    urlparts = {
      plaintext = true;
      urlParts.port = 3000;
      prefixes = ["/api"];
      stripPrefix = false;
    };
  };
}
