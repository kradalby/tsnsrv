{
  pkgs,
  nixos-lib,
  nixosModule,
  headscale,
}: let
  common = import ./common.nix {inherit pkgs headscale nixosModule;};
in
  nixos-lib.runTest {
    name = "oci";
    hostPkgs = pkgs;
    imports = [{inherit (common) nodes;}];
    nodes.machine = {
      lib,
      nodes,
      ...
    }: {
      virtualisation.oci-sidecars.tsnsrv = {
        enable = true;
        containers =
          lib.mapAttrs (name: service: {
            inherit name service;
            forContainer = "web-server";
          })
          common.services;
      };
      virtualisation.oci-containers = {
        backend = "podman";
        containers =
          lib.mapAttrs (_: _: {
            autoStart = false;
            environment.TS_NO_LOGS_NO_SUPPORT = "1";
          })
          common.services
          // {
            web-server = {
              autoStart = false;
              image = "web-server:latest";
              imageFile = pkgs.dockerTools.buildLayeredImage {
                name = "web-server";
                tag = "latest";
                contents = [pkgs.python3];
                config.Cmd = ["${pkgs.python3}/bin/python" "${./backend.py}" "0.0.0.0"];
              };
              # Podman's resolver cannot read the VM driver's /etc/hosts.
              extraOptions = ["--add-host=headscale:${nodes.headscale.networking.primaryIPAddress}"];
            };
          };
      };
      # The test starts sidecars after writing their enrollment credential.
      systemd.services =
        {
          podman-web-server.unitConfig.Upholds = lib.mkForce [];
        }
        // lib.mapAttrs' (name: _:
          lib.nameValuePair "podman-${name}" {
            enableStrictShellChecks = true;
          })
        common.services;
    };
    testScript =
      ''
        backend_unit = "podman-web-server"
        unit_prefix = "podman-"
      ''
      + builtins.readFile ./test.py;
  }
