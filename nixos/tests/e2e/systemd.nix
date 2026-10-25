{
  pkgs,
  nixos-lib,
  nixosModule,
  headscale,
}: let
  common = import ./common.nix {inherit pkgs headscale nixosModule;};
in
  nixos-lib.runTest {
    name = "systemd";
    hostPkgs = pkgs;
    imports = [{inherit (common) nodes;}];
    nodes.machine = {lib, ...}: {
      services.tsnsrv.services = common.services;
      systemd.services =
        lib.mapAttrs' (name: _:
          lib.nameValuePair "tsnsrv-${name}" {
            wantedBy = lib.mkForce [];
            environment.TS_NO_LOGS_NO_SUPPORT = "1";
            enableStrictShellChecks = true;
          })
        common.services
        // {
          backend = {
            serviceConfig.ExecStart = "${pkgs.python3}/bin/python ${./backend.py} 127.0.0.1 local";
          };
        };
    };
    testScript =
      ''
        backend_unit = "backend"
        unit_prefix = "tsnsrv-"
        container = False
      ''
      + builtins.readFile ./test.py;
  }
