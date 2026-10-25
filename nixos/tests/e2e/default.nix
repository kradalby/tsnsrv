{
  pkgs,
  nixos-lib,
  nixosModule,
  headscale,
  ...
}: {
  systemd = import ./systemd.nix {inherit pkgs nixos-lib nixosModule headscale;};
  oci = import ./oci.nix {inherit pkgs nixos-lib nixosModule headscale;};
}
