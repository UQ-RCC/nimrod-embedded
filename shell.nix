{ pkgs ? (import <nixpkgs> {}) }:
pkgs.mkShell {
  pname   = "nimrun";
  version = "dev";

  nativeBuildInputs = with pkgs; [ cmake ];
  buildInputs = with pkgs; [ openssl.dev ];
}
