{ pkgs ? import <nixpkgs> {} }:
	pkgs.mkShell {
		nativeBuildInputs = with pkgs.buildPackages; [ openssl pkg-config ];
		# mkShell sets CC/CXX/AR/PKG_CONFIG*, which C build scripts (aws-lc-sys, ring, …)
		# fingerprint; a separate target dir stops rebuilds when switching shells.
		shellHook = ''
			export CARGO_TARGET_DIR="$PWD/target/nix-shell"
		'';
	}

# vim: ts=4
