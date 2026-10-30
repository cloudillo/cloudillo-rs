{ pkgs ? import <nixpkgs> {} }:
	pkgs.mkShell {
		nativeBuildInputs = with pkgs.buildPackages; [ openssl pkg-config ];
		# mkShell sets CC/CXX/AR/PKG_CONFIG*, which C build scripts (aws-lc-sys, ring, …)
		# fingerprint; a separate target dir stops rebuilds when switching shells.
		shellHook = ''
			export CARGO_TARGET_DIR="$PWD/target/nix-shell"
			# cargo-llvm-cov (release.sh): LLVM major must match `rustc -vV`
			export LLVM_COV=${pkgs.llvmPackages_21.llvm}/bin/llvm-cov
			export LLVM_PROFDATA=${pkgs.llvmPackages_21.llvm}/bin/llvm-profdata
		'';
	}

# vim: ts=4
