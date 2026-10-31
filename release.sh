#!/usr/bin/env bash
# Builds, SBOMs, signs and publishes release vX.Y.Z from this workstation.
# Spec: 2-03-sbom-signed-releases-spec.md §3-§6; 3-01-lts-release-line-spec.md §4, §11 step 4.
# Release steps are in README.md "Releasing"; operator verification in DOCKER.md.
#
# Usage: ./release.sh vX.Y.Z
# Env: FRONTEND_DIR (default ../cloudillo), COSIGN_KEY (default ~/.cosign/cloudillo.key),
#      IMAGE (default docker.io/cloudillo/cloudillo)
#
# Everything before the typed confirmation is local and read-only (apart from git fetch and
# target/); everything after it pushes.

set -euo pipefail

fail() { echo "error: $*" >&2; exit 1; }

[ $# -eq 1 ] || fail "usage: $0 vX.Y.Z"
TAG=$1
VERSION="${TAG#v}"
[[ "$TAG" == v* && "$VERSION" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || fail "tag $TAG is not vX.Y.Z"
LINE="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"
# Print the body of the "## [$VERSION]" section of changelog $1
changelog_section() {
	awk -v h="## [$VERSION]" 'index($0, h) == 1 { f = 1; next } /^## / { f = 0 } f' "$1"
}

cd "$(dirname "$0")"
export LC_ALL=C RUSTC_WRAPPER="" CARGO_TERM_COLOR=always
FRONTEND_DIR=${FRONTEND_DIR:-../cloudillo}
COSIGN_KEY=${COSIGN_KEY:-$HOME/.cosign/cloudillo.key}
IMAGE=${IMAGE:-docker.io/cloudillo/cloudillo}
DIST="target/release-dist/$VERSION"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# Tools and credentials
for t in git jq cargo cargo-deny cargo-llvm-cov cargo-cyclonedx cyclonedx syft cosign docker gh \
	pnpm npx sha256sum; do
	command -v "$t" > /dev/null || fail "$t not found"
done
docker buildx version > /dev/null || fail "docker buildx not available"
# The default `docker` driver cannot attach provenance or push by digest.
export BUILDX_BUILDER=cloudillo-release
docker buildx inspect > /dev/null 2>&1 \
	|| docker buildx create --name cloudillo-release --driver docker-container > /dev/null
[ -r "$COSIGN_KEY" ] || fail "cosign key $COSIGN_KEY not readable"
[ -r cosign.pub ] || fail "cosign.pub missing (README \"Releasing\", one-time setup)"
[ -d "$FRONTEND_DIR/.git" ] || fail "frontend checkout $FRONTEND_DIR not found"

# Both checkouts clean, on the tag, and the tag pushed unchanged: the Dockerfile clones both
# repositories from GitHub at the tag, so the pushed tag is what gets built.
for repo in . "$FRONTEND_DIR"; do
	git -C "$repo" fetch origin --tags
	[ -z "$(git -C "$repo" status --porcelain)" ] || fail "$repo has uncommitted changes"
	local_tag=$(git -C "$repo" rev-parse -q --verify "refs/tags/$TAG") \
		|| fail "$TAG does not exist in $repo"
	[ "$(git -C "$repo" rev-parse HEAD)" = "$(git -C "$repo" rev-parse "$TAG^{commit}")" ] \
		|| fail "$repo is not checked out at $TAG"
	remote_tag=$(git -C "$repo" ls-remote origin "refs/tags/$TAG" | cut -f1)
	[ "$remote_tag" = "$local_tag" ] || fail "$TAG in $repo is not pushed to origin unchanged"
done

# Tag, version, branch and changelog gates
[ "$(git cat-file -t "$TAG")" = tag ] || fail "$TAG must be an annotated tag"
[ "$(git -C "$FRONTEND_DIR" cat-file -t "$TAG")" = tag ] \
	|| fail "$TAG in cloudillo/cloudillo must be an annotated tag"

cargo_version=$(cargo metadata --no-deps --format-version 1 --locked \
	| jq -r '.packages[] | select(.name == "cloudillo-server") | .version')
[ "$cargo_version" = "$VERSION" ] || fail "Cargo.toml version $cargo_version != $VERSION"
frontend_version=$(jq -r .version "$FRONTEND_DIR/package.json")
[ "$frontend_version" = "$VERSION" ] \
	|| fail "frontend package.json version $frontend_version != $VERSION"
grep -qF "## [$VERSION]" CHANGELOG.md || fail "CHANGELOG.md has no '## [$VERSION]' section"
grep -qF "## [$VERSION]" "$FRONTEND_DIR/CHANGELOG.md" \
	|| fail "frontend CHANGELOG.md has no '## [$VERSION]' section"

# Branch model (3-01 §4): vX.Y.0 from main; later patches from release/X.Y or
# lts/X.Y once the line has such a branch, from main before it.
commit=$(git rev-parse "$TAG^{commit}")
if [ "$PATCH" = 0 ] \
	|| [ -z "$(git branch -r --list "origin/release/$LINE" "origin/lts/$LINE")" ]; then
	want="origin/main"
else
	want="origin/release/$LINE origin/lts/$LINE"
fi
on=$(git branch -r --contains "$commit" | tr -d ' ')
ok=
for b in $want; do grep -qxF "$b" <<< "$on" && ok=1; done
[ -n "$ok" ] || fail "$TAG ($commit) is not on $want"

# ponytail: no migration gate for patch releases (3-01 §11 step 4) while in alpha; restore it
# from git history when the LTS line starts.

# Dependency policy and audit
cargo deny check
(cd "$FRONTEND_DIR" && pnpm audit --prod --audit-level high)

# Full test suite with coverage (includes the access matrix), and its evidence
rm -rf "$DIST"
mkdir -p "$DIST"
find target -name 'access-matrix-*.md' -delete 2>/dev/null || true
cargo llvm-cov --workspace --locked --no-report
cargo llvm-cov report --summary-only | tee "$DIST/cloudillo-$VERSION-coverage.txt"
mapfile -t reports < <(find target -name 'access-matrix-*.md' | sort)
[ "${#reports[@]}" -gt 0 ] || fail "no access-matrix report found"
for f in "${reports[@]}"; do cat "$f"; echo; done > "$DIST/cloudillo-$VERSION-access-matrix.md"

# Native SBOM part. The committed file lists the Debian packages (those with a debian:source
# property) without versions; version, purl, .deb URL and SHA-256 are filled in from apt in
# the poppler-extractor stage. The scratch image has no package database; that stage and
# rust-builder both run `apt-get upgrade`, so they resolve the same versions. Local build only,
# so it runs before anything is pushed.
docker buildx build --target poppler-extractor --load -t cloudillo-native-check .
mapfile -t debs < <(jq -r '.components[] | select(any(.properties[]?; .name == "debian:source"))
	| .name' sbom/native-components.cdx.json)
# Each line: name version url file size SHA256:hash
docker run --rm cloudillo-native-check sh -c '
	set -e
	for p in "$@"; do
		v=$(dpkg-query -W -f "\${Version}" "$p")
		[ -n "$v" ] || { echo "error: $p is not installed" >&2; exit 1; }
		apt-get download --print-uris -qq "$p=$v" | sed "s|^|$p $v |"
	done' sh "${debs[@]}" > "$WORK/debs.txt"
[ "$(wc -l < "$WORK/debs.txt")" -eq "${#debs[@]}" ] || fail "apt did not resolve every package"
deb_release=$(docker run --rm cloudillo-native-check cat /etc/debian_version)
jq -R 'split(" ") | {key: .[0], value: {v: .[1], url: (.[2] | gsub("'\''"; "")
		| sub("^http:"; "https:") | gsub("%2b"; "+")), arch: (.[3] | capture("_(?<a>[^_]+)\\.deb$").a),
		sha: (.[5] | ltrimstr("SHA256:"))}}' "$WORK/debs.txt" \
	| jq -s from_entries > "$WORK/debs.json"
jq --arg v "$VERSION" --arg rel "$deb_release (trixie)" --slurpfile d "$WORK/debs.json" '
	.metadata.component.version = $v
	| (.metadata.properties[] | select(.name == "debian:release")).value = $rel
	| .components |= map(
		if any(.properties[]?; .name == "debian:source") then
			$d[0][.name] as $p
			| "pkg:deb/debian/\(.name)@\($p.v)?arch=\($p.arch)&distro=debian-13" as $purl
			| {type, "bom-ref": $purl, name, version: $p.v, description, scope, purl: $purl,
				hashes: [{alg: "SHA-256", content: $p.sha}],
				externalReferences: [{type: "distribution", url: $p.url,
					comment: "SHA-256 is of this .deb; licence per /usr/share/doc/\(.name)/copyright"}],
				properties}
		else . end)' sbom/native-components.cdx.json > "$DIST/cloudillo-$VERSION-native.cdx.json"

# Approval: everything below pushes.
echo
echo "Release $TAG at commit $commit, image $IMAGE"
read -rp "Type $VERSION to build, sign and publish: " answer
[ "$answer" = "$VERSION" ] || fail "not confirmed"

# Build and push the image (untagged). The Dockerfile clones both repositories at RS_REF /
# FRONTEND_REF; both are this tag, so the image is built from the sources tested above. Pushed
# by digest only: the version tags are added once every gate below has passed.
# provenance keeps the push an image index, so `imagetools create` copies it unchanged.
docker buildx build --build-arg "RS_REF=$TAG" --build-arg "FRONTEND_REF=$TAG" \
	--provenance=mode=min --metadata-file "$DIST/../build-meta.json" \
	--output "type=image,name=$IMAGE,push-by-digest=true,name-canonical=true,push=true" .
DIGEST=$(jq -r '."containerimage.digest"' "$DIST/../build-meta.json")
[[ "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "bad digest '$DIGEST'"
echo "$DIGEST" > "$DIST/cloudillo-$VERSION.image-digest.txt"

# SBOM parts
cargo cyclonedx --manifest-path server/Cargo.toml --format json --spec-version 1.5 \
	--target x86_64-unknown-linux-gnu --override-filename cloudillo-server
mv server/cloudillo-server.json "$DIST/cloudillo-$VERSION-server.cdx.json"
# It writes one per workspace member; the leftovers would make `cargo publish` refuse.
find . -name cloudillo-server.json -type f -not -path './target/*' -delete

npx --yes @cyclonedx/cdxgen@12.8.7 -t js --no-install-deps --spec-version 1.5 \
	-o "$DIST/cloudillo-$VERSION-frontend.cdx.json" "$FRONTEND_DIR"

# Gate: server SBOM covers the resolved dependency graph
cargo metadata --format-version 1 --locked --filter-platform x86_64-unknown-linux-gnu \
	| jq -r '
		(.resolve.nodes | map({key: .id, value: [.deps[]
			| select(any(.dep_kinds[]; .kind == null)) | .pkg]}) | from_entries) as $g
		| (.packages | map({key: .id, value: "\(.name)@\(.version)"}) | from_entries) as $n
		| def reach: . as $s | ($s + [$s[] | $g[.][]] | unique) as $t
			| if ($t | length) == ($s | length) then $s else ($t | reach) end;
		[.packages[] | select(.name == "cloudillo-server") | .id] | reach | .[] | $n[.]' \
	| sort -u > "$WORK/expected.txt"
jq -r '.metadata.component // empty, (.components[]? | recurse(.components[]?))
		| "\(.name)@\(.version)"' "$DIST/cloudillo-$VERSION-server.cdx.json" \
	| sort -u > "$WORK/declared-server.txt"
comm -23 "$WORK/expected.txt" "$WORK/declared-server.txt" | tee "$WORK/missing.txt"
[ ! -s "$WORK/missing.txt" ] || fail "server SBOM misses resolved packages"

# Release SBOM (merge, complete, validate)
out="$DIST/cloudillo-$VERSION.cdx.json"
cyclonedx merge --hierarchical --name cloudillo --version "$VERSION" \
	--input-files "$DIST/cloudillo-$VERSION-server.cdx.json" \
		"$DIST/cloudillo-$VERSION-frontend.cdx.json" "$DIST/cloudillo-$VERSION-native.cdx.json" \
	--output-format json --output-file "$WORK/merged.cdx.json"
jq --arg v "$VERSION" --arg d "$DIGEST" --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	--arg uuid "$(cat /proc/sys/kernel/random/uuid)" '
		.serialNumber //= "urn:uuid:\($uuid)"
		| .metadata.timestamp = $ts
		| .metadata.tools //= {components: [
			{type: "application", name: "cyclonedx-cli", version: "0.33.1"},
			{type: "application", name: "cargo-cyclonedx", version: "0.5.9"},
			{type: "application", name: "cdxgen", version: "12.8.7"}]}
		| .metadata.component += {type: "container", name: "cloudillo", version: $v,
			purl: "pkg:docker/cloudillo/cloudillo@\($v)",
			licenses: [{license: {id: "MPL-2.0"}}],
			externalReferences: [{type: "distribution",
				url: "docker.io/cloudillo/cloudillo@\($d)"}]}' "$WORK/merged.cdx.json" > "$out"
for f in "$DIST"/*.cdx.json; do cyclonedx validate --input-file "$f" --fail-on-errors; done

# Gate: syft cross-check. syft sees in the FROM scratch image only what carries its own
# metadata (e.g. crate lists embedded by cargo auditable); anything it finds must be declared.
syft scan "registry:$IMAGE@$DIGEST" -o "cyclonedx-json=$WORK/image.cdx.json"
jq -r '.components[]? | select(.purl) | "\(.name)@\(.version)"' "$WORK/image.cdx.json" \
	| sort -u > "$WORK/found.txt"
# Debian ELF package notes carry the source package name (gcc-14, not libgcc-s1).
jq -r '.metadata.component // empty, .components[]? | recurse(.components[]?) | . as $c
		| "\(.name)@\(.version)",
			(.properties[]? | select(.name == "debian:source") | "\(.value)@\($c.version)")' \
	"$out" | sort -u > "$WORK/declared.txt"
comm -23 "$WORK/found.txt" "$WORK/declared.txt" > "$WORK/undeclared.txt"
[ ! -s "$WORK/undeclared.txt" ] \
	|| fail "image holds undeclared components: $(tr '\n' ' ' < "$WORK/undeclared.txt")"

# Sign the image, attest the SBOM, sign the checksums (cosign prompts for COSIGN_PASSWORD
# unless it is set).
cosign sign --yes --key "$COSIGN_KEY" "$IMAGE@$DIGEST"
cosign attest --yes --key "$COSIGN_KEY" --type cyclonedx --predicate "$out" "$IMAGE@$DIGEST"
(
	cd "$DIST"
	sha256sum cloudillo-* > SHA256SUMS
	cosign sign-blob --yes --key "$COSIGN_KEY" --bundle SHA256SUMS.sigstore.json SHA256SUMS
)

# Self-check of the operator verification, with the committed public key
pub="$PWD/cosign.pub"
(
	cd "$DIST"
	cosign verify-blob --key "$pub" --bundle SHA256SUMS.sigstore.json SHA256SUMS
	sha256sum -c SHA256SUMS
)
cosign verify --key cosign.pub "$IMAGE@$DIGEST" > /dev/null
cosign verify-attestation --key cosign.pub --type cyclonedx "$IMAGE@$DIGEST" > /dev/null

# Tag the image. :X.Y follows the newest release of its line; :latest only the newest release
# overall.
tags=(-t "$IMAGE:$VERSION" -t "$IMAGE:${VERSION%.*}")
newest=$(git tag -l 'v[0-9]*' --sort=-v:refname | head -n1)
[ "$newest" != "$TAG" ] || tags+=(-t "$IMAGE:latest")
docker buildx imagetools create "${tags[@]}" "$IMAGE@$DIGEST"

# Publish crates (credentials from `cargo login`)
cargo publish --workspace --locked

# GitHub release (credentials from `gh auth login`)
{
	changelog_section CHANGELOG.md
	# shellcheck disable=SC2016 # Markdown backticks
	printf '\n## Image\n\n`cloudillo/cloudillo@%s`\n\n' "$DIGEST"
	printf 'Verify before installing: DOCKER.md, "Verifying a release".\n'
} > "$WORK/notes.md"
gh release create "$TAG" --verify-tag --title "Cloudillo $VERSION" \
	--notes-file "$WORK/notes.md" "$DIST"/*

# Frontend release; its SBOM's checksum and signature are in the server release's SHA256SUMS
{
	changelog_section "$FRONTEND_DIR/CHANGELOG.md"
	printf '\n## Server and image\n\n'
	# shellcheck disable=SC2016 # Markdown backticks
	printf 'Server changes, container image `cloudillo/cloudillo@%s`, signed SBOMs and\n' "$DIGEST"
	printf 'verification: https://github.com/cloudillo/cloudillo-rs/releases/tag/%s\n' "$TAG"
} > "$WORK/frontend-notes.md"
gh release create "$TAG" --repo cloudillo/cloudillo --verify-tag --title "Cloudillo $VERSION" \
	--notes-file "$WORK/frontend-notes.md" "$DIST/cloudillo-$VERSION-frontend.cdx.json"

echo "Released $TAG: $IMAGE@$DIGEST"
