# BUILD ARGUMENTS #
###################

# Source refs default to the release tag of this version (bump with the workspace
# version in Cargo.toml). Never a branch. Tag-pinned, not commit-pinned: tags are mutable;
# pass a commit SHA via `--build-arg RS_REF=<sha>` (and FRONTEND_REF) for byte-reproducible
# builds.
ARG RS_REF=v0.8.21
ARG FRONTEND_REF=v0.8.21
ARG UID=10001
ARG GID=10001

# RUST BUILDER STAGE #
######################

# rust:1-slim-trixie
FROM rust:1-slim-trixie@sha256:4df2ae8cfdfebdfc13a65da7f253b73d68983dc0339f2719bc17a279c913b13d AS rust-builder
ARG RS_REF
WORKDIR /app
RUN apt-get update && apt-get install -y libssl-dev pkg-config git
# fetch, not `clone --branch`: takes a tag or a commit SHA
RUN git init -q && git fetch --depth 1 https://github.com/cloudillo/cloudillo-rs.git ${RS_REF} && git checkout -q FETCH_HEAD
# Disable sccache wrapper (not available in Docker)
ENV RUSTC_WRAPPER=""
# cargo auditable embeds the resolved crate list in the binary (kept by strip), so scanners
# read it from the image; release.sh's syft cross-check relies on it.
RUN cargo install cargo-auditable --locked --version 0.7.7
RUN cargo auditable build --profile release-lto
RUN strip /app/target/release-lto/cloudillo-server
ARG UID
ARG GID
# Create non-root user files for scratch image
RUN echo "cloudillo:x:${UID}:${GID}::/cloudillo/data:/sbin/nologin" > /etc/passwd.scratch && \
    echo "cloudillo:x:${GID}:" > /etc/group.scratch
# Create data directory for scratch image (root-owned, so app fails without volume mount)
# The directory must be mounted with proper permissions for the app to work
RUN mkdir -p /cloudillo-data && touch /cloudillo-data/.keep && chmod 0755 /cloudillo-data

# FRONTEND BUILDER STAGE #
##########################

# node:22-slim
FROM node:22-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS frontend-builder
ARG FRONTEND_REF
WORKDIR /app
RUN apt-get update && apt-get install -y git python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages fonttools brotli
# Matches packageManager in the frontend's package.json
RUN npm install -g pnpm@11.4.0
# fetch, not `clone --branch`: takes a tag or a commit SHA
RUN git init -q && git fetch --depth 1 https://github.com/cloudillo/cloudillo.git ${FRONTEND_REF} && git checkout -q FETCH_HEAD
# Lockfile-bound only; @symbion/opalui comes from npm, pinned by the lockfile.
RUN pnpm install --frozen-lockfile
# Ensure fonts are downloaded with TTF files (postinstall may run before wawoff2 is ready)
RUN node libs/fonts/scripts/download-fonts.js --force
ENV COMPRESS=true
RUN pnpm -r --filter '!@cloudillo/storybook' build

# Assemble final dist structure: shell/dist/* + apps under /dist/apps/
RUN mkdir -p /dist/apps \
    && cp -r shell/dist/* /dist/ \
    && for app in apps/*/; do \
         name=$(basename "$app"); \
         if [ -d "$app/dist" ]; then \
           cp -r "$app/dist" "/dist/apps/$name"; \
         fi; \
       done

# FFMPEG STATIC BUILD STAGE #
#############################

# debian:trixie-slim
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS ffmpeg-builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    curl \
    nasm \
    yasm \
    pkg-config \
    libssl-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Pinned sources; versions and hashes are mirrored in sbom/native-components.cdx.json
ARG X264_COMMIT=0480cb05fa188d37ae87e8f4fd8f1aea3711f7ee
ARG X264_SHA256=d0967a1348c85dfde363bb52610403be898171493100561efa0dd05d5fd1ae50
ARG OPUS_VERSION=1.4
ARG OPUS_SHA256=c9b32b4253be5ae63d1ff16eea06b94b5f0f2951b7a02aceef58e3a3ce49c51f
ARG FFMPEG_VERSION=7.0.2
ARG FFMPEG_SHA256=8646515b638a3ad303e23af6a3587734447cb8fc0a0c064ecdb8e95c4fd8b389

# Build x264 (static)
RUN curl -fsSLo x264.tar.gz https://code.videolan.org/videolan/x264/-/archive/${X264_COMMIT}/x264-${X264_COMMIT}.tar.gz \
    && echo "${X264_SHA256}  x264.tar.gz" | sha256sum -c - \
    && tar xzf x264.tar.gz \
    && cd x264-${X264_COMMIT} \
    && ./configure \
        --prefix=/usr/local \
        --enable-static \
        --disable-shared \
        --enable-pic \
        --disable-cli \
    && make -j$(nproc) \
    && make install

# Build opus (static)
RUN curl -fsSLo opus.tar.gz https://downloads.xiph.org/releases/opus/opus-${OPUS_VERSION}.tar.gz \
    && echo "${OPUS_SHA256}  opus.tar.gz" | sha256sum -c - \
    && tar xzf opus.tar.gz \
    && cd opus-${OPUS_VERSION} \
    && ./configure \
        --prefix=/usr/local \
        --enable-static \
        --disable-shared \
        --disable-doc \
        --disable-extra-programs \
    && make -j$(nproc) \
    && make install

# Build ffmpeg (static, minimal codecs)
RUN curl -fsSLo ffmpeg.tar.xz https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz \
    && echo "${FFMPEG_SHA256}  ffmpeg.tar.xz" | sha256sum -c - \
    && tar xJf ffmpeg.tar.xz \
    && cd ffmpeg-${FFMPEG_VERSION} \
    && PKG_CONFIG_PATH="/usr/local/lib/pkgconfig" ./configure \
        --prefix=/usr/local \
        --enable-static \
        --disable-shared \
        --disable-debug \
        --disable-doc \
        --disable-ffplay \
        --disable-network \
        --disable-autodetect \
        \
        --enable-gpl \
        --enable-libx264 \
        --enable-libopus \
        \
        --enable-demuxer=mov,mp4,m4a,matroska,webm,mp3,ogg,flac,wav,aac,image2,image2pipe,png_pipe,jpeg_pipe,webp_pipe \
        --enable-muxer=mp4,webm,matroska,opus,image2,mjpeg,png \
        --enable-decoder=h264,hevc,vp8,vp9,av1,aac,mp3,opus,flac,vorbis,pcm_s16le,png,mjpeg,webp \
        --enable-encoder=libx264,libopus,mjpeg,png \
        --enable-parser=h264,hevc,vp8,vp9,av1,aac,opus,png,mjpeg \
        --enable-filter=scale,thumbnail,select,fps,aresample,volume,anull \
        --enable-protocol=file,pipe \
        \
        --extra-cflags="-I/usr/local/include -static" \
        --extra-ldflags="-L/usr/local/lib -static" \
        --extra-libs="-lpthread -lm" \
        --pkg-config-flags="--static" \
    && make -j$(nproc) \
    && make install \
    && strip /usr/local/bin/ffmpeg /usr/local/bin/ffprobe

# Verify static linking
RUN file /usr/local/bin/ffmpeg && ldd /usr/local/bin/ffmpeg || echo "Static binary - no dynamic deps"
RUN /usr/local/bin/ffmpeg -version
RUN ls -lh /usr/local/bin/ffmpeg /usr/local/bin/ffprobe

# POPPLER EXTRACT STAGE #
#########################

# debian:trixie-slim
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS poppler-extractor
# poppler-data carries the predefined CMaps. Without them pdftotext extracts
# nothing from CJK-encoded PDFs that ship no embedded ToUnicode map.
# Package versions are recorded in sbom/native-components.cdx.json; the base digest
# pins the Debian point release, apt still resolves current trixie(-security) versions.
RUN apt-get update && apt-get install -y poppler-utils poppler-data

# Create staging directory
RUN mkdir -p /staging/usr/bin /staging/usr/share /staging/lib /staging/lib64

# Copy the binaries
RUN cp -L $(which pdftoppm) $(which pdfinfo) $(which pdftotext) $(which prlimit) /staging/usr/bin/

# Poppler's compiled-in data path on Debian, so the same path in the final stage
# needs no POPPLER_DATADIR.
RUN cp -a /usr/share/poppler /staging/usr/share/

# Copy all shared library dependencies
RUN for bin in /staging/usr/bin/*; do \
        ldd "$bin" 2>/dev/null | grep '=>' | awk '{print $3}' | while read lib; do \
            [ -n "$lib" ] && [ -f "$lib" ] && cp -Ln "$lib" /staging/lib/ 2>/dev/null || true; \
        done; \
    done

# Copy the dynamic linker
RUN cp -L /lib64/ld-linux-x86-64.so.2 /staging/lib64/

# Verify
RUN echo "=== Poppler binaries ===" && ls -la /staging/usr/bin/
RUN echo "=== Poppler libs: $(ls /staging/lib/ | wc -l) ==="

# FINAL STAGE #
###############

FROM scratch

# Copy user/group files for non-root execution
COPY --from=rust-builder /etc/passwd.scratch /etc/passwd
COPY --from=rust-builder /etc/group.scratch /etc/group

# Copy data directory as root-owned - app will fail to write without proper volume mount
# Mount /cloudillo/data with a volume that has correct permissions for the cloudillo user
COPY --from=rust-builder /cloudillo-data /cloudillo/data

WORKDIR /cloudillo

# Copy cloudillo binary and its dependencies
COPY --from=rust-builder /app/target/release-lto/cloudillo-server /usr/bin/cloudillo
COPY --from=rust-builder /app/templates /cloudillo/templates
COPY --from=rust-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust-builder /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
COPY --from=rust-builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/

# Copy static ffmpeg binaries (no library dependencies needed!)
COPY --from=ffmpeg-builder /usr/local/bin/ffmpeg /usr/local/bin/ffprobe /usr/bin/

# Copy poppler with all its dependencies
COPY --from=poppler-extractor /staging/usr/bin/ /usr/bin/
COPY --from=poppler-extractor /staging/usr/share/poppler/ /usr/share/poppler/
COPY --from=poppler-extractor /staging/lib/ /lib/
COPY --from=poppler-extractor /staging/lib64/ /lib64/

# Copy assembled frontend dist
COPY --from=frontend-builder /dist /cloudillo/dist

ENV LD_LIBRARY_PATH=/lib
ENV LISTEN=0.0.0.0:443
ENV LISTEN_HTTP=0.0.0.0:80
ENV RUST_LOG=info

USER cloudillo

CMD ["/usr/bin/cloudillo"]
