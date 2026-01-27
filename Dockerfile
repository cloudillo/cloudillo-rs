# BUILD ARGUMENTS #
###################

ARG RS_REF=main
ARG FRONTEND_REF=main
ARG OPALUI_REF=
ARG UID=10001
ARG GID=10001

# RUST BUILDER STAGE #
######################

FROM rust:1-slim-trixie AS rust-builder
ARG RS_REF
WORKDIR /app
RUN apt-get update && apt-get install -y libssl-dev pkg-config git
RUN git clone --depth 1 --branch ${RS_REF} https://github.com/cloudillo/cloudillo-rs.git .
# Disable sccache wrapper (not available in Docker)
ENV RUSTC_WRAPPER=""
RUN cargo build --profile release-lto
RUN strip /app/target/release-lto/cloudillo-basic-server
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

FROM node:22-slim AS frontend-builder
ARG FRONTEND_REF
ARG OPALUI_REF
WORKDIR /app
RUN apt-get update && apt-get install -y git python3 python3-pip && rm -rf /var/lib/apt/lists/*
RUN pip3 install --break-system-packages fonttools brotli
RUN npm install -g pnpm
RUN git clone --depth 1 --branch ${FRONTEND_REF} https://github.com/cloudillo/cloudillo.git .
RUN if [ -n "${OPALUI_REF}" ]; then \
        git clone --depth 1 --branch ${OPALUI_REF} https://github.com/szilu/opalui.git local/opalui; \
        pnpm install --no-frozen-lockfile; \
    else \
        pnpm install --frozen-lockfile; \
    fi
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

FROM debian:trixie-slim AS ffmpeg-builder

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

# Build x264 (static)
RUN curl -fsSL https://code.videolan.org/videolan/x264/-/archive/master/x264-master.tar.gz | tar xz \
    && cd x264-master \
    && ./configure \
        --prefix=/usr/local \
        --enable-static \
        --disable-shared \
        --enable-pic \
        --disable-cli \
    && make -j$(nproc) \
    && make install

# Build opus (static)
RUN curl -fsSL https://downloads.xiph.org/releases/opus/opus-1.4.tar.gz | tar xz \
    && cd opus-1.4 \
    && ./configure \
        --prefix=/usr/local \
        --enable-static \
        --disable-shared \
        --disable-doc \
        --disable-extra-programs \
    && make -j$(nproc) \
    && make install

# Build ffmpeg (static, minimal codecs)
RUN curl -fsSL https://ffmpeg.org/releases/ffmpeg-7.0.2.tar.xz | tar xJ \
    && cd ffmpeg-7.0.2 \
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

FROM debian:trixie-slim AS poppler-extractor
RUN apt-get update && apt-get install -y poppler-utils

# Create staging directory
RUN mkdir -p /staging/usr/bin /staging/lib /staging/lib64

# Copy the binaries
RUN cp -L $(which pdftoppm) $(which pdfinfo) /staging/usr/bin/

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
COPY --from=rust-builder /app/target/release-lto/cloudillo-basic-server /usr/bin/cloudillo
COPY --from=rust-builder /app/templates /cloudillo/templates
COPY --from=rust-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=rust-builder /lib64/ld-linux-x86-64.so.2 /lib64/ld-linux-x86-64.so.2
COPY --from=rust-builder /lib/x86_64-linux-gnu/libgcc_s.so.1 /lib/x86_64-linux-gnu/libc.so.6 /lib/x86_64-linux-gnu/libm.so.6 /lib/x86_64-linux-gnu/

# Copy static ffmpeg binaries (no library dependencies needed!)
COPY --from=ffmpeg-builder /usr/local/bin/ffmpeg /usr/local/bin/ffprobe /usr/bin/

# Copy poppler with all its dependencies
COPY --from=poppler-extractor /staging/usr/bin/ /usr/bin/
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
