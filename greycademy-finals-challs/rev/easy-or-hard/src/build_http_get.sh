#!/usr/bin/env bash
# build.sh — builds zlib and libcurl with musl for a statically linked http_get binary
# Usage: ./build.sh
# This script documents the commands used to reproduce the steps I ran interactively.
# It tries to be idempotent and installs artifacts under ./build-*/

set -euo pipefail
cd "$(dirname "$0")"
ROOT="$(pwd)"
BUILD_DIR="$ROOT/build"
CURL_VER="8.6.0"
ZLIB_VER="1.3.1"
CURL_SRC="$BUILD_DIR/curl-$CURL_VER"
ZLIB_SRC="$BUILD_DIR/zlib-$ZLIB_VER"
CURL_PREFIX="$CURL_SRC/musl-curl"
ZLIB_PREFIX="$ZLIB_SRC/musl-zlib"
OUT_BIN="$BUILD_DIR/http_get_musl"
SRC="$ROOT/http_get.c"

echo "Starting musl static-build automation"

# Basic checks
command -v musl-gcc >/dev/null 2>&1 || { echo "musl-gcc not found. Install musl-tools (e.g., sudo apt install musl-tools)."; exit 1; }
command -v make >/dev/null 2>&1 || { echo "make not found.", exit 1; }
command -v wget >/dev/null 2>&1 || { echo "wget not found. Install wget."; exit 1; }

mkdir -p "$BUILD_DIR"

# 1) Build zlib (musl)
if [ ! -f "$ZLIB_PREFIX/lib/libz.a" ]; then
  echo "Building zlib $ZLIB_VER for musl..."
  cd "$BUILD_DIR"
  if [ ! -d "zlib-$ZLIB_VER" ]; then
    wget "https://zlib.net/zlib-$ZLIB_VER.tar.gz"
    tar xzf "zlib-$ZLIB_VER.tar.gz"
  fi
  cd "zlib-$ZLIB_VER"
  CC=musl-gcc ./configure --prefix="$(pwd)/musl-zlib"
  make -j"$(nproc)"
  make install
else
  echo "zlib (musl) already built at $ZLIB_PREFIX"
fi

# 2) Build libcurl (musl) — without SSL to avoid extra deps (HTTP only)
if [ ! -f "$CURL_PREFIX/lib/libcurl.a" ]; then
  echo "Building curl $CURL_VER for musl (no SSL)..."
  cd "$BUILD_DIR"
  if [ ! -d "curl-$CURL_VER" ]; then
    wget "https://curl.se/download/curl-$CURL_VER.tar.gz"
    tar xzf "curl-$CURL_VER.tar.gz"
  fi
  cd "curl-$CURL_VER"
  # Minimal options used here to reproduce the non-SSL static build (HTTP only)
  ./configure CC=musl-gcc --disable-shared --enable-static \
    --without-ssl --without-libpsl --without-librtmp --without-libssh2 --disable-ldap \
    --prefix="$(pwd)/musl-curl"
  make -j"$(nproc)"
  make install
else
  echo "curl (musl, no-ssl) already built at $CURL_PREFIX"
fi

# 3) Link the final static program
echo "Linking $OUT_BIN (static)..."
musl-gcc -static -O2 -s \
-I"$CURL_PREFIX/include" -I"$ZLIB_PREFIX/include" -I . \
-L"$CURL_PREFIX/lib" -L"$ZLIB_PREFIX/lib" \
-o "$OUT_BIN" "$SRC" chacha20.c -lcurl -lz -ldl -lpthread

# 4) Report
echo "Build complete. Binary info:"
file "$OUT_BIN" || true
ldd "$OUT_BIN" || true

echo "Tip: the libcurl built by this script is HTTP-only (no SSL). To add HTTPS, build OpenSSL (or mbedTLS) with musl and reconfigure curl with --with-openssl=..."

echo "Done."
