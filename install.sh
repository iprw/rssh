#!/bin/sh
set -e

# rssh installer — curl -fsSL https://raw.githubusercontent.com/iprw/rssh/main/install.sh | sh
# Override install dir: INSTALL_DIR=/usr/bin sh -c '...'

REPO="iprw/rssh"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

main() {
    OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    ARCH=$(uname -m)

    case "$ARCH" in
        x86_64)        ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l)        ARCH="armv7" ;;
        armv6l)        ARCH="armv6" ;;
        i386|i686)     ARCH="386" ;;
        riscv64)       ARCH="riscv64" ;;
        mips)          ARCH="mips" ;;
        mipsel)        ARCH="mipsle" ;;
        mips64)        ARCH="mips64" ;;
        mips64el)      ARCH="mips64le" ;;
        ppc64le)       ARCH="ppc64le" ;;
        s390x)         ARCH="s390x" ;;
        loongarch64)   ARCH="loong64" ;;
        *)             echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    case "$OS" in
        linux|darwin|freebsd|openbsd|netbsd) ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *) echo "unsupported OS: $OS" >&2; exit 1 ;;
    esac

    BINARY="rssh-${OS}-${ARCH}"
    BASE_URL="https://github.com/${REPO}/releases/latest/download"
    URL="${BASE_URL}/${BINARY}"
    CHECKSUMS_URL="${BASE_URL}/checksums.txt"

    echo "=> downloading ${BINARY}..."

    TMP=$(mktemp)
    trap 'rm -f "$TMP" "${TMP}.checksums"' EXIT

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$TMP" "$URL"
        curl -fsSL -o "${TMP}.checksums" "$CHECKSUMS_URL" 2>/dev/null || true
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMP" "$URL"
        wget -qO "${TMP}.checksums" "$CHECKSUMS_URL" 2>/dev/null || true
    else
        echo "error: curl or wget required" >&2
        exit 1
    fi

    # Verify checksum if checksums.txt was downloaded and sha256sum is available.
    if [ -s "${TMP}.checksums" ] && command -v sha256sum >/dev/null 2>&1; then
        EXPECTED=$(grep "  ${BINARY}\$" "${TMP}.checksums" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            ACTUAL=$(sha256sum "$TMP" | awk '{print $1}')
            if [ "$EXPECTED" != "$ACTUAL" ]; then
                echo "error: checksum mismatch (expected ${EXPECTED}, got ${ACTUAL})" >&2
                exit 1
            fi
            echo "=> checksum verified"
        fi
    elif [ -s "${TMP}.checksums" ] && command -v shasum >/dev/null 2>&1; then
        EXPECTED=$(grep "  ${BINARY}\$" "${TMP}.checksums" | awk '{print $1}')
        if [ -n "$EXPECTED" ]; then
            ACTUAL=$(shasum -a 256 "$TMP" | awk '{print $1}')
            if [ "$EXPECTED" != "$ACTUAL" ]; then
                echo "error: checksum mismatch (expected ${EXPECTED}, got ${ACTUAL})" >&2
                exit 1
            fi
            echo "=> checksum verified"
        fi
    fi

    chmod +x "$TMP"

    # Install — use sudo if needed and available.
    DEST="${INSTALL_DIR}/rssh"
    if [ -w "$INSTALL_DIR" ]; then
        mv -f "$TMP" "$DEST"
    elif command -v sudo >/dev/null 2>&1; then
        echo "=> installing to ${DEST} (sudo)"
        sudo mv -f "$TMP" "$DEST"
    elif command -v doas >/dev/null 2>&1; then
        echo "=> installing to ${DEST} (doas)"
        doas mv -f "$TMP" "$DEST"
    else
        echo "error: cannot write to ${INSTALL_DIR} — run as root or set INSTALL_DIR" >&2
        exit 1
    fi

    trap - EXIT
    echo "=> rssh installed to ${DEST}"
    echo "   run: rssh user@host"
}

main
