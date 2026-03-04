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
        x86_64)       ARCH="amd64" ;;
        aarch64|arm64) ARCH="arm64" ;;
        armv7l)       ARCH="armv7" ;;
        armv6l)       ARCH="armv6" ;;
        i386|i686)    ARCH="386" ;;
        riscv64)      ARCH="riscv64" ;;
        mips)         ARCH="mips" ;;
        mipsel)       ARCH="mipsle" ;;
        mips64)       ARCH="mips64" ;;
        mips64el)     ARCH="mips64le" ;;
        ppc64le)      ARCH="ppc64le" ;;
        s390x)        ARCH="s390x" ;;
        loongarch64)  ARCH="loong64" ;;
        *)            echo "unsupported architecture: $ARCH" >&2; exit 1 ;;
    esac

    case "$OS" in
        linux|darwin|freebsd|openbsd|netbsd) ;;
        mingw*|msys*|cygwin*) OS="windows" ;;
        *) echo "unsupported OS: $OS" >&2; exit 1 ;;
    esac

    BINARY="rssh-${OS}-${ARCH}"
    URL="https://github.com/${REPO}/releases/latest/download/${BINARY}"

    echo "=> downloading ${BINARY}..."

    TMP=$(mktemp)
    trap 'rm -f "$TMP"' EXIT

    if command -v curl >/dev/null 2>&1; then
        curl -fsSL -o "$TMP" "$URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO "$TMP" "$URL"
    else
        echo "error: curl or wget required" >&2
        exit 1
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
