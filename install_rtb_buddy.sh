#!/usr/bin/env bash
set -euo pipefail

REPO="rtbrick/tools"
BINARY="rtb-buddy"
INSTALL_DIR="/usr/local/bin"
GITHUB_API="https://api.github.com/repos/${REPO}/releases"
GITHUB_DOWNLOAD="https://github.com/${REPO}/releases/download"

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Install ${BINARY} from GitHub releases.

Options:
  --uninstall          Remove ${BINARY} from ${INSTALL_DIR}
  --version VERSION    Install a specific version (default: latest)
  --dir DIR            Install directory (default: ${INSTALL_DIR})
  -h, --help           Show this help message
EOF
}

log() {
    echo "==> $*"
}

error() {
    echo "ERROR: $*" >&2
    exit 1
}

detect_os() {
    local os
    os="$(uname -s)"
    case "${os}" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "darwin" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *) error "Unsupported OS: ${os}" ;;
    esac
}

detect_arch() {
    local arch
    arch="$(uname -m)"
    case "${arch}" in
        x86_64|amd64)   echo "amd64" ;;
        aarch64|arm64)  echo "arm64" ;;
        *) error "Unsupported architecture: ${arch}" ;;
    esac
}

check_deps() {
    for cmd in curl jq sha256sum; do
        if ! command -v "${cmd}" &>/dev/null; then
            error "Required command not found: ${cmd}"
        fi
    done
}

# sha256sum is not available on macOS by default, use shasum
verify_checksum() {
    local file="$1"
    local checksum_file="$2"

    local expected
    expected="$(grep "$(basename "${file}")" "${checksum_file}" | awk '{print $1}')"
    if [[ -z "${expected}" ]]; then
        error "No checksum found for $(basename "${file}")"
    fi

    local actual
    if command -v sha256sum &>/dev/null; then
        actual="$(sha256sum "${file}" | awk '{print $1}')"
    else
        actual="$(shasum -a 256 "${file}" | awk '{print $1}')"
    fi

    if [[ "${expected}" != "${actual}" ]]; then
        error "Checksum mismatch: expected ${expected}, got ${actual}"
    fi

    log "Checksum verified"
}

get_latest_version() {
    local version
    version="$(curl -fsSL "${GITHUB_API}/latest" | jq -r '.tag_name')"
    if [[ -z "${version}" || "${version}" == "null" ]]; then
        error "Failed to fetch latest version"
    fi
    echo "${version}"
}

uninstall() {
    local target="${INSTALL_DIR}/${BINARY}"
    if [[ ! -f "${target}" ]]; then
        log "${BINARY} not found at ${target}, nothing to uninstall"
        return 0
    fi

    rm -f "${target}"
    log "Removed ${target}"
}

install_binary() {
    local version="$1"
    local os="$2"
    local arch="$3"
    local install_dir="$4"

    local archive_name="${BINARY}_${version#v}_${os}_${arch}.tar.gz"
    local download_url="${GITHUB_DOWNLOAD}/${version}/${archive_name}"
    local checksum_url="${GITHUB_DOWNLOAD}/${version}/checksums.txt"

    local tmpdir
    tmpdir="$(mktemp -d)"

    log "Downloading ${archive_name}..."
    curl -fsSL -o "${tmpdir}/${archive_name}" "${download_url}"

    log "Downloading checksums..."
    curl -fsSL -o "${tmpdir}/checksums.txt" "${checksum_url}"

    log "Verifying checksum..."
    verify_checksum "${tmpdir}/${archive_name}" "${tmpdir}/checksums.txt"

    log "Extracting..."
    tar -xzf "${tmpdir}/${archive_name}" -C "${tmpdir}"

    if [[ ! -f "${tmpdir}/${BINARY}" ]]; then
        error "Binary not found in archive"
    fi

    chmod +x "${tmpdir}/${BINARY}"

    log "Installing to ${install_dir}/${BINARY}..."
    if [[ "${install_dir}" == "/usr/local/bin" ]]; then
        sudo mv "${tmpdir}/${BINARY}" "${install_dir}/${BINARY}"
    else
        mv "${tmpdir}/${BINARY}" "${install_dir}/${BINARY}"
    fi

    rm -rf "${tmpdir}"
    log "Installed ${BINARY} ${version} to ${install_dir}/${BINARY}"
}

main() {
    local version=""
    local install_dir="${INSTALL_DIR}"
    local do_uninstall=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --uninstall)
                do_uninstall=true
                shift
                ;;
            --version)
                version="$2"
                shift 2
                ;;
            --dir)
                install_dir="$2"
                shift 2
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                error "Unknown option: $1"
                ;;
        esac
    done

    if [[ "${do_uninstall}" == true ]]; then
        uninstall
        exit 0
    fi

    check_deps

    local os arch
    os="$(detect_os)"
    arch="$(detect_arch)"

    log "Detected: ${os}/${arch}"

    if [[ -z "${version}" ]]; then
        version="$(get_latest_version)"
    fi

    log "Version: ${version}"
    install_binary "${version}" "${os}" "${arch}" "${install_dir}"

    log "Done! Run '${BINARY} --help' to get started."
}

main "$@"
