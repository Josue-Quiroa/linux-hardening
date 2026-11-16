# shellcheck shell=bash
# =============================================================================
# lib/all.sh — Carga todas las librerías comunes en el orden correcto.
# Los módulos lo incluyen si se ejecutan de forma aislada (p. ej. para tests).
# =============================================================================
_HARDENING_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/common.sh
source "${_HARDENING_LIB_DIR}/common.sh"
# shellcheck source=lib/distro.sh
source "${_HARDENING_LIB_DIR}/distro.sh"
# shellcheck source=lib/backup.sh
source "${_HARDENING_LIB_DIR}/backup.sh"
# shellcheck source=lib/fileops.sh
source "${_HARDENING_LIB_DIR}/fileops.sh"
# shellcheck source=lib/report.sh
source "${_HARDENING_LIB_DIR}/report.sh"
# shellcheck source=lib/control.sh
source "${_HARDENING_LIB_DIR}/control.sh"
# shellcheck source=lib/context.sh
source "${_HARDENING_LIB_DIR}/context.sh"
# shellcheck source=lib/fwsafety.sh
source "${_HARDENING_LIB_DIR}/fwsafety.sh"
# shellcheck source=lib/changes.sh
source "${_HARDENING_LIB_DIR}/changes.sh"
# shellcheck source=lib/listing.sh
source "${_HARDENING_LIB_DIR}/listing.sh"
# shellcheck source=lib/workloads.sh
source "${_HARDENING_LIB_DIR}/workloads.sh"
_HARDENING_LIBS=1
