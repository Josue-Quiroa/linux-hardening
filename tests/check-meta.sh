#!/usr/bin/env bash
# tests/check-meta.sh — Verifica que TODO control/aviso del código tiene metadatos
# ctl_meta (fuente única de --list-controls, pre-check y resumen de reinicio).
# Uso: bash tests/check-meta.sh   (no requiere root; no modifica nada)
set -Eeuo pipefail
cd "$(dirname "$0")/.."
code=$(grep -hoE '(control|advise)[[:space:]]+[A-Z]{2,3}-[0-9]+' modules/*.sh | grep -oE '[A-Z]{2,3}-[0-9]+' | sort -u)
code+=$'\n'$(grep -hoE '"SYS-[0-9]+' modules/20-sysctl.sh | tr -d '"' | sort -u)
meta=$(bash harden.sh --list-controls --format csv | tail -n +2 | cut -d, -f1 | sort -u)
missing=$(comm -23 <(sort -u <<<"$code") <(sort -u <<<"$meta"))
if [[ -n "$missing" ]]; then echo "FALTAN metadatos para: $missing" >&2; exit 1; fi
echo "OK: $(wc -l <<<"$meta") controles con metadatos; todos los IDs del código están cubiertos."
