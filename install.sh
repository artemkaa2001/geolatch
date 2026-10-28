#!/usr/bin/env bash
# Installs only GeoLatch. Firewall changes are made by the confirmed TUI workflow.
set -Eeuo pipefail
umask 022

geolatch_lang=${LC_ALL:-${LC_MESSAGES:-${LANG:-en}}}
[[ $geolatch_lang == ru* ]] && geolatch_lang=ru || geolatch_lang=en
geolatch_no_setup=0
geolatch_action=
geolatch_release=
geolatch_old_current=
geolatch_switched=0
geolatch_install_complete=0

message() {
    if [[ $geolatch_lang == ru ]]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi
}
fail() { message "$1" "$2" >&2; exit 1; }
usage() {
    printf '%s\n' 'Usage / Использование: sudo ./install.sh [--lang en|ru] [--no-setup] [--upgrade|--repair]'
}
cleanup() {
    local result=$?
    if (( result != 0 )); then
        message "Installation failed (exit $result). Read the error above; no firewall rules were changed by this installer." \
            "Установка прервана (код $result). Причина указана выше; установщик не менял правила firewall." >&2
        if (( geolatch_switched && !geolatch_install_complete )); then
            if [[ -n $geolatch_old_current ]]; then
                ln -s -- "$geolatch_old_current" /opt/geolatch/current.rollback
                mv -Tf -- /opt/geolatch/current.rollback /opt/geolatch/current
            else
                rm -f -- /opt/geolatch/current /usr/local/bin/geolatch
            fi
        fi
        if [[ -n $geolatch_release ]] && (( !geolatch_install_complete )); then
            rm -rf -- "$geolatch_release"
        fi
    fi
}
trap cleanup EXIT

while (($#)); do
    case $1 in
        --lang) [[ $# -ge 2 ]] || { usage; exit 2; }; geolatch_lang=$2; shift 2 ;;
        --no-setup) geolatch_no_setup=1; shift ;;
        --upgrade) geolatch_action=upgrade; shift ;;
        --repair) geolatch_action=repair; shift ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ $geolatch_lang == en || $geolatch_lang == ru ]] || { usage >&2; exit 2; }
[[ $(uname -s) == Linux ]] || fail 'GeoLatch requires Linux.' 'GeoLatch требует Linux.'
(( EUID == 0 )) || fail 'Run this installer with sudo.' 'Запустите установщик через sudo.'
exec 9>/run/lock/geolatch-install.lock
flock -n 9 || fail 'Another GeoLatch installation or removal is running.' 'Уже выполняется установка или удаление GeoLatch.'
case $(uname -m) in
    x86_64|aarch64|arm64) ;;
    *) fail 'Supported architectures: x86_64 and ARM64.' 'Поддерживаются x86_64 и ARM64.' ;;
esac
[[ -r /etc/os-release ]] || fail 'Cannot identify the Linux distribution.' 'Не удалось определить дистрибутив.'
# shellcheck source=/dev/null
source /etc/os-release
case ${ID:-} in
    ubuntu|debian) ;;
    *) fail 'The automatic installer supports Ubuntu and Debian.' 'Автоматический установщик поддерживает Ubuntu и Debian.' ;;
esac
[[ -d /run/systemd/system ]] || fail 'A running systemd system is required.' 'Необходима работающая система systemd.'
if (( !geolatch_no_setup )) && [[ ! -t 0 || ! -t 1 ]]; then
    fail 'Interactive installation requires a terminal. For automation, explicitly use --no-setup.' \
        'Для установки нужен терминал. Для автоматизации явно укажите --no-setup.'
fi

geolatch_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f $geolatch_source/pyproject.toml && -f $geolatch_source/geolatch/cli.py ]] || \
    fail 'Run install.sh from a complete GeoLatch checkout.' 'Запустите install.sh из полного репозитория GeoLatch.'

if [[ -e /opt/geolatch/current || -L /opt/geolatch/current ]]; then
    [[ -L /opt/geolatch/current ]] || fail '/opt/geolatch/current must be a GeoLatch symlink.' '/opt/geolatch/current должен быть ссылкой GeoLatch.'
    geolatch_old_current=$(readlink -- /opt/geolatch/current)
    if [[ -z $geolatch_action ]]; then
        if [[ ! -t 0 || ! -t 1 ]]; then
            fail 'Existing installation: explicitly choose --upgrade or --repair.' \
                'Программа уже установлена: явно выберите --upgrade или --repair.'
        fi
        message 'GeoLatch is already installed: [1] Open  [2] Upgrade  [3] Repair  [4] Cancel' \
            'GeoLatch уже установлен: [1] Открыть  [2] Обновить  [3] Восстановить  [4] Отмена'
        read -r -p '> ' geolatch_choice
        case $geolatch_choice in
            1) exec 9>&-; exec /usr/local/bin/geolatch ;;
            2) geolatch_action=upgrade ;;
            3) geolatch_action=repair ;;
            *) exit 0 ;;
        esac
    fi
fi

[[ ! -e /var/lib/geolatch/pending.json ]] || fail \
    'An apply is awaiting confirmation. Confirm it or roll back before changing the installed program.' \
    'Ожидается подтверждение правил. Подтвердите применение или выполните откат до обновления программы.'
message 'Installing GeoLatch dependencies…' 'Установка зависимостей GeoLatch…'
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip nftables iproute2 ca-certificates sudo
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else "Python 3.10+ required / Требуется Python 3.10+")'
nft --version
python3 -I -c 'import re, subprocess; version = re.search(r"v(\d+)\.(\d+)", subprocess.check_output(["nft", "--version"], text=True)); raise SystemExit(0 if version and tuple(map(int, version.groups())) >= (1, 0) else "nftables 1.0+ required / Требуется nftables 1.0+")'

install -d -o root -g root -m 0755 /opt/geolatch /opt/geolatch/releases /usr/local/bin
install -d -o root -g root -m 0755 /etc/geolatch
install -d -o root -g root -m 0755 /var/lib/geolatch
install -d -o root -g root -m 0700 /var/cache/geolatch /var/log/geolatch
install -d -o root -g root -m 0755 /etc/systemd/system/geolatch-update.timer.d
if [[ ! -e /etc/systemd/system/geolatch-update.timer.d/schedule.conf ]]; then
    printf '[Timer]\nOnCalendar=\nOnCalendar=daily\n' > /etc/systemd/system/geolatch-update.timer.d/schedule.conf
    chmod 0644 /etc/systemd/system/geolatch-update.timer.d/schedule.conf
fi
geolatch_release=$(mktemp -d /opt/geolatch/releases/release.XXXXXXXX)
chmod 0755 "$geolatch_release"
python3 -m venv "$geolatch_release/venv"
"$geolatch_release/venv/bin/python" -m pip install --disable-pip-version-check "$geolatch_source"
"$geolatch_release/venv/bin/python" -I -m geolatch version
"$geolatch_release/venv/bin/python" -I -c 'import textual, yaml; from geolatch.i18n import Translator; assert Translator("en")'
install -o root -g root -m 0755 "$geolatch_source/uninstall.sh" "$geolatch_release/uninstall.sh"

ln -s -- "$geolatch_release" /opt/geolatch/current.new
mv -Tf -- /opt/geolatch/current.new /opt/geolatch/current
geolatch_switched=1
geolatch_launcher=$(mktemp /usr/local/bin/.geolatch.XXXXXXXX)
cat > "$geolatch_launcher" <<'LAUNCHER'
#!/bin/sh
exec /opt/geolatch/current/venv/bin/python -I -m geolatch "$@"
LAUNCHER
chmod 0755 "$geolatch_launcher"
chown root:root "$geolatch_launcher"
mv -f -- "$geolatch_launcher" /usr/local/bin/geolatch
for geolatch_unit in geolatch-restore.service geolatch-update.service geolatch-update.timer; do
    install -o root -g root -m 0644 "$geolatch_source/systemd/$geolatch_unit" "/etc/systemd/system/$geolatch_unit"
done
systemctl daemon-reload
systemctl enable geolatch-restore.service
/usr/local/bin/geolatch version
geolatch_install_complete=1
exec 9>&-
message 'GeoLatch is installed. Configuration and firewall rules were preserved.' \
    'GeoLatch установлен. Конфигурация и действующие правила сохранены.'
if (( geolatch_no_setup )); then
    message 'Automation mode: open geolatch in a terminal, or review and apply an explicit configuration.' \
        'Автоматический режим: откройте geolatch в терминале или проверьте и примените явную конфигурацию.'
elif [[ -f /etc/geolatch/config.yaml ]]; then
    exec /usr/local/bin/geolatch
else
    exec /usr/local/bin/geolatch setup
fi
