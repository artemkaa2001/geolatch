#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

geolatch_purge=0
geolatch_yes=0
geolatch_lang=${LC_ALL:-${LC_MESSAGES:-${LANG:-en}}}
[[ $geolatch_lang == ru* ]] && geolatch_lang=ru || geolatch_lang=en
message() {
    if [[ $geolatch_lang == ru ]]; then printf '%s\n' "$2"; else printf '%s\n' "$1"; fi
}
usage() { printf '%s\n' 'Usage / Использование: sudo ./uninstall.sh [--yes] [--purge] [--lang en|ru]'; }
while (($#)); do
    case $1 in
        --yes) geolatch_yes=1; shift ;;
        --purge) geolatch_purge=1; shift ;;
        --lang) [[ $# -ge 2 ]] || { usage; exit 2; }; geolatch_lang=$2; shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ $geolatch_lang == en || $geolatch_lang == ru ]] || { usage >&2; exit 2; }
(( EUID == 0 )) || { message 'Run with sudo.' 'Запустите через sudo.' >&2; exit 1; }
exec 9>/run/lock/geolatch-install.lock
flock -n 9 || { message 'Another GeoLatch installation or removal is running.' 'Уже выполняется установка или удаление GeoLatch.' >&2; exit 1; }
if (( !geolatch_yes )); then
    [[ -t 0 ]] || { message 'For automation, explicitly use --yes.' 'Для автоматизации явно укажите --yes.' >&2; exit 2; }
    message 'Remove GeoLatch and its firewall rules? Type yes to continue.' 'Удалить GeoLatch и его правила? Для продолжения введите yes.'
    read -r geolatch_answer
    [[ $geolatch_answer == yes ]] || exit 0
    if (( !geolatch_purge )); then
        message 'Also delete configuration, snapshots, cache and logs? Type yes; otherwise keep them.' \
            'Удалить также конфигурацию, снимки, базы и журналы? Введите yes; иначе данные будут сохранены.'
        read -r geolatch_answer
        [[ $geolatch_answer == yes ]] && geolatch_purge=1
    fi
fi

if [[ ! -x /usr/local/bin/geolatch ]]; then
    message 'The installed GeoLatch command is missing. Repair installation first so rules can be removed safely.' \
        'Установленная команда GeoLatch отсутствует. Восстановите установку для безопасного удаления правил.' >&2
    exit 1
fi
trap 'message "Removal stopped on an error; retained files allow repair." "Удаление остановлено из-за ошибки; оставшиеся файлы позволяют восстановление." >&2' ERR
if [[ -d /run/systemd/system ]]; then
    if systemctl cat geolatch-update.timer >/dev/null 2>&1; then
        systemctl disable --now geolatch-update.timer
    fi
    if systemctl cat geolatch-update.service >/dev/null 2>&1; then
        systemctl stop geolatch-update.service
    fi
fi
# The backend verifies ownership and removes only table inet geolatch.
/usr/local/bin/geolatch disable --yes
if [[ -d /run/systemd/system ]]; then
    if systemctl cat geolatch-restore.service >/dev/null 2>&1; then
        systemctl disable --now geolatch-restore.service
    fi
fi
rm -f -- /etc/systemd/system/geolatch-restore.service /etc/systemd/system/geolatch-update.service /etc/systemd/system/geolatch-update.timer
rm -rf -- /etc/systemd/system/geolatch-update.timer.d
[[ ! -d /run/systemd/system ]] || systemctl daemon-reload
rm -f -- /usr/local/bin/geolatch
rm -rf -- /opt/geolatch
if (( geolatch_purge )); then
    rm -rf -- /etc/geolatch /var/lib/geolatch /var/cache/geolatch /var/log/geolatch
    message 'GeoLatch and its local data were removed.' 'GeoLatch и локальные данные удалены.'
else
    message 'GeoLatch removed. Configuration and local data were retained.' 'GeoLatch удалён. Конфигурация и локальные данные сохранены.'
fi
