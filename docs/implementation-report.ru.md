# Отчёт о реализации GeoLatch 0.1.0

Реализован новый проект по `AGENTS.MD`. Первичный отчёт подготовлен после локальной проверки; публикация в GitHub выполняется отдельным шагом по запросу владельца. Установка в системные каталоги этой среды не выполнялась.

## Архитектура и поведение

CLI и полноэкранный Textual-интерфейс используют общий `Controller`. Конфигурация проходит строгую проверку YAML, типов, ISO-кодов, адресов и имён интерфейсов. Интерфейсы и адреса определяются через JSON-интерфейс iproute2. Политики одного назначения объединяют запрещённые страны; остальные назначения не получают географических ограничений.

Два провайдера ipverse загружают только необходимые страны и семейства. Проверяются HTTPS, размер, формат CIDR, служебные диапазоны, изменения покрытия и локальные SHA-256. Проверенные объекты cache публикуются через атомарный manifest. `--force` не отключает защитные проверки. Пути upstream и обе CC0-лицензии проверены через GitHub; сведения приведены в [sources.md](sources.md).

nftables использует собственную таблицу `inet geolatch`, interval sets и prerouting priority `-150`, после conntrack и до обычного DNAT. Ограничения привязаны к выбранным интерфейсам и точным destination IP. Allowlist возвращает управление из цепочки GeoLatch, сохраняя действие остальных firewall. Учитываются IPv4, IPv6, направление соединения и established/related; необходимые ICMPv6-протоколы исключены из блокировки.

Замена таблицы выполняется одной транзакцией после `nft --check`. До изменения ядра записывается журнал и запускается независимый watchdog. В системе systemd это отдельный transient unit; вне systemd используется отсоединённый процесс с более слабыми гарантиями при уничтожении всей группы процессов. Подтверждение проверяет версию правил в ядре. Без подтверждения восстанавливается прежнее состояние; отсчёт watchdog защищён от перевода часов назад. Подтверждённые snapshots позволяют восстанавливать правила без загрузки GeoIP.

Ежедневное обновление и восстановление после загрузки оформлены systemd units. Переключение релизов установщиком атомарно, Python работает в отдельном venv и isolated mode. Runtime-данные находятся вне исходников и сохраняются при обновлении программы.

## Установка и первый запуск

Целевые системы: Ubuntu 22.04/24.04/26.04 LTS и актуальный Debian, x86_64/ARM64, Python 3.10+, nftables 1.0+, systemd.

```sh
git clone https://github.com/artemkaa2001/geolatch.git && cd geolatch && sudo ./install.sh
```

Установщик автоматически открывает мастер. Сначала выбирается English или Русский, затем интерфейсы, IP, страны, семейства адресов, источник и административные исключения. Можно добавить следующую политику без повторения всего мастера. Правила применяются после обзора, затем требуют отдельного подтверждения доступности.

В дальнейшем меню открывается командой `geolatch`; повторный мастер — `geolatch setup`. Смена языка в настройках немедленно перерисовывает интерфейс и сохраняется. `geolatch --lang en status` временно меняет язык CLI. Машинные JSON-ключи остаются стабильными.

## Пример нескольких стран и IP

В мастере создайте `primary` для первого IP и выберите `IR`, `PK`; создайте `secondary` для второго IP и выберите `CN`. Вне этих политик адреса остаются без ограничений GeoLatch. Эквивалентный фрагмент YAML:

```yaml
policies:
  - name: primary
    enabled: true
    destinations: [203.0.113.10]
    block_countries: [IR, PK]
  - name: secondary
    enabled: true
    destinations: [203.0.113.20]
    block_countries: [CN]
```

Это документационные адреса. Полный пример — [examples/config.yaml](../examples/config.yaml); при использовании CLI необходимо указать реальные выбранные интерфейсы и адреса. Предварительный просмотр — `sudo geolatch plan`; применение — `sudo geolatch apply`; подтверждение — `sudo geolatch confirm TOKEN`. Аварийное удаление только собственных ограничений — `sudo geolatch disable --yes`.

## Проверки

Последний полный локальный прогон: **274 passed, 8 skipped**. Пропущены восемь реальных kernel-сценариев. Отдельно после последней правки экрана обновлений выполнены все **17 TUI-тестов**, успешно.

- Проверены строгая конфигурация, локализация, IPv4/IPv6, политики и их объединение, allowlist, генерация и собственность nftables-объектов.
- Проверены повреждённые/пустые загрузки, подмена HTML, аномалии, cache integrity и атомарная публикация кандидата.
- Проверены journal/last-known-good, подтверждение, истечение срока, восстановление после ошибок и offline restore с подменённым IO ядра.
- Реальный отдельный процесс watchdog пережил `SIGKILL` запускающего процесса и восстановил файлы состояния через файловую эмуляцию nft. Это проверка процессов и восстановления, а не netfilter.
- Реальные PTY-тесты проверили alternate screen, курсор, Q/Ctrl+C и восстановление termios. Проверено переключение терминала в обычный режим на время привилегированного помощника; реальная аутентификация sudo не выполнялась.
- Ruff lint и форматирование проходят; `bash -n` и справка обоих shell-скриптов проходят.
- Построены sdist и wheel. Wheel установлен в отдельное окружение; команда версии и 249 русских названий стран проверены из `/tmp`. Подтверждено, что импорт идёт из wheel, а TUI-каталоги и стили включены. Зависимости для этой проверки взяты из уже проверенного локального окружения без сети.
- Все Python-файлы разбираются с грамматикой Python 3.10. CI содержит матрицу 3.10/3.12/3.14, сборку, ShellCheck и отдельный обязательный integration job; удалённый CI здесь не запускался.

Разработка и тесты выполнялись в ограниченной среде **Debian 13.6**, Python **3.12.14**, Linux **6.18.55**. Это не проверка установки на полноценном Debian-сервере. Замер 50 000 префиксов и его ограничения приведены в [verification.md](verification.md).

## Непроверенные сценарии и ограничения

Среда не предоставляет nftables, sudo, доступ к netlink и создание network namespaces. Поэтому фактическая фильтрация пакетов, pre-DNAT hook ordering и kernel atomicity здесь не подтверждены. Тесты этих сценариев реализованы с проверкой изоляции и явными skips; строгий CI-режим превращает отсутствие необходимых возможностей в ошибку.

Не проверены системная установка/удаление от root, реальная загрузка systemd и reboot, отдельный cgroup watchdog, ARM64, Ubuntu и комбинации с настоящими Docker/UFW/VPN/Xray. Не выполнена полная загрузка базы через production HTTP-клиент; отдельно проверены upstream через GitHub и клиент через управляемые HTTP-ответы в тестах. ShellCheck предусмотрен в CI, но локально отсутствует.

`destinations: all` пересчитывается при apply/update/restore; постоянного наблюдения за сменой адресов нет. Точная география не гарантируется. Пустая или отсутствующая страна/семейство отвергается вместо тихого отключения фильтрации. `update --dry-run` выполняет offline-проверку готовности без загрузки и изменения cache. Статус без доступа к ядру показывает неизвестное состояние и явно обозначенные сохранённые сведения. Низкоуровневые сообщения nftables/ОС могут сохранять технический английский текст внутри локализованной оболочки ошибки.

Конфигурация и публичный status доступны локальным пользователям для чтения, включая IP и allowlist; snapshots и cache закрыты. Счётчики сбрасываются при замене таблицы. Сторонний reload firewall может удалить таблицу GeoLatch; произвольные NAT priorities, notrack и offload требуют отдельной проверки. При повреждении исходного cache обновление отвергается; подтверждённый snapshot остаётся независимым источником для восстановления.

## Первый deployment

Сначала используйте одноразовую VM и выполните строгие namespace-тесты:

```sh
sudo env GEOLATCH_REQUIRE_INTEGRATION=1 "$PWD/.venv/bin/python" -m pytest tests/test_integration.py -m integration -v
```

Затем проверьте установку, таймер, отдельный rollback unit и реальный reboot. Для первого VPS обеспечьте доступ к консоли провайдера, вторую SSH-сессию и явный административный CIDR. Проверьте новый SSH-сеанс и доступ к каждому выбранному и невыбранному destination с разрешённого и блокируемого источника до подтверждения. Не отключайте защитное окно через `--confirm` при первом ручном внедрении.

Проект не объявляется production-ready на основании unit-тестов. Перед таким выводом нужны реальные kernel-тесты и проверка топологии целевого сервера.

## Файлы

Изменён `README.md`, исходный `AGENTS.MD` сохранён. Созданы:

```text
.github/workflows/ci.yml
.gitignore
CHANGELOG.md
CONTRIBUTING.md
LICENSE
MANIFEST.in
README.ru.md
SECURITY.md
pyproject.toml
install.sh
uninstall.sh
benchmarks/README.md
benchmarks/performance.py
docs/architecture.md
docs/configuration.md
docs/firewall.md
docs/implementation-report.ru.md
docs/installation.md
docs/localization.md
docs/security.md
docs/sources.md
docs/troubleshooting.md
docs/verification.md
examples/config.yaml
geolatch/__init__.py
geolatch/__main__.py
geolatch/cli.py
geolatch/config.py
geolatch/controller.py
geolatch/firewall.py
geolatch/geoip.py
geolatch/i18n.py
geolatch/metadata.py
geolatch/networks.py
geolatch/nftables.py
geolatch/paths.py
geolatch/rollback.py
geolatch/utils.py
geolatch/providers/__init__.py
geolatch/providers/base.py
geolatch/providers/ipverse_geo.py
geolatch/providers/ipverse_rir.py
geolatch/locales/en.json
geolatch/locales/ru.json
geolatch/locales/countries.json
geolatch/locales/COUNTRIES-LICENSE.txt
geolatch/tui/__init__.py
geolatch/tui/app.py
geolatch/tui/translations.py
geolatch/tui/styles.tcss
geolatch/tui/locales/en.json
geolatch/tui/locales/ru.json
systemd/geolatch-restore.service
systemd/geolatch-update.service
systemd/geolatch-update.timer
tests/integration_helper.py
tests/test_cli.py
tests/test_config.py
tests/test_controller.py
tests/test_geoip.py
tests/test_i18n.py
tests/test_integration.py
tests/test_networks.py
tests/test_nftables.py
tests/test_rollback.py
tests/test_tui.py
```

Разработчик: [@artemkaa_2001](https://t.me/artemkaa_2001). Код — MIT; отдельная LGPL-лицензия названий стран включена в пакет.
