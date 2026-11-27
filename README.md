# tailmeta

Версия и метаданные в хвосте готового файла. Записывайте версию после сборки,
читайте её без запуска приложения и заменяйте без пересборки.
Подпись Ed25519 — необязательное расширение.

Python 3.10+. Базовая установка не требует сторонних библиотек.
Пакет подготовлен локально; в PyPI пока не опубликован.

## Установка

Из каталога проекта:

```bash
python -m pip install .
# С поддержкой подписи:
python -m pip install '.[signing]'
```

Из собранного wheel:

```bash
python -m pip install packages/tailmeta-*.whl
```

## Командная строка

```bash
python -m tailmeta stamp app.bin --version 1.2.4
python -m tailmeta read app.bin
python -m tailmeta read app.bin --version-only
python -m tailmeta stamp app.bin --version 1.2.5 --channel stable --commit abc123
python -m tailmeta --version
```

После установки также доступна команда `tailmeta` с теми же аргументами.
`stamp` требует существующий файл, сохраняет его исходные байты и заменяет
предыдущий хвост. Повторная запись не накапливает метаданные.
`read` не проверяет подлинность даже подписанного хвоста.
При отсутствии метаданных CLI `read` завершается с кодом 1; ошибки чтения,
формата и проверки также возвращают код 1.

## Python API

```python
from tailmeta import read_metadata, stamp

stamp("app.bin", {"version": "1.2.4", "channel": "stable"})
metadata = read_metadata("app.bin")
print(metadata["version"] if metadata else "unknown")
```

`stamp(path, metadata, private_key=None)` принимает словарь с обязательной
непустой строкой `version` и дополнительными JSON-полями. `sha256` и
`signature` зарезервированы и генерируются при подписании.
`read_metadata(path)` возвращает словарь либо `None`, если хвоста нет.
Некорректный распознанный хвост вызывает `ValueError`, ошибки файлов — `OSError`.
Поддерживаются строки путей и `pathlib.Path`.

## Необязательная подпись

```bash
python -m tailmeta keygen --private-key private.pem --public-key public.pem
python -m tailmeta stamp app.bin --version 1.2.4 --private-key private.pem
python -m tailmeta verify app.bin --public-key public.pem
```

```python
from tailmeta import generate_keys, stamp, verify

generate_keys("private.pem", "public.pem")
stamp("app.bin", {"version": "1.2.4"}, private_key="private.pem")
metadata = verify("app.bin", public_key="public.pem")
```

Для этих операций установите extra `signing`. Без него запись и чтение версии
продолжают работать; операции подписи сообщают об отсутствующей зависимости.
`verify` проверяет подпись всех полей и SHA-256 исходной части файла, возвращает
проверенные поля без `signature`. Неподписанные файлы отклоняются.
Ключи Ed25519 хранятся в PEM; закрытый ключ создаётся незашифрованным с правами
0600. `keygen` не перезаписывает существующие ключи.
Повторный `stamp` без ключа заменяет подписанный хвост неподписанным.
Подписание удостоверяет текущие байты, не проверяя прежнюю подпись.

## Формат v1

```text
[исходный файл][JSON UTF-8][длина JSON: uint32 big endian][MYAPPv01: 8 байт]
```

Сигнатура `MYAPPv01` сохранена для совместимости с исходным экспериментом.
JSON ограничен 1 МиБ. Поля сортируются, сериализация использует
`ensure_ascii=False`, `allow_nan=False`, `separators=(",", ":")`.
Подписывается `b"MYAPPv01\x00" + JSON` всех полей, кроме `signature`.
Это Python-сериализация, не JCS. Подпись хранится в Base64; хеш — SHA-256
исходной части до JSON, в шестнадцатеричном виде.

Запись копирует исходную часть в соседний временный файл и атомарно заменяет
целевой файл, сохраняя режим доступа. Символьные ссылки разрешаются до цели.
Владелец, ACL, расширенные атрибуты и связи hard link не сохраняются специально.
Параллельная запись не поддерживается. Повреждённую сигнатуру нельзя отличить
от отсутствующего хвоста. Старые текстовые `MYAPP_VER:` не удаляются.

## Пример с Nuitka

`main.py` читает версию собственного onefile; без метаданных выводит `unknown`.
Проверка подписи включается явно через `--public-key`.

```bash
make deps
make build
make stamp VERSION=1.2.4
make version
make run

# Необязательно, демонстрационные ключи:
make keygen
make sign VERSION=1.2.4
make verify
./dist/main.bin --public-key dist/main.bin.pub.pem
```

Makefile использует `.venv/bin/python`. `make deps` устанавливает пакет в
editable-режиме с extra `signing` и инструменты для эксперимента с Nuitka.
`version_tail.py` оставлен как совместимый запуск старой CLI после установки пакета.

## Разработка и сборка пакета

```bash
python -m pip install -e '.[signing]'
python -m unittest discover -s tests -v
python -m pip install build
python -m build --outdir packages
make test  # дополнительно пересобирает и проверяет настоящий onefile
```

Wheel содержит только `tailmeta`, без тестовых ключей, бинарников и Nuitka.
`make test` работает с временными копиями, проверяет версии без подписи,
подпись, подмену данных и ключей. Оставляет свежий бинарник без хвоста.
`make clean` удаляет dist, включая демонстрационный открытый ключ.

Для окружения с недоступными системными кешами:

```bash
mkdir -p /tmp/nuitka-version-test-ccache-tmp
NUITKA_CACHE_DIR=/tmp/nuitka-version-test-cache \
CCACHE_DIR=/tmp/nuitka-version-test-ccache \
CCACHE_TEMPDIR=/tmp/nuitka-version-test-ccache-tmp make test
```

## Совместимость

Добавлять хвост можно только к форматам, допускающим посторонние байты в конце.
Работа с Nuitka onefile проверяется на Linux; это не обещание совместимости
с любым исполняемым файлом. При обновлении загрузчика повторяйте проверку.
Системные подписи и хеши всего файла нужно формировать после записи хвоста.
Доверие к открытому ключу и проверяющему коду обеспечивает развёртывание;
самопроверка не заменяет проверку доверенным launcher до запуска.

## GitHub Actions и PyPI

Workflow `.github/workflows/publish.yml` выполняется на push, pull request и
ручном запуске. Он собирает wheel **из sdist**, проверяет метаданные через
`twine check --strict`, затем тестирует этот wheel в чистых окружениях на
Python 3.10–3.14 с extra `signing` и без него. Отдельный job собирает настоящий
Nuitka onefile на Linux и проверяет версию и подпись.

Публикация выполняется только при push тега `vX.Y.Z`, после успешного
завершения всех проверок. Допускаются prerelease-теги, например `v0.2.0rc1`.
Артефакты публикуются те же, которые прошли тесты. OIDC-разрешение
`id-token: write` получает только job публикации; API-токен PyPI не нужен.
Ручной запуск workflow и обычные коммиты ничего не публикуют.

### Автоверсионирование

`setuptools-scm` получает версию из Git-тегов; вручную редактировать версию
в `pyproject.toml` и Python-коде не нужно. Это версионирование **по тегам**:
workflow не создаёт теги и не выбирает major/minor/patch за разработчика.

```bash
git tag v0.1.0
git push origin v0.1.0
```

На теге получается версия `0.1.0`. Между тегами — автоматически вычисляемая
версия разработки. При сборке генерируется `src/tailmeta/_version.py`, который
попадает в пакет и доступен внутри Nuitka без Git и setuptools-scm во время
работы. Файл не нужно коммитить. Для исходников без Git-истории и метаданных
sdist используется `0.0.0.dev0`; такой fallback не пройдёт проверку релизного
тега. Версия установленного пакета доступна через `tailmeta.__version__` и
`python -m tailmeta --version`.

### Однократная настройка Trusted Publishing

1. Разместите проект в GitHub и создайте environment **`pypi`** в настройках
   репозитория. При необходимости ограничьте его релизными тегами.
2. В PyPI добавьте Trusted Publisher для существующего `tailmeta`, либо
   Pending Publisher для первого выпуска через
   https://pypi.org/manage/account/publishing/ . Укажите:
   - PyPI project name: `tailmeta`;
   - GitHub owner и repository: фактические владелец и имя репозитория;
   - workflow filename: **`publish.yml`**;
   - environment name: **`pypi`**.
3. Отправьте релизный тег. GitHub Actions выполнит тесты и публикацию.

Конфигурация workflow сама по себе не регистрирует доверие в аккаунте PyPI.
Опубликованные версии PyPI не перезаписываются: для следующего выпуска
создайте новый тег. Полный справочник:
https://docs.pypi.org/trusted-publishers/using-a-publisher/ .
