# Secret Scanner

**Secret Scanner** — это инструмент для поиска конфиденциальной информации (паролей, токенов, ключей API и т.д.) в исходном коде. Он использует комбинацию методов: регулярные выражения, анализ энтропии и статический анализ AST для Python и Java. Результаты сканирования можно сохранять в JSON и HTML, а также выводить в цветном формате в консоль.

## Особенности

- Многопоточное сканирование для максимальной скорости.
- Гибкие правила игнорирования файлов, расширений и директорий.
- Регулярные выражения с поддержкой групп риска и рекомендаций.
- Энтропийный анализ для обнаружения потенциальных секретов (например, base64) с пометкой `warning`.
- AST-анализ Python и Java для поиска присваиваний строк в переменные с чувствительными именами.
- **Сканирование удалённых Git-репозиториев** (без предварительного клонирования).
- Кэширование результатов для повторных запусков (отключается флагом `--no-cache`).
- Дедупликация находок на основе файла и строки с приоритетом анализаторов.
- Повышение критичности для секретов, найденных в специальных директориях (например, `.env`, `config`).
- Генерация HTML-отчёта с возможностью фильтрации и сортировки.
- **Готовый Docker-образ** для запуска без установки зависимостей.

## Установка

### Локальная установка

1. Клонируйте репозиторий или скопируйте файлы проекта.
2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```
   Основные зависимости:
   - `colorama` — цветной вывод в консоль.
   - `javalang` — парсинг Java-кода.

### Запуск через Docker (рекомендуется)

Образ доступен на Docker Hub:
```bash
docker pull konstantingresov/secscanner:latest
```

Подробнее см. раздел [🐳 Использование с Docker](#-использование-с-docker).

## Структура проекта

```
.
├── secscanner.py          # Основной скрипт
├── settings.ini           # Конфигурация по умолчанию
├── requirements.txt       # Зависимости
├── Dockerfile             # Для сборки Docker-образа
├── rules/                 # Папка с правилами
    ├── default_regex.json      # Регулярные выражения
    ├── default_ignore.json     # Правила игнорирования
    ├── ast_keywords.json       # Чувствительные имена для AST
    └── criticality_paths.json  # Директории для повышения критичности
```

## Использование

```bash
python secscanner.py [project_directory] [опции]
```

### Аргументы

- `project_directory` — путь к локальной директории для сканирования (необязателен, если используется `--repo`).

### Основные опции

| Флаг                | Описание |
|---------------------|----------|
| `-r, --rules FILE`  | Путь к JSON-файлу с регулярными выражениями (по умолчанию из settings.ini: `rules/default_regex.json`) |
| `-i, --ignore FILE` | Путь к JSON-файлу с правилами игнорирования (по умолчанию `rules/default_ignore.json`) |
| `-a, --ast`         | Включить AST-анализ (Python и Java) |
| `-e, --entropy`     | Включить энтропийный анализ |
| `-s, --save FILE`   | Имя файла для сохранения результатов (JSON) |
| `--html`            | Генерировать HTML-отчёт (добавляет файл с тем же именем, но с расширением .html) |
| `--no-cache`        | Отключить кэширование результатов |
| `--repo URL`        | Сканировать удалённый Git-репозиторий (вместо локальной директории) |

### Примеры

**Сканирование локального проекта с AST и энтропией, сохранение в JSON и HTML:**
```bash
python secscanner.py ./my_project -a -e -s report.json --html
```

**Сканирование удалённого репозитория:**
```bash
python secscanner.py --repo https://github.com/example/repo.git -a -e --html
```

**С отключённым кэшем:**
```bash
python secscanner.py ./my_project -a --no-cache
```

## Распределение и обоснование уровней критичности

Классификация секретов разделена на четыре уровня: `CRITICAL`, `HIGH`, `MEDIUM` и `WARNING` (только для энтропии).

| Уровень     | Описание | Примеры |
|-------------|----------|---------|
| **CRITICAL** | Прямой контроль над инфраструктурой, финансами или кодом. | AWS Keys, Private Keys, Database Connection Strings, Stripe Live Keys |
| **HIGH**     | Доступ к сторонним сервисам, может нанести существенный ущерб. | Slack/Telegram Bots, SendGrid Keys, Google Maps API Key |
| **MEDIUM**   | Риск ложных срабатываний или ограниченное влияние. | Firebase keys, UUID, Base64 строки, внутренние IP |
| **WARNING**  | Только для энтропийного анализа — подозрительно высокая энтропия, требует ручной проверки. | Длинные случайные строки, похожие на токены |

## Конфигурационные файлы

### `settings.ini`

Задаёт пути к файлам по умолчанию:

```ini
[json_settings]
rules_regex = rules/default_regex.json
rules_ignore = rules/default_ignore.json
default_result_filename = result.json
ast_keywords = rules/ast_keywords.json
criticality_paths = rules/criticality_paths.json
```

### `default_regex.json`

Содержит правила поиска на основе регулярных выражений. Каждое правило включает:
- `regex` — само выражение.
- `risk group` — уровень критичности (CRITICAL, HIGH, MEDIUM).
- `recommendation` — рекомендация по устранению.

Пример:
```json
{
  "patterns": {
    "AWS Access Key ID": {
      "regex": "AKIA[0-9A-Z]{16}",
      "risk group": "CRITICAL",
      "recommendation": "Immediately revoke this key..."
    }
  }
}
```

### `default_ignore.json`

Определяет, какие файлы, расширения и директории следует игнорировать:

```json
{
  "ignore": {
    "files": ["default_regex.json", "default_ignore.json", "requirements.txt"],
    "extensions": [".png", ".jpg", ".exe", ".dll", ".css", ".html"],
    "dirs": [".git", "__pycache__", "venv", "env", "node_modules"]
  }
}
```

### `ast_keywords.json`

Список ключевых слов, по которым AST-анализатор определяет чувствительные имена:

```json
["password", "token", "secret", "api_key", "auth", "credential", "private_key"]
```

### `criticality_paths.json`

Список поддиректорий (имён папок), при нахождении в которых критичность секрета повышается (`low → medium → high → critical`). Пример:

```json
[".env", "config", "secrets", "deploy"]
```

## Как это работает

1. **Сбор файлов** — рекурсивный обход директории проекта (или клонированного репозитория) с учётом правил игнорирования.
2. **Кэширование** — для каждого файла сохраняется время модификации и размер; при повторном запуске неизменённые файлы не сканируются заново.
3. **Применение анализаторов**:
   - **RegexCheckerAdapter**: применяет регулярные выражения к каждой строке.
   - **EntropyAnalyzer**: вычисляет энтропию Шеннона; если энтропия > 4.5 и длина ≥ 12, помечает как `warning`.
   - **ASTAnalyzer** (Python) и **JavaASTAnalyzer** (Java) ищут присваивания строк чувствительным переменным, ключам словарей и аргументам функций.
4. **Повышение критичности по директориям** — если путь содержит одну из папок из `criticality_paths.json`, критичность повышается.
5. **Дедупликация** — на одной строке может быть несколько находок; остаётся одна с наивысшим приоритетом (regex > AST > entropy).
6. **Вывод** — результаты показываются в консоли (цветная таблица), сохраняются в JSON и, при необходимости, в HTML.

## Пример вывода

```
┌──────────────────────────────────────────────────────────┐
│                         RESULTS                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│ Secret #1                                                │
├──────────────────────────────────────────────────────────┤
│ Found      : AWS Access Key ID                           │
│ Criticality : CRITICAL                                    │
│ File        : ./my_project/config/aws.yml                │
│ Line        : 23                                          │
│ Analyzer    : regex                                       │
├──────────────────────────────────────────────────────────┤
│ Secret: AKIAIOSFODNN7EXAMPLE                              │
│ ←                                                         │
│ Recommendation: Immediately revoke this key...            │
└──────────────────────────────────────────────────────────┘
```

## 🐳 Использование с Docker

Вы можете запускать **Secret Scanner** в Docker-контейнере, не устанавливая Python и зависимости локально.

### Быстрый старт

1. Установите [Docker](https://docs.docker.com/get-docker/).
2. Загрузите образ:
   ```bash
   docker pull konstantingresov/secscanner:latest
   ```
3. Запустите сканирование локальной директории:
   ```bash
   docker run --rm -v /абсолютный/путь/к/проекту:/code konstantingresov/secscanner /code -e -a --html
   ```

### Примеры команд

**Сканирование локального проекта с сохранением отчётов в текущую папку:**
```bash
docker run --rm -v $(pwd):/code konstantingresov/secscanner /code -e -a --html -s /code/report.json
```

**Сканирование удалённого Git-репозитория:**
```bash
docker run --rm konstantingresov/secscanner --repo https://github.com/example/repo.git -e -a --html
```

**Сохранение отчёта из удалённого репозитория в текущую папку:**
```bash
docker run --rm -v $(pwd):/output konstantingresov/secscanner --repo https://github.com/example/repo.git -e -a --html -s /output/report.json
```

**Показать справку:**
```bash
docker run --rm konstantingresov/secscanner --help
```

### Где найти образ

Образ опубликован на Docker Hub:  
🔗 **[konstantingresov/secscanner](https://hub.docker.com/r/konstantingresov/secscanner)**

### Сборка образа самостоятельно

```bash
git clone https://github.com/ваш_username/ваш_репозиторий.git
cd ваш_репозиторий
docker build -t secscanner .
```

## Примечания

- Для работы с Java-файлами необходима установка `javalang` (в Docker она уже есть).
- AST-анализ работает только для файлов с расширениями `.py` и `.java`.
- Кэш хранится в файле `.secretscanner_cache.pkl` в рабочей директории.
- При использовании `--repo` обязательно наличие Git в системе (в Docker он установлен).

## Разработка и расширение

Проект построен по модульному принципу. Чтобы добавить новый анализатор, создайте класс с методом `analyze(filepath, lines)` (или `analyze(filepath, content)` для AST) и добавьте его в список анализаторов в `Scanner.__init__`.

---

Если у вас возникнут вопросы или предложения, создайте issue в репозитории или свяжитесь с автором.
