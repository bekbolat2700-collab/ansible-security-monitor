"""
Security Agent
==============
AI-агент для security-review Pull Request. Агентный цикл:
TASK -> PLAN -> TOOL CALL -> OBSERVE -> DECIDE -> ... -> REPORT

Инструменты: analyze_git_diff (GitHub API), run_kics и run_trivy (Docker).
query_falco пока заглушка (Phase 2).

Полное описание, переменные окружения и запуск -- в README.md.
"""

import json
import os
import requests
from groq import Groq

# ---------------------------------------------------------------------------
# GitHub config -- нужны для реального analyze_git_diff()
# ---------------------------------------------------------------------------
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")
GITHUB_REPO = os.environ.get("GITHUB_REPO")  # формат "owner/repo"
LOCAL_REPO_PATH = os.environ.get("LOCAL_REPO_PATH", os.getcwd())  # локальный клон репо для run_kics

# Модель Groq. Список доступных моделей зависит от аккаунта и меняется со временем --
# посмотреть свой: LIST_MODELS=1 python3 security_agent.py
GROQ_MODEL = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")

# ---------------------------------------------------------------------------
# 1. TOOLS -- run_trivy, run_kics, analyze_git_diff РЕАЛЬНЫЕ; query_falco пока заглушка
# ---------------------------------------------------------------------------

def run_trivy(path: str) -> dict:
    """
    РЕАЛЬНЫЙ вызов: гоняет Trivy (aquasec/trivy через Docker) в режиме `fs`
    на локальной копии репозитория. Находит CVE в зависимостях из requirements.txt
    и других lock/manifest-файлов. Проверяет только уязвимости (vuln) --
    мисконфиги и секреты не трогает, чтобы не дублировать KICS.

    path -- абсолютный путь к директории репозитория.
    """
    import subprocess

    print(f"    -> запускаю реальный Trivy (Docker, fs-режим) на: {path}")

    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return {"error": f"Путь не найден или не директория: {abs_path}"}

    # Кэш базы уязвимостей на хосте -- чтобы не качать её заново при каждом вызове
    cache_dir = os.path.expanduser("~/.cache/trivy-agent")
    os.makedirs(cache_dir, exist_ok=True)

    # В WSL контейнеры иногда не могут резолвить имена (DNS-таймаут при скачивании
    # базы уязвимостей). Если так -- задай DOCKER_DNS=8.8.8.8 (или 1.1.1.1).
    dns_args = ["--dns", os.environ["DOCKER_DNS"]] if os.environ.get("DOCKER_DNS") else []

    cmd = [
        "docker", "run", "--rm",
        *dns_args,
        "-v", f"{abs_path}:/scan:ro",
        "-v", f"{cache_dir}:/root/.cache/",
        "aquasec/trivy:latest", "fs",
        "--scanners", "vuln",
        "--severity", "CRITICAL,HIGH,MEDIUM",
        "--format", "json",
        "-q",
        "/scan",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,  # первый запуск качает базу уязвимостей -- даём больше времени
        )
    except subprocess.TimeoutExpired:
        return {"error": "Trivy не уложился в таймаут (600с)"}
    except FileNotFoundError:
        return {"error": "docker не найден в PATH -- убедись, что Docker установлен и запущен"}

    if proc.returncode != 0 and not proc.stdout.strip():
        return {"error": f"Trivy завершился с ошибкой: {proc.stderr[-500:]}"}

    try:
        raw = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {"error": "Не удалось разобрать JSON-вывод Trivy", "stderr": proc.stderr[-500:]}

    # Нормализуем: только суть каждой уязвимости, без километров описаний
    findings = []
    for result in raw.get("Results", []) or []:
        for vuln in result.get("Vulnerabilities", []) or []:
            findings.append({
                "cve": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed": vuln.get("InstalledVersion"),
                "fixed_in": vuln.get("FixedVersion") or "no fix available",
                "severity": vuln.get("Severity"),
                "file": result.get("Target"),
            })

    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda x: priority.get(x["severity"], 99))
    total = len(findings)

    return {
        "path": abs_path,
        "total_findings": total,
        "findings": findings[:15],
    }


def run_kics(path: str) -> dict:
    """
    РЕАЛЬНЫЙ вызов: гоняет KICS через тот же Docker-образ, что и твой CI
    (checkmarx/kics:latest), на локальной копии репозитория.

    path -- абсолютный путь к директории с манифестами/кодом для сканирования
            (например, путь к локальному клону репозитория).
    """
    import subprocess
    import tempfile

    print(f"    -> запускаю реальный KICS (Docker) на: {path}")

    abs_path = os.path.abspath(path)
    if not os.path.isdir(abs_path):
        return {"error": f"Путь не найден или не директория: {abs_path}"}

    # Отдельная временная папка под результаты, чтобы не мусорить в репозитории
    with tempfile.TemporaryDirectory() as out_dir:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{abs_path}:/path",
            "-v", f"{out_dir}:/output",
            "checkmarx/kics:latest", "scan",
            "-p", "/path",
            "--report-formats", "json",
            "-o", "/output",
            "--exclude-paths", "/path/k8s/gatekeeper",
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 минут -- защита от зависания
            )
        except subprocess.TimeoutExpired:
            return {"error": "KICS не уложился в таймаут (300с)"}
        except FileNotFoundError:
            return {"error": "docker не найден в PATH -- убедись, что Docker установлен и запущен"}

        results_path = os.path.join(out_dir, "results.json")
        if not os.path.exists(results_path):
            return {"error": "KICS не создал results.json -- проверь вывод вручную"}

        with open(results_path, "r") as f:
            raw = json.load(f)

    # Нормализуем вывод KICS -- оставляем только суть, без лишнего объёма
    findings = []
    for query in raw.get("queries", []):
        severity = query.get("severity", "UNKNOWN")
        rule_name = query.get("query_name", "unknown_rule")
        for file_entry in query.get("files", []):
            findings.append({
                "rule": rule_name,
                "severity": severity,
                "file": file_entry.get("file_name"),
                "line": file_entry.get("line"),
            })

    # Чтобы не раздувать контекст модели -- берём только HIGH/MEDIUM, максимум 15 находок
    priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda x: priority.get(x["severity"], 99))
    findings = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH", "MEDIUM")]
    total = len(findings)

    return {
        "path": abs_path,
        "total_findings": total,
        "findings": findings[:15],
    }


def analyze_git_diff(pr_number: int) -> dict:
    """
    РЕАЛЬНЫЙ вызов: получает список изменённых файлов и краткое summary
    через GitHub REST API.

    Требует переменные окружения:
        GITHUB_TOKEN  -- personal access token с правом чтения PR
        GITHUB_REPO   -- "owner/repo"
    """
    print(f"    -> читаю реальный diff PR #{pr_number} из {GITHUB_REPO}")

    if not GITHUB_TOKEN or not GITHUB_REPO:
        return {"error": "GITHUB_TOKEN или GITHUB_REPO не заданы в окружении"}

    url = f"https://api.github.com/repos/{GITHUB_REPO}/pulls/{pr_number}/files"
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as e:
        return {"error": f"GitHub API ошибка: {e}"}

    files = resp.json()

    changed_files = []
    total_additions = 0
    total_deletions = 0

    for f in files:
        changed_files.append({
            "filename": f["filename"],
            "status": f["status"],          # added / modified / removed
            "additions": f["additions"],
            "deletions": f["deletions"],
            # patch может быть очень длинным -- обрезаем, чтобы не раздувать контекст модели
            "patch_preview": (f.get("patch") or "")[:500],
        })
        total_additions += f["additions"]
        total_deletions += f["deletions"]

    return {
        "pr_number": pr_number,
        "files_changed": len(changed_files),
        "total_additions": total_additions,
        "total_deletions": total_deletions,
        "changed_files": changed_files,
    }


def query_falco(minutes: int = 30) -> dict:
    """Заглушка: runtime security события за последние N минут."""
    print(f"    -> [mock] запрашиваю Falco события за {minutes} мин")
    return {
        "events": [
            {"rule": "Terminal shell in container", "priority": "WARNING", "time": "5m ago"},
        ]
    }


AVAILABLE_FUNCTIONS = {
    "run_trivy": run_trivy,
    "run_kics": run_kics,
    "analyze_git_diff": analyze_git_diff,
    "query_falco": query_falco,
}

# ---------------------------------------------------------------------------
# 2. TOOL SCHEMAS -- описание для модели (что делает функция и когда её звать)
# ---------------------------------------------------------------------------

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "run_trivy",
            "description": (
                "Запускает реальный Trivy на локальной копии репозитория и возвращает известные CVE "
                "(CRITICAL/HIGH/MEDIUM) в зависимостях, например из requirements.txt: пакет, "
                "установленная версия, версия с исправлением. Вызывай, если в PR менялись "
                "файлы зависимостей. "
                f"Для этого PR путь к репозиторию: {LOCAL_REPO_PATH}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Абсолютный путь к локальной копии репозитория"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "run_kics",
            "description": (
                "Запускает реальный KICS-сканер на локальной копии репозитория и возвращает "
                "misconfiguration-находки (HIGH/MEDIUM severity) в Kubernetes/Terraform/Docker файлах. "
                f"Для этого PR путь к репозиторию: {LOCAL_REPO_PATH}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Абсолютный путь к локальной копии репозитория"}
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "analyze_git_diff",
            "description": "Возвращает реальный список изменённых файлов из GitHub PR: имена, статус (added/modified/removed), количество добавленных/удалённых строк и превью патча",
            "parameters": {
                "type": "object",
                "properties": {
                    "pr_number": {"type": "integer", "description": "Номер Pull Request"}
                },
                "required": ["pr_number"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "query_falco",
            "description": "Возвращает runtime security события (Falco) за последние N минут",
            "parameters": {
                "type": "object",
                "properties": {
                    "minutes": {"type": "integer", "description": "За сколько минут назад смотреть"}
                },
                "required": []
            }
        }
    },
]

SYSTEM_PROMPT = (
    "Ты security-агент, который делает review Pull Request перед merge. "
    "У тебя есть инструменты для анализа diff, сканирования image и манифестов, "
    "а также просмотра runtime-событий. "
    "Стратегия: сначала пойми, что изменилось (git diff), затем вызови релевантные "
    "сканеры, скоррелируй находки между собой (например, если в diff появилась новая "
    "зависимость - это объясняет новый CVE). "
    "Вызывай инструменты по одному и решай на основе полученных данных, что делать дальше. "
    "ПРАВИЛА ДОСТОВЕРНОСТИ: указывай только находки, которые реально вернули инструменты "
    "(с конкретными CVE-номерами, правилами и файлами). Никогда не додумывай уязвимости "
    "из собственных знаний. Если инструмент вернул поле error или не дал результата - "
    "прямо напиши в отчёте, что этот сканер НЕ отработал, и что проверка по нему не выполнена. "
    "Нельзя писать, что проблем нет, если сканер упал. В этом случае рекомендация - "
    "REQUEST CHANGES или NEEDS MANUAL CHECK, а не APPROVE.\n"
    "КЛАССИФИКАЦИЯ ПО SEVERITY (строго, без исключений): находки со severity CRITICAL или HIGH "
    "попадают ТОЛЬКО в блок 🔴 Критично; MEDIUM - в блок 🟡 Средне; LOW и INFO - в блок "
    "✅ Не критично. Блок не может быть 'нет', если по этим правилам в нём должна быть находка. "
    "Перечисляй находки конкретно (CVE-номер или имя правила, файл, строка), без обобщений "
    "вроде 'несколько проблем'. Если находок одного типа больше пяти - перечисли самые важные "
    "и укажи общее количество (поле total_findings в результате инструмента).\n"
    "Когда данных достаточно - НЕ вызывай больше tools, а выдай финальный отчёт в формате:\n"
    "  🔴 Критично: ...\n"
    "  🟡 Средне: ...\n"
    "  ✅ Не критично: ...\n"
    "  ⚙️ Статус сканеров: какие отработали, какие упали\n"
    "  Рекомендация: APPROVE, REQUEST CHANGES или NEEDS MANUAL CHECK, с коротким обоснованием."
)


def summarize_result(result: dict) -> str:
    """Короткая строка о том, что вернул инструмент -- для лога в консоли."""
    if "error" in result:
        return f"ОШИБКА: {str(result['error'])[:200]}"
    if "findings" in result:
        total = result.get("total_findings", len(result["findings"]))
        return f"находок: {total} (передано модели: {len(result['findings'])})"
    if "changed_files" in result:
        return f"файлов в PR: {len(result['changed_files'])}"
    if "events" in result:
        return f"событий: {len(result['events'])}"
    return "ok"

# ---------------------------------------------------------------------------
# 3. AGENT LOOP -- ядро: plan -> tool call -> observe -> decide -> ...
# ---------------------------------------------------------------------------

def run_security_agent(task: str, max_iterations: int = 8, verbose: bool = True) -> str:
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]

    for i in range(1, max_iterations + 1):
        if verbose:
            print(f"\n=== Итерация {i} ===")

        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=messages,
            tools=TOOLS,
            tool_choice="auto",
            temperature=0.2,
        )

        msg = response.choices[0].message
        messages.append(msg)

        # Модель решила, что данных достаточно -> финальный ответ, без вызовов tools
        if not msg.tool_calls:
            if verbose:
                print("[agent] данных достаточно, формирую финальный отчёт")
            return msg.content

        # Модель хочет вызвать один или несколько tools
        for tool_call in msg.tool_calls:
            fn_name = tool_call.function.name
            try:
                fn_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                fn_args = {}

            if verbose:
                print(f"[agent] вызывает {fn_name}({fn_args})")

            try:
                fn = AVAILABLE_FUNCTIONS[fn_name]
                result = fn(**fn_args)
            except Exception as e:
                result = {"error": str(e)}

            if verbose:
                print(f"    <- {fn_name}: {summarize_result(result)}")

            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "name": fn_name,
                "content": json.dumps(result),
            })

    return "⚠️ Достигнут лимит итераций, финальный отчёт не сформирован."


# ---------------------------------------------------------------------------
# 4. ТОЧКА ВХОДА
# ---------------------------------------------------------------------------

def list_available_models():
    """Показывает, какие модели реально доступны для твоего API-ключа."""
    client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
    models = client.models.list()
    print("Доступные модели для твоего ключа:")
    for m in models.data:
        print(f"  - {m.id}")


if __name__ == "__main__":
    if not os.environ.get("GROQ_API_KEY"):
        raise SystemExit("Установи переменную окружения GROQ_API_KEY перед запуском")

    if os.environ.get("LIST_MODELS"):
        list_available_models()
        raise SystemExit(0)

    pr_number = int(os.environ.get("PR_NUMBER", "42"))
    task = f"Проверь PR #{pr_number} на security-риски перед merge."
    result = run_security_agent(task)

    print("\n" + "=" * 60)
    print("ФИНАЛЬНЫЙ ОТЧЁТ АГЕНТА")
    print("=" * 60)
    print(result)
