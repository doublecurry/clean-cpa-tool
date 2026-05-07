#!/usr/bin/env python3
"""扫描 Codex 认证文件，检测 401、超限和不限额状态。
默认定时模式（每 15 分钟执行一次）
  python3 autoclear.py

单次扫描
  python3 autoclear.py --once

指定目录 + 50 并发
  python3 autoclear.py --auth-dir ./auths --workers 50

自动删除 401 文件（默认行为）
  python3 autoclear.py --workers 50

删除 401 前要求确认
  python3 autoclear.py --confirm-delete-401 --workers 50

先刷新 token 再检测
  python3 autoclear.py --refresh-before-check --workers 50

JSON 输出（适合管道处理）
  python3 autoclear.py --output-json --workers 50

禁用超限文件自动隔离
  python3 autoclear.py --no-quarantine --workers 50
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime as _dt
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Iterable
from urllib import error, parse, request


DEFAULT_CODEX_BASE_URL = "https://chatgpt.com/backend-api/codex"
DEFAULT_REFRESH_URL = "https://auth.openai.com/oauth/token"
DEFAULT_AUTH_DIR = "~/cpa/cpa1/.cli-proxy-api"
DEFAULT_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_VERSION = "0.98.0"
DEFAULT_USER_AGENT = "codex_cli_rs/0.98.0 (python-port)"
DEFAULT_WORKERS = min(32, max(4, (os.cpu_count() or 1) * 4))
DEFAULT_RETRY_ATTEMPTS = 3
DEFAULT_RETRY_BACKOFF = 0.6
DEFAULT_INTERVAL_MINUTES = 15.0
DEFAULT_DELETE_401 = True
DEFAULT_MIN_AUTH_FILES = 300
DEFAULT_REG_WORKERS = 3
DEFAULT_REG_POLL_SECONDS = 180
DEFAULT_REG_WORKDIR = Path("/root/注册机")
DEFAULT_REG_TOKENS_DIR = DEFAULT_REG_WORKDIR / "tokens"
ANSI_RESET = "\033[0m"
ANSI_BOLD = "\033[1m"
ANSI_DIM = "\033[2m"
ANSI_RED = "\033[31m"
ANSI_GREEN = "\033[32m"
ANSI_YELLOW = "\033[33m"
ANSI_CYAN = "\033[36m"
ANSI_MAGENTA = "\033[35m"
DEFAULT_EXCEEDED_DIR_NAME = "exceeded"

_ACCESS_TOKEN_KEYS = [
    "access_token", "accessToken",
    "token.access_token", "token.accessToken",
    "metadata.access_token", "metadata.accessToken",
    "metadata.token.access_token", "metadata.token.accessToken",
    "attributes.api_key",
]
_REFRESH_TOKEN_KEYS = [
    "refresh_token", "refreshToken",
    "token.refresh_token", "token.refreshToken",
    "metadata.refresh_token", "metadata.refreshToken",
    "metadata.token.refresh_token", "metadata.token.refreshToken",
]
_ACCOUNT_ID_KEYS = [
    "account_id", "accountId", "metadata.account_id", "metadata.accountId",
]
_PROVIDER_KEYS = ["type", "provider", "metadata.type"]
_EMAIL_KEYS = ["email", "metadata.email", "attributes.email"]
_BASE_URL_KEYS = [
    "base_url", "baseUrl",
    "metadata.base_url", "metadata.baseUrl",
    "attributes.base_url", "attributes.baseUrl",
]


@dataclass
class CheckResult:
    file: str
    provider: str
    email: str
    account_id: str
    status_code: int | None
    unauthorized_401: bool
    no_limit_unlimited: bool
    quota_exceeded: bool
    quota_resets_at: int | None
    error: str
    response_preview: str


@dataclass
class DeleteError:
    file: str
    error: str


def _error_check_result(
    file: str, error: str,
    provider: str = "unknown", email: str = "", account_id: str = "",
) -> CheckResult:
    return CheckResult(
        file=file, provider=provider, email=email, account_id=account_id,
        status_code=None, unauthorized_401=False, no_limit_unlimited=False,
        quota_exceeded=False, quota_resets_at=None,
        error=error, response_preview="",
    )


def _is_tty_stdout() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _supports_color(disabled: bool) -> bool:
    return (not disabled) and _is_tty_stdout() and ("NO_COLOR" not in os.environ)


def _paint(text: str, *codes: str, enabled: bool) -> str:
    if not enabled or not codes:
        return text
    return "".join(codes) + text + ANSI_RESET


def _truncate(text: str, limit: int) -> str:
    if limit <= 0 or len(text) <= limit:
        return text
    if limit <= 3:
        return "." * limit
    return text[: limit - 3] + "..."


class _ProgressDisplay:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._last_len = 0
        self._finished = False

    def update(self, current: int, total: int, path: Path) -> None:
        if not self.enabled or total <= 0:
            return

        width = shutil.get_terminal_size(fallback=(100, 20)).columns
        bar_width = max(12, min(30, width - 52))
        percent = int((current * 100) / total)
        filled = int((current * bar_width) / total)
        bar = "#" * filled + "-" * (bar_width - filled)
        message = f"[{bar}] {current}/{total} {percent:>3}% {_truncate(path.name, 28)}"
        message = _truncate(message, max(10, width - 1))
        padding = " " * max(0, self._last_len - len(message))
        sys.stdout.write(f"\r{message}{padding}")
        sys.stdout.flush()
        self._last_len = len(message)

    def finish(self) -> None:
        if not self.enabled or self._finished:
            return
        self._finished = True
        sys.stdout.write("\n")
        sys.stdout.flush()


class _LiveLineDisplay:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled
        self._last_len = 0
        self._active = False

    def update(self, message: str) -> None:
        if not self.enabled:
            return
        width = shutil.get_terminal_size(fallback=(100, 20)).columns
        rendered = _truncate(message, max(10, width - 1))
        padding = " " * max(0, self._last_len - len(rendered))
        sys.stdout.write(f"\r{rendered}{padding}")
        sys.stdout.flush()
        self._last_len = len(rendered)
        self._active = True

    def finish(self) -> None:
        if not self.enabled or not self._active:
            return
        sys.stdout.write("\n")
        sys.stdout.flush()
        self._active = False
        self._last_len = 0


def _first_non_empty_str(values: Iterable[Any]) -> str:
    for value in values:
        if isinstance(value, str):
            stripped = value.strip()
            if stripped:
                return stripped
    return ""


def _dot_get(data: Any, dotted_key: str) -> Any:
    current = data
    for key in dotted_key.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _pick(data: dict[str, Any], candidates: list[str]) -> str:
    values = [_dot_get(data, key) for key in candidates]
    return _first_non_empty_str(values)


def _looks_like_codex(path: Path, payload: dict[str, Any]) -> bool:
    provider = _pick(payload, _PROVIDER_KEYS)
    if provider:
        return provider.lower() == "codex"

    if path.name.lower().startswith("codex-"):
        return True

    access_token = _pick(payload, _ACCESS_TOKEN_KEYS)
    refresh_token = _pick(payload, _REFRESH_TOKEN_KEYS)
    account_id = _pick(payload, _ACCOUNT_ID_KEYS)
    return bool(access_token and (refresh_token or account_id))


def _extract_auth_fields(payload: dict[str, Any]) -> dict[str, str]:
    return {
        "provider": _pick(payload, _PROVIDER_KEYS) or "codex",
        "email": _pick(payload, _EMAIL_KEYS),
        "access_token": _pick(payload, _ACCESS_TOKEN_KEYS),
        "refresh_token": _pick(payload, _REFRESH_TOKEN_KEYS),
        "account_id": _pick(payload, _ACCOUNT_ID_KEYS),
        "base_url": _pick(payload, _BASE_URL_KEYS),
    }


def _http_request(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
) -> tuple[int, bytes]:
    req = request.Request(url=url, data=body, method=method.upper())
    for key, value in headers.items():
        req.add_header(key, value)

    try:
        with request.urlopen(req, timeout=timeout) as resp:
            return int(resp.status), resp.read()
    except error.HTTPError as exc:
        return int(exc.code), exc.read()


def _http_request_with_retry(
    *,
    url: str,
    method: str,
    headers: dict[str, str],
    body: bytes | None,
    timeout: float,
    retry_attempts: int,
    retry_backoff: float,
) -> tuple[int, bytes]:
    last_exc: Exception | None = None
    for attempt in range(1, retry_attempts + 1):
        try:
            return _http_request(
                url=url,
                method=method,
                headers=headers,
                body=body,
                timeout=timeout,
            )
        except error.URLError as exc:
            last_exc = exc
            if attempt >= retry_attempts:
                break
            if retry_backoff > 0:
                sleep_seconds = retry_backoff * (2 ** (attempt - 1))
                time.sleep(sleep_seconds)

    if last_exc is not None:
        raise last_exc
    raise RuntimeError("请求失败，且未捕获到具体异常")


_UNLIMITED_TEXT_MARKERS = (
    "unlimited",
    "no limit",
    "no-limit",
    "without limit",
    "limitless",
    "不限额",
    "无限额",
    "无限制",
)

_UNLIMITED_KEY_HINTS = (
    "unlimited",
    "no_limit",
    "nolimit",
    "limitless",
)

_LIMIT_LIKE_KEY_HINTS = (
    "quota",
    "limit",
    "cap",
)


def _looks_unlimited_from_response(status_code: int | None, response_text: str) -> bool:
    if status_code is None or status_code < 200 or status_code >= 300:
        return False

    lowered = (response_text or "").lower()
    if any(marker in lowered for marker in _UNLIMITED_TEXT_MARKERS):
        return True

    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        return False

    stack: list[Any] = [parsed]
    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            for key, value in current.items():
                key_lc = str(key).lower()
                if any(hint in key_lc for hint in _UNLIMITED_KEY_HINTS):
                    if isinstance(value, bool) and value:
                        return True
                    if isinstance(value, str) and value.strip().lower() in {
                        "1",
                        "true",
                        "yes",
                        "unlimited",
                        "no_limit",
                        "nolimit",
                    }:
                        return True
                    if isinstance(value, (int, float)) and value == -1:
                        return True
                if any(hint in key_lc for hint in _LIMIT_LIKE_KEY_HINTS):
                    if value is None:
                        return True
                    if isinstance(value, (int, float)) and (
                        value == -1 or value >= 9999
                    ):
                        return True
                    if isinstance(value, str) and value.strip().lower() in {
                        "none",
                        "null",
                        "unlimited",
                        "no limit",
                        "no-limit",
                        "无限",
                        "不限额",
                        "无限额",
                    }:
                        return True
                if isinstance(value, (dict, list)):
                    stack.append(value)
                elif isinstance(value, str):
                    text_value = value.lower()
                    if any(marker in text_value for marker in _UNLIMITED_TEXT_MARKERS):
                        return True
        elif isinstance(current, list):
            stack.extend(current)

    return False



_QUOTA_EXCEEDED_TEXT_MARKERS = (
    "usage_limit_reached",
    "usage limit has been reached",
    "quota exceeded",
    "limit exceeded",
    "超出配额",
    "额度已用完",
)


def _detect_quota_exceeded(response_text: str) -> tuple[bool, int | None]:
    """Return (is_exceeded, resets_at_unix_or_None).

    Primary detection: ``error.type == 'usage_limit_reached'`` in JSON body.
    Secondary: text marker scan for common quota-exceeded phrases.
    """
    if not response_text:
        return False, None

    try:
        parsed = json.loads(response_text)
    except json.JSONDecodeError:
        parsed = None

    if isinstance(parsed, dict):
        err = parsed.get("error")
        if isinstance(err, dict):
            if err.get("type") == "usage_limit_reached":
                resets_at = err.get("resets_at")
                if isinstance(resets_at, (int, float)):
                    return True, int(resets_at)
                return True, None

    lowered = response_text.lower()
    if any(marker in lowered for marker in _QUOTA_EXCEEDED_TEXT_MARKERS):
        return True, None

    return False, None


def _refresh_access_token(
    refresh_url: str, refresh_token: str, timeout: float
) -> tuple[str, str]:
    body = parse.urlencode(
        {
            "client_id": DEFAULT_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "openid profile email",
        }
    ).encode("utf-8")

    status, resp_body = _http_request(
        url=refresh_url,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        body=body,
        timeout=timeout,
    )

    if status != 200:
        msg = resp_body.decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"刷新令牌失败，状态码 {status}: {msg}")

    try:
        parsed = json.loads(resp_body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"刷新令牌返回的内容不是有效 JSON: {exc}") from exc

    new_token = _first_non_empty_str([parsed.get("access_token")])
    new_refresh = _first_non_empty_str([parsed.get("refresh_token")])
    if not new_token:
        raise RuntimeError("刷新令牌成功，但响应中缺少 access_token")

    return new_token, new_refresh


def _build_probe_headers(access_token: str, account_id: str) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Version": DEFAULT_VERSION,
        "Openai-Beta": "responses=experimental",
        "User-Agent": DEFAULT_USER_AGENT,
        "Originator": "codex_cli_rs",
    }
    if account_id:
        headers["Chatgpt-Account-Id"] = account_id
    return headers


def _build_probe_body(model: str) -> bytes:
    payload = {
        "model": model,
        "stream": True,
        "store": False,
        "instructions": "",
        # Some proxies strictly validate `input` as a list for /responses.
        "input": [
            {
                "role": "user",
                "content": [
                    {
                        "type": "input_text",
                        "text": "ping",
                    }
                ],
            }
        ],

    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _load_json(path: Path) -> dict[str, Any]:
    raw = path.read_text(encoding="utf-8-sig")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError("root JSON value is not an object")
    return obj


def _scan_single_file(path: Path, args: argparse.Namespace) -> list[CheckResult]:
    try:
        payload = _load_json(path)
    except Exception as exc:  # noqa: BLE001
        return [_error_check_result(str(path), f"解析失败: {exc}")]

    if not _looks_like_codex(path, payload):
        return []

    fields = _extract_auth_fields(payload)
    access_token = fields["access_token"]
    refresh_token = fields["refresh_token"]

    try:
        if args.refresh_before_check and refresh_token:
            access_token, _ = _refresh_access_token(
                args.refresh_url, refresh_token, args.timeout
            )
    except Exception as exc:  # noqa: BLE001
        return [_error_check_result(
            str(path), str(exc),
            provider=fields["provider"], email=fields["email"],
            account_id=fields["account_id"],
        )]

    if not access_token:
        return [_error_check_result(
            str(path), "缺少 access_token",
            provider=fields["provider"], email=fields["email"],
            account_id=fields["account_id"],
        )]

    base_url = fields["base_url"] or args.base_url
    probe_url = base_url.rstrip("/") + "/" + args.quota_path.lstrip("/")
    headers = _build_probe_headers(access_token, fields["account_id"])
    body = _build_probe_body(args.model)

    try:
        status, resp_body = _http_request_with_retry(
            url=probe_url,
            method="POST",
            headers=headers,
            body=body,
            timeout=args.timeout,
            retry_attempts=args.retry_attempts,
            retry_backoff=args.retry_backoff,
        )
        response_text = resp_body.decode("utf-8", errors="replace")
        preview = response_text[:300]
        _quota_exceeded, _resets_at = _detect_quota_exceeded(response_text)
        return [
            CheckResult(
                file=str(path),
                provider=fields["provider"],
                email=fields["email"],
                account_id=fields["account_id"],
                status_code=status,
                unauthorized_401=(status == 401),
                no_limit_unlimited=_looks_unlimited_from_response(
                    status, response_text
                ),
                quota_exceeded=_quota_exceeded,
                quota_resets_at=_resets_at,
                error="",
                response_preview=preview,
            )
        ]
    except error.URLError as exc:
        return [_error_check_result(
            str(path), f"网络错误: {exc}",
            provider=fields["provider"], email=fields["email"],
            account_id=fields["account_id"],
        )]


def _scan_files(
    json_files: list[Path],
    args: argparse.Namespace,
    progress_callback: Callable[[int, int, Path], None] | None = None,
) -> list[CheckResult]:
    total = len(json_files)
    if total == 0:
        return []

    indexed_results: list[tuple[int, list[CheckResult]]] = []
    workers = min(args.workers, total)

    if workers <= 1:
        for index, path in enumerate(json_files, start=1):
            if progress_callback is not None:
                progress_callback(index, total, path)
            file_results = _scan_single_file(path, args)
            if file_results:
                indexed_results.append((index, file_results))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_map = {
                pool.submit(_scan_single_file, path, args): (index, path)
                for index, path in enumerate(json_files, start=1)
            }
            completed = 0
            for future in as_completed(future_map):
                completed += 1
                index, path = future_map[future]
                if progress_callback is not None:
                    progress_callback(completed, total, path)
                try:
                    file_results = future.result()
                except Exception as exc:  # noqa: BLE001
                    file_results = [_error_check_result(str(path), f"内部错误: {exc}")]
                if file_results:
                    indexed_results.append((index, file_results))

    indexed_results.sort(key=lambda item: item[0])
    return [row for _, group in indexed_results for row in group]


def scan_auth_files(
    args: argparse.Namespace,
    progress_callback: Callable[[int, int, Path], None] | None = None,
) -> list[CheckResult]:
    auth_dir = Path(args.auth_dir).expanduser().resolve()
    if not auth_dir.exists() or not auth_dir.is_dir():
        raise FileNotFoundError(f"认证目录不存在: {auth_dir}")
    return _scan_files(sorted(auth_dir.rglob("*.json")), args, progress_callback)


def _status_label(item: CheckResult, use_color: bool) -> str:
    if item.unauthorized_401:
        return _paint("401", ANSI_BOLD, ANSI_RED, enabled=use_color)
    if item.quota_exceeded:
        return _paint("超限", ANSI_BOLD, ANSI_MAGENTA, enabled=use_color)
    if item.status_code is None:
        return _paint("错误", ANSI_BOLD, ANSI_YELLOW, enabled=use_color)
    code = str(item.status_code)
    if 200 <= item.status_code < 300:
        return _paint(code, ANSI_GREEN, enabled=use_color)
    if 400 <= item.status_code < 500:
        return _paint(code, ANSI_YELLOW, enabled=use_color)
    if item.status_code >= 500:
        return _paint(code, ANSI_RED, enabled=use_color)
    return code


def _print_table(results: list[CheckResult], use_color: bool, label: str = "扫描摘要") -> None:
    if not results:
        print(_paint("未找到可检测的 Codex 认证文件。", ANSI_YELLOW, enabled=use_color))
        return

    unauthorized = [r for r in results if r.unauthorized_401]
    quota_exceeded_list = [r for r in results if r.quota_exceeded and not r.unauthorized_401]
    no_limit_unlimited = [r for r in results if r.no_limit_unlimited]
    ok_count = sum(
        1
        for item in results
        if item.status_code is not None and 200 <= item.status_code < 300
    )
    failed_count = len(results) - ok_count

    print(
        _paint(
            (
                f"{label}"
                f" | 文件 {len(results)}"
                f" | 正常 {ok_count}"
                f" | 401 {len(unauthorized)}"
                f" | 超限 {len(quota_exceeded_list)}"
                f" | 不限额 {len(no_limit_unlimited)}"
                f" | 异常 {failed_count}"
            ),
            ANSI_BOLD,
            ANSI_CYAN,
            enabled=use_color,
        )
    )



def _move_file_safely(
    src: Path, dst_dir: Path
) -> tuple[str | None, str | None]:
    """Move *src* into *dst_dir*, creating dst_dir if necessary.

    Returns ``(dst_path, None)`` on success or ``(None, error_message)`` on failure.
    """
    try:
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / src.name
        # If a file with the same name already exists, append a counter suffix.
        counter = 1
        while dst.exists():
            dst = dst_dir / f"{src.stem}_{counter}{src.suffix}"
            counter += 1
        shutil.move(str(src), str(dst))
        return str(dst), None
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def _scan_dir_flat(
    dir_path: Path,
    args: argparse.Namespace,
    progress_callback: Callable[[int, int, Path], None] | None = None,
) -> list[CheckResult]:
    if not dir_path.exists() or not dir_path.is_dir():
        return []
    return _scan_files(sorted(dir_path.glob("*.json")), args, progress_callback)


def _confirm_deletion(targets: list[str], assume_yes: bool) -> bool:
    if not targets:
        return False
    if assume_yes:
        return True
    if not sys.stdin.isatty():
        print(
            "当前不是交互终端，已取消删除。可使用 --yes 跳过确认。"
        )
        return False

    print()
    print(f"确认删除 {len(targets)} 个返回 401 的文件吗？此操作不可恢复。")
    answer = input("请输入 y 确认，其他任意键取消 [y/N]: ").strip().lower()
    return answer in {"y", "yes"}


def _delete_files(paths: list[str]) -> tuple[list[str], list[DeleteError]]:
    deleted: list[str] = []
    errors: list[DeleteError] = []
    seen: set[str] = set()

    for raw_path in paths:
        path = Path(raw_path)
        normalized = str(path.resolve())
        if normalized in seen:
            continue
        seen.add(normalized)

        try:
            path.unlink()
            deleted.append(str(path))
        except Exception as exc:  # noqa: BLE001
            errors.append(DeleteError(file=str(path), error=str(exc)))

    return deleted, errors


def _print_deletion_summary(
    *,
    requested: bool,
    target_count: int,
    confirmed: bool,
    deleted_files: list[str],
    errors: list[DeleteError],
    use_color: bool,
) -> None:
    if target_count == 0:
        print(
            _paint(
                "删除结果 | 本轮未发现需要删除的 401 文件",
                ANSI_DIM,
                enabled=use_color,
            )
        )
        return

    if not confirmed:
        print(_paint("删除结果 | 已取消删除操作", ANSI_YELLOW, enabled=use_color))
        return

    print(
        _paint(
            (
                "删除结果"
                f" | 成功 {len(deleted_files)}/{target_count}"
                f" | 失败 {len(errors)}"
            ),
            ANSI_BOLD,
            ANSI_GREEN if not errors else ANSI_YELLOW,
            enabled=use_color,
        )
    )


def _format_utc_timestamp(ts: float | None = None) -> str:
    moment = _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc) if ts is not None else _dt.datetime.now(_dt.timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_mmss(seconds: float) -> str:
    total = max(0, int(seconds))
    minutes, secs = divmod(total, 60)
    hours, minutes = divmod(minutes, 60)
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"
    return f"{minutes:02d}:{secs:02d}"


def _progress_bar(current: int, total: int, width: int = 16) -> tuple[float, str]:
    if total <= 0:
        return 100.0, "#" * width
    ratio = min(1.0, max(0.0, current / total))
    filled = int(ratio * width)
    bar = "#" * filled + "-" * (width - filled)
    return ratio * 100.0, bar


def _inventory_progress_text(current: int, total: int) -> str:
    percent, bar = _progress_bar(current, total)
    return f"{current}/{total} {percent:5.1f}% [{bar}]"


def _sleep_with_countdown(
    seconds: float,
    *,
    enabled: bool,
    render_message: Callable[[float], str],
) -> None:
    if seconds <= 0:
        return
    if not enabled:
        time.sleep(seconds)
        return

    live = _LiveLineDisplay(True)
    end_time = time.time() + seconds
    try:
        while True:
            remaining = end_time - time.time()
            if remaining <= 0:
                break
            live.update(render_message(remaining))
            time.sleep(min(1.0, max(0.05, remaining)))
    finally:
        live.finish()


def _count_json_files(dir_path: Path) -> int:
    if not dir_path.exists() or not dir_path.is_dir():
        return 0
    return sum(1 for _ in dir_path.rglob("*.json"))


def _move_all_files_to_auth_dir(
    src_dir: Path,
    dst_dir: Path,
) -> tuple[list[str], list[DeleteError]]:
    moved: list[str] = []
    errors: list[DeleteError] = []
    if not src_dir.exists() or not src_dir.is_dir():
        return moved, errors

    for path in sorted(src_dir.rglob("*")):
        if not path.is_file():
            continue
        dst, err = _move_file_safely(path, dst_dir)
        if err:
            errors.append(DeleteError(file=str(path), error=err))
        elif dst is not None:
            moved.append(dst)

    return moved, errors


def _start_registrar_process() -> tuple[subprocess.Popen[Any] | None, str]:
    try:
        DEFAULT_REG_TOKENS_DIR.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(
            [
                "uv",
                "run",
                "python",
                "openai_reg.py",
                "--workers",
                str(DEFAULT_REG_WORKERS),
            ],
            cwd=str(DEFAULT_REG_WORKDIR),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return proc, ""
    except Exception as exc:  # noqa: BLE001
        return None, str(exc)


def _stop_registrar_process(
    proc: subprocess.Popen[Any],
    timeout_seconds: float = 20.0,
) -> dict[str, Any]:
    status = {
        "attempted": True,
        "already_exited": False,
        "terminated": False,
        "killed": False,
        "exit_code": None,
    }

    if proc.poll() is not None:
        status["already_exited"] = True
        status["exit_code"] = proc.returncode
        return status

    proc.terminate()
    try:
        status["exit_code"] = proc.wait(timeout=timeout_seconds)
        status["terminated"] = True
        return status
    except subprocess.TimeoutExpired:
        proc.kill()
        status["exit_code"] = proc.wait(timeout=timeout_seconds)
        status["killed"] = True
        return status


def _ensure_min_auth_files(
    auth_dir: Path,
    *,
    use_color: bool,
    output_json: bool,
    live_updates_enabled: bool,
) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "threshold": DEFAULT_MIN_AUTH_FILES,
        "poll_seconds": DEFAULT_REG_POLL_SECONDS,
        "registrar_workdir": str(DEFAULT_REG_WORKDIR),
        "registrar_tokens_dir": str(DEFAULT_REG_TOKENS_DIR),
        "triggered": False,
        "initial_count": _count_json_files(auth_dir),
        "final_count": _count_json_files(auth_dir),
        "satisfied": _count_json_files(auth_dir) >= DEFAULT_MIN_AUTH_FILES,
        "registrar_started": False,
        "registrar_restarts": 0,
        "check_rounds": 0,
        "moved_count": 0,
        "move_error_count": 0,
        "start_error": "",
        "stop": None,
    }

    if summary["initial_count"] >= DEFAULT_MIN_AUTH_FILES:
        return summary

    summary["triggered"] = True
    proc: subprocess.Popen[Any] | None = None

    if not output_json:
        print(
            _paint(
                (
                    "库存补充"
                    f" | 当前 {_inventory_progress_text(summary['initial_count'], DEFAULT_MIN_AUTH_FILES)}"
                    f" | 目标至少 {DEFAULT_MIN_AUTH_FILES}"
                ),
                ANSI_BOLD,
                ANSI_CYAN,
                enabled=use_color,
            )
        )

    try:
        while True:
            current_count = _count_json_files(auth_dir)
            summary["final_count"] = current_count
            summary["satisfied"] = current_count >= DEFAULT_MIN_AUTH_FILES
            if current_count >= DEFAULT_MIN_AUTH_FILES:
                break

            if proc is None or proc.poll() is not None:
                if proc is not None and proc.returncode is not None:
                    summary["registrar_restarts"] += 1
                    if not output_json:
                        print(
                            _paint(
                                f"库存补充 | 注册机进程已退出，正在重启 | 退出码 {proc.returncode}",
                                ANSI_YELLOW,
                                enabled=use_color,
                            )
                        )
                proc, err = _start_registrar_process()
                if proc is None:
                    summary["start_error"] = err
                    if not output_json:
                        print(
                            _paint(
                                f"库存补充 | 启动注册机失败 | {err}",
                                ANSI_RED,
                                enabled=use_color,
                            )
                        )
                    break
                summary["registrar_started"] = True
                if not output_json:
                    print(
                        _paint(
                            f"库存补充 | 已启动注册机 | 目录 {DEFAULT_REG_WORKDIR} | 并发 {DEFAULT_REG_WORKERS}",
                            ANSI_CYAN,
                            enabled=use_color,
                        )
                    )

            summary["check_rounds"] += 1
            moved_files, move_errors = _move_all_files_to_auth_dir(
                DEFAULT_REG_TOKENS_DIR, auth_dir
            )
            summary["moved_count"] += len(moved_files)
            summary["move_error_count"] += len(move_errors)
            current_count = _count_json_files(auth_dir)
            summary["final_count"] = current_count
            summary["satisfied"] = current_count >= DEFAULT_MIN_AUTH_FILES
            status_message = _paint(
                (
                    f"补货检查 {summary['check_rounds']}"
                    f" | 迁入 {len(moved_files)}"
                    f" | 失败 {len(move_errors)}"
                    f" | 进度 {_inventory_progress_text(current_count, DEFAULT_MIN_AUTH_FILES)}"
                ),
                ANSI_BOLD if current_count >= DEFAULT_MIN_AUTH_FILES else "",
                ANSI_GREEN if current_count >= DEFAULT_MIN_AUTH_FILES else ANSI_CYAN,
                enabled=use_color,
            )

            if not output_json and not live_updates_enabled:
                print(status_message)

            if current_count >= DEFAULT_MIN_AUTH_FILES:
                break

            _sleep_with_countdown(
                DEFAULT_REG_POLL_SECONDS,
                enabled=live_updates_enabled,
                render_message=lambda remaining, current=current_count, moved=len(moved_files), failed=len(move_errors), check_round=summary["check_rounds"]: _paint(
                    (
                        f"补货检查 {check_round}"
                        f" | 迁入 {moved}"
                        f" | 失败 {failed}"
                        f" | 下次检查 {_format_mmss(remaining)}"
                        f" | 进度 {_inventory_progress_text(current, DEFAULT_MIN_AUTH_FILES)}"
                    ),
                    ANSI_DIM,
                    enabled=use_color,
                ),
            )
    finally:
        if proc is not None:
            summary["stop"] = _stop_registrar_process(proc)
            if not output_json:
                stop = summary["stop"]
                if stop["already_exited"]:
                    print(f"库存补充 | 注册机进程已结束 | 退出码 {stop['exit_code']}")
                elif stop["killed"]:
                    print(
                        _paint(
                            f"库存补充 | 注册机进程未在超时内退出，已强制结束 | 退出码 {stop['exit_code']}",
                            ANSI_YELLOW,
                            enabled=use_color,
                        )
                    )
                else:
                    print(f"库存补充 | 已停止注册机进程 | 退出码 {stop['exit_code']}")

    if not output_json and summary["triggered"]:
        result_text = "库存补充完成" if summary["satisfied"] else "库存补充结束"
        print(
            _paint(
                (
                    f"{result_text}"
                    f" | 最终进度 {_inventory_progress_text(summary['final_count'], DEFAULT_MIN_AUTH_FILES)}"
                    f" | 检查次数 {summary['check_rounds']}"
                    f" | 累计迁入 {summary['moved_count']}"
                    f" | 累计失败 {summary['move_error_count']}"
                ),
                ANSI_GREEN if summary["final_count"] >= DEFAULT_MIN_AUTH_FILES else ANSI_YELLOW,
                enabled=use_color,
            )
        )

    return summary


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="扫描认证目录中的 Codex JSON 文件，检测 401、配额超限和不限额状态。",
        add_help=False,
    )
    parser._positionals.title = "位置参数"
    parser._optionals.title = "可选参数"
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        help="显示帮助信息并退出。",
    )
    parser.add_argument(
        "--auth-dir",
        default=DEFAULT_AUTH_DIR,
        help=f"认证 JSON 文件所在目录（默认：{DEFAULT_AUTH_DIR}）。",
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_CODEX_BASE_URL,
        help=f"Codex 接口基础地址（默认：{DEFAULT_CODEX_BASE_URL}）。",
    )
    parser.add_argument(
        "--quota-path",
        default="/responses",
        help="用于检测鉴权和配额的接口路径（默认：/responses）。",
    )
    parser.add_argument(
        "--model",
        default="gpt-5",
        help="探测请求使用的模型名（默认：gpt-5）。",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=20,
        help="HTTP 超时时间，单位秒（默认：20）。",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help=f"扫描和探测时的并发数（默认：{DEFAULT_WORKERS}）。",
    )
    parser.add_argument(
        "--retry-attempts",
        type=int,
        default=DEFAULT_RETRY_ATTEMPTS,
        help=f"每个文件遇到网络错误时的最大重试次数（默认：{DEFAULT_RETRY_ATTEMPTS}）。",
    )
    parser.add_argument(
        "--retry-backoff",
        type=float,
        default=DEFAULT_RETRY_BACKOFF,
        help=f"网络重试指数退避的基础秒数（默认：{DEFAULT_RETRY_BACKOFF}）。",
    )
    parser.add_argument(
        "--refresh-before-check",
        action="store_true",
        help="探测前先用 refresh_token 刷新 access_token。",
    )
    parser.add_argument(
        "--refresh-url",
        default=DEFAULT_REFRESH_URL,
        help=f"刷新令牌接口地址（默认：{DEFAULT_REFRESH_URL}）。",
    )
    parser.add_argument(
        "--output-json",
        action="store_true",
        help="以 JSON 输出完整结果，而不是终端摘要。",
    )
    parser.add_argument(
        "--no-progress",
        action="store_true",
        help="关闭终端中的实时扫描进度显示。",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="关闭 ANSI 彩色输出。",
    )
    parser.add_argument(
        "--delete-401",
        action="store_true",
        default=DEFAULT_DELETE_401,
        help="删除返回 HTTP 401 的认证文件（默认启用）。",
    )
    parser.add_argument(
        "--no-delete-401",
        action="store_false",
        dest="delete_401",
        help="关闭自动删除 401 文件。",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="跳过删除确认提示；兼容旧参数，仅在开启 401 删除时生效。",
    )
    parser.add_argument(
        "--confirm-delete-401",
        action="store_true",
        help="删除 401 文件前要求交互确认。",
    )
    parser.add_argument(
        "--exceeded-dir",
        default=None,
        help=(
            "配额超限文件的隔离目录。"
            f" 默认放到 --auth-dir 同级的 '{DEFAULT_EXCEEDED_DIR_NAME}/' 目录。"
        ),
    )
    parser.add_argument(
        "--no-quarantine",
        action="store_true",
        help="关闭自动隔离：不移动超限文件，也不执行恢复扫描。",
    )
    parser.add_argument(
        "--interval-minutes",
        type=float,
        default=DEFAULT_INTERVAL_MINUTES,
        help=(
            "循环模式下两次扫描之间的间隔分钟数"
            f"（默认：{DEFAULT_INTERVAL_MINUTES:g}）。"
        ),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="只执行一次扫描后退出，不进入定时循环。",
    )
    return parser


def _run_once(args: argparse.Namespace) -> int:
    use_color = _supports_color(args.no_color) and (not args.output_json)
    progress_enabled = (
        _is_tty_stdout() and (not args.no_progress) and (not args.output_json)
    )
    progress = _ProgressDisplay(progress_enabled)

    auth_dir = Path(args.auth_dir).expanduser().resolve()
    exceeded_dir = (
        Path(args.exceeded_dir).expanduser().resolve()
        if args.exceeded_dir
        else auth_dir.parent / DEFAULT_EXCEEDED_DIR_NAME
    )

    if progress_enabled:
        print(_paint("正在扫描认证 JSON 文件...", ANSI_DIM, enabled=use_color))

    try:
        results = scan_auth_files(
            args,
            progress_callback=progress.update if progress_enabled else None,
        )
    except Exception as exc:  # noqa: BLE001
        progress.finish()
        print(f"错误：{exc}", file=sys.stderr)
        return 2
    progress.finish()

    # --- Quarantine: move exceeded files out of auth_dir ---
    moved_to_exceeded: list[str] = []   # dst paths
    move_to_exceeded_errors: list[DeleteError] = []
    if not args.no_quarantine:
        for item in results:
            if item.quota_exceeded:
                dst, err = _move_file_safely(Path(item.file), exceeded_dir)
                if err:
                    move_to_exceeded_errors.append(DeleteError(file=item.file, error=err))
                else:
                    if dst is not None:
                        moved_to_exceeded.append(dst)

    # --- Recovery: scan exceeded_dir, move back files that are no longer limited ---
    exceeded_results: list[CheckResult] = []
    moved_from_exceeded: list[str] = []  # dst paths (back in auth_dir)
    move_from_exceeded_errors: list[DeleteError] = []
    if not args.no_quarantine and exceeded_dir.exists():
        if progress_enabled:
            print(
                _paint(
                    f"正在扫描隔离目录：{exceeded_dir} ...",
                    ANSI_DIM,
                    enabled=use_color,
                )
            )
        exceeded_results = _scan_dir_flat(exceeded_dir, args)
        for item in exceeded_results:
            recovered = (
                not item.quota_exceeded
                and item.status_code is not None
                and 200 <= item.status_code < 300
            )
            if recovered:
                dst, err = _move_file_safely(Path(item.file), auth_dir)
                if err:
                    move_from_exceeded_errors.append(
                        DeleteError(file=item.file, error=err)
                    )
                else:
                    if dst is not None:
                        moved_from_exceeded.append(dst)

    # --- Delete-401 flow ---
    unauthorized_files = [item.file for item in results if item.unauthorized_401]
    delete_confirmed = False
    deleted_files: list[str] = []
    delete_errors: list[DeleteError] = []

    if args.delete_401 and unauthorized_files:
        assume_yes = args.yes or (not args.confirm_delete_401)
        delete_confirmed = _confirm_deletion(unauthorized_files, assume_yes)
        if delete_confirmed:
            deleted_files, delete_errors = _delete_files(unauthorized_files)

    if args.output_json:
        inventory_replenishment = _ensure_min_auth_files(
            auth_dir,
            use_color=use_color,
            output_json=True,
            live_updates_enabled=False,
        )
        print(
            json.dumps(
                {
                    "results": [asdict(item) for item in results],
                    "exceeded_dir_results": [asdict(item) for item in exceeded_results],
                    "quarantine": {
                        "enabled": not args.no_quarantine,
                        "exceeded_dir": str(exceeded_dir),
                        "moved_to_exceeded": moved_to_exceeded,
                        "moved_to_exceeded_errors": [
                            asdict(e) for e in move_to_exceeded_errors
                        ],
                        "moved_from_exceeded": moved_from_exceeded,
                        "moved_from_exceeded_errors": [
                            asdict(e) for e in move_from_exceeded_errors
                        ],
                    },
                    "deletion": {
                        "requested": args.delete_401,
                        "target_count": len(unauthorized_files),
                        "auto_delete_enabled": args.delete_401,
                        "confirmation_required": args.confirm_delete_401 and not args.yes,
                        "confirmed": delete_confirmed,
                        "deleted_count": len(deleted_files),
                        "deleted_files": deleted_files,
                        "errors": [asdict(item) for item in delete_errors],
                    },
                    "inventory_replenishment": inventory_replenishment,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    else:
        _print_table(results, use_color=use_color, label="扫描摘要")

        if exceeded_results:
            _print_table(
                exceeded_results,
                use_color=use_color,
                label=f"隔离目录摘要({exceeded_dir.name})",
            )

        if moved_to_exceeded or move_to_exceeded_errors:
            print(
                _paint(
                    (
                        "自动隔离结果"
                        f" | 已移入 {len(moved_to_exceeded)}"
                        f" | 失败 {len(move_to_exceeded_errors)}"
                    ),
                    ANSI_BOLD,
                    ANSI_MAGENTA,
                    enabled=use_color,
                )
            )

        if moved_from_exceeded or move_from_exceeded_errors:
            print(
                _paint(
                    (
                        "自动恢复结果"
                        f" | 已恢复 {len(moved_from_exceeded)}"
                        f" | 失败 {len(move_from_exceeded_errors)}"
                    ),
                    ANSI_BOLD,
                    ANSI_GREEN,
                    enabled=use_color,
                )
            )

        if args.delete_401:
            _print_deletion_summary(
                requested=args.delete_401,
                target_count=len(unauthorized_files),
                confirmed=delete_confirmed,
                deleted_files=deleted_files,
                errors=delete_errors,
                use_color=use_color,
            )

        _ensure_min_auth_files(
            auth_dir,
            use_color=use_color,
            output_json=False,
            live_updates_enabled=progress_enabled,
        )

    has_401 = any(item.unauthorized_401 for item in results)
    return 1 if has_401 else 0


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers 必须大于等于 1")
    if args.retry_attempts < 1:
        parser.error("--retry-attempts 必须大于等于 1")
    if args.retry_backoff < 0:
        parser.error("--retry-backoff 不能小于 0")
    if args.interval_minutes <= 0:
        parser.error("--interval-minutes 必须大于 0")

    if args.once:
        return _run_once(args)

    interval_seconds = args.interval_minutes * 60
    cycle = 0
    auth_dir = Path(args.auth_dir).expanduser().resolve()
    live_updates_enabled = _is_tty_stdout() and (not args.no_progress) and (not args.output_json)
    try:
        while True:
            cycle += 1
            use_color = _supports_color(args.no_color) and (not args.output_json)
            if not args.output_json:
                print(
                    _paint(
                        f"第 {cycle} 轮定时扫描开始，时间：{_format_utc_timestamp()}",
                        ANSI_BOLD,
                        ANSI_CYAN,
                        enabled=use_color,
                    )
                )
            cycle_exit = _run_once(args)
            if cycle_exit == 2:
                return 2
            next_run = time.time() + interval_seconds
            current_count = _count_json_files(auth_dir)
            if not args.output_json:
                print(
                    _paint(
                        (
                            "扫描完成"
                            f" | 当前库存 {_inventory_progress_text(current_count, DEFAULT_MIN_AUTH_FILES)}"
                            f" | 下一轮 {_format_utc_timestamp(next_run)}"
                        ),
                        ANSI_DIM,
                        enabled=use_color,
                    )
                )
            _sleep_with_countdown(
                interval_seconds,
                enabled=live_updates_enabled,
                render_message=lambda remaining, count=current_count: _paint(
                    (
                        "扫描等待"
                        f" | 剩余 {_format_mmss(remaining)}"
                        f" | 当前库存 {_inventory_progress_text(count, DEFAULT_MIN_AUTH_FILES)}"
                    ),
                    ANSI_DIM,
                    enabled=use_color,
                ),
            )
    except KeyboardInterrupt:
        if not args.output_json:
            print()
            print("定时扫描已停止。")
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
