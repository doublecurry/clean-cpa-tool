# cpa-cleaner

用于批量扫描 CPA 认证 JSON 文件，检测账号是否失效、配额是否超限，并自动清理或隔离异常账号文件。

## 功能

- 扫描认证目录中的 CPA JSON 文件。
- 向 CPA `/responses` 接口发送轻量探测请求。
- 识别以下状态：
  - `401 Unauthorized`：认证失效。
  - `usage_limit_reached` / quota exceeded：配额超限。
  - unlimited / no limit：疑似不限额账号。
- 默认自动删除返回 `401` 的认证文件。
- 默认自动把超限账号移动到隔离目录。
- 自动扫描隔离目录，恢复已解除限制的账号文件。
- 支持定时循环扫描、单次扫描、并发探测、JSON 输出。
- 当认证文件库存低于阈值时，会尝试启动注册机补充库存。

## 环境要求

- Python 3.10+
- 标准库即可，无需额外依赖。

## 快速开始

```bash
python cpa-cleaner.py --once
```

默认会扫描：

```text
~/cpa/cpa1/.cli-proxy-api
```

默认行为：

- 删除 HTTP `401` 的认证文件。
- 将配额超限文件移动到 `--auth-dir` 同级的 `exceeded/` 目录。
- 扫描 `exceeded/`，若账号已恢复可用，则移动回认证目录。

## 常用命令

### 单次扫描

```bash
python cpa-cleaner.py --once
```

### 定时扫描

不加 `--once` 时进入循环模式，默认每 15 分钟执行一次。

```bash
python cpa-cleaner.py
```

自定义间隔：

```bash
python cpa-cleaner.py --interval-minutes 10
```

### 指定认证目录

```bash
python cpa-cleaner.py --auth-dir ./auths --once
```

### 调整并发数

```bash
python cpa-cleaner.py --workers 50 --once
```

### 删除 401 前要求确认

```bash
python cpa-cleaner.py --confirm-delete-401 --once
```

### 禁用自动删除 401

```bash
python cpa-cleaner.py --no-delete-401 --once
```

### 禁用超限文件隔离

```bash
python cpa-cleaner.py --no-quarantine --once
```

### 刷新 token 后再检测

```bash
python cpa-cleaner.py --refresh-before-check --once
```

### 输出 JSON

适合脚本、管道或监控系统消费。

```bash
python cpa-cleaner.py --output-json --once
```

## 参数说明

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| `--auth-dir` | `~/cpa/cpa1/.cli-proxy-api` | 认证 JSON 文件目录 |
| `--base-url` | `https://chatgpt.com/backend-api/codex` | Codex 接口基础地址 |
| `--quota-path` | `/responses` | 用于鉴权和配额探测的接口路径 |
| `--model` | `gpt-5` | 探测请求使用的模型名 |
| `--timeout` | `20` | HTTP 超时时间，单位秒 |
| `--workers` | 自动计算，通常为 `32` | 并发扫描数量 |
| `--retry-attempts` | `3` | 网络错误最大重试次数 |
| `--retry-backoff` | `0.6` | 网络重试指数退避基础秒数 |
| `--refresh-before-check` | 关闭 | 探测前先刷新 access token |
| `--refresh-url` | `https://auth.openai.com/oauth/token` | token 刷新接口 |
| `--output-json` | 关闭 | 输出完整 JSON 结果 |
| `--no-progress` | 关闭 | 关闭实时进度显示 |
| `--no-color` | 关闭 | 关闭 ANSI 彩色输出 |
| `--delete-401` | 开启 | 删除 HTTP 401 认证文件 |
| `--no-delete-401` | 关闭 | 禁用 401 自动删除 |
| `--yes` | 关闭 | 跳过删除确认提示 |
| `--confirm-delete-401` | 关闭 | 删除 401 前交互确认 |
| `--exceeded-dir` | `--auth-dir` 同级 `exceeded/` | 配额超限文件隔离目录 |
| `--no-quarantine` | 关闭 | 禁用超限隔离和恢复扫描 |
| `--interval-minutes` | `15` | 循环模式扫描间隔 |
| `--once` | 关闭 | 只扫描一次后退出 |

## 返回码

| 返回码 | 含义 |
| --- | --- |
| `0` | 扫描完成，未发现 401 |
| `1` | 扫描完成，发现过 401 |
| `2` | 扫描过程发生错误 |
| `130` | 用户通过 `Ctrl+C` 中断定时扫描 |

## JSON 输出结构

启用 `--output-json` 后，输出包含：

- `results`：认证目录扫描结果。
- `exceeded_dir_results`：隔离目录扫描结果。
- `quarantine`：隔离和恢复移动结果。
- `deletion`：401 删除结果。
- `inventory_replenishment`：库存补充结果。

示例：

```bash
python cpa-cleaner.py --output-json --once
```

## 注意事项

- 默认会自动删除返回 `401` 的认证文件；如需只观察不删除，请加 `--no-delete-401`。
- 默认会移动配额超限文件；如需保持文件不动，请加 `--no-quarantine`。
- `--refresh-before-check` 会使用文件中的 `refresh_token` 请求刷新接口。
- 请确认认证目录路径正确，避免误操作无关 JSON 文件。
