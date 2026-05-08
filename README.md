# cpa-cleaner

Used for batch scanning of CPA authentication JSON files, detecting account expiration and quota exceeding limits, and automatically cleaning up or isolating abnormal account files.

## Features

- Scans CPA JSON files in the authentication directory.

- Sends lightweight probe requests to the CPA `/responses` interface.

- Identifies the following states:

- `401 Unauthorized`: Authentication expired.

- `usage_limit_reached` / quota exceeded: Quota exceeded.

- unlimited / no limit: Suspected unlimited quota account.

- Automatically deletes authentication files returning `401` by default.

- Automatically moves accounts exceeding limits to the isolation directory by default.

- Automatically scans the isolation directory and restores account files that have had their limits lifted.

- Supports scheduled loop scanning, single scan, concurrent probes, and JSON output.

- When the authentication file inventory falls below a threshold, it will attempt to launch a registration generator to replenish the inventory.

## Environment Requirements

- Python 3.10+

- Standard library is sufficient; no additional dependencies are required.

## Quick Start

```bash
python cpa-cleaner.py --once

```

Default scan:

```text
~/cpa/cpa1/.cli-proxy-api

```

Default behavior:

- Delete HTTP `401` authentication files.

- Move quota-exceeded files to the `exceeded/` directory at the same level as `--auth-dir`.

- Scan `exceeded/`; if the account has been restored, move it back to the authentication directory.

## Common Commands

### Single Scan

```bash
python cpa-cleaner.py --once

```
### Scheduled Scan

Without `--once`, it enters loop mode, executing every 15 minutes by default.

```bash

python cpa-cleaner.py

```

Custom Interval:

```bash

python cpa-cleaner.py --interval-minutes 10

```

### Specify Authentication Directory

```bash

python cpa-cleaner.py --auth-dir ./auths --once

```

### Adjust Concurrency

```bash

python cpa-cleaner.py --workers 50 --once

```

### Require Confirmation Before Deleting 401 Redirects

```bash

python cpa-cleaner.py --confirm-delete-401 --once

```

### Disable Automatic 401 Redirects

```bash

python cpa-cleaner.py --no-delete-401 --once

```

### Disable quarantine for excessive files

```bash
python cpa-cleaner.py --no-quarantine --once

```

### Refresh token before checking

```bash
python cpa-cleaner.py --refresh-before-check --once

```

### Output JSON

Suitable for scripts, pipelines, or monitoring systems.

```bash
python cpa-cleaner.py --refresh-before-check --once

```

### Output JSON

Suitable for scripts, pipelines, or monitoring systems.` ```bash
python cpa-cleaner.py --output-json --once

```
## Parameter Description

| Parameter | Default Value | Description |

| --- | --- | --- |

| `--auth-dir` | `~/cpa/cpa1/.cli-proxy-api` | Authentication JSON file directory |

| `--base-url` | `https://chatgpt.com/backend-api/codex` | Codex API base address |

| `--quota-path` | `/responses` | API path used for authentication and quota probing |

| `--model` | `gpt-5` | Model name used for probing requests |

| `--timeout` | `20` | HTTP timeout in seconds |

| `--workers` | Automatically calculated, usually `32` | Number of concurrent scans |

| `--retry-attempts` | `3` | Maximum number of retries for network errors |

| `--retry-backoff` | `0.6` | Base seconds for network retry backoff |

| `--refresh-before-check` | Off | Refresh access token before probe |

| `--refresh-url` | `https://auth.openai.com/oauth/token` | Token refresh interface |

| `--output-json` | Off | Output complete JSON result |

| `--no-progress` | Off | Turn off real-time progress display |

| `--no-color` | Off | Turn off ANSI color output |

| `--delete-401` | On | Delete HTTP 401 authentication file |

| `--no-delete-401` | Off | Disable automatic 401 deletion |

| `--yes` | Off | Skip deletion confirmation prompt |

| `--confirm-delete-401` | Off | Before deleting a 401 redirect, confirm interactively.

| `--exceeded-dir` | `--auth-dir` sibling `exceeded/` | Quota-exceeded file quarantine directory |

| `--no-quarantine` | Off | Disable over-quota quarantine and recovery scans |

| `--interval-minutes` | `15` | Cyclic scan interval |

| `--once` | Off | Exit after scanning only once |

## Return Codes

| Return Code | Meaning |

| --- | --- |

| `0` | Scan completed, no 401 redirects found |

| `1` | Scan completed, 401 redirects found |

| `2` | An error occurred during the scan |

| `130` | The user interrupted the scheduled scan using `Ctrl+C` |

## JSON Output Structure

With `--output-json` enabled, the output includes:

- `results`: Authentication directory scan results. - `exceeded_dir_results`: Results of quarantining directory scans.

- `quarantine`: Results of quarantining and restoring moved files.

- `deletion`: Results of 401 deletions.

- `inventory_replenishment`: Results of inventory replenishment.

Example:

```bash
python cpa-cleaner.py --output-json --once

```
## Notes

- By default, authentication files returning `401` will be automatically deleted; to observe without deletion, add `--no-delete-401`.

- By default, files exceeding quota limits will be moved; to keep files unchanged, add `--no-quarantine`.

- `--refresh-before-check` will use the `refresh_token` in the file to request a refresh of the API.

- Please ensure the authentication directory path is correct to avoid accidentally modifying irrelevant JSON files.
