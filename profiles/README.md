# AURORA C2 Profiles

Profiles are the single source of runtime configuration for the team server. They use a Cobalt-Strike-like text syntax with `block { set key "value"; }` declarations.

## Profile Syntax

```
# Comments start with # or //
block_name {
    set field_name "value";
    set another_field "another_value";
}
```

- All values are strings (quotes recommended but optional for simple tokens).
- Paths are resolved relative to the project root unless absolute.
- Boolean values: `true` / `false` / `1` / `0` / `yes` / `no` / `on` / `off`.

## Field Reference

### `server` — Team Server Settings

| Field | Type | Description |
|-------|------|-------------|
| `database` | path | SQLite database file path |
| `webui_dir` | path | Web UI static files directory |
| `operator_port` | int | Operator console port (API + WebSocket + Web UI). Bound to 127.0.0.1 only. |
| `beacon_timeout` | int (seconds) | Beacon inactivity timeout before marking as stale |
| `clear_events_on_start` | bool | Clear all event logs when the team server starts |
| `transfer_chunk_size` | int (bytes) | Chunk size for file transfer between beacon and team server |
| `browser_upload_max_bytes` | int (bytes) | Maximum file size for browser-based uploads via Web UI |

### `operator` — Default Operator Credentials

| Field | Type | Description |
|-------|------|-------------|
| `user` | str | Default operator username (created on first start) |
| `password` | str | Default operator password (bcrypt-hashed in database) |

### `jwt` — JSON Web Token

| Field | Type | Description |
|-------|------|-------------|
| `secret` | str | JWT signing secret (change in production) |
| `algo` | str | JWT algorithm (e.g. `HS256`) |
| `exp_hours` | int (hours) | Token expiration time |

### `resources` — Encrypted Resources

| Field | Type | Description |
|-------|------|-------------|
| `key` | str | AES-256 encryption key for `resources/*.enc` files. SHA-256 hashed before use. Change in production and re-encrypt all resources. |
| `rsa_key_resource` | str | Encrypted resource name for the RSA private key (default: `rsa_private_key`). Used for beacon registration decryption and payload generation. |

### `implant` — Beacon Runtime

| Field | Type | Description |
|-------|------|-------------|
| `spawn_process` | str | Default process for beacon to spawn into |
| `user_agent` | str | Default HTTP User-Agent string for beacon HTTP requests |
| `default_sleep` | int (seconds) | Default beacon sleep interval (overridable per payload) |
| `default_jitter` | int (percent) | Default beacon jitter percentage (overridable per payload) |

## Listener Configuration

Listener fields (`name`, `bind_host`, `bind_port`, `public_host`, `public_port`, `protocol`) are **database records** managed exclusively from the Web UI `LISTENER` panel. They must **not** appear in profile files.

All listeners are started automatically when the team server launches. There is no `enabled` or `active` flag.

## Usage

```bash
./start.sh                          # default profile (profiles/default.profile)
./start.sh lab                      # profiles/lab.profile
./start.sh profiles/lab.profile     # explicit path
./start.sh --profile lab            # alternative syntax
```
