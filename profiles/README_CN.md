# AURORA C2 Profile

Profile（配置文件）是 team server 运行时配置的唯一来源。使用类 Cobalt Strike 的文本语法，通过 `block { set key "value"; }` 声明配置项。

## 语法说明

```
# 注释以 # 或 // 开头
block_name {
    set field_name "value";
    set another_field "another_value";
}
```

- 所有值均为字符串（简单标记可省略引号，建议始终使用引号）。
- 路径如果不是绝对路径，则相对于项目根目录解析。
- 布尔值支持：`true` / `false` / `1` / `0` / `yes` / `no` / `on` / `off`。

## 字段说明

### `server` — Team Server 设置

| 字段 | 类型 | 说明 |
|------|------|------|
| `database` | 路径 | SQLite 数据库文件路径 |
| `webui_dir` | 路径 | Web UI 静态文件目录 |
| `operator_port` | 整数 | 操作员控制台端口（API + WebSocket + Web UI），仅绑定 127.0.0.1 |
| `beacon_timeout` | 整数（秒） | Beacon 不活动超时时间，超过后标记为失联 |
| `clear_events_on_start` | 布尔 | Team server 启动时是否清空所有事件日志 |
| `transfer_chunk_size` | 整数（字节） | Beacon 与 team server 之间文件传输的分块大小 |
| `browser_upload_max_bytes` | 整数（字节） | 通过 Web UI 浏览器上传文件的最大大小 |

### `operator` — 默认操作员凭证

| 字段 | 类型 | 说明 |
|------|------|------|
| `user` | 字符串 | 默认操作员用户名（首次启动时创建） |
| `password` | 字符串 | 默认操作员密码（在数据库中以 bcrypt 哈希存储） |

### `jwt` — JSON Web Token

| 字段 | 类型 | 说明 |
|------|------|------|
| `secret` | 字符串 | JWT 签名密钥（生产环境必须修改） |
| `algo` | 字符串 | JWT 算法（如 `HS256`） |
| `exp_hours` | 整数（小时） | Token 过期时间 |

### `resources` — 加密资源

| 字段 | 类型 | 说明 |
|------|------|------|
| `key` | 字符串 | `resources/*.enc` 文件的 AES-256 加密密钥。使用前经 SHA-256 派生。生产环境必须修改并重新加密所有资源。 |
| `rsa_key_resource` | 字符串 | RSA 私钥的加密资源名称（默认：`rsa_private_key`）。用于 beacon 注册解密和 payload 生成。 |

### `implant` — Beacon 运行时

| 字段 | 类型 | 说明 |
|------|------|------|
| `spawn_process` | 字符串 | Beacon 默认注入的目标进程名 |
| `user_agent` | 字符串 | Beacon HTTP 请求的默认 User-Agent |
| `default_sleep` | 整数（秒） | 默认 Beacon sleep 间隔（生成 payload 时可覆盖） |
| `default_jitter` | 整数（百分比） | 默认 Beacon jitter 百分比（生成 payload 时可覆盖） |

## 使用方法

```bash
./start.sh                          # 默认 profile（profiles/default.profile）
./start.sh lab                      # profiles/lab.profile
./start.sh profiles/lab.profile     # 显式指定路径
./start.sh --profile lab            # 替代语法
```
