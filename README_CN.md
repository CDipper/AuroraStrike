# AURORA C2

AURORA C2 是一个用于**授权内部安全演练**的轻量级 C2 框架，采用 Team Server + Web UI + Windows Beacon(x64) 架构。

> 仅供已授权的安全测试、红蓝对抗演练和教学研究使用。未经授权使用是违法行为。

![image-20260708151356241](README_CN.assets/image-20260708151356241.png)

## 组件

| 组件 | 技术栈 | 说明 |
|---|---|---|
| Team Server | Python / FastAPI / SQLite | Beacon 注册、任务队列、结果回传、事件记录等 |
| Web UI | HTML / CSS / JS | 操作员控制台、Beacon 管理、文件/进程视图等 |
| Implant | C / Win32 / WinHTTP | 支持命令执行、文件传输、BOF执行、.NET程序集内存加载、sRDI（dllinject）等 |

Implant暂时不开源，有任何bug可以提issue。

## 快速开始

### Linux / macOS

```bash
./start.sh
```

![image-20260708150759576](README_CN.assets/image-20260708150759576.png)

### Windows

```cmd
start.bat
```

## 操作

浏览器访问：

```text
http://127.0.0.1:5001
```

Team Server 运行两个端口：
- **操作员端口**（默认 5001，仅本地）— Web UI、REST API、WebSocket
- **Listener 端口**（默认 8443，来自 listener 配置）— 仅 Beacon 回连，可在 WebUI 的 LISTENERS 中修改（修改后需重启 Team Server）

默认登录（建议在profile中修改一下）：

```text
admin / aurora_admin_2026
```

## 命令

```text
Available commands:
  help                         Show this help
  shell <cmd>                  Execute command via cmd.exe
  exec <cmd>                   Alias of shell
  pwd                          Print current working directory
  cd <path>                    Change working directory
  ls [path]                    List files
  drives                       List logical drives
  mkdir <path>                 Create directory
  rm <path>                    Remove file or empty directory
  cp <src> <dst>               Copy file
  mv <src> <dst>               Move/rename file
  download <remote>            Download remote file to ./download/random-name
  upload <local> <remote>      Upload local absolute/cwd-relative file
  whoami                       Show current user
  ps                           List processes
  kill <pid>                   Terminate process
  jobs                         List async beacon jobs
  jobkill <job_id>             Request cancellation for an async job
  ifconfig                     Show local IP addresses
  portscan <host> <ports>      TCP scan, e.g. 10.0.0.1 1-1000
  setenv <name> <value>        Set environment variable
  sleep <sec> <jitter>         Change beacon sleep/jitter
  inline-execute <path> [args] Execute a BOF (.o or .obj) inline on the beacon
  dllinject <pid> <dll_path> [export_fn] Inject DLL into remote process via sRDI
  execute-assembly <path> [args] Run .NET assembly in-memory via CLR hosting (sRDI)
  exit                         Terminate beacon
```

## Profile

参考 [profiles/README_CN.md](profiles/README_CN.md)。

## 安全说明

- 演练前务必修改默认账号、密码和 RSA 密钥对。
- 默认使用 HTTP；如需生产/跨网段使用，建议放在 TLS 反向代理后。
- Beacon 会话和任务队列主要保存在 Team Server 运行时内存中，重启后会清空在线状态和任务历史。

## 法律声明

仅供授权安全测试使用。在部署或测试前必须获得明确授权。开发者不对任何滥用行为承担责任。
