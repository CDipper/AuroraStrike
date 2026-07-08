"""
AURORA C2 - Team Server entrypoint.

Runs two FastAPI applications concurrently on separate ports:

  - Beacon app  (listener bind_host:bind_port) — /beacon/* routes only
  - Operator app (127.0.0.1:operator_port)      — /api/*, /ws, static Web UI

This separation ensures the beacon callback port never exposes
operator management endpoints.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, Response

import config
import database as db
from api_routes import router as api_router
from app_state import close_conn, set_conn, set_listener_reload_callback
from beacon_routes import router as beacon_router
from ws import router as ws_router

# ════════════════════════════════════════════════════════
#  Beacon app — listener port, beacon traffic only
# ════════════════════════════════════════════════════════

beacon_app = FastAPI(title="AURORA C2 Beacon Listener")
beacon_app.include_router(beacon_router)

# ════════════════════════════════════════════════════════
#  Operator app — operator port, API + WebSocket + Web UI
# ════════════════════════════════════════════════════════


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init_db()
    conn = db.get_db()
    if config.CLEAR_EVENTS_ON_START:
        db.clear_events(conn)
    set_conn(conn)
    yield
    close_conn()


operator_app = FastAPI(title="AURORA C2 Operator Console", lifespan=lifespan)
operator_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
operator_app.include_router(api_router)
operator_app.include_router(ws_router)

# Backward-compatible alias
app = operator_app


# ════════════════════════════════════════════════════════
#  Static Web UI (operator app only)
# ════════════════════════════════════════════════════════

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


@operator_app.get("/static/{asset_path:path}")
async def static_asset(asset_path: str):
    base = Path(config.WEBUI_DIR).resolve()
    target = (base / asset_path).resolve()

    try:
        target.relative_to(base)
    except ValueError:
        raise HTTPException(404, "Static asset not found")

    if not target.is_file():
        raise HTTPException(404, "Static asset not found")

    return FileResponse(str(target), headers=NO_CACHE_HEADERS)


@operator_app.get("/favicon.ico")
async def favicon():
    return Response(status_code=204, headers=NO_CACHE_HEADERS)


@operator_app.get("/", response_class=HTMLResponse)
async def index():
    with open(f"{config.WEBUI_DIR}/index.html") as f:
        html = f.read()
    return HTMLResponse(html, headers=NO_CACHE_HEADERS)


# ════════════════════════════════════════════════════════
#  Main — start both servers concurrently
# ════════════════════════════════════════════════════════

if __name__ == "__main__":
    import asyncio
    import signal
    import socket
    import contextlib
    import uvicorn

    def _listener_lines(listeners: list[dict]) -> list[str]:
        lines = []
        for listener in listeners:
            public_url = f"{listener['protocol']}://{listener['public_host']}:{listener['public_port']}"
            lines.append(f"    - {listener['id']} {listener['bind_host']}:{listener['bind_port']} -> {public_url}")
        return lines

    def _create_listener_sockets(listeners: list[dict]) -> list[socket.socket]:
        sockets: list[socket.socket] = []
        seen_binds: set[tuple[str, int]] = set()
        try:
            for listener in listeners:
                bind_host = listener["bind_host"]
                bind_port = int(listener["bind_port"])
                bind_key = (bind_host, bind_port)
                if bind_key in seen_binds:
                    continue
                seen_binds.add(bind_key)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                sock.bind(bind_key)
                sock.listen(2048)
                sockets.append(sock)
            return sockets
        except Exception:
            for sock in sockets:
                with contextlib.suppress(Exception):
                    sock.close()
            raise

    class BeaconListenerManager:
        def __init__(self):
            self.server: uvicorn.Server | None = None
            self.task: asyncio.Task | None = None
            self.sockets: list[socket.socket] = []
            self.lock = asyncio.Lock()

        async def start(self) -> None:
            conn = db.get_db()
            listeners = db.list_listeners(conn)
            conn.close()
            sockets = _create_listener_sockets(listeners)
            server = uvicorn.Server(uvicorn.Config(beacon_app, log_level="error"))
            self.server = server
            self.sockets = sockets
            self.task = asyncio.create_task(server.serve(sockets=sockets))

        async def stop(self) -> None:
            if self.server:
                self.server.should_exit = True
            if self.task:
                with contextlib.suppress(Exception):
                    await asyncio.wait_for(self.task, timeout=5)
            for sock in self.sockets:
                with contextlib.suppress(Exception):
                    sock.close()
            self.server = None
            self.task = None
            self.sockets = []

        async def reload(self) -> None:
            async with self.lock:
                await self.stop()
                await self.start()

        def request_stop(self) -> None:
            if self.server:
                self.server.should_exit = True

    db.init_db()
    _conn = db.get_db()
    _listeners = db.list_listeners(_conn)
    _conn.close()

    # --- Auto-generate webui/config.js with current operator port ---
    operator_port = config.OPERATOR_PORT
    _config_js = Path(config.WEBUI_DIR) / "config.js"
    _config_js.write_text(
        f"// Auto-generated by teamserver\n"
        f'window.AURORA_API = "http://127.0.0.1:{operator_port}";\n'
        f'window.AURORA_WS = "ws://127.0.0.1:{operator_port}";\n',
        encoding="utf-8",
    )

    listener_lines = _listener_lines(_listeners)

    # --- Operator socket (localhost only) ---
    operator_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    operator_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    operator_sock.bind(("127.0.0.1", operator_port))
    operator_sock.listen(2048)

    import pyfiglet

    _art = pyfiglet.figlet_format("AURORA", font="slant").rstrip().splitlines()
    _art_w = max(len(line) for line in _art)
    _d = "·-·" * ((_art_w + 5) // 3)
    _inner = len(f"  {_d}") - 6  # total width minus "  · " and " ·"

    _banner = f"  {_d}\n"
    _banner += f"  · {' ' * _inner} ·\n"
    for _line in _art:
        _banner += f"  · {_line.ljust(_inner)} ·\n"
    _banner += f"  · {' ' * _inner} ·\n"
    _banner += f"  {_d}\n"

    print(f"""
{_banner}
  Author   · · · · · · · · · · · · · · · cdipp3r
  Profile  · · · · · · · · · · · · · · · {config.PROFILE_PATH.name}
  Operator · · · · · · · · · · · · · · · {config.DEFAULT_OP_USER}

  Operator Console · · · http://127.0.0.1:{operator_port}

  Listeners (Beacon):
{chr(10).join(f'    {line.strip()}' for line in listener_lines)}
    """)

    listener_manager = BeaconListenerManager()
    set_listener_reload_callback(listener_manager.reload)
    operator_server = uvicorn.Server(uvicorn.Config(operator_app, log_level="error"))

    # Link signal handlers so both servers shut down together
    def _handle_exit(sig, frame):
        listener_manager.request_stop()
        operator_server.handle_exit(sig, frame)

    try:
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, _handle_exit)
    except (ValueError, OSError):
        pass  # Not in main thread or unsupported signal

    async def _run():
        await listener_manager.start()
        try:
            await operator_server.serve(sockets=[operator_sock])
        finally:
            await listener_manager.stop()

    asyncio.run(_run())
