#!/usr/bin/env python3
"""
AURORA C2 - Resource encryption CLI.

Usage:
  python teamserver/encrypt_resources.py encrypt <name> <input_file>
  python teamserver/encrypt_resources.py encrypt-all
  python teamserver/encrypt_resources.py list
  python teamserver/encrypt_resources.py dump <name>

Examples:
  python teamserver/encrypt_resources.py encrypt clr_loader test/assets/clr_loader.dll
  python teamserver/encrypt_resources.py encrypt-all
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from resource_manager import encrypt_file, load_resource, list_resources, has_resource

TEAMSERVER_DIR = Path(__file__).resolve().parent
ROOT_DIR = TEAMSERVER_DIR.parent
TEST_ASSETS_DIR = ROOT_DIR / "test" / "assets"
IMPLANT_DIR = ROOT_DIR / "implant"

# All encrypted resources: name → source file path
ASSET_MAP = {
    "rsa_private_key": TEAMSERVER_DIR / "rsa_private.pem",
    "clr_loader": TEST_ASSETS_DIR / "clr_loader.dll",
    "beacon_template_x64": IMPLANT_DIR / "aurora_beacon_template.exe",
}


def cmd_encrypt(name: str, input_path: str) -> None:
    src = Path(input_path)
    if not src.is_file():
        print(f"Error: input file not found: {src}")
        sys.exit(1)
    data = src.read_bytes()
    out = encrypt_file(data, name)
    print(f"Encrypted: {src} -> {out} ({len(data)} bytes plaintext)")


def cmd_encrypt_all() -> None:
    found = 0
    for name, src in ASSET_MAP.items():
        if src.is_file():
            data = src.read_bytes()
            out = encrypt_file(data, name)
            print(f"  {name}: {src} -> {out} ({len(data)} bytes)")
            found += 1
        else:
            print(f"  {name}: SKIP (source not found: {src})")
    if found == 0:
        print("No source assets found. Build them first:")
        print("  cd test/assets && make clr_loader.dll")
        print("  cd implant && make template CROSS=x86_64-w64-mingw32-")
    else:
        print(f"\n{found} resource(s) encrypted into resources/")
        print("All data files are now encrypted. You can delete the plaintext sources.")
        print("IMPORTANT: Delete teamserver/rsa_private.pem after verifying decryption works.")


def cmd_list() -> None:
    resources = list_resources()
    if not resources:
        print("No encrypted resources found in resources/")
        return
    print("Encrypted resources:")
    for name in resources:
        print(f"  {name}")


def cmd_dump(name: str) -> None:
    if not has_resource(name):
        print(f"Error: resource not found: {name}")
        sys.exit(1)
    data = load_resource(name)
    sys.stdout.buffer.write(data)


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "encrypt" and len(sys.argv) == 4:
        cmd_encrypt(sys.argv[2], sys.argv[3])
    elif cmd == "encrypt-all" and len(sys.argv) == 2:
        cmd_encrypt_all()
    elif cmd == "list" and len(sys.argv) == 2:
        cmd_list()
    elif cmd == "dump" and len(sys.argv) == 3:
        cmd_dump(sys.argv[2])
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
