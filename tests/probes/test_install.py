"""Install/uninstall round-trip tests for supported MCP client configs.

The test runs the built Guard binary in a temporary HOME/APPDATA/XDG tree and a
temporary project directory, so it never touches real client configs.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GUARD = os.environ.get("SYLENIX_GUARD") or os.path.join(
    ROOT, "bin", "sylenix-guard.exe" if sys.platform == "win32" else "sylenix-guard")

passed, failed = 0, []


def check(label, cond, detail=""):
    global passed
    if cond:
        passed += 1
        print(f"  ok   {label}")
    else:
        failed.append(label)
        print(f"  FAIL {label} {detail}")


def config_dir(home, appdata, xdg):
    if sys.platform == "win32":
        return appdata
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support")
    return xdg


def write_json(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, indent=2, sort_keys=True)
        fh.write("\n")


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def canonical(path):
    return json.dumps(read_json(path), sort_keys=True, separators=(",", ":"))


def strip_ws(text):
    return "".join(text.split())


def set_map(root, parts, servers):
    cur = root
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
    cur[parts[-1]] = servers


def make_entry(command, args=None, env=None):
    entry = {"command": command}
    if args is not None:
        entry["args"] = args
    if env is not None:
        entry["env"] = env
    return entry


def run(args, env, cwd, input_text=None):
    return subprocess.run([GUARD, *args], env=env, cwd=cwd, input=input_text,
                          capture_output=True, text=True)


def setup_tree(base):
    home = os.path.join(base, "home")
    appdata = os.path.join(base, "appdata")
    xdg = os.path.join(base, "xdg")
    project = os.path.join(base, "project")
    for path in (home, appdata, xdg, project):
        os.makedirs(path, exist_ok=True)
    env = dict(os.environ)
    env.update({
        "HOME": home,
        "USERPROFILE": home,
        "APPDATA": appdata,
        "XDG_CONFIG_HOME": xdg,
    })
    cfg = config_dir(home, appdata, xdg)
    return home, project, cfg, env


def build_configs(home, project, cfg):
    cmd = sys.executable
    configs = []

    desktop = {"mcpServers": {
        "desk": make_entry(cmd, ["-c", "print('desk')"], {"DESK_TOKEN": "x"}),
        "remote": {"type": "http", "url": "https://example.com/mcp"},
    }}
    p = os.path.join(cfg, "Claude", "claude_desktop_config.json")
    write_json(p, desktop)
    configs.append((p, ["mcpServers"]))

    claude = {"mcpServers": {
        "code_user": make_entry(cmd),
    }, "keep": {"untouched": True}}
    p = os.path.join(home, ".claude.json")
    write_json(p, claude)
    configs.append((p, ["mcpServers"]))

    project_mcp = {"mcpServers": {
        "code_project": make_entry(cmd, [], {}),
    }}
    p = os.path.join(project, ".mcp.json")
    write_json(p, project_mcp)
    configs.append((p, ["mcpServers"]))

    cursor_user = {"mcpServers": {
        "cursor_user": make_entry(cmd, ["serve"]),
    }}
    p = os.path.join(home, ".cursor", "mcp.json")
    write_json(p, cursor_user)
    configs.append((p, ["mcpServers"]))

    cursor_project = {"mcpServers": {
        "cursor_project": make_entry(cmd, ["--stdio"]),
    }}
    p = os.path.join(project, ".cursor", "mcp.json")
    write_json(p, cursor_project)
    configs.append((p, ["mcpServers"]))

    vscode_settings = {"editor.fontSize": 14, "mcp": {"servers": {
        "vscode_settings": make_entry(cmd, ["--settings"]),
    }}}
    p = os.path.join(cfg, "Code", "User", "settings.json")
    write_json(p, vscode_settings)
    configs.append((p, ["mcp", "servers"]))

    vscode_mcp = {"servers": {
        "vscode_user": make_entry(cmd, ["--user"]),
    }}
    p = os.path.join(cfg, "Code", "User", "mcp.json")
    write_json(p, vscode_mcp)
    configs.append((p, ["servers"]))

    vscode_workspace = {"servers": {
        "vscode_workspace": make_entry(cmd, ["--workspace"]),
    }}
    p = os.path.join(project, ".vscode", "mcp.json")
    write_json(p, vscode_workspace)
    configs.append((p, ["servers"]))
    return configs


def get_servers(obj, parts):
    cur = obj
    for part in parts:
        cur = cur[part]
    return cur


def server_map(obj, parts, name):
    return get_servers(obj, parts)[name]


def is_guard(command):
    return os.path.normcase(os.path.abspath(command)) == os.path.normcase(os.path.abspath(GUARD))


def round_trip_test():
    with tempfile.TemporaryDirectory() as base:
        home, project, cfg, env = setup_tree(base)
        configs = build_configs(home, project, cfg)
        originals = {path: canonical(path) for path, _ in configs}
        raw_originals = {path: strip_ws(open(path, encoding="utf-8").read()) for path, _ in configs}
        before = {path: open(path, "rb").read() for path, _ in configs}

        dry = run(["install", "--yes", "--dry-run"], env, project)
        check("dry-run exits successfully", dry.returncode == 0, dry.stderr)
        check("dry-run leaves every config unchanged",
              all(open(p, "rb").read() == before[p] for p, _ in configs))
        check("dry-run creates no backups",
              all(not glob.glob(p + ".sylenix-backup-*") for p, _ in configs))
        check("dry-run shows a diff", "+++" in dry.stdout and "wrap " in dry.stdout, dry.stdout[-300:])

        installed = run(["install", "--yes"], env, project)
        check("install exits successfully", installed.returncode == 0, installed.stderr)
        for path, parts in configs:
            obj = read_json(path)
            for name, entry in get_servers(obj, parts).items():
                if name == "remote":
                    check(f"{os.path.basename(path)}/{name}: remote entry untouched",
                          entry == {"type": "http", "url": "https://example.com/mcp"})
                    continue
                check(f"{os.path.basename(path)}/{name}: command is Guard",
                      is_guard(entry.get("command", "")), str(entry))
                args = entry.get("args", [])
                check(f"{os.path.basename(path)}/{name}: wrapper starts with --",
                      len(args) >= 2 and args[0] == "--", str(args))
                check(f"{os.path.basename(path)}/{name}: Guard metadata present",
                      isinstance(entry.get("_sylenixGuard"), dict), str(entry))
            check(f"{os.path.basename(path)}: backup exists",
                  bool(glob.glob(path + ".sylenix-backup-*")))

        for path, _ in configs:
            for backup in glob.glob(path + ".sylenix-backup-*"):
                os.remove(backup)

        uninstalled = run(["uninstall", "--yes"], env, project)
        check("uninstall exits successfully", uninstalled.returncode == 0, uninstalled.stderr)
        for path, _ in configs:
            check(f"{os.path.basename(path)}: round-trip restored",
                  canonical(path) == originals[path],
                  f"{canonical(path)} != {originals[path]}")
            check(f"{os.path.basename(path)}: round-trip byte-identical ignoring whitespace",
                  strip_ws(open(path, encoding="utf-8").read()) == raw_originals[path])


def already_wrapped_test():
    with tempfile.TemporaryDirectory() as base:
        home, project, cfg, env = setup_tree(base)
        path = os.path.join(home, ".claude.json")
        original_entry = {"command": GUARD, "args": ["--", sys.executable, "serve"]}
        write_json(path, {"mcpServers": {"already": original_entry}})
        before = canonical(path)
        result = run(["install", "--yes"], env, project)
        check("already-wrapped config exits successfully", result.returncode == 0, result.stderr)
        check("already-wrapped entry is skipped and unchanged",
              canonical(path) == before and "already" in result.stdout, result.stdout)


def confirmation_test():
    with tempfile.TemporaryDirectory() as base:
        home, project, cfg, env = setup_tree(base)
        path = os.path.join(home, ".claude.json")
        write_json(path, {"mcpServers": {
            "confirm": make_entry(sys.executable, ["serve"]),
        }})
        before = open(path, "rb").read()
        answer_no = run(["install"], env, project, "n\n")
        check("confirmation decline exits successfully", answer_no.returncode == 0, answer_no.stderr)
        check("confirmation decline leaves config unchanged", open(path, "rb").read() == before)
        check("confirmation decline creates no backup",
              not glob.glob(path + ".sylenix-backup-*"))
        check("confirmation decline shows the prompt", "Apply changes" in answer_no.stdout)
        answer_yes = run(["install"], env, project, "y\n")
        check("confirmation accept writes the config", answer_yes.returncode == 0, answer_yes.stderr)
        check("confirmation accept wraps the entry",
              is_guard(read_json(path)["mcpServers"]["confirm"]["command"]))
        check("confirmation accept creates a backup",
              bool(glob.glob(path + ".sylenix-backup-*")))


def broken_config_test():
    with tempfile.TemporaryDirectory() as base:
        home, project, cfg, env = setup_tree(base)
        path = os.path.join(home, ".claude.json")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{broken json\n")
        before = open(path, "rb").read()
        result = run(["install", "--yes"], env, project)
        check("broken config makes install fail", result.returncode != 0, result.stdout)
        check("broken config is left byte-for-byte untouched",
              open(path, "rb").read() == before)
        check("broken config error is clear",
              path in (result.stdout + result.stderr) and "parse" in (result.stdout + result.stderr).lower(),
              result.stdout + result.stderr)


def main():
    if not os.path.exists(GUARD):
        sys.exit("build first: CGO_ENABLED=0 go build -o bin/sylenix-guard ./cmd/sylenix-guard")
    round_trip_test()
    already_wrapped_test()
    confirmation_test()
    broken_config_test()
    print(f"\n{passed} passed, {len(failed)} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
