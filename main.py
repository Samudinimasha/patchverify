#!/usr/bin/env python3
"""
PatchVerify — CLI entry point
Usage:
  patchverify --setup
  patchverify --app django --old 4.1.0 --new 4.2.0
  patchverify --app requests --old 2.28.0 --new 2.31.0 --no-probe
  patchverify --history
  patchverify --serve
"""
import argparse
import sys
import json
import os

def main():
    parser = argparse.ArgumentParser(
        prog="patchverify",
        description="PatchVerify — Verify whether a software update actually fixed what it promised.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  patchverify --setup
  patchverify --app django --old 4.1.0 --new 4.2.0
  patchverify --app requests --old 2.28.0 --new 2.31.0
  patchverify --app pillow --old 9.5.0 --new 10.0.0 --no-probe
  patchverify --history
  patchverify --serve
        """
    )

    parser.add_argument("--setup",           action="store_true", help="First-time setup: register device via email OTP")
    parser.add_argument("--serve",           action="store_true", help="Start the web dashboard server")
    parser.add_argument("--history",         action="store_true", help="Show past scan history")
    parser.add_argument("--install-service", action="store_true", help="Install dashboard as a background service (auto-starts on login)")
    parser.add_argument("--app",      type=str, help="App/package name to scan")
    parser.add_argument("--old",      type=str, help="Old (previous) version number")
    parser.add_argument("--new",      type=str, help="New (updated) version number")
    parser.add_argument("--token",    type=str, help="GitHub personal access token (optional, increases rate limits)")
    parser.add_argument("--no-probe", action="store_true", help="Skip behavioral probing (faster)")
    parser.add_argument("--json",     action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # ── Setup ──────────────────────────────────────────────────────────────
    if args.setup:
        from cli.auth import setup_flow
        setup_flow()
        return

    # ── Install as background service ──────────────────────────────────────
    if args.install_service:
        _install_service()
        return

    # ── Serve dashboard ────────────────────────────────────────────────────
    if args.serve:
        _check_registered()
        from server.app import run_server
        run_server()
        return

    # ── History ────────────────────────────────────────────────────────────
    if args.history:
        _show_history()
        return

    # ── Scan ───────────────────────────────────────────────────────────────
    if args.app:
        if not args.old or not args.new:
            print("Error: --old and --new version numbers are required for scanning.")
            print("Example: patchverify --app django --old 4.1.0 --new 4.2.0")
            sys.exit(1)

        _check_registered()
        _ensure_server_running()

        # Get GitHub token from args or env or config
        github_token = (
            args.token
            or os.environ.get("GITHUB_TOKEN")
            or _get_config_token()
        )

        from cli.scanner import run_scan
        result = run_scan(
            app_name=args.app,
            old_version=args.old,
            new_version=args.new,
            github_token=github_token,
            skip_probe=args.no_probe,
        )

        # Send email notification
        try:
            from cli.auth import send_scan_notification
            send_scan_notification(result)
        except Exception:
            pass

        if args.json:
            print(json.dumps(result, indent=2, default=str))

        from cli.config import C
        print(f"  {C.CYAN}Dashboard: http://localhost:8080{C.RESET}\n")
        return

    # No command given
    parser.print_help()


def _ensure_server_running():
    """Start the dashboard as a detached background process (survives terminal close)."""
    import socket
    import subprocess
    import time
    from pathlib import Path
    from cli.config import C

    pid_file = Path.home() / '.patchverify' / 'server.pid'

    # Check if already listening on port 8080
    def _is_up():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex(('127.0.0.1', 8080)) == 0

    if _is_up():
        return

    # Locate the repo root (where server/app.py lives)
    repo_root = Path(__file__).resolve().parent

    kwargs = dict(
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=str(repo_root),
    )
    if sys.platform == 'win32':
        kwargs['creationflags'] = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        kwargs['start_new_session'] = True  # detach from terminal on Mac/Linux

    proc = subprocess.Popen(
        [sys.executable, '-c',
         'import logging; logging.getLogger("werkzeug").setLevel(logging.ERROR); '
         'from server.app import app; app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)'],
        **kwargs
    )

    # Save PID so we can check it next time
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(str(proc.pid))

    # Wait up to 4 seconds for the server to be ready
    for _ in range(40):
        time.sleep(0.1)
        if _is_up():
            break

    print(f"  {C.CYAN}Dashboard: http://localhost:8080{C.RESET}  {C.GRAY}(running in background){C.RESET}\n")


def _install_service():
    """Install the dashboard server as a background service that starts on login."""
    from pathlib import Path
    from cli.config import C

    repo_root = Path(__file__).resolve().parent
    python_exe = sys.executable

    if sys.platform == 'darwin':
        plist_dir = Path.home() / 'Library' / 'LaunchAgents'
        plist_dir.mkdir(parents=True, exist_ok=True)
        plist_path = plist_dir / 'com.patchverify.server.plist'
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.patchverify.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_exe}</string>
        <string>-c</string>
        <string>import logging; logging.getLogger("werkzeug").setLevel(logging.ERROR); from server.app import app; app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)</string>
    </array>
    <key>WorkingDirectory</key>
    <string>{repo_root}</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/patchverify-server.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/patchverify-server.log</string>
</dict>
</plist>"""
        plist_path.write_text(plist_content)

        import subprocess
        # Unload first in case it was already loaded
        subprocess.run(['launchctl', 'unload', str(plist_path)],
                       capture_output=True)
        result = subprocess.run(['launchctl', 'load', str(plist_path)],
                                capture_output=True, text=True)

        if result.returncode == 0:
            print(f"\n  {C.GREEN}✓ Service installed and started.{C.RESET}")
            print(f"  Dashboard runs at {C.CYAN}http://localhost:8080{C.RESET} automatically on every login.")
            print(f"  {C.GRAY}To remove: launchctl unload {plist_path}{C.RESET}\n")
        else:
            print(f"\n  {C.YELLOW}Installed but could not load service: {result.stderr}{C.RESET}")
            print(f"  Try running manually: {C.BOLD}patchverify --serve{C.RESET}\n")

    elif sys.platform == 'win32':
        import subprocess
        cmd = (
            f'schtasks /create /tn "PatchVerifyServer" /tr '
            f'"{python_exe} -c \\"from server.app import app; app.run(host=\'0.0.0.0\', port=8080)\\"" '
            f'/sc onlogon /rl limited /f'
        )
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            print(f"\n  {C.GREEN}✓ Scheduled task created — dashboard auto-starts on login.{C.RESET}")
            print(f"  Dashboard: {C.CYAN}http://localhost:8080{C.RESET}\n")
        else:
            print(f"\n  {C.YELLOW}Could not create scheduled task: {result.stderr}{C.RESET}\n")
    else:
        print(f"\n  {C.YELLOW}Auto-service not supported on this platform.{C.RESET}")
        print(f"  Add this to your shell startup (~/.bashrc / ~/.zshrc):")
        print(f"  {C.BOLD}patchverify --serve &{C.RESET}\n")


def _check_registered():
    from cli.auth import is_registered, setup_flow
    from cli.config import C
    if not is_registered():
        print(f"\n{C.YELLOW}First time running PatchVerify!{C.RESET}\n")
        setup_flow()
        print(f"\n{C.GREEN}Setup complete! Continuing with your request...{C.RESET}\n")


def _get_config_token():
    try:
        from cli.auth import load_config
        cfg = load_config()
        return cfg.get("github_token")
    except Exception:
        return None


def _show_history():
    from cli.config import HISTORY_FILE, C
    if not HISTORY_FILE.exists():
        print(f"\n{C.YELLOW}No scan history found. Run a scan first.{C.RESET}\n")
        return

    with open(HISTORY_FILE) as f:
        history = json.load(f)

    if not history:
        print(f"\n{C.YELLOW}Scan history is empty.{C.RESET}\n")
        return

    print(f"\n{C.CYAN}{C.BOLD}PatchVerify — Scan History ({len(history)} scans){C.RESET}\n")
    print(f"{'─'*70}")
    for record in history[:20]:
        risk_colors = {"NONE":"", "LOW": C.GREEN, "MEDIUM": C.YELLOW,
                       "HIGH": C.ORANGE, "CRITICAL": C.RED}
        rcol = risk_colors.get(record.get("risk_label",""), C.GRAY)
        print(f"  {C.BOLD}{record['app']}{C.RESET}  "
              f"{record['old_version']} → {record['new_version']}  "
              f"[{rcol}{record.get('risk_label','?')}{C.RESET}  {record.get('risk_score',0)}/100]  "
              f"{C.GRAY}{record['scan_id']}{C.RESET}")
        print(f"  {C.GRAY}Fixed: {record.get('fixed',0)}/{record.get('total',0)}  "
              f"Not fixed: {record.get('not_fixed',0)}  "
              f"Unconfirmed: {record.get('unconfirmed',0)}  "
              f"| {record.get('started','')[:10]}{C.RESET}")
        print(f"{'─'*70}")
    print()


if __name__ == "__main__":
    main()
