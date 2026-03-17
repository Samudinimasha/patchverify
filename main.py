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

    parser.add_argument("--setup",    action="store_true", help="First-time setup: register device via email OTP")
    parser.add_argument("--serve",    action="store_true", help="Start the web dashboard server")
    parser.add_argument("--history",  action="store_true", help="Show past scan history")
    parser.add_argument("--app",      type=str,            help="App/package name to scan")
    parser.add_argument("--old",      type=str,            help="Old (previous) version number")
    parser.add_argument("--new",      type=str,            help="New (updated) version number")
    parser.add_argument("--token",    type=str,            help="GitHub personal access token (optional, increases rate limits)")
    parser.add_argument("--no-probe", action="store_true", help="Skip behavioral probing (faster)")
    parser.add_argument("--json",     action="store_true", help="Output results as JSON")

    args = parser.parse_args()

    # ── Setup ──────────────────────────────────────────────────────────────
    if args.setup:
        from cli.auth import setup_flow
        setup_flow()
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
        print(f"  {C.CYAN}Dashboard live at: http://localhost:8080{C.RESET}")
        print(f"  {C.GRAY}Press Ctrl+C to exit{C.RESET}\n")
        return

    # No command given
    parser.print_help()


def _ensure_server_running():
    """Start the web dashboard in a background thread if not already running."""
    import socket
    import threading
    import time
    from cli.config import C

    # Check if something is already listening on port 8080
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        already_up = s.connect_ex(('127.0.0.1', 8080)) == 0

    if already_up:
        return

    def _run():
        import logging
        logging.getLogger('werkzeug').setLevel(logging.ERROR)
        from server.app import app
        app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

    t = threading.Thread(target=_run, daemon=False)
    t.start()

    # Wait up to 3 seconds for the server to be ready
    for _ in range(30):
        time.sleep(0.1)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            if s.connect_ex(('127.0.0.1', 8080)) == 0:
                break

    print(f"  {C.CYAN}Dashboard: http://localhost:8080{C.RESET}  {C.GRAY}(auto-started){C.RESET}\n")


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
