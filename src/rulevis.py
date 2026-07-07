#!/usr/bin/env python3

import argparse
import logging
import os
import re
import sys
import webbrowser
from threading import Timer
from typing import Final

from internal.visualizer import create_app

APP_NAME: Final[str] = 'rulevis'
DESCRIPTION: Final[str] = f"{APP_NAME} is a Wazuh rule visualization platform."
ENCODING: Final[str] = "utf-8"
PORT: Final[int] = 5000

# Precompiled regex to remove ANSI color/control sequences
ANSI_ESCAPE_RE: re.Pattern[str] = re.compile(
    r"""
    (?:                           # Non-capturing group for all patterns
      \x1B\[                      # ESC [ (CSI)
      [0-?]*[ -/]*[@-~]           # Parameter bytes + intermediate + final byte
     |                            # OR
      \x1B[@-Z\\-_]               # 2-byte sequences
     |                            # OR
      \x1B\][^\x07]*(?:\x07|\x1B\\) # OSC sequences
     |                            # OR literal representations (\x1b, <0x1b>)
      (?:\\x1[bB]|\<0x1[bB]\>)(?:\[[0-?]*[ -/]*[@-~])?
    )
    """,
    re.VERBOSE,
)


class CustomFileHandler(logging.FileHandler):
    """FileHandler that strips all escape sequences and representations."""

    def emit(self, record) -> None:
        record.msg = ANSI_ESCAPE_RE.sub('', str(record.msg))  # Escape ANSI Color Sequences
        record.name = APP_NAME  # Rename source
        super().emit(record)


class Rulevis():

    def __init__(self, paths: list[str]) -> None:
        self.__validate_paths(paths)
        self.__paths: list[str] = paths

    def run(self) -> None:
        app = create_app(self.__paths)
        Timer(1, self.__open_browser).start()
        try:
            from waitress import serve
            # Flask's built-in server prints its own "do not use in
            # production" warning — waitress is a real (if modest) WSGI
            # server: multi-threaded, no dev-reloader, safe to leave running.
            logging.info("Starting server (waitress)...")
            serve(app, port=PORT, threads=8)
        except ImportError:
            logging.warning(
                "waitress is not installed — falling back to Flask's development "
                "server. Run 'pip install waitress' for a production-appropriate server.")
            app.run(debug=False, use_reloader=False, port=PORT, threaded=True)

    def __validate_paths(self, paths: list[str]) -> None:
        for path in paths:
            if not os.path.isdir(path):
                logging.error(f"Invalid directory path: {path}", exc_info=True)
                print(f"ERROR: Invalid directory path: {path}")
                sys.exit(1)

    def __open_browser(self) -> None:
        new_url = f'http://localhost:{PORT}/'

        if (webbrowser.get().name != 'gio'):
            webbrowser.open_new(new_url)

        print(f"Access the app over {new_url}")


def main() -> None:
    parser = argparse.ArgumentParser(prog=APP_NAME, description=DESCRIPTION)

    parser.add_argument("--path", "-p", dest="path", required=False, type=str, default="",
                        help="Path to the Wazuh rule directories. Comma-separated "
                             "multiple paths are accepted. Optional when paths or "
                             "Wazuh managers are already configured in the app.")

    args: argparse.Namespace = parser.parse_args()
    paths: list[str] = [p for p in str(args.path).split(',') if p != '']
    logging.info(f"Paths: {paths}")

    # Rule sources are now per-tenant (configured in-app after login), so there's
    # no single global config to sanity-check here; create_app() handles first-run
    # migration + bootstrap.
    rulevis = Rulevis(paths)
    rulevis.run()


def _get_log_path() -> str:
    """
    Return a per-user log file path appropriate for Windows, Linux, and macOS.
    Uses only os and sys modules.
    """
    # Determine base OS type
    if os.name == "nt":  # Windows
        base_dir = os.getenv(
            "LOCALAPPDATA", os.path.expanduser("~\\AppData\\Local"))
        log_dir = os.path.join(base_dir, APP_NAME, "Logs")

    elif sys.platform == "darwin":  # macOS
        log_dir = os.path.expanduser(f"~/Library/Logs/{APP_NAME}")

    else:  # Linux / other Unix-like
        xdg_state_home = os.getenv(
            "XDG_STATE_HOME", os.path.expanduser("~/.local/state"))
        log_dir = os.path.join(xdg_state_home, APP_NAME)
        if not os.access(os.path.dirname(log_dir), os.W_OK):
            log_dir = os.path.expanduser(f"~/.local/share/{APP_NAME}/logs")

    os.makedirs(log_dir, exist_ok=True)
    return os.path.abspath(os.path.join(log_dir, f"{APP_NAME}.log"))


if __name__ == "__main__":
    try:
        handler = CustomFileHandler(_get_log_path(), encoding=ENCODING)

        logging.basicConfig(handlers=[handler],
                            format='%(asctime)s:%(name)s:%(levelname)s:%(message)s',
                            datefmt="%Y-%m-%dT%H:%M:%S%z",
                            level=logging.INFO)
        # Get the loggers used by Flask and prevent them from propagating to the root logger
        wl = logging.getLogger('werkzeug')
        wl.disabled = True
        excepthook = logging.error
        logging.info('Starting')
        main()
        logging.info('Exiting.')
    except KeyboardInterrupt:
        print('Cancelled by user.')
        logging.info('Cancelled by user.')
        try:
            sys.exit(0)
        except SystemExit:
            os._exit(0)
    except Exception as ex:
        print('ERROR: ' + str(ex))
        logging.error(str(ex), exc_info=True)
        try:
            sys.exit(1)
        except SystemExit:
            os._exit(1)
