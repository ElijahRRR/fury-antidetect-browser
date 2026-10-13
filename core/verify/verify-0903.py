#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright 2026 Bogdan Shapovalov and the Fury authors
"""On macOS a profile's browser quits when its last window closes.

macOS Chrome keeps running with no windows until Cmd+Q. For a profile the
agent started that is a process with nothing on screen which the agent still
counts as open, and a team profile whose session is not pushed. 0903 drops
the AppController's keep-alive once a browser window exists, so the last
window's close takes the ordinary shutdown path, as on Windows.

The 0.3.5 core did that only for a window that already existed when AppKit
finished launching. A profile with a session to restore -- every profile after
its first launch, since the agent passes --restore-last-session -- gets its
windows later, so the keep-alive stayed and the process outlived its window
(tester, 13.10.2026: closed with the red button, the profile hung on as open).
Measured on that core: a fresh profile quit within a second, the same profile
relaunched with its session did not quit at all.

Claims:

  * a fresh profile quits when its window closes;
  * a profile relaunched the way the agent relaunches it, restoring the
    session it left, quits when its window closes -- the case 0.3.5 missed;
  * with two windows open, closing one leaves the browser running, and
    closing the second quits it;
  * the CONTROL: a launch that never opens a window (--no-startup-window)
    stays up, as Chrome does. That shows the keep-alive is released for a
    window and not dropped outright, and that "still running" is something
    this script can see.

Windows are closed by closing their tabs over CDP: a window whose last tab
closes is destroyed the same way as one closed with its button, and that is
the path the bug was measured on.

Usage: core/verify/verify-0903.py <core binary>
"""

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from harness import PAGE, Claims, launch  # noqa: E402

CORE = sys.argv[1]
KEY = bytes(range(32))

# How long a browser with no windows gets to exit. The 0.3.5 core quit a fresh
# profile in under a second; a restored one never.
GRACE = 10


def pages(s):
    targets = s.ws.call("Target.getTargets")["targetInfos"]
    return [t["targetId"] for t in targets if t["type"] == "page"]


def close_targets(s, ids):
    for t in ids:
        try:
            s.ws.call("Target.closeTarget", {"targetId": t})
        except Exception:
            # The connection goes when the browser does, which is the point.
            break


def exits(proc, seconds=GRACE):
    try:
        proc.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


def main():
    if sys.platform != "darwin":
        # Windows quits with its last window without any patch, and keeps no
        # process up for --no-startup-window either, so the control would fail
        # for a reason that is not 0903's.
        print("verify 0903 — macOS only, nothing to check here")
        return 0
    claims = Claims("0903 — the last window's close quits on macOS", CORE)

    with launch(CORE, None, page=PAGE, os_crypt_key=KEY) as s:
        close_targets(s, pages(s))
        quit_fresh = exits(s.proc)
    claims.check(quit_fresh, "a fresh profile quits when its last window closes")

    udd = tempfile.mkdtemp(prefix="fury-verify-0903-")
    try:
        # Leave a session behind: a window with a page, closed by SIGHUP the
        # way the agent closes a profile, so the session is written.
        with launch(CORE, None, page=PAGE, os_crypt_key=KEY, user_data_dir=udd):
            time.sleep(2)
        with launch(CORE, None, page=PAGE, os_crypt_key=KEY, user_data_dir=udd,
                    extra_args=("--restore-last-session",)) as s:
            restored = len(pages(s))
            close_targets(s, pages(s))
            quit_restored = exits(s.proc)
        print(f"  pages after restoring: {restored}")
        claims.check(
            quit_restored,
            "a profile relaunched with --restore-last-session quits when its "
            "last window closes (0.3.5 stayed up)",
        )
    finally:
        shutil.rmtree(udd, ignore_errors=True)

    with launch(CORE, None, page=PAGE, os_crypt_key=KEY) as s:
        first = pages(s)
        s.ws.call("Target.createTarget", {"url": PAGE, "newWindow": True})
        time.sleep(2)
        second = [t for t in pages(s) if t not in first]
        close_targets(s, first)
        alive_with_one = not exits(s.proc, 4)
        close_targets(s, second)
        quit_after_both = exits(s.proc)
    claims.check(alive_with_one, "closing one of two windows leaves the browser running")
    claims.check(quit_after_both, "closing the second window quits it")

    # The control, without the harness: it opens a tab over CDP, which is a
    # window, and the point here is a launch with none.
    udd = tempfile.mkdtemp(prefix="fury-verify-0903-")
    try:
        proc = subprocess.Popen(
            [CORE, f"--user-data-dir={udd}", "--no-first-run",
             "--no-default-browser-check", "--use-mock-keychain",
             "--no-startup-window"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        stayed = not exits(proc, GRACE)
        if proc.poll() is None:
            proc.send_signal(signal.SIGHUP)
            if not exits(proc, 12):
                proc.kill()
    finally:
        shutil.rmtree(udd, ignore_errors=True)
    claims.control(
        stayed,
        "a launch that never opens a window stays up, as Chrome does: the "
        "keep-alive goes with the first window, not unconditionally",
    )

    return claims.done()


if __name__ == "__main__":
    sys.exit(main())
