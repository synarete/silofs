# SPDX-License-Identifier: GPL-3.0
import datetime


def println(msg: str) -> None:
    """Prints message as info log-line"""
    now = datetime.datetime.now()
    ts = now.strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] {msg}")


def printsl(msg: str) -> None:
    """Prints message as info sub-line"""
    println("  " + msg)
