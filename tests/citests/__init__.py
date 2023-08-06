# SPDX-License-Identifier: GPL-3.0
from .start import start_citests


def _setproctitle() -> None:
    try:
        # pylint: disable=C0415
        from setproctitle import setproctitle  # type: ignore

        setproctitle("silofs-citests")
    except ImportError:
        pass


def _exectests() -> None:
    start_citests()


def citests_main() -> None:
    _setproctitle()
    _exectests()


if __name__ == "__main__":
    citests_main()
