# SPDX-License-Identifier: GPL-3.0
from .start import start_qatests


def _setproctitle() -> None:
    try:
        # pylint: disable=C0415
        from setproctitle import setproctitle  # type: ignore

        setproctitle("silofs-qatests")
    except ImportError:
        pass


def _exectests() -> None:
    start_qatests()


def qatests_main() -> None:
    _setproctitle()
    _exectests()


if __name__ == "__main__":
    qatests_main()
