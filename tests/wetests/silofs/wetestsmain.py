# SPDX-License-Identifier: GPL-3.0

from .wetests import run


def main() -> None:
    run.run_tests()


if __name__ == "__main__":
    main()
