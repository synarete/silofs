# SPDX-License-Identifier: GPL-3.0

from .funtests import context


def main() -> None:
    env = context.Env()
    env.show()


if __name__ == "__main__":
    main()
