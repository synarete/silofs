# SPDX-License-Identifier: GPL-3.0
from .execute import ProgInfo, run_silofs_archive


def main(prog_info: ProgInfo = ProgInfo()) -> None:
    run_silofs_archive(prog_info)


if __name__ == "__main__":
    main()
