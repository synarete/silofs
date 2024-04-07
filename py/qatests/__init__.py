# SPDX-License-Identifier: GPL-3.0
from .start import ProgInfo, run_silofs_qatests


def main(prog_info: ProgInfo = ProgInfo()) -> None:
    run_silofs_qatests(prog_info)


if __name__ == "__main__":
    main()
