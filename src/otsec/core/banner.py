def banner_text(version: str = "0.1") -> str:
    # ANSI styles
    BLUE = "\033[94m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"

    # Single-line bold text
    line = f"{BLD}O   T   S   e   c{RST}"

    # Width and border
    width = len(line) + 8
    border = f"{BLD}{BLUE}{'-' * width}{RST}"
    centered_line = f"{BLD}{BLUE}{line.center(width)}{RST}"

    # Final banner
    art = f"{border}\n{centered_line}\n{border}"

    # Subtitle and author
    subtitle = f"{BLD}OTSec{RST} v{version}  {DIM}|{RST}  Offensive OT/IoT Security Toolkit"
    author = (
        f"Made by {BLD}Omar Tamer{RST}  {DIM}|{RST} https://omar-tamerr.github.io/\n"
        f"YouTube: https://www.youtube.com/@OTSec"
    )

    return f"\n{art}\n\n{subtitle}\n{author}\n"

# Default exported symbol
BANNER = banner_text("0.1")

