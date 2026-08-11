from pathlib import Path
import sys


def main() -> None:
    target = Path(
        "/home/nathan/go/src/github.com/bomfather/bomfather-private/agent/example/protected/protected1/protected.txt"
    )

    print("argv:", sys.argv)
    print(target.read_text().strip())


if __name__ == "__main__":
    main()
