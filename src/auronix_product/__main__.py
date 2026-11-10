import sys
from .core.agent import Agent


def main():
    text_mode = "--text" in sys.argv
    Agent().run(text_mode=text_mode)


if __name__ == "__main__":
    main()
