import os
import warnings

os.environ["TOKENIZERS_PARALLELISM"] = "false"
warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)

import sys
from .core.agent import Agent


def main():
    text_mode = "--text" in sys.argv
    Agent().run(text_mode=text_mode)


if __name__ == "__main__":
    main()
