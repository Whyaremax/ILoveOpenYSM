from _extractor_bootstrap import ensure_local_extractors

ensure_local_extractors(__file__)

from extractors.ysgp_container_scanner import *  # noqa: F401,F403


if __name__ == "__main__":
    main()
