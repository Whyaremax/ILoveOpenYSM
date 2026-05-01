from _extractor_bootstrap import ensure_local_extractors

ensure_local_extractors(__file__)

from extractors.bom_v3_payload_assets import *  # noqa: F401,F403
from extractors.bom_v3_payload_assets import (
    _canonical_animation_stub_name,
    _canonical_model_stub_name,
    _parse_animation_headers,
    _read_property_format,
    _read_property_name,
    _sanitize_name,
)


if __name__ == "__main__":
    main()
