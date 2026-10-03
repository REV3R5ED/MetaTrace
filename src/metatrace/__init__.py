"""MetaTrace — image forensics and metadata analysis.

Trace the story behind the image.

v0.7: core framework (config, models, hashing, logging, results,
plugin registry) + file identification + full EXIF/GPS extraction
and normalization + XMP/IPTC/ICC extraction + timestamp/device
normalization + cross-source comparison + timelines + batch
analysis (parallel scans, duplicate detection, grouping) + anomaly
engine (rule-based consistency checks) + embedded thumbnail
extraction and metadata-level thumbnail comparison (no pixel
decoding). Later phases (cases, reporting) plug into the models
defined here.
"""

__version__ = "0.7.0"
__author__ = "Pouya Shini Karim"
__license__ = "MIT"

from metatrace import batch, geo, normalize, thumbnails
from metatrace.core import config, hashing, logging, models, plugins, results

__all__ = [
    "__version__",
    "batch",
    "config",
    "geo",
    "hashing",
    "logging",
    "models",
    "normalize",
    "plugins",
    "results",
    "thumbnails",
]
