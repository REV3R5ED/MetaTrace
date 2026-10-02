"""MetaTrace — image forensics and metadata analysis.

Trace the story behind the image.

v0.1: core framework (config, models, hashing, logging, results,
plugin registry) + file identification + basic EXIF extraction.
Later phases (GPS normalization, XMP/IPTC/ICC, batch, anomaly
engine, thumbnails, cases, reporting) plug into the models defined
here.
"""

__version__ = "0.1.0"
__author__ = "Pouya Shini Karim"
__license__ = "MIT"

from metatrace.core import config, hashing, logging, models, plugins, results

__all__ = [
    "__version__",
    "config",
    "hashing",
    "logging",
    "models",
    "plugins",
    "results",
]
