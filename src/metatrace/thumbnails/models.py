"""Thumbnail data models (v0.7).

Re-exported from :mod:`metatrace.core.models` (the shared model
module, like ``AnomalyFlag``) so ``core.models`` stays free of
package imports and no import cycle is possible.
"""

from metatrace.core.models import ThumbnailInfo, ThumbnailsData

__all__ = ["ThumbnailInfo", "ThumbnailsData"]
