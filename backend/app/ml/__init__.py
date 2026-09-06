"""Machine-learning layer: feature extraction, classifier and service."""
from .classifier import ScamClassifier  # noqa: F401
from .features import FEATURE_NAMES, extract_features  # noqa: F401
from .service import get_classifier, predict_scam  # noqa: F401