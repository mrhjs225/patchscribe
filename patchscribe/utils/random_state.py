"""
Utility helpers for deterministic experiments.

The PatchScribe paper mandates running every experiment with fixed random
seeds (42, 123, 7220) and temperature=0 settings so that formal analysis can
be replicated.  This module centralizes the seeding logic across Python's
standard ``random`` module, NumPy, and optional frameworks like PyTorch.
"""
from __future__ import annotations

import os
import random
from typing import Dict


def seed_everything(seed: int | None) -> Dict[str, bool]:
    """
    Seed every supported RNG to make experiments reproducible.

    Args:
        seed: Integer seed value. If ``None`` the function is a no-op.

    Returns:
        Dictionary describing which backends were successfully seeded.
    """
    status = {
        "python_random": False,
        "numpy": False,
        "torch": False,
    }

    if seed is None:
        return status

    os.environ["PYTHONHASHSEED"] = str(seed)

    random.seed(seed)
    status["python_random"] = True

    try:
        import numpy as np  # type: ignore

        np.random.seed(seed)
        status["numpy"] = True
    except Exception:
        # NumPy is optional; silently continue when unavailable.
        pass

    try:
        import torch  # type: ignore

        torch.manual_seed(seed)
        torch.cuda.manual_seed_all(seed)
        if hasattr(torch, "use_deterministic_algorithms"):
            torch.use_deterministic_algorithms(True)
        if hasattr(torch.backends, "cudnn"):
            torch.backends.cudnn.deterministic = True
            torch.backends.cudnn.benchmark = False
        status["torch"] = True
    except Exception:
        # PyTorch is optional in this repository.
        pass

    return status
