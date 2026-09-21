"""Download and cache the models required by SENTINEL Part 2."""

from __future__ import annotations

import os
from pathlib import Path

# Repository root
ROOT = Path(__file__).resolve().parent.parent

# Store Hugging Face models inside the project
HF_HOME = ROOT / "models" / ".hf"
HF_HOME.mkdir(parents=True, exist_ok=True)

# IMPORTANT: set before importing Hugging Face
os.environ["HF_HOME"] = str(HF_HOME)

from huggingface_hub import snapshot_download


MODELS = [
    {
        "name": "Prompt injection classifier",
        "repo_id": "protectai/deberta-v3-base-prompt-injection-v2",
        "revision": "90c9989b1a342275dd0d1a95aad283c04e075671",
    },
    {
        "name": "Sentence embedding model",
        "repo_id": "sentence-transformers/all-MiniLM-L6-v2",
        "revision": None,
    },
]


def main() -> None:
    print(f"HF_HOME: {HF_HOME}\n")

    for model in MODELS:
        print(f"Downloading: {model['name']}")
        print(f"Repository : {model['repo_id']}")

        path = snapshot_download(
            repo_id=model["repo_id"],
            revision=model["revision"],
        )

        print(f"Saved at   : {path}")

        # The snapshot folder name is normally the resolved commit hash.
        resolved_revision = Path(path).name

        print(f"Revision   : {resolved_revision}")
        print("-" * 70)

    print("\nAll models downloaded successfully.")
    print("They can now be used with HF_HUB_OFFLINE=1.")


if __name__ == "__main__":
    main()
