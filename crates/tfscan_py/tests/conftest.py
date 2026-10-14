import os
import pathlib
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = pathlib.Path(os.environ.get("OXTF_REPO", HERE.parents[2]))
FIXTURES = REPO / "fixtures" / "rules"
SSH_FIXTURES = FIXTURES / "aws-sg-open-ssh"
CORPUS = REPO / "corpus" / "repos"
SCRIPTS = HERE.parent / "scripts"
RULES = HERE.parent / "rules"


@pytest.fixture(scope="session")
def generated(tmp_path_factory):
    """A seeded generated corpus (scripts/gen_differential.py)."""

    def make(n, seed):
        out = tmp_path_factory.mktemp(f"gen{n}_{seed}")
        subprocess.run(
            [sys.executable, str(SCRIPTS / "gen_differential.py"), str(out), str(n), str(seed)],
            check=True,
        )
        return out

    return make
