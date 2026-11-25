"""Linux/POSIX native fixture for the HMT host contract."""
from contextlib import contextmanager

@contextmanager
def setup(tmp, root, config):
    (tmp / "workspace").mkdir()
    (tmp / "workspace/report.txt").write_text("approved")
    path = tmp / "hmt.toml"
    path.write_bytes((root / "examples/hmt_policy.toml").read_bytes())
    path.chmod(0o600)
    yield config.replace(".local/hmt_policy.toml",path.as_posix())


def check(effect):
    assert effect["disposition"] == "PASS" and effect["payload"]["files"] == ["report.txt"]
