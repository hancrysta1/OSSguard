"""Benign: Legitimate use of subprocess to run git commands."""
import subprocess
import logging

logger = logging.getLogger(__name__)


def get_git_hash() -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True
    )
    return result.stdout.strip()


def get_git_diff(base_branch: str = "main") -> str:
    result = subprocess.Popen(
        ["git", "diff", f"{base_branch}...HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, _ = result.communicate()
    return stdout.decode("utf-8")


def clone_repo(url: str, dest: str) -> None:
    logger.info("Cloning %s to %s", url, dest)
    subprocess.run(["git", "clone", "--depth", "1", url, dest], check=True)
