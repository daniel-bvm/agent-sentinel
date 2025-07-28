"""Git repository utility functions for the agent sentinel."""

import os
import tempfile
import shutil
import hashlib
import git
import re
import logging
from typing import Union, Dict, List, Any
import json

logger = logging.getLogger(__name__)

def clone_repo(repo_url: str, branch_name: str = None) -> str:
    """Clone a repository and return the path. If repository is already cloned in temp directory, reuse it."""
    # Create a deterministic directory name based on repo URL
    token = os.getenv("GITHUB_ACCESS_TOKEN", "")
    if (
        token
        and token != "your-github-classic-access-token"
    ):
        repo_url = repo_url.replace(
            "https://",
            f"https://{token}:x-oauth-basic@",
        )

    os.environ["GIT_TERMINAL_PROMPT"] = "0"

    repo_hash = hashlib.sha256(repo_url.encode()).hexdigest()[:12]
    temp_dir = os.path.join(tempfile.gettempdir(), f"sentinel_{repo_hash}")

    # If directory exists and is a valid git repo, return it
    if os.path.exists(temp_dir):
        try:
            repo = git.Repo(temp_dir)
            if not repo.bare and repo.remote().url == repo_url:
                origin = repo.remotes.origin
                origin.pull()

                # Checkout the specified branch if provided
                if branch_name:
                    try:
                        # Fetch all branches to ensure we have the latest
                        origin.fetch()

                        # Check if branch exists locally
                        if branch_name in [branch.name for branch in repo.branches]:
                            repo.git.checkout(branch_name)
                        # Check if branch exists remotely
                        elif f"origin/{branch_name}" in [ref.name for ref in repo.remote().refs]:
                            repo.git.checkout('-b', branch_name, f'origin/{branch_name}')
                        else:
                            raise Exception(f"Branch '{branch_name}' does not exist in the repository")
                    except Exception as e:
                        # Clean up on error and re-clone
                        shutil.rmtree(temp_dir, ignore_errors=True)
                        raise Exception(f"Failed to checkout branch '{branch_name}': {str(e)}")

                return temp_dir
        except Exception:
            # If there's any error with existing repo, clean it up
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Create directory and clone repository
    os.makedirs(temp_dir, exist_ok=True)
    try:
        if branch_name:
            # Clone specific branch
            git.Repo.clone_from(repo_url, temp_dir, branch=branch_name)
        else:
            # Clone default branch
            git.Repo.clone_from(repo_url, temp_dir)
        return temp_dir
    except Exception as e:
        # Clean up on error
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception(f"Failed to clone repository: {str(e)}")

def prune_data(d: Union[Dict, List, Any], list_limit: int=10, str_len_limit: int=1024) -> Union[Dict, List, Any]:
    if isinstance(d, list):
        orig_length = len(d)
        x = [
            prune_data(item, list_limit, str_len_limit)
            for item in d[:list_limit]
        ]

        if orig_length > list_limit:
            x.append(f"... and {orig_length - list_limit} more")

        return x

    if isinstance(d, dict):
        return {
            k: prune_data(v, list_limit, str_len_limit)
            for k, v in d.items()
        }

    if isinstance(d, str):
        orig_length = len(d)
        x = d[:str_len_limit]

        if orig_length > str_len_limit:
            x += f"... and {orig_length - str_len_limit} more"

        return x

    return d

def _get_directory_tree(path: str) -> dict | list:
    """Get directory tree as a nested dictionary structure."""
    if not os.path.exists(path):
        return {}

    if not os.path.isdir(path):
        return os.path.basename(path)

    info = {}

    try:
        for entry in sorted(
            e for e in os.listdir(path)
            if not e.startswith('.') and e not in {'__pycache__', 'node_modules', '.venv'}
        ):
            inspect = _get_directory_tree(os.path.join(path, entry))

            if isinstance(inspect, dict): # directory
                if 'directories' not in info:
                    info['directories'] = []

                info['directories'].append(inspect)
            else: # file
                if 'files' not in info:
                    info['files'] = []

                info['files'].append(inspect)

    except PermissionError:
        logger.info(f"Permission denied for {path}")

    except Exception as e:
        logger.info(f"Error getting directory tree for {path}: {e}")

    return info


def get_directory_tree(path: str, max_depth: int = 3, current_depth: int = 0, max_items: int = 10) -> str:
    """Compact directory tree, includes files, no indentation, low context size."""
    return json.dumps(prune_data(_get_directory_tree(path), list_limit=max_items), ensure_ascii=False)

def git_directory_structure(repo_url: str, subfolder: str = "", max_depth: int = None, branch_name: str = None) -> str:
    """
    Clone a Git repository and return its directory structure in a tree format.

    Args:
        repo_url: The URL of the Git repository
        subfolder: Optional path to a specific subfolder within the repository (e.g., "src", "docs/api")
        max_depth: Optional maximum depth to traverse (useful for large repositories)
        branch_name: Optional branch name to checkout before scanning

    Returns:
        A string representation of the repository's directory structure
    """
    try:
        # Clone the repository and checkout branch if specified
        repo_path = clone_repo(repo_url, branch_name)

        # Determine the target path
        if subfolder:
            target_path = os.path.join(repo_path, subfolder)
            if not os.path.exists(target_path):
                return f"Error: Subfolder '{subfolder}' does not exist in the repository"
            if not os.path.isdir(target_path):
                return f"Error: '{subfolder}' is not a directory"
        else:
            target_path = repo_path

        # Generate the directory tree
        tree = get_directory_tree(target_path, max_depth=max_depth)

        # Add header to show which part of the repo we're showing
        header = f"Directory structure for: {repo_url}"
        if branch_name:
            header += f" (branch: {branch_name})"
        if subfolder:
            header += f" (subfolder: {subfolder})"
        if max_depth:
            header += f" (max depth: {max_depth})"

        return f"{header}\n\n\n{tree}"

    except Exception as e:
        return f"Error: {str(e)}"

class RepoInfo:
    DEFAULT_REMOTE_NAME = 'origin'

    def __init__(self, repo_path: str, target_path: str = ""):
        self.repo_path = repo_path
        self.target_path = target_path
        self.repo = git.Repo(repo_path)
        self.branch = re.sub(rf'^(remotes/)?{self.DEFAULT_REMOTE_NAME}/', '', self.repo.active_branch.name)
        self.repo_url = re.sub(r'\.git$', '', self.repo.remote(self.DEFAULT_REMOTE_NAME).url).strip("/")

        # Determine scan context
        if target_path:
            full_target_path = os.path.join(repo_path, target_path)
            self.is_single_file = os.path.isfile(full_target_path)
            self.scan_target = target_path  # Relative path within repo
        else:
            self.is_single_file = False
            self.scan_target = ""

    def __str__(self) -> str:
        context = f", target={self.scan_target}" if self.scan_target else ""
        file_type = " (file)" if self.is_single_file else " (directory)" if self.scan_target else ""
        return f"RepoInfo(repo_url={self.repo_url}, branch={self.branch}{context}{file_type})"

    def get_reference(self, file: str, line_start: str | int | None = None, line_end: str | int | None = None) -> str:
        if line_start is not None and line_end is None:
            return f"{self.repo_url}/blob/{self.branch}/{file}#L{line_start}"

        elif line_start is not None and line_end is not None:
            return f"{self.repo_url}/blob/{self.branch}/{file}#L{line_start}-L{line_end}" if line_start != line_end else f"{self.repo_url}/blob/{self.branch}/{file}#L{line_start}"

        else:
            return f"{self.repo_url}/blob/{self.branch}/{file}"

    def reveal_content(self, file: str, line_start: str | int, line_end: str | int, A: int = 0, B: int = 0) -> str | None:
        if isinstance(line_start, str) and line_start.isdigit():
            line_start = int(line_start)

        if isinstance(line_end, str) and line_end.isdigit():
            line_end = int(line_end)

        if not isinstance(line_start, int) or not isinstance(line_end, int):
            logger.warning(f"Invalid line number: {line_start} or {line_end}")
            return None

        line_start -= A
        line_end += B

        file_path = (
            os.path.join(self.repo_path, self.target_path, file)
            if self.target_path
            else os.path.join(self.repo_path, file)
        )

        if self.is_single_file:
            file_path = os.path.join(self.repo_path, self.scan_target)

        logger.info(f"Revealing content of {file_path} from line {line_start} to {line_end}")

        if not os.path.exists(file_path):
            logger.warning(f"File {file} does not exist in the repository")
            return None

        with open(file_path, 'r') as f:
            lines = f.readlines()

        return ''.join(lines[line_start:line_end])

    def is_file_in_scan_target(self, file_path: str) -> bool:
        """Check if a file is within the scan target scope."""
        if not self.scan_target:
            # No specific target, so all files are in scope
            return True

        if self.is_single_file:
            # Scanning a single file, check if this is that file
            return file_path == self.scan_target or file_path.endswith(self.scan_target)
        else:
            # Scanning a directory, check if file is within that directory
            return file_path.startswith(self.scan_target)

    def get_scan_context(self) -> str:
        """Get a human-readable description of what is being scanned."""
        if not self.scan_target:
            return "entire repository"
        elif self.is_single_file:
            return f"file '{self.scan_target}'"
        else:
            return f"directory '{self.scan_target}'"

    def get_relative_path(self, file_path: str) -> str:
        """Get the file path relative to the scan target."""
        if not self.scan_target:
            return file_path

        if self.is_single_file:
            # For single file, return just the filename
            return os.path.basename(file_path)
        else:
            # For directory, return path relative to target directory
            if file_path.startswith(self.scan_target):
                relative = file_path[len(self.scan_target):].lstrip('/')
                return relative if relative else os.path.basename(self.scan_target)
            return file_path