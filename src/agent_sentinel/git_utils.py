"""Git repository utility functions for the agent sentinel."""

import os
import tempfile
import shutil
import hashlib
import git
import re

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


def get_directory_tree(path: str, max_depth: int = 3, current_depth: int = 0, max_items: int = 50) -> str:
    """Compact directory tree, includes files, no indentation, low context size."""
    if max_depth is not None and current_depth >= max_depth:
        return ""

    output = ""
    try:
        entries = sorted(
            e for e in os.listdir(path)
            if not e.startswith('.') and e not in {'__pycache__', 'node_modules', '.venv'}
        )
    except Exception:
        return ""

    count = 0
    for entry in entries:
        if count >= max_items:
            output += f"{'/'.join(['...'] * (current_depth + 1))} ({len(entries) - max_items} more)\n"
            break

        entry_path = os.path.join(path, entry)
        line = '/'.join([''] * current_depth + [entry])  # depth-based prefix
        output += f"{line}\n"
        if os.path.isdir(entry_path):
            output += get_directory_tree(entry_path, max_depth, current_depth + 1, max_items)
        count += 1

    return output


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

    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        self.repo = git.Repo(repo_path)
        self.branch = re.sub(rf'^(remotes/)?{self.DEFAULT_REMOTE_NAME}/', '', self.repo.active_branch.name)
        self.repo_url = re.sub(r'\.git$', '', self.repo.remote(self.DEFAULT_REMOTE_NAME).url).strip("/")
    

    def __str__(self) -> str:
        return f"RepoInfo(repo_url={self.repo_url}, branch={self.branch})"

    def get_reference(self, file: str, line_start: str, line_end: str) -> str:
        return f"{self.repo_url}/blob/{self.branch}/{file}#L{line_start}-L{line_end}"