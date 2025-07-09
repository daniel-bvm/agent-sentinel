"""Git repository utility functions for the agent sentinel."""

import os
import tempfile
import shutil
import hashlib
import git
from .github_utils import get_github_headers

PER_PAGE = 100


def clone_repo(repo_url: str) -> str:
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
    temp_dir = os.path.join(tempfile.gettempdir(), f"github_tools_{repo_hash}")

    # If directory exists and is a valid git repo, return it
    if os.path.exists(temp_dir):
        try:
            repo = git.Repo(temp_dir)
            if not repo.bare and repo.remote().url == repo_url:
                origin = repo.remotes.origin
                origin.pull()
                return temp_dir
        except Exception:
            # If there's any error with existing repo, clean it up
            shutil.rmtree(temp_dir, ignore_errors=True)

    # Create directory and clone repository
    os.makedirs(temp_dir, exist_ok=True)
    try:
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


def git_directory_structure(repo_url: str, subfolder: str = "", max_depth: int = None) -> str:
    """
    Clone a Git repository and return its directory structure in a tree format.

    Args:
        repo_url: The URL of the Git repository
        subfolder: Optional path to a specific subfolder within the repository (e.g., "src", "docs/api")
        max_depth: Optional maximum depth to traverse (useful for large repositories)

    Returns:
        A string representation of the repository's directory structure
    """
    try:
        # Clone the repository
        repo_path = clone_repo(repo_url)

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
        if subfolder:
            header += f" (subfolder: {subfolder})"
        if max_depth:
            header += f" (max depth: {max_depth})"

        return f"{header}\n\n\n{tree}"

    except Exception as e:
        return f"Error: {str(e)}"


def checkout_branch(repo_path: str, branch_name: str) -> str:
    """
    Checkout a specific branch in a Git repository.

    Args:
        repo_path: The path to the local Git repository
        branch_name: The name of the branch to checkout
    Returns:
        A message indicating success or failure
    """
    try:
        repo = git.Repo(repo_path)
        if branch_name not in repo.branches:
            return f"Error: Branch '{branch_name}' does not exist in the repository."

        repo.git.checkout(branch_name)
        return f"Successfully checked out branch '{branch_name}'."
    except git.exc.GitCommandError as e:
        return f"Error checking out branch: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


def git_read_important_files(repo_url: str, file_paths: list[str]) -> dict[str, str]:
    """
    Read the contents of specified files in a given Git repository.
    """
    try:
        # Clone the repository
        repo_path = clone_repo(repo_url)
        results = {}

        for file_path in file_paths:
            full_path = os.path.join(repo_path, file_path)

            # Check if file exists
            if not os.path.isfile(full_path):
                results[file_path] = "Error: File not found"
                continue

            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    results[file_path] = f.read()
            except Exception as e:
                results[file_path] = f"Error reading file: {str(e)}"

        return results
    except Exception as e:
        return {"error": f"Failed to process repository: {str(e)}"}


def git_list_directories(repo_url: str, subfolder: str = "", max_depth: int = 1) -> str:
    """
    List directories in a Git repository at a specified depth for quick exploration.

    Args:
        repo_url: The URL of the Git repository
        subfolder: Optional path to a specific subfolder within the repository
        max_depth: Maximum depth to show (default: 1 for top-level only)

    Returns:
        A list of directories at the specified depth
    """
    try:
        # Clone the repository
        repo_path = clone_repo(repo_url)

        # Determine the target path
        if subfolder:
            target_path = os.path.join(repo_path, subfolder)
            if not os.path.exists(target_path):
                return f"Error: Subfolder '{subfolder}' does not exist in the repository"
            if not os.path.isdir(target_path):
                return f"Error: '{subfolder}' is not a directory"
        else:
            target_path = repo_path

        # Get only directories
        directories = []
        try:
            for entry in sorted(os.listdir(target_path)):
                if (not entry.startswith('.') and
                        entry not in {'__pycache__', 'node_modules', '.venv'} and
                        os.path.isdir(os.path.join(target_path, entry))):
                    directories.append(entry)
        except PermissionError:
            return "Error: Permission denied accessing directory"

        # Format output
        base_path = subfolder if subfolder else "repository root"
        result = f"Directories in {base_path} ({repo_url}):\n"
        result += "=" * (len(result) - 1) + "\n"

        if directories:
            for directory in directories:
                result += f"📁 {directory}/\n"
        else:
            result += "No directories found\n"

        return result

    except Exception as e:
        return f"Error: {str(e)}"