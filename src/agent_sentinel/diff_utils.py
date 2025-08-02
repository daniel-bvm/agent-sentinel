"""Git working tree analysis utility functions for scanning current development changes."""

import os
import git
import logging
from typing import Any

logger = logging.getLogger(__name__)

def scan_git_diff(
    local_repo_path: str,
    target_path: str = None,
    mode: str = "working"
) -> dict[str, Any]:
    """
    Scan git working tree for current development changes in a locally mounted repository.

    Args:
        local_repo_path: Local path to the git repository (mounted in container)
        target_path: Path to analyze (file or directory within the repository, None for entire repo)
        mode: Analysis mode for working tree scanning:
            - "working": Show all working tree changes vs HEAD (committed + staged + unstaged)
            - "staged": Show staged changes ready for commit (git diff --cached)
            - "unstaged": Show unstaged changes in working directory (git diff)
            - "status": Show git status information (modified, added, deleted files)

    Returns:
        Dictionary containing working tree analysis results
    """
    try:
        # Validate that the local path exists and is a git repository
        if not os.path.exists(local_repo_path):
            return {"error": f"Local repository path '{local_repo_path}' does not exist"}

        if not os.path.isdir(local_repo_path):
            return {"error": f"Local repository path '{local_repo_path}' is not a directory"}

        try:
            repo = git.Repo(local_repo_path)
        except git.exc.InvalidGitRepositoryError:
            return {"error": f"Path '{local_repo_path}' is not a valid git repository"}

        if mode == "working":
            return _scan_working_tree_changes(repo, local_repo_path, target_path)
        elif mode == "staged":
            return _scan_staged_changes(repo, local_repo_path, target_path)
        elif mode == "unstaged":
            return _scan_unstaged_changes(repo, local_repo_path, target_path)
        elif mode == "status":
            return _get_working_tree_status(repo, local_repo_path, target_path)
        else:
            return {"error": f"Invalid mode '{mode}'. Supported modes: working, staged, unstaged, status"}

    except Exception as e:
        logger.error(f"Error in scan_git_diff: {e}")
        return {"error": str(e)}

def _scan_working_tree_changes(repo: git.Repo, local_repo_path: str, target_path: str) -> dict[str, Any]:
    """Scan all working tree changes vs HEAD - only analyze files that have actually changed."""
    try:
        # Validate target path if specified
        if target_path:
            full_target_path = os.path.join(local_repo_path, target_path)
            if not os.path.exists(full_target_path):
                return {"error": f"Target path '{target_path}' does not exist in repository"}

        # First, get list of changed files to avoid scanning unchanged files
        if target_path:
            changed_files = repo.git.diff("HEAD", target_path, name_only=True).split('\n')
        else:
            changed_files = repo.git.diff("HEAD", name_only=True).split('\n')
        changed_files = [f for f in changed_files if f.strip()]

        if not changed_files:
            return {
                "mode": "working",
                "local_repo_path": local_repo_path,
                "target_path": target_path,
                "branch": repo.active_branch.name,
                "changed_files": [],
                "files_changed": 0,
                "diff": "",
                "stats": "No changes detected",
                "description": "No working tree changes found"
            }

        # Only get diff for changed files to be efficient
        if target_path:
            diff_output = repo.git.diff("HEAD", target_path, unified=3)
            stats_output = repo.git.diff("HEAD", target_path, stat=True)
        else:
            diff_output = repo.git.diff("HEAD", unified=3)
            stats_output = repo.git.diff("HEAD", stat=True)

        return {
            "mode": "working",
            "local_repo_path": local_repo_path,
            "target_path": target_path,
            "branch": repo.active_branch.name,
            "diff": diff_output,
            "stats": stats_output,
            "changed_files": changed_files,
            "files_changed": len(changed_files),
            "description": f"Working tree changes in {len(changed_files)} files vs HEAD"
        }

    except Exception as e:
        path_info = f"{local_repo_path}" + (f"/{target_path}" if target_path else "")
        logger.error(f"Error scanning working tree changes for {path_info}: {e}")
        return {"error": f"Error scanning working tree changes: {str(e)}"}

def _scan_staged_changes(repo: git.Repo, local_repo_path: str, target_path: str) -> dict[str, Any]:
    """Scan staged changes ready for commit - only analyze files that are actually staged."""
    try:
        # Validate target path if specified
        if target_path:
            full_target_path = os.path.join(local_repo_path, target_path)
            if not os.path.exists(full_target_path):
                return {"error": f"Target path '{target_path}' does not exist in repository"}

        # First, get list of staged files to avoid scanning if nothing is staged
        if target_path:
            changed_files = repo.git.diff("--cached", target_path, name_only=True).split('\n')
        else:
            changed_files = repo.git.diff("--cached", name_only=True).split('\n')
        changed_files = [f for f in changed_files if f.strip()]

        if not changed_files:
            return {
                "mode": "staged",
                "local_repo_path": local_repo_path,
                "target_path": target_path,
                "branch": repo.active_branch.name,
                "changed_files": [],
                "files_changed": 0,
                "diff": "",
                "stats": "No staged changes",
                "description": "No staged changes found"
            }

        # Only get diff for staged files
        if target_path:
            diff_output = repo.git.diff("--cached", target_path, unified=3)
            stats_output = repo.git.diff("--cached", target_path, stat=True)
        else:
            diff_output = repo.git.diff("--cached", unified=3)
            stats_output = repo.git.diff("--cached", stat=True)

        return {
            "mode": "staged",
            "local_repo_path": local_repo_path,
            "target_path": target_path,
            "branch": repo.active_branch.name,
            "diff": diff_output,
            "stats": stats_output,
            "changed_files": changed_files,
            "files_changed": len(changed_files),
            "description": f"Staged changes in {len(changed_files)} files ready for commit"
        }

    except Exception as e:
        path_info = f"{local_repo_path}" + (f"/{target_path}" if target_path else "")
        logger.error(f"Error scanning staged changes for {path_info}: {e}")
        return {"error": f"Error scanning staged changes: {str(e)}"}

def _scan_unstaged_changes(repo: git.Repo, local_repo_path: str, target_path: str) -> dict[str, Any]:
    """Scan unstaged changes in working directory - only analyze files that have unstaged changes."""
    try:
        # Validate target path if specified
        if target_path:
            full_target_path = os.path.join(local_repo_path, target_path)
            if not os.path.exists(full_target_path):
                return {"error": f"Target path '{target_path}' does not exist in repository"}

        # First, get list of unstaged files to avoid scanning if nothing is unstaged
        if target_path:
            changed_files = repo.git.diff(target_path, name_only=True).split('\n')
        else:
            changed_files = repo.git.diff(name_only=True).split('\n')
        changed_files = [f for f in changed_files if f.strip()]

        if not changed_files:
            return {
                "mode": "unstaged",
                "local_repo_path": local_repo_path,
                "target_path": target_path,
                "branch": repo.active_branch.name,
                "changed_files": [],
                "files_changed": 0,
                "diff": "",
                "stats": "No unstaged changes",
                "description": "No unstaged changes found"
            }

        # Only get diff for unstaged files
        if target_path:
            diff_output = repo.git.diff(target_path, unified=3)
            stats_output = repo.git.diff(target_path, stat=True)
        else:
            diff_output = repo.git.diff(unified=3)
            stats_output = repo.git.diff(stat=True)

        return {
            "mode": "unstaged",
            "local_repo_path": local_repo_path,
            "target_path": target_path,
            "branch": repo.active_branch.name,
            "diff": diff_output,
            "stats": stats_output,
            "changed_files": changed_files,
            "files_changed": len(changed_files),
            "description": f"Unstaged changes in {len(changed_files)} files in working directory"
        }

    except Exception as e:
        path_info = f"{local_repo_path}" + (f"/{target_path}" if target_path else "")
        logger.error(f"Error scanning unstaged changes for {path_info}: {e}")
        return {"error": f"Error scanning unstaged changes: {str(e)}"}

def _get_working_tree_status(repo: git.Repo, local_repo_path: str, target_path: str) -> dict[str, Any]:
    """Get git status information for working tree - only report files that have changes."""
    try:
        # Get git status information - only for files with changes
        if target_path:
            status = repo.git.status("--porcelain", target_path).split('\n')
        else:
            status = repo.git.status("--porcelain").split('\n')
        status = [line for line in status if line.strip()]

        if not status:
            return {
                "mode": "status",
                "local_repo_path": local_repo_path,
                "target_path": target_path,
                "branch": repo.active_branch.name,
                "modified": [],
                "added": [],
                "deleted": [],
                "renamed": [],
                "untracked": [],
                "total_changes": 0,
                "has_changes": False,
                "description": "No changes detected in working tree"
            }

        # Parse status into categories
        modified = []
        added = []
        deleted = []
        renamed = []
        untracked = []

        for line in status:
            if len(line) >= 2:
                index_status = line[0]
                worktree_status = line[1]
                filename = line[3:].strip()

                if index_status == 'A' or worktree_status == 'A':
                    added.append(filename)
                elif index_status == 'M' or worktree_status == 'M':
                    modified.append(filename)
                elif index_status == 'D' or worktree_status == 'D':
                    deleted.append(filename)
                elif index_status == 'R':
                    renamed.append(filename)
                elif index_status == '?' and worktree_status == '?':
                    untracked.append(filename)

        # Get branch info
        try:
            current_branch = repo.active_branch.name
        except:
            current_branch = "HEAD (detached)"

        total_changes = len(modified) + len(added) + len(deleted) + len(renamed)

        return {
            "mode": "status",
            "local_repo_path": local_repo_path,
            "target_path": target_path,
            "branch": current_branch,
            "modified": modified,
            "added": added,
            "deleted": deleted,
            "renamed": renamed,
            "untracked": untracked,
            "total_changes": total_changes,
            "has_changes": total_changes > 0 or len(untracked) > 0,
            "description": f"Working tree status: {total_changes} changes, {len(untracked)} untracked files"
        }

    except Exception as e:
        path_info = f"{local_repo_path}" + (f"/{target_path}" if target_path else "")
        logger.error(f"Error getting working tree status for {path_info}: {e}")
        return {"error": f"Error getting working tree status: {str(e)}"}