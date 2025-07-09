"""GitHub API utility functions for the agent sentinel."""

import os
import requests


def get_github_headers():
    """Get GitHub API headers with authentication token."""
    token = os.getenv("GITHUB_ACCESS_TOKEN", "")
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
    }


def validate_and_set_github_token(token: str | None = None) -> str:
    """
    Validates a GitHub personal access token and sets it as an environment variable.
    """
    # Prevent the case that the model give a null token
    token = token or ""
    if not token:
        return "Token has been set to the environment variable GITHUB_ACCESS_TOKEN."

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json"
    }

    response = requests.get("https://api.github.com/user", headers=headers)

    if response.status_code == 200:
        os.environ["GITHUB_ACCESS_TOKEN"] = token
        return "Token has been set to the environment variable GITHUB_ACCESS_TOKEN."
    else:
        return (
            f"Invalid token. Please check and try again.\nGitHub API response: {response.status_code} - {response.text}"
          )


def provide_guide_for_github_access_token() -> str:
    """
    Provide a guide for obtaining a GitHub personal access token.
    """
    return (
        "To create a GitHub personal access token, follow these steps:\n"
        "1. Go to your GitHub account settings.\n"
        "2. Navigate to 'Developer settings'.\n"
        "3. Click on 'Personal access tokens'.\n"
        "4. Choose `Tokens (classic)`.\n"
        "5. Click on 'Generate new token'.\n"
        "6. Click on 'Generate new token (classic)'\n"
        "7. Select the scopes or permissions you'd like to grant this token. "
        "(at least all permissions under the 'repos' category must be granted).\n"
        "8. Click 'Generate token'.\n"
        "9. Copy the generated token and store it securely.\n"
        "10. Use this token in your API requests as a Bearer token."
    )