from pydantic import BaseModel


class GitHubRepo(BaseModel):
    github_url: str
