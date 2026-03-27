from pydantic import BaseModel
from typing import Optional


class WSMessage(BaseModel):
    stage: str
    status: str  # "running", "completed", "failed"
    progress: int  # 0-100
    message: str
    data: Optional[dict] = None
