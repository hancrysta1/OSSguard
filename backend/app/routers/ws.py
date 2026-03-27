"""WebSocket endpoints for real-time analysis progress via async Redis pub/sub.

Inspired by: 배달의민족 Redis Pub/Sub pattern, 토스 실시간 처리 패턴.
Uses redis.asyncio to avoid blocking the FastAPI event loop.
"""

import asyncio
import json
import redis.asyncio as aioredis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.config import settings
from app.utils.logging import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["websocket"])


def _get_async_redis() -> aioredis.Redis:
    return aioredis.Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        db=settings.REDIS_DB,
        decode_responses=True,
    )


@router.websocket("/ws/analysis/{task_id}")
async def websocket_analysis(websocket: WebSocket, task_id: str):
    """Stream analysis progress to the client via WebSocket.

    Uses async Redis pub/sub so the event loop is never blocked.
    Includes heartbeat to detect stale connections and fallback polling.
    """
    await websocket.accept()
    log.info("ws_connected", task_id=task_id)

    r = _get_async_redis()
    pubsub = r.pubsub()
    channel = f"analysis_progress:{task_id}"
    await pubsub.subscribe(channel)

    try:
        idle_seconds = 0
        max_idle_seconds = 600  # 10 min timeout
        heartbeat_interval = 15  # Send ping every 15s to keep connection alive

        while idle_seconds < max_idle_seconds:
            # Non-blocking: wait for message with 1s timeout
            message = await pubsub.get_message(
                ignore_subscribe_messages=True, timeout=1.0
            )

            if message and message["type"] == "message":
                data = json.loads(message["data"])
                await websocket.send_json(data)
                idle_seconds = 0

                if data.get("stage") in ("done", "error"):
                    break
            else:
                idle_seconds += 1

            # Heartbeat: keep WebSocket alive through proxies/load balancers
            # Uses a ping frame instead of a JSON message to avoid polluting the client log
            if idle_seconds > 0 and idle_seconds % heartbeat_interval == 0:
                try:
                    await websocket.send_text("")
                except Exception:
                    break

            # Fallback: check task status if no pub/sub messages for 5+ seconds
            if idle_seconds >= 5 and idle_seconds % 5 == 0:
                task_status = await r.get(f"task_status:{task_id}")
                if task_status in ("completed", "failed"):
                    final = {
                        "stage": "done",
                        "status": task_status,
                        "progress": 100,
                        "message": "Analysis complete",
                    }
                    await websocket.send_json(final)
                    break

    except WebSocketDisconnect:
        log.info("ws_disconnected", task_id=task_id)
    except Exception as e:
        log.error("ws_error", task_id=task_id, error=str(e))
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.close()
        await r.close()