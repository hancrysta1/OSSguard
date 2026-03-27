import { WS_BASE_URL } from "../config/env";
import { WSMessage } from "../types/ws";

export function createWebSocket(
  taskId: string,
  onMessage: (msg: WSMessage) => void,
  onClose?: () => void
): WebSocket {
  const ws = new WebSocket(`${WS_BASE_URL}/ws/analysis/${taskId}`);

  ws.onmessage = (event) => {
    try {
      const data: WSMessage = JSON.parse(event.data);
      onMessage(data);
    } catch (e) {
      console.error("WS parse error:", e);
    }
  };

  ws.onclose = () => onClose?.();
  ws.onerror = (err) => console.error("WS error:", err);

  return ws;
}
