import { useState, useEffect, useCallback, useRef } from "react";
import { WS_BASE_URL } from "../config/env";
import { WSMessage } from "../types/ws";

export function useWebSocket(taskId: string | null) {
  const [messages, setMessages] = useState<WSMessage[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const [latestMessage, setLatestMessage] = useState<WSMessage | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const connect = useCallback(() => {
    if (!taskId) return;
    const ws = new WebSocket(`${WS_BASE_URL}/ws/analysis/${taskId}`);

    ws.onopen = () => setIsConnected(true);
    ws.onclose = () => setIsConnected(false);
    ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data);
        setMessages((prev) => [...prev, msg]);
        setLatestMessage(msg);
      } catch (e) {
        console.error("WS parse error:", e);
      }
    };

    wsRef.current = ws;
    return () => ws.close();
  }, [taskId]);

  useEffect(() => {
    const cleanup = connect();
    return () => cleanup?.();
  }, [connect]);

  const disconnect = useCallback(() => {
    wsRef.current?.close();
  }, []);

  return { messages, latestMessage, isConnected, disconnect };
}
