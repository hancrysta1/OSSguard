import { createContext, useContext, useRef, useCallback, ReactNode } from "react";
import { WS_BASE_URL } from "../config/env";
import { WSMessage } from "../types/ws";
import toast from "react-hot-toast";

interface WSCtx {
  connect: (taskId: string, onMessage: (msg: WSMessage) => void) => void;
  disconnect: () => void;
}

const WebSocketContext = createContext<WSCtx>({
  connect: () => {},
  disconnect: () => {},
});

const MAX_RECONNECT_ATTEMPTS = 5;

export function WebSocketProvider({ children }: { children: ReactNode }) {
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttempts = useRef(0);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const activeTaskId = useRef<string | null>(null);
  const activeCallback = useRef<((msg: WSMessage) => void) | null>(null);

  const disconnect = useCallback(() => {
    activeTaskId.current = null;
    activeCallback.current = null;
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    reconnectAttempts.current = 0;
  }, []);

  const doConnect = useCallback(
    (taskId: string, onMessage: (msg: WSMessage) => void) => {
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      const ws = new WebSocket(`${WS_BASE_URL}/ws/analysis/${taskId}`);

      ws.onmessage = (event) => {
        // Skip empty heartbeat pings
        if (!event.data) return;
        try {
          const data: WSMessage = JSON.parse(event.data);
          onMessage(data);
        } catch {
          // Ignore non-JSON messages (heartbeat keepalives)
        }
      };

      ws.onerror = () => {
        // Error is also followed by onclose, reconnection handled there
      };

      ws.onclose = () => {
        wsRef.current = null;
        // Auto-reconnect with exponential backoff if we still have an active task
        if (activeTaskId.current === taskId && reconnectAttempts.current < MAX_RECONNECT_ATTEMPTS) {
          const delay = Math.min(1000 * Math.pow(2, reconnectAttempts.current), 10000);
          reconnectAttempts.current++;
          reconnectTimer.current = setTimeout(() => {
            if (activeTaskId.current === taskId) {
              doConnect(taskId, onMessage);
            }
          }, delay);
        } else if (activeTaskId.current === taskId && reconnectAttempts.current >= MAX_RECONNECT_ATTEMPTS) {
          toast.error("서버 연결이 끊어졌습니다. 페이지를 새로고침해주세요.");
        }
      };

      ws.onopen = () => {
        reconnectAttempts.current = 0; // Reset on successful connection
      };

      wsRef.current = ws;
    },
    []
  );

  const connect = useCallback(
    (taskId: string, onMessage: (msg: WSMessage) => void) => {
      disconnect();
      activeTaskId.current = taskId;
      activeCallback.current = onMessage;
      doConnect(taskId, onMessage);
    },
    [disconnect, doConnect]
  );

  return (
    <WebSocketContext.Provider value={{ connect, disconnect }}>
      {children}
    </WebSocketContext.Provider>
  );
}

export const useWS = () => useContext(WebSocketContext);
