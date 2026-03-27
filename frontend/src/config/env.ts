export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
const defaultWs = import.meta.env.VITE_WS_BASE_URL || `${wsProtocol}//${window.location.host}`;
export const WS_BASE_URL = defaultWs === "/" ? `${wsProtocol}//${window.location.host}` : defaultWs;
