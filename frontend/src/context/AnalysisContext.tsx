import { createContext, useContext, useReducer, ReactNode, useCallback } from "react";
import { AnalysisData } from "../types/analysis";
import { WSMessage } from "../types/ws";

type AnalysisType = "github" | "pypi" | "npm";
type Status = "idle" | "loading" | "success" | "error";

const MAX_MESSAGES = 100;

interface State {
  analysisData: AnalysisData | null;
  analysisType: AnalysisType;
  targetUrl: string;
  status: Status;
  progress: number;
  error: string | null;
  taskId: string | null;
  messages: WSMessage[];
  /** Pre-computed stage status map to avoid repeated array filtering */
  stageStatus: Record<string, WSMessage>;
}

type Action =
  | { type: "SET_TARGET"; payload: { analysisType: AnalysisType; targetUrl: string } }
  | { type: "SET_LOADING"; payload: { taskId?: string } }
  | { type: "SET_PROGRESS"; payload: number }
  | { type: "SET_SUCCESS"; payload: AnalysisData }
  | { type: "SET_ERROR"; payload: string }
  | { type: "ADD_MESSAGE"; payload: WSMessage }
  | { type: "RESET" };

const initialState: State = {
  analysisData: null,
  analysisType: "github",
  targetUrl: "",
  status: "idle",
  progress: 0,
  error: null,
  taskId: null,
  messages: [],
  stageStatus: {},
};

function reducer(state: State, action: Action): State {
  switch (action.type) {
    case "SET_TARGET":
      return { ...state, analysisType: action.payload.analysisType, targetUrl: action.payload.targetUrl };
    case "SET_LOADING":
      return { ...state, status: "loading", error: null, progress: 0, taskId: action.payload.taskId || null, messages: [], stageStatus: {} };
    case "SET_PROGRESS":
      return { ...state, progress: action.payload };
    case "SET_SUCCESS":
      return { ...state, status: "success", analysisData: action.payload, progress: 100 };
    case "SET_ERROR":
      return { ...state, status: "error", error: action.payload };
    case "ADD_MESSAGE": {
      const msg = action.payload;
      // Skip heartbeat messages
      if (msg.stage === "heartbeat") return { ...state, progress: msg.progress > 0 ? msg.progress : state.progress };
      // Windowed message buffer (LINE 패턴: 메시지 윈도잉으로 메모리 관리)
      const messages = state.messages.length >= MAX_MESSAGES
        ? [...state.messages.slice(-Math.floor(MAX_MESSAGES / 2)), msg]
        : [...state.messages, msg];
      // Update stage status map (O(1) lookup instead of O(n) filter)
      const stageStatus = { ...state.stageStatus, [msg.stage]: msg };
      return { ...state, messages, stageStatus, progress: msg.progress };
    }
    case "RESET":
      return initialState;
    default:
      return state;
  }
}

interface AnalysisCtx {
  state: State;
  dispatch: React.Dispatch<Action>;
  setTarget: (type: AnalysisType, url: string) => void;
}

const AnalysisContext = createContext<AnalysisCtx>({
  state: initialState,
  dispatch: () => {},
  setTarget: () => {},
});

export function AnalysisProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  const setTarget = useCallback(
    (type: AnalysisType, url: string) => {
      dispatch({ type: "SET_TARGET", payload: { analysisType: type, targetUrl: url } });
    },
    []
  );

  return (
    <AnalysisContext.Provider value={{ state, dispatch, setTarget }}>
      {children}
    </AnalysisContext.Provider>
  );
}

export const useAnalysisContext = () => useContext(AnalysisContext);
