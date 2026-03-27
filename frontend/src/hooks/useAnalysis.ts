import { useCallback } from "react";
import { useAnalysisContext } from "../context/AnalysisContext";
import { useWS } from "../context/WebSocketContext";
import { requestAnalysis, getAnalysisResults } from "../services/github";
import { installPackage, storeAnalysis, checkInstallStatus, preCheckPackage } from "../services/pypiNpm";
import { WSMessage } from "../types/ws";
import toast from "react-hot-toast";

export function useAnalysis() {
  const { state, dispatch } = useAnalysisContext();
  const { connect, disconnect } = useWS();

  const fetchResults = useCallback(
    async (githubUrl: string) => {
      const data = await getAnalysisResults(githubUrl);
      dispatch({ type: "SET_SUCCESS", payload: data });
    },
    [dispatch]
  );

  const startGithubAnalysis = useCallback(
    async (githubUrl: string) => {
      dispatch({ type: "SET_TARGET", payload: { analysisType: "github", targetUrl: githubUrl } });
      dispatch({ type: "SET_LOADING", payload: {} });

      try {
        const result = await requestAnalysis(githubUrl);
        const taskId = result.task_id;
        dispatch({ type: "SET_LOADING", payload: { taskId } });

        connect(taskId, (msg: WSMessage) => {
          // Skip heartbeat — it's only for keeping the connection alive
          if (msg.stage === "heartbeat") return;

          dispatch({ type: "ADD_MESSAGE", payload: msg });

          if (msg.status === "completed" && msg.stage === "done") {
            disconnect();
            fetchResults(githubUrl).catch(() => {
              dispatch({ type: "SET_ERROR", payload: "Failed to fetch results" });
            });
          } else if (msg.status === "failed") {
            disconnect();
            dispatch({ type: "SET_ERROR", payload: msg.message });
            toast.error(msg.message);
          }
        });
      } catch {
        dispatch({ type: "SET_ERROR", payload: "Analysis request failed" });
      }
    },
    [dispatch, connect, disconnect, fetchResults]
  );

  const startPackageAnalysis = useCallback(
    async (manager: "pypi" | "npm", name: string, version: string) => {
      dispatch({ type: "SET_TARGET", payload: { analysisType: manager, targetUrl: name } });
      dispatch({ type: "SET_LOADING", payload: {} });

      try {
        // 설치 전 타이포스쿼팅 사전 검사
        const preCheck = await preCheckPackage(manager, name);
        if (preCheck.typosquatting?.detected) {
          const official = preCheck.typosquatting.official_package;
          toast.error(
            `타이포스쿼팅 의심: '${name}'은(는) '${official}'의 유사 패키지입니다. 설치를 중단합니다.`,
            { duration: 8000 }
          );
          dispatch({
            type: "SET_ERROR",
            payload: `타이포스쿼팅 탐지: '${name}' → 정식 패키지 '${official}'`,
          });
          return;
        }

        const installResult = await installPackage(manager, name, version);
        if (!installResult.task_id) {
          dispatch({ type: "SET_ERROR", payload: "Installation failed" });
          return;
        }

        // Poll with exponential backoff + max retries (토스 패턴)
        let status = "STARTED";
        let delay = 1000;
        let retries = 0;
        const maxRetries = 30;

        while ((status === "STARTED" || status === "PENDING") && retries < maxRetries) {
          await new Promise((r) => setTimeout(r, delay));
          const statusRes = await checkInstallStatus(installResult.task_id);
          status = statusRes.status;
          retries++;
          delay = Math.min(delay * 1.5, 5000); // Cap at 5s
        }

        if (retries >= maxRetries) {
          dispatch({ type: "SET_ERROR", payload: "Installation timed out" });
          return;
        }

        if (status !== "SUCCESS") {
          dispatch({ type: "SET_ERROR", payload: "Package installation failed" });
          return;
        }

        const analysisResult = await storeAnalysis(manager, name, version);
        dispatch({ type: "SET_LOADING", payload: { taskId: analysisResult.task_id } });

        // Connect WebSocket for package analysis progress too
        if (analysisResult.task_id) {
          connect(analysisResult.task_id, (msg: WSMessage) => {
            if (msg.stage === "heartbeat") return;

            dispatch({ type: "ADD_MESSAGE", payload: msg });

            if (msg.status === "completed" && msg.stage === "done") {
              disconnect();
              import("../services/pypiNpm").then(({ getDashboard }) => {
                getDashboard(name).then((data) => {
                  dispatch({ type: "SET_SUCCESS", payload: data });
                }).catch(() => {
                  dispatch({ type: "SET_ERROR", payload: "Failed to fetch package results" });
                });
              });
            } else if (msg.status === "failed") {
              disconnect();
              dispatch({ type: "SET_ERROR", payload: msg.message });
              toast.error(msg.message);
            }
          });
        }

        toast.success("Analysis started");
      } catch {
        dispatch({ type: "SET_ERROR", payload: "Package analysis failed" });
      }
    },
    [dispatch, connect, disconnect]
  );

  return { state, dispatch, startGithubAnalysis, startPackageAnalysis, fetchResults };
}
