export interface WSMessage {
  stage: string;
  status: "running" | "completed" | "failed";
  progress: number;
  message: string;
  data?: Record<string, unknown>;
}

export type AnalysisStage =
  | "clone"
  | "sbom"
  | "sca"
  | "malware"
  | "typosquatting"
  | "dependency_confusion"
  | "ai"
  | "done";
