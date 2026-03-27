import api from "./api";

export const requestAnalysis = async (githubUrl: string) => {
  const res = await api.post("/github/store_analysis", { github_url: githubUrl });
  return res.data;
};

export const getAnalysisResults = async (githubUrl: string) => {
  const res = await api.post("/github/g_dashboard", { github_url: githubUrl }, { _silent: true } as any);
  return res.data;
};

export const getPackages = async (githubUrl: string) => {
  const res = await api.post("/github/packages", { github_url: githubUrl });
  return res.data;
};

export const getVulnerabilities = async (githubUrl: string) => {
  const res = await api.post("/github/vulnerabilities", { github_url: githubUrl });
  return res.data;
};

export const getUpdateRecommendations = async (githubUrl: string) => {
  const res = await api.post("/github/updates", { github_url: githubUrl });
  return res.data;
};

export const getMaliciousCodeAnalysis = async (githubUrl: string) => {
  const res = await api.post("/github/malicious_code", { github_url: githubUrl });
  return res.data;
};

export const getMaliciousCodeAnalysisText = async (githubUrl: string) => {
  const res = await api.post("/github/malicious_code/text", { github_url: githubUrl });
  return res.data;
};

export const getTyposquattingAnalysis = async (githubUrl: string) => {
  const res = await api.post("/github/typosquatting", { github_url: githubUrl });
  return res.data;
};

export const getDependencyConfusionAnalysis = async (githubUrl: string) => {
  const res = await api.post("/github/dependency_confusion", { github_url: githubUrl });
  return res.data;
};

export const getAiInsights = async (githubUrl: string) => {
  const res = await api.post("/ai/full-report", { github_url: githubUrl });
  return res.data;
};

export const getAiSummary = async (githubUrl: string) => {
  const res = await api.post("/ai/summarize", { github_url: githubUrl });
  return res.data;
};

export const getAiPrioritization = async (githubUrl: string) => {
  const res = await api.post("/ai/prioritize", { github_url: githubUrl });
  return res.data;
};

export const getAiRiskScore = async (githubUrl: string) => {
  const res = await api.post("/ai/risk-score", { github_url: githubUrl });
  return res.data;
};

export const resetCache = async (githubUrl: string) => {
  const res = await api.post("/github/reset_cache", { github_url: githubUrl });
  return res.data;
};

// --- New AI endpoints ---

export const getFixSuggestions = async (githubUrl: string) => {
  const res = await api.post("/ai/fix-suggestions", { github_url: githubUrl });
  return res.data;
};

export const getLicenseCheck = async (githubUrl: string) => {
  const res = await api.post("/ai/license-check", { github_url: githubUrl });
  return res.data;
};

export const getPackageHealth = async (githubUrl: string) => {
  const res = await api.post("/ai/package-health", { github_url: githubUrl });
  return res.data;
};

export const chatWithAi = async (githubUrl: string, question: string, history: any[] = []) => {
  const res = await api.post("/ai/chat", { github_url: githubUrl, question, history });
  return res.data;
};

export const getUpgradeImpact = async (
  githubUrl: string, packageName: string, currentVersion: string, targetVersion: string
) => {
  const res = await api.post("/ai/upgrade-impact", {
    github_url: githubUrl, package_name: packageName,
    current_version: currentVersion, target_version: targetVersion,
  });
  return res.data;
};
