import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useAnalysis } from "../hooks/useAnalysis";
import { resetCache } from "../services/github";
import ErrorBoundary from "../components/common/ErrorBoundary";
import { LoadingSkeleton } from "../components/common/LoadingSkeleton";
import ProgressTracker from "../components/analysis/ProgressTracker";
import SearchBar from "../components/common/SearchBar";
import toast from "react-hot-toast";
import Overview from "./tabs/Overview";
import SbomAnalysis from "./tabs/SbomAnalysis";
import VulnerabilityAnalysis from "./tabs/VulnerabilityAnalysis";
import PackageUpdate from "./tabs/PackageUpdate";
import MalwareDetection from "./tabs/MalwareDetection";
import AiInsights from "./tabs/AiInsights";

const Container = styled.div`
  max-width: 1200px;
  margin: 0 auto;
`;

const SearchSection = styled.div`
  margin-bottom: 1.5rem;
`;

const TargetHeader = styled.div`
  padding: 1.25rem 1.5rem;
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 8px;
  margin-bottom: 1.5rem;
`;

const TargetTopRow = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.35rem;
`;

const TargetName = styled.h2`
  font-size: 1.3rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 0.5rem;
`;

const RefreshButton = styled.button<{ $spinning?: boolean }>`
  display: flex;
  align-items: center;
  justify-content: center;
  width: 36px;
  height: 36px;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 8px;
  background: ${({ theme }) => theme.colors.bg};
  cursor: pointer;
  transition: all 0.2s;
  flex-shrink: 0;

  &:hover {
    background: ${({ theme }) => theme.colors.primary};
    border-color: ${({ theme }) => theme.colors.primary};
    color: white;
  }

  &:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  svg {
    width: 18px;
    height: 18px;
    animation: ${({ $spinning }) => ($spinning ? "spin 1s linear infinite" : "none")};
  }

  @keyframes spin {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
  }
`;

const TargetMeta = styled.div`
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.textSecondary};
  display: flex;
  gap: 1.25rem;
  flex-wrap: wrap;
`;

const MetaItem = styled.span`
  display: flex;
  align-items: center;
  gap: 0.3rem;
`;

const TabBar = styled.div`
  display: flex;
  gap: 0.25rem;
  border-bottom: 1px solid ${({ theme }) => theme.colors.border};
  margin-bottom: 1.5rem;
  overflow-x: auto;
`;

const Tab = styled.button<{ $active: boolean }>`
  padding: 0.75rem 1rem;
  font-size: 0.9rem;
  font-weight: 600;
  border: none;
  background: none;
  color: ${({ $active, theme }) => ($active ? theme.colors.primary : theme.colors.textSecondary)};
  border-bottom: 2px solid ${({ $active, theme }) => ($active ? theme.colors.primary : "transparent")};
  cursor: pointer;
  white-space: nowrap;
  &:hover { color: ${({ theme }) => theme.colors.primary}; }
`;

const TABS = [
  { key: "overview", label: "종합 분석" },
  { key: "sbom", label: "SBOM 분석" },
  { key: "vulnerability", label: "취약점 분석" },
  { key: "update", label: "패키지 업데이트" },
  { key: "detection", label: "악성 코드 탐지" },
  { key: "ai", label: "AI Insights" },
];

export default function AnalysisPage() {
  const location = useLocation();
  const navigate = useNavigate();
  const params = new URLSearchParams(location.search);
  const repoUrl = params.get("url") || "";
  const activeTab = params.get("tab") || "overview";
  const { state, startGithubAnalysis, fetchResults } = useAnalysis();

  const [searchCategory, setSearchCategory] = useState("github");
  const [searchValue, setSearchValue] = useState(repoUrl);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    if (!repoUrl || isRefreshing) return;
    setIsRefreshing(true);
    try {
      await resetCache(repoUrl);
      toast.success("캐시 초기화 완료, 재분석을 시작합니다");
      startGithubAnalysis(repoUrl);
    } catch {
      toast.error("재분석 요청에 실패했습니다");
    } finally {
      setIsRefreshing(false);
    }
  };

  // Single entry point: fetch cached results or start analysis
  useEffect(() => {
    if (!repoUrl) return;
    if (state.status === "loading") return;
    if (state.status === "success" && state.targetUrl === repoUrl) return;

    fetchResults(repoUrl).catch(() => {
      startGithubAnalysis(repoUrl);
    });
  }, [repoUrl]);

  const setTab = (tab: string) => {
    const newParams = new URLSearchParams(location.search);
    newParams.set("tab", tab);
    navigate(`/analysis?${newParams.toString()}`, { replace: true });
  };

  const handleSearch = () => {
    if (searchCategory === "github" && searchValue.trim()) {
      navigate(`/analysis?url=${encodeURIComponent(searchValue.trim())}&tab=overview`);
    }
  };

  if (state.status === "loading") {
    return (
      <Container>
        <ProgressTracker
          progress={state.progress}
          messages={state.messages}
          stageStatus={state.stageStatus}
        />
      </Container>
    );
  }

  const data = state.analysisData;

  // 검색 대상 정보 추출
  const repoName = data?.repository || repoUrl.replace(/https?:\/\/github\.com\//, "");
  const analysisDate = data?.analysis_date
    ? new Date(data.analysis_date).toLocaleString("ko-KR")
    : null;
  const totalVulns = data?.security_overview?.total_vulnerabilities ?? 0;
  const totalPackages = data?.packages?.length ?? 0;

  const renderTab = () => {
    if (!data && state.status !== "success") {
      return <LoadingSkeleton lines={8} />;
    }

    switch (activeTab) {
      case "overview":
        return <Overview repoUrl={repoUrl} analysisData={data} />;
      case "sbom":
        return <SbomAnalysis analysisData={data} />;
      case "vulnerability":
        return <VulnerabilityAnalysis analysisData={data} />;
      case "update":
        return <PackageUpdate analysisData={data} />;
      case "detection":
        return <MalwareDetection analysisData={data} />;
      case "ai":
        return <AiInsights repoUrl={repoUrl} analysisData={data} />;
      default:
        return <Overview repoUrl={repoUrl} analysisData={data} />;
    }
  };

  return (
    <Container>
      <SearchSection>
        <SearchBar
          category={searchCategory}
          onCategoryChange={setSearchCategory}
          value={searchValue}
          onChange={setSearchValue}
          onSubmit={handleSearch}
          placeholder="GitHub URL 또는 패키지명"
        />
      </SearchSection>

      {data && (
        <TargetHeader>
          <TargetTopRow>
            <TargetName>
              {repoName}
            </TargetName>
            <RefreshButton
              onClick={handleRefresh}
              disabled={isRefreshing}
              $spinning={isRefreshing}
              title="캐시 초기화 후 재분석"
            >
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10" />
                <polyline points="1 20 1 14 7 14" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </svg>
            </RefreshButton>
          </TargetTopRow>
          <TargetMeta>
            <MetaItem>
              {repoUrl.includes("github.com") ? "GitHub" : "Package"}
            </MetaItem>
            {analysisDate && (
              <MetaItem>
                {analysisDate}
              </MetaItem>
            )}
            <MetaItem>
              {totalPackages}개 패키지
            </MetaItem>
            <MetaItem>
              {totalVulns}개 취약점
            </MetaItem>
          </TargetMeta>
        </TargetHeader>
      )}

      <TabBar>
        {TABS.map((t) => (
          <Tab key={t.key} $active={activeTab === t.key} onClick={() => setTab(t.key)}>
            {t.label}
          </Tab>
        ))}
      </TabBar>

      <ErrorBoundary>
        {renderTab()}
      </ErrorBoundary>
    </Container>
  );
}
