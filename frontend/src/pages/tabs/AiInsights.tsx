import { useEffect, useState } from "react";
import styled from "styled-components";
import { getAiInsights } from "../../services/github";
import { AnalysisData, AiInsights as AiInsightsType } from "../../types/analysis";
import RiskScoreGauge from "../../components/charts/RiskScoreGauge";
import SeverityBadge from "../../components/common/SeverityBadge";
import { LoadingSkeleton } from "../../components/common/LoadingSkeleton";
import toast from "react-hot-toast";

const Grid = styled.div`
  display: grid;
  grid-template-columns: 300px 1fr;
  gap: 1.5rem;
  margin-bottom: 2rem;

  @media (max-width: 768px) {
    grid-template-columns: 1fr;
  }
`;

const Card = styled.div`
  padding: 1.25rem;
  background: ${({ theme }) => theme.colors.surface};
  border-radius: 8px;
  border: 1px solid ${({ theme }) => theme.colors.border};
`;

const CardTitle = styled.h4`
  font-size: 0.95rem;
  margin-bottom: 1rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const SummaryText = styled.p`
  font-size: 0.95rem;
  line-height: 1.6;
  white-space: pre-wrap;
`;

const Section = styled.div`
  margin-bottom: 2rem;
`;

const SectionTitle = styled.h3`
  font-size: 1.1rem;
  margin-bottom: 1rem;
`;

const VulnCard = styled.div`
  padding: 1rem;
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 8px;
  margin-bottom: 0.75rem;
`;

const ScoreBadge = styled.span`
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 4px;
  background: ${({ theme }) => theme.colors.primaryLight};
  color: ${({ theme }) => theme.colors.primary};
  font-weight: 600;
  font-size: 0.85rem;
  margin-left: 0.5rem;
`;

const BreakdownGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 0.5rem;
  margin-top: 1rem;
`;

const BreakdownItem = styled.div`
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: ${({ theme }) => theme.colors.surfaceHover};
  border-radius: 4px;
  font-size: 0.85rem;
`;

const ReanalyzeBtn = styled.button`
  padding: 0.5rem 1.25rem;
  background: ${({ theme }) => theme.colors.primary};
  color: white;
  border: none;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 600;
  cursor: pointer;
  margin-bottom: 1.5rem;
  &:hover { opacity: 0.9; }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;

const ErrorCard = styled(Card)`
  text-align: center;
  padding: 2rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

interface Props {
  repoUrl: string;
  analysisData: AnalysisData | null;
}

export default function AiInsights({ repoUrl, analysisData }: Props) {
  const [insights, setInsights] = useState<AiInsightsType | null>(null);
  const [loading, setLoading] = useState(true);
  const [reanalyzing, setReanalyzing] = useState(false);

  const fetchInsights = async () => {
    try {
      const data = await getAiInsights(repoUrl);
      setInsights(data);
    } catch {
      // If AI endpoint fails, fall back to risk_score from analysisData
      if (analysisData) {
        setInsights({
          repository: analysisData.repository,
          analysis_date: analysisData.analysis_date,
          risk_score: (analysisData as any).risk_score,
          ai_summary: "",
          prioritized_vulnerabilities: [],
        });
      }
    } finally {
      setLoading(false);
      setReanalyzing(false);
    }
  };

  useEffect(() => {
    fetchInsights();
  }, [repoUrl]);

  const handleReanalyze = async () => {
    setReanalyzing(true);
    await fetchInsights();
    toast.success("AI 분석이 완료되었습니다");
  };

  if (loading) return <LoadingSkeleton lines={10} />;
  if (!insights) return (
    <ErrorCard>
      <p style={{ fontSize: "1.1rem", marginBottom: "0.5rem" }}>AI 분석 결과가 없습니다</p>
      <p style={{ fontSize: "0.85rem" }}>먼저 저장소 분석을 실행한 후, Ollama가 실행 중인지 확인해주세요.</p>
      <ReanalyzeBtn onClick={handleReanalyze} disabled={reanalyzing} style={{ marginTop: "1rem" }}>
        {reanalyzing ? "분석 중..." : "AI 분석 실행"}
      </ReanalyzeBtn>
    </ErrorCard>
  );

  return (
    <div>
      <ReanalyzeBtn onClick={handleReanalyze} disabled={reanalyzing}>
        {reanalyzing ? "재분석 중..." : "AI 재분석"}
      </ReanalyzeBtn>
      <Grid>
        <Card>
          <CardTitle>종합 위험 점수</CardTitle>
          {insights.risk_score && <RiskScoreGauge riskScore={insights.risk_score} />}
          {insights.risk_score && (
            <BreakdownGrid>
              <BreakdownItem>
                <span>CVE</span>
                <strong>{insights.risk_score.breakdown.cve_score}</strong>
              </BreakdownItem>
              <BreakdownItem>
                <span>타이포스쿼팅</span>
                <strong>{insights.risk_score.breakdown.typosquatting_score}</strong>
              </BreakdownItem>
              <BreakdownItem>
                <span>의존성 혼동</span>
                <strong>{insights.risk_score.breakdown.dependency_confusion_score}</strong>
              </BreakdownItem>
              <BreakdownItem>
                <span>악성 코드</span>
                <strong>{insights.risk_score.breakdown.malware_score}</strong>
              </BreakdownItem>
            </BreakdownGrid>
          )}
        </Card>

        <Card>
          <CardTitle>AI 보안 요약</CardTitle>
          <SummaryText>{insights.ai_summary || "AI 요약을 불러오려면 'AI 재분석' 버튼을 클릭하세요."}</SummaryText>
        </Card>
      </Grid>

      <Section>
        <SectionTitle>AI 우선순위 취약점</SectionTitle>
        {insights.prioritized_vulnerabilities?.length === 0 && <p>취약점 없음</p>}
        {insights.prioritized_vulnerabilities?.map((vuln, i) => (
          <VulnCard key={i}>
            <div style={{ display: "flex", alignItems: "center", marginBottom: "0.5rem" }}>
              <strong>{vuln.cve_id}</strong>
              <SeverityBadge severity={vuln.severity} />
              {vuln.ai_priority_score && (
                <ScoreBadge>AI 점수: {vuln.ai_priority_score}/10</ScoreBadge>
              )}
            </div>
            <p style={{ fontSize: "0.9rem" }}>패키지: {vuln.package}</p>
            {vuln.ai_reasoning && (
              <p style={{ fontSize: "0.85rem", color: "#718096", marginTop: "0.25rem" }}>
                {vuln.ai_reasoning}
              </p>
            )}
          </VulnCard>
        ))}
      </Section>
    </div>
  );
}
