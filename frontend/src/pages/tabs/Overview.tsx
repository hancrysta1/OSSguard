import styled from "styled-components";
import { AnalysisData } from "../../types/analysis";
import SeverityPieChart from "../../components/charts/SeverityPieChart";
import SeverityBadge from "../../components/common/SeverityBadge";

const Grid = styled.div`
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
`;

const Card = styled.div`
  padding: 1.25rem;
  background: ${({ theme }) => theme.colors.surface};
  border-radius: 8px;
  border: 1px solid ${({ theme }) => theme.colors.border};
`;

const CardTitle = styled.h4`
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.textSecondary};
  margin-bottom: 0.5rem;
`;

const CardValue = styled.div`
  font-size: 1.75rem;
  font-weight: 700;
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

const VulnHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
`;

interface Props {
  repoUrl: string;
  analysisData: AnalysisData | null;
}

export default function Overview({ repoUrl, analysisData }: Props) {
  if (!analysisData) return <p>데이터를 불러오는 중...</p>;

  const overview = analysisData.security_overview;
  const topVulns = analysisData.top_vulnerabilities;

  // 백엔드는 severity_count(dict)로 보내고, 프론트는 severity_distribution(array)을 기대
  const severity = analysisData.severity_distribution?.length
    ? analysisData.severity_distribution
    : Object.entries((overview as any)?.severity_count || {}).map(([level, count]) => ({
        level,
        count: count as number,
      }));

  return (
    <div>
      <Grid>
        <Card>
          <CardTitle>총 취약점</CardTitle>
          <CardValue>{overview?.total_vulnerabilities ?? 0}</CardValue>
        </Card>
        <Card>
          <CardTitle>누락된 패키지</CardTitle>
          <CardValue>{overview?.missing_packages_count ?? 0}</CardValue>
        </Card>
        <Card>
          <CardTitle>업데이트 권장</CardTitle>
          <CardValue>{overview?.recommended_updates_count ?? 0}</CardValue>
        </Card>
        <Card>
          <CardTitle>영향받는 패키지</CardTitle>
          <CardValue>{overview?.affected_packages_count ?? 0}</CardValue>
        </Card>
      </Grid>

      <Section>
        <SectionTitle>취약점 심각도 분포</SectionTitle>
        <Card>
          <SeverityPieChart data={severity || []} />
        </Card>
      </Section>

      <Section>
        <SectionTitle>주요 취약점 (Top 3)</SectionTitle>
        {topVulns?.map((vuln) => (
          <VulnCard key={vuln.cve_id}>
            <VulnHeader>
              <strong>{vuln.cve_id}</strong>
              <SeverityBadge severity={vuln.severity} />
            </VulnHeader>
            <p style={{ fontSize: "0.9rem", marginBottom: "0.25rem" }}>
              패키지: {vuln.package}
            </p>
            <p style={{ fontSize: "0.85rem", color: "#718096" }}>
              {vuln.description}
            </p>
          </VulnCard>
        ))}
        {(!topVulns || topVulns.length === 0) && <p>발견된 취약점 없음</p>}
      </Section>
    </div>
  );
}
