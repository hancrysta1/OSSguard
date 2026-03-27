import styled from "styled-components";
import { AnalysisData, UpdateRecommendation } from "../../types/analysis";
import SeverityBadge from "../../components/common/SeverityBadge";
import ExportButton from "../../components/common/ExportButton";

const Header = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
`;

const Card = styled.div`
  padding: 1rem;
  background: ${({ theme }) => theme.colors.surface};
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 8px;
  margin-bottom: 0.75rem;
`;

const CardHeader = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
`;

const Label = styled.span`
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

interface Props {
  analysisData: AnalysisData | null;
}

export default function PackageUpdate({ analysisData }: Props) {
  // 백엔드: update_recommendations (dict: {패키지명: {...}})
  // 프론트: updates (array: [{package_name, ...}])
  const rawUpdates = analysisData?.updates || [];
  const rawRecommendations = (analysisData as any)?.update_recommendations;

  const updates: UpdateRecommendation[] = rawUpdates.length
    ? rawUpdates
    : rawRecommendations && typeof rawRecommendations === "object" && !Array.isArray(rawRecommendations)
      ? Object.entries(rawRecommendations).map(([name, val]: [string, any]) => ({
          package_name: name,
          installed_version: val.installed_version || "N/A",
          recommended_versions: val.recommended_versions || [],
          severities: val.severities || [],
          cve_list: val.cve_list || [],
        }))
      : [];

  return (
    <div>
      <Header>
        <h3>업데이트 권장 패키지 ({updates.length}개)</h3>
        <ExportButton data={updates as unknown as Record<string, unknown>[]} filename="update-recommendations" />
      </Header>
      {updates.length === 0 && <p>업데이트가 필요한 패키지가 없습니다.</p>}
      {updates.map((u, i) => (
        <Card key={i}>
          <CardHeader>
            <strong>{u.package_name}</strong>
            <div style={{ display: "flex", gap: "0.25rem" }}>
              {u.severities.map((s) => (
                <SeverityBadge key={s} severity={s} />
              ))}
            </div>
          </CardHeader>
          <p><Label>현재 버전:</Label> {u.installed_version}</p>
          <p><Label>권장 버전:</Label> {u.recommended_versions.join(", ")}</p>
          <p><Label>CVE:</Label> {u.cve_list.join(", ")}</p>
        </Card>
      ))}
    </div>
  );
}
