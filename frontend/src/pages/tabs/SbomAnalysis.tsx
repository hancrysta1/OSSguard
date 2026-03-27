import styled from "styled-components";
import { AnalysisData, PackageInfo } from "../../types/analysis";
import DataTable from "../../components/common/DataTable";
import ExportButton from "../../components/common/ExportButton";

const Header = styled.div`
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
`;

const Title = styled.h3`
  font-size: 1.1rem;
`;

const Count = styled.span`
  color: ${({ theme }) => theme.colors.textSecondary};
  font-size: 0.9rem;
`;

interface Props {
  analysisData: AnalysisData | null;
}

export default function SbomAnalysis({ analysisData }: Props) {
  const rawPackages = analysisData?.packages || [];

  // 백엔드 SPDX 원본 구조 → 프론트 구조로 변환
  const packages = rawPackages.map((pkg: any) => {
    // 이미 변환된 구조면 그대로
    if (pkg.package_name) return pkg;

    // SPDX 원본 구조 변환
    const purl = pkg.externalRefs?.find((r: any) => r.referenceType === "purl")?.referenceLocator || "";
    return {
      package_name: pkg.name || pkg.package_name || "N/A",
      version: pkg.versionInfo || pkg.version || "N/A",
      license: pkg.licenseDeclared !== "NOASSERTION" ? pkg.licenseDeclared : (pkg.licenseConcluded !== "NOASSERTION" ? pkg.licenseConcluded : pkg.license || "N/A"),
      download_link: purl || pkg.downloadLocation || pkg.download_link || "N/A",
    };
  });

  const columns = [
    { key: "package_name" as const, label: "패키지명", sortable: true },
    { key: "version" as const, label: "버전", sortable: true },
    { key: "license" as const, label: "라이선스", sortable: true },
    {
      key: "download_link" as const,
      label: "다운로드",
      render: (val: unknown) => {
        const link = String(val);
        if (link === "N/A" || !link) return "N/A";
        const url = link.startsWith("pkg:") ? convertPurl(link) : link;
        return <a href={url} target="_blank" rel="noreferrer">링크</a>;
      },
    },
  ];

  return (
    <div>
      <Header>
        <Title>SBOM 패키지 목록 <Count>({packages.length}개)</Count></Title>
        <ExportButton data={packages as unknown as Record<string, unknown>[]} filename="sbom-packages" />
      </Header>
      <DataTable data={packages as unknown as Record<string, unknown>[]} columns={columns as any} />
    </div>
  );
}

function convertPurl(purl: string): string {
  if (purl.includes("github")) {
    const match = purl.match(/pkg:github\/([^@]+)/);
    return match ? `https://github.com/${match[1]}` : purl;
  }
  if (purl.includes("pypi")) {
    const match = purl.match(/pkg:pypi\/([^@]+)/);
    return match ? `https://pypi.org/project/${match[1]}` : purl;
  }
  return purl;
}
