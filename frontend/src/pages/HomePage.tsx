import { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import toast from "react-hot-toast";
import { useAnalysis } from "../hooks/useAnalysis";

const Container = styled.div`
  max-width: 800px;
  margin: 0 auto;
  padding: 3rem 1rem;
`;

const HeroTitle = styled.h1`
  font-size: 2rem;
  font-weight: 700;
  text-align: center;
  margin-bottom: 0.5rem;
`;

const Subtitle = styled.p`
  text-align: center;
  color: ${({ theme }) => theme.colors.textSecondary};
  margin-bottom: 3rem;
`;

const CategoryCards = styled.div`
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-bottom: 2rem;

  @media (max-width: 600px) {
    grid-template-columns: 1fr;
  }
`;

const Card = styled.div<{ $selected: boolean }>`
  padding: 1.5rem;
  border-radius: 8px;
  border: 2px solid ${({ $selected, theme }) => ($selected ? theme.colors.primary : theme.colors.border)};
  background: ${({ $selected, theme }) => ($selected ? theme.colors.primaryLight : theme.colors.surface)};
  cursor: pointer;
  text-align: center;
  transition: all 0.15s;

  &:hover {
    border-color: ${({ theme }) => theme.colors.primary};
  }
`;

const CardTitle = styled.h3`
  margin-bottom: 0.25rem;
`;

const CardDesc = styled.p`
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const InputGroup = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
  margin-top: 2rem;
`;

const Label = styled.label`
  font-weight: 600;
  font-size: 0.9rem;
`;

const Input = styled.input`
  padding: 0.75rem 1rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 8px;
  background: ${({ theme }) => theme.colors.surface};
  color: ${({ theme }) => theme.colors.text};
  font-size: 1rem;
  &:focus { border-color: ${({ theme }) => theme.colors.primary}; outline: none; }
`;

const Row = styled.div`
  display: flex;
  gap: 0.75rem;
`;

const SubmitBtn = styled.button`
  padding: 0.75rem 2rem;
  background: ${({ theme }) => theme.colors.primary};
  color: white;
  border: none;
  border-radius: 8px;
  font-size: 1rem;
  font-weight: 600;
  cursor: pointer;
  margin-top: 1rem;
  &:hover { opacity: 0.9; }
  &:disabled { opacity: 0.5; cursor: not-allowed; }
`;

const Hint = styled.p`
  font-size: 0.85rem;
  color: ${({ theme }) => theme.colors.textSecondary};
  margin-top: 0.25rem;
`;

const ExampleList = styled.div`
  margin-top: 1rem;
  text-align: left;
`;

const ExampleTitle = styled.p`
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.textSecondary};
  margin-bottom: 0.5rem;
`;

const ExampleItem = styled.div`
  padding: 0.5rem 0.75rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 6px;
  margin-bottom: 0.35rem;
  cursor: pointer;
  font-size: 0.85rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
  &:hover { border-color: ${({ theme }) => theme.colors.primary}; background: ${({ theme }) => theme.colors.surfaceHover}; }
`;

const ExampleDesc = styled.span`
  font-size: 0.75rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const GITHUB_EXAMPLES = [
  { name: "exploitable-repo", url: "https://github.com/mu-pamang/exploitable-repo", desc: "취약점 다수 포함" },
  { name: "pallets/flask", url: "https://github.com/pallets/flask", desc: "Python 웹 프레임워크" },
  { name: "psf/requests", url: "https://github.com/psf/requests", desc: "Python HTTP 라이브러리" },
  { name: "expressjs/express", url: "https://github.com/expressjs/express", desc: "Node.js 웹 프레임워크" },
];

const PYPI_EXAMPLES = [
  { name: "requests", version: "2.26.0", desc: "취약점 포함된 구버전" },
  { name: "flask", version: "2.0.0", desc: "Python 웹 프레임워크" },
  { name: "django", version: "3.2.0", desc: "취약점 포함 가능" },
  { name: "numpy", version: "1.21.0", desc: "과학 계산 라이브러리" },
];

const NPM_EXAMPLES = [
  { name: "axios", version: "0.21.0", desc: "취약점 포함된 구버전" },
  { name: "lodash", version: "4.17.19", desc: "프로토타입 오염 취약점" },
  { name: "express", version: "4.17.1", desc: "Node.js 웹 프레임워크" },
  { name: "minimist", version: "1.2.5", desc: "프로토타입 오염 취약점" },
];

type Category = "github" | "pypi" | "npm";

export default function HomePage() {
  const navigate = useNavigate();
  const { startGithubAnalysis, startPackageAnalysis } = useAnalysis();
  const [category, setCategory] = useState<Category>("github");
  const [githubUrl, setGithubUrl] = useState("");
  const [packageName, setPackageName] = useState("");
  const [packageVersion, setPackageVersion] = useState("");
  const [loading, setLoading] = useState(false);

  const githubUrlPattern = /^https:\/\/github\.com\/[\w.-]+\/[\w.-]+$/;

  const saveToHistory = (url: string, type: string) => {
    const stored = localStorage.getItem("ossguard_history");
    const history: HistoryEntry[] = stored ? JSON.parse(stored) : [];
    const entry = { url, type, timestamp: new Date().toISOString() };
    const filtered = history.filter((h) => h.url !== url);
    filtered.unshift(entry);
    localStorage.setItem("ossguard_history", JSON.stringify(filtered.slice(0, 20)));
  };

  const handleSubmit = async () => {
    setLoading(true);
    try {
      if (category === "github") {
        if (!githubUrlPattern.test(githubUrl)) {
          toast.error("유효한 GitHub URL을 입력해주세요");
          return;
        }
        saveToHistory(githubUrl, "github");
        await startGithubAnalysis(githubUrl);
        navigate(`/analysis?url=${encodeURIComponent(githubUrl)}&tab=overview`);
      } else {
        if (!packageName.trim()) {
          toast.error("패키지명을 입력해주세요");
          return;
        }
        await startPackageAnalysis(category, packageName, packageVersion || "latest");
        navigate(`/analysis?package=${encodeURIComponent(packageName)}&manager=${category}&tab=overview`);
      }
    } catch {
      toast.error("분석 요청 실패");
    } finally {
      setLoading(false);
    }
  };

  return (
    <Container>
      <HeroTitle>OSSGuard</HeroTitle>
      <Subtitle>오픈소스 공급망 보안 분석 플랫폼</Subtitle>

      <CategoryCards>
        <Card $selected={category === "github"} onClick={() => setCategory("github")}>
          <CardTitle>GitHub</CardTitle>
          <CardDesc>저장소 보안 분석</CardDesc>
        </Card>
        <Card $selected={category === "pypi"} onClick={() => setCategory("pypi")}>
          <CardTitle>PyPI</CardTitle>
          <CardDesc>Python 패키지 분석</CardDesc>
        </Card>
        <Card $selected={category === "npm"} onClick={() => setCategory("npm")}>
          <CardTitle>npm</CardTitle>
          <CardDesc>Node.js 패키지 분석</CardDesc>
        </Card>
      </CategoryCards>

      {category === "github" ? (
        <InputGroup>
          <Label>GitHub 저장소 URL</Label>
          <Input
            placeholder="https://github.com/user/repository"
            value={githubUrl}
            onChange={(e) => setGithubUrl(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          />
          <Hint>예: https://github.com/mu-pamang/exploitable-repo</Hint>
          <ExampleList>
            <ExampleTitle>바로 테스트해보기</ExampleTitle>
            {GITHUB_EXAMPLES.map((ex) => (
              <ExampleItem key={ex.url} onClick={() => { setGithubUrl(ex.url); }}>
                <span>{ex.name}</span>
                <ExampleDesc>{ex.desc}</ExampleDesc>
              </ExampleItem>
            ))}
          </ExampleList>
        </InputGroup>
      ) : (
        <InputGroup>
          <Label>패키지 정보</Label>
          <Row>
            <Input
              style={{ flex: 2 }}
              placeholder="패키지명"
              value={packageName}
              onChange={(e) => setPackageName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            />
            <Input
              style={{ flex: 1 }}
              placeholder="버전 (선택)"
              value={packageVersion}
              onChange={(e) => setPackageVersion(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
            />
          </Row>
          <Hint>예: {category === "pypi" ? "requests 2.26.0" : "axios 1.3.0"}</Hint>
          <ExampleList>
            <ExampleTitle>바로 테스트해보기</ExampleTitle>
            {(category === "pypi" ? PYPI_EXAMPLES : NPM_EXAMPLES).map((ex) => (
              <ExampleItem key={ex.name} onClick={() => { setPackageName(ex.name); setPackageVersion(ex.version); }}>
                <span>{ex.name} {ex.version}</span>
                <ExampleDesc>{ex.desc}</ExampleDesc>
              </ExampleItem>
            ))}
          </ExampleList>
        </InputGroup>
      )}

      <SubmitBtn onClick={handleSubmit} disabled={loading}>
        {loading ? "분석 중..." : "분석 시작"}
      </SubmitBtn>

      <FeaturesSection />
      <RecentHistory navigate={navigate} />
    </Container>
  );
}

/* --- Feature Highlights --- */

const FeaturesGrid = styled.div`
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
  margin-top: 3rem;
  @media (max-width: 600px) {
    grid-template-columns: 1fr;
  }
`;

const FeatureCard = styled.div`
  padding: 1.25rem;
  border-radius: 8px;
  border: 1px solid ${({ theme }) => theme.colors.border};
  text-align: center;
`;

const FeatureIcon = styled.div`
  font-size: 1.5rem;
  margin-bottom: 0.5rem;
`;

const FeatureTitle = styled.h4`
  font-size: 0.9rem;
  margin-bottom: 0.25rem;
`;

const FeatureDesc = styled.p`
  font-size: 0.8rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

function FeaturesSection() {
  const features = [
    { icon: "\u{1F6E1}", title: "SBOM/SCA 분석", desc: "Syft + Trivy 기반 패키지 및 취약점 분석" },
    { icon: "\u{1F50D}", title: "공급망 위협 탐지", desc: "Typosquatting, Dependency Confusion 탐지" },
    { icon: "\u{1F916}", title: "AI 보안 분석", desc: "Ollama + CodeBERT 기반 지능형 위험 평가" },
    { icon: "\u{1F4CA}", title: "실시간 모니터링", desc: "WebSocket + gRPC 실시간 분석 진행률" },
    { icon: "\u{26A0}", title: "악성 코드 탐지", desc: "YARA 룰 + 문자열 기반 악성 코드 스캔" },
    { icon: "\u{1F4DD}", title: "보안 보고서", desc: "CSV/JSON 내보내기 및 AI 요약 보고서" },
  ];

  return (
    <FeaturesGrid>
      {features.map((f, i) => (
        <FeatureCard key={i}>
          <FeatureIcon>{f.icon}</FeatureIcon>
          <FeatureTitle>{f.title}</FeatureTitle>
          <FeatureDesc>{f.desc}</FeatureDesc>
        </FeatureCard>
      ))}
    </FeaturesGrid>
  );
}

/* --- Recent Analysis History --- */

const HistorySection = styled.div`
  margin-top: 2.5rem;
`;

const HistoryTitle = styled.h3`
  font-size: 1rem;
  margin-bottom: 0.75rem;
  color: ${({ theme }) => theme.colors.textSecondary};
`;

const HistoryItem = styled.div`
  padding: 0.75rem 1rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 6px;
  margin-bottom: 0.5rem;
  cursor: pointer;
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: 0.85rem;
  &:hover { border-color: ${({ theme }) => theme.colors.primary}; }
`;

interface HistoryEntry {
  url: string;
  type: string;
  timestamp: string;
}

function RecentHistory({ navigate }: { navigate: (path: string) => void }) {
  const stored = localStorage.getItem("ossguard_history");
  const history: HistoryEntry[] = stored ? JSON.parse(stored) : [];

  if (history.length === 0) return null;

  return (
    <HistorySection>
      <HistoryTitle>최근 분석 기록</HistoryTitle>
      {history.slice(0, 5).map((h, i) => (
        <HistoryItem key={i} onClick={() => navigate(`/analysis?url=${encodeURIComponent(h.url)}&tab=overview`)}>
          <span>{h.url}</span>
          <span style={{ opacity: 0.5 }}>{new Date(h.timestamp).toLocaleDateString()}</span>
        </HistoryItem>
      ))}
    </HistorySection>
  );
}
