import { useRef, useEffect } from "react";
import styled, { keyframes } from "styled-components";
import { WSMessage, AnalysisStage } from "../../types/ws";

const pulse = keyframes`
  0%, 100% { opacity: 1; }
  50% { opacity: 0.4; }
`;

const shimmer = keyframes`
  0% { background-position: -200% 0; }
  100% { background-position: 200% 0; }
`;

const spin = keyframes`
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
`;

const Container = styled.div`
  padding: 2rem;
  background: ${({ theme }) => theme.colors.surface};
  border-radius: 12px;
  border: 1px solid ${({ theme }) => theme.colors.border};
  max-width: 640px;
  margin: 2rem auto;
`;

const Title = styled.h3`
  margin-bottom: 0.5rem;
  font-size: 1.2rem;
`;

const ProgressPercent = styled.span`
  font-size: 1.5rem;
  font-weight: 700;
  color: ${({ theme }) => theme.colors.primary};
  margin-bottom: 0.75rem;
  display: block;
`;

const ProgressBarTrack = styled.div`
  width: 100%;
  height: 10px;
  background: ${({ theme }) => theme.colors.border};
  border-radius: 5px;
  margin-bottom: 2rem;
  overflow: hidden;
`;

const ProgressBarFill = styled.div<{ $progress: number }>`
  width: ${({ $progress }) => $progress}%;
  height: 100%;
  border-radius: 5px;
  background: linear-gradient(
    90deg,
    ${({ theme }) => theme.colors.primary} 0%,
    ${({ theme }) => theme.colors.primaryLight || theme.colors.primary} 50%,
    ${({ theme }) => theme.colors.primary} 100%
  );
  background-size: 200% 100%;
  animation: ${shimmer} 1.5s ease-in-out infinite;
  transition: width 0.5s ease;
`;

const StageList = styled.div`
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
`;

const StageRow = styled.div<{ $status: string }>`
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.6rem 0.75rem;
  border-radius: 6px;
  font-size: 0.9rem;
  background: ${({ $status, theme }) =>
    $status === "running" ? (theme.colors.primaryLight || theme.colors.surface) : "transparent"};
  color: ${({ $status, theme }) => {
    if ($status === "completed") return theme.colors.success;
    if ($status === "running") return theme.colors.primary;
    if ($status === "failed") return theme.colors.error;
    return theme.colors.textSecondary;
  }};
  font-weight: ${({ $status }) => ($status === "running" ? 600 : 400)};
`;

const IconWrap = styled.span<{ $status: string }>`
  width: 22px;
  height: 22px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 0.85rem;
`;

const Spinner = styled.span`
  display: inline-block;
  width: 16px;
  height: 16px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: ${spin} 0.8s linear infinite;
`;

const StageLabel = styled.span`
  flex: 1;
`;

const StageMsg = styled.span`
  font-size: 0.75rem;
  opacity: 0.7;
  animation: ${pulse} 2s ease-in-out infinite;
`;

const LogSection = styled.div`
  margin-top: 1.5rem;
  padding-top: 1rem;
  border-top: 1px solid ${({ theme }) => theme.colors.border};
`;

const LogTitle = styled.div`
  font-size: 0.8rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.textSecondary};
  margin-bottom: 0.5rem;
`;

const LogList = styled.div`
  max-height: 160px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  gap: 0.15rem;
`;

const LogEntry = styled.div<{ $status: string }>`
  font-size: 0.75rem;
  font-family: "SF Mono", "Fira Code", monospace;
  color: ${({ $status, theme }) => {
    if ($status === "failed") return theme.colors.error;
    if ($status === "completed") return theme.colors.success;
    return theme.colors.textSecondary;
  }};
  padding: 0.15rem 0;

  &:last-child {
    color: ${({ theme }) => theme.colors.text};
    font-weight: 500;
  }
`;

const STAGES: { key: AnalysisStage; label: string }[] = [
  { key: "clone", label: "저장소 클론" },
  { key: "sbom", label: "SBOM 생성" },
  { key: "sca", label: "취약점 분석 (SCA)" },
  { key: "malware", label: "악성 코드 탐지" },
  { key: "typosquatting", label: "타이포스쿼팅 탐지" },
  { key: "dependency_confusion", label: "의존성 혼동 탐지" },
  { key: "ai", label: "AI 위험 분석" },
];

interface Props {
  progress: number;
  messages: WSMessage[];
  /** Pre-computed stage→latest message map from context (O(1) lookup) */
  stageStatus: Record<string, WSMessage>;
}

export default function ProgressTracker({ progress, messages, stageStatus }: Props) {
  const logRef = useRef<HTMLDivElement>(null);

  // Auto-scroll log to bottom
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [messages.length]);

  const getStatus = (stage: string): string => {
    return stageStatus[stage]?.status || "pending";
  };

  const getMessage = (stage: string): string | null => {
    return stageStatus[stage]?.message || null;
  };

  const renderIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <IconWrap $status={status}>&#10003;</IconWrap>;
      case "running":
        return (
          <IconWrap $status={status}>
            <Spinner />
          </IconWrap>
        );
      case "failed":
        return <IconWrap $status={status}>&#10007;</IconWrap>;
      default:
        return <IconWrap $status={status}>&#9675;</IconWrap>;
    }
  };

  // Only show the last 30 log entries to prevent DOM bloat
  const visibleLogs = messages.length > 30 ? messages.slice(-30) : messages;

  return (
    <Container>
      <Title>분석 진행 상황</Title>
      <ProgressPercent>{Math.round(progress)}%</ProgressPercent>
      <ProgressBarTrack>
        <ProgressBarFill $progress={progress} />
      </ProgressBarTrack>

      <StageList>
        {STAGES.map(({ key, label }) => {
          const status = getStatus(key);
          const msg = getMessage(key);
          return (
            <StageRow key={key} $status={status}>
              {renderIcon(status)}
              <StageLabel>{label}</StageLabel>
              {status === "running" && msg && <StageMsg>{msg}</StageMsg>}
            </StageRow>
          );
        })}
      </StageList>

      {messages.length > 0 && (
        <LogSection>
          <LogTitle>실시간 로그</LogTitle>
          <LogList ref={logRef}>
            {visibleLogs.map((m, i) => (
              <LogEntry key={i} $status={m.status}>
                [{m.stage}] {m.message}
              </LogEntry>
            ))}
          </LogList>
        </LogSection>
      )}
    </Container>
  );
}
