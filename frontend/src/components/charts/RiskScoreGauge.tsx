import styled from "styled-components";
import { RiskScore } from "../../types/analysis";

const GaugeContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1rem;
`;

const SVGWrapper = styled.div`
  width: 200px;
  height: 120px;
`;

const ScoreText = styled.div<{ $level: string }>`
  font-size: 2rem;
  font-weight: 700;
  margin-top: 0.5rem;
  color: ${({ $level }) => {
    switch ($level) {
      case "CRITICAL": return "#dc2626";
      case "HIGH": return "#ea580c";
      case "MEDIUM": return "#d97706";
      default: return "#16a34a";
    }
  }};
`;

const LevelBadge = styled.span<{ $level: string }>`
  padding: 0.25rem 0.75rem;
  border-radius: 9999px;
  font-size: 0.85rem;
  font-weight: 600;
  color: white;
  background: ${({ $level }) => {
    switch ($level) {
      case "CRITICAL": return "#dc2626";
      case "HIGH": return "#ea580c";
      case "MEDIUM": return "#d97706";
      default: return "#16a34a";
    }
  }};
`;

interface Props {
  riskScore: RiskScore;
}

export default function RiskScoreGauge({ riskScore }: Props) {
  const { total_score, level } = riskScore;
  const angle = (total_score / 100) * 180;
  const radians = (angle * Math.PI) / 180;
  const x = 100 - 80 * Math.cos(radians);
  const y = 100 - 80 * Math.sin(radians);

  const getColor = (score: number) => {
    if (score >= 70) return "#dc2626";
    if (score >= 50) return "#ea580c";
    if (score >= 30) return "#d97706";
    return "#16a34a";
  };

  return (
    <GaugeContainer>
      <SVGWrapper>
        <svg viewBox="0 0 200 120" width="200" height="120">
          {/* Background arc */}
          <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#e5e7eb" strokeWidth="12" strokeLinecap="round" />
          {/* Score arc */}
          <path
            d={`M 20 100 A 80 80 0 ${angle > 90 ? 1 : 0} 1 ${x} ${y}`}
            fill="none"
            stroke={getColor(total_score)}
            strokeWidth="12"
            strokeLinecap="round"
          />
        </svg>
      </SVGWrapper>
      <ScoreText $level={level}>{total_score}</ScoreText>
      <LevelBadge $level={level}>{level}</LevelBadge>
    </GaugeContainer>
  );
}
