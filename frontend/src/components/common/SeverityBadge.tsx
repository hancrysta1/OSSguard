import styled from "styled-components";

const Badge = styled.span<{ $severity: string }>`
  display: inline-block;
  padding: 0.2rem 0.6rem;
  border-radius: 9999px;
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: uppercase;
  color: white;
  background-color: ${({ $severity, theme }) => {
    switch ($severity.toUpperCase()) {
      case "CRITICAL": return theme.colors.critical;
      case "HIGH": return theme.colors.high;
      case "MEDIUM": return theme.colors.medium;
      case "LOW": return theme.colors.low;
      default: return theme.colors.unknown;
    }
  }};
`;

export default function SeverityBadge({ severity }: { severity: string }) {
  return <Badge $severity={severity}>{severity}</Badge>;
}
