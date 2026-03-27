import styled, { keyframes } from "styled-components";

const shimmer = keyframes`
  0% { background-position: -200px 0; }
  100% { background-position: 200px 0; }
`;

const SkeletonBox = styled.div<{ width?: string; height?: string }>`
  width: ${({ width }) => width || "100%"};
  height: ${({ height }) => height || "20px"};
  background: linear-gradient(90deg, ${({ theme }) => theme.colors.border} 25%, ${({ theme }) => theme.colors.surfaceHover} 50%, ${({ theme }) => theme.colors.border} 75%);
  background-size: 400px 100%;
  animation: ${shimmer} 1.5s infinite;
  border-radius: 4px;
  margin-bottom: 0.5rem;
`;

export function LoadingSkeleton({ lines = 5, width, height }: { lines?: number; width?: string; height?: string }) {
  return (
    <div>
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonBox key={i} width={i === lines - 1 ? "60%" : width} height={height} />
      ))}
    </div>
  );
}
