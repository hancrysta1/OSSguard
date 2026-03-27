import styled from "styled-components";
import { useExport } from "../../hooks/useExport";

const BtnGroup = styled.div`
  display: flex;
  gap: 0.5rem;
`;

const Btn = styled.button`
  padding: 0.4rem 0.8rem;
  font-size: 0.8rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 4px;
  background: ${({ theme }) => theme.colors.surface};
  color: ${({ theme }) => theme.colors.text};
  cursor: pointer;
  &:hover { background: ${({ theme }) => theme.colors.surfaceHover}; }
`;

interface Props {
  data: Record<string, unknown>[];
  filename: string;
}

export default function ExportButton({ data, filename }: Props) {
  const { exportCSV, exportJSON } = useExport();

  return (
    <BtnGroup>
      <Btn onClick={() => exportCSV(data, filename)}>CSV</Btn>
      <Btn onClick={() => exportJSON(data, filename)}>JSON</Btn>
    </BtnGroup>
  );
}
