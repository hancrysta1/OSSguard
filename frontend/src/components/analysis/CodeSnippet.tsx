import styled from "styled-components";

const Container = styled.div`
  background: #1e1e2e;
  border-radius: 6px;
  overflow: hidden;
  margin: 0.5rem 0;
  font-family: "Fira Code", "Consolas", monospace;
  font-size: 0.82rem;
`;

const Header = styled.div`
  padding: 0.5rem 0.75rem;
  background: #181825;
  color: #a6adc8;
  font-size: 0.75rem;
  border-bottom: 1px solid #313244;
`;

const Lines = styled.div`
  padding: 0.5rem 0;
  overflow-x: auto;
`;

const Line = styled.div<{ $danger?: boolean }>`
  display: flex;
  padding: 0.1rem 0.75rem;
  background: ${({ $danger }) => ($danger ? "rgba(243, 139, 168, 0.15)" : "transparent")};

  &:hover {
    background: rgba(255, 255, 255, 0.05);
  }
`;

const LineNumber = styled.span`
  color: #585b70;
  min-width: 2.5rem;
  text-align: right;
  margin-right: 1rem;
  user-select: none;
`;

const LineContent = styled.span`
  color: #cdd6f4;
  white-space: pre;
`;

interface CodeLine {
  line: number;
  code: string;
  isDangerous?: boolean;
}

interface Props {
  fileName?: string;
  lines: CodeLine[];
}

export default function CodeSnippet({ fileName, lines }: Props) {
  if (!lines.length) return null;

  return (
    <Container>
      {fileName && <Header>{fileName}</Header>}
      <Lines>
        {lines.map((l, i) => (
          <Line key={i} $danger={l.isDangerous}>
            <LineNumber>{l.line}</LineNumber>
            <LineContent>{l.code}</LineContent>
          </Line>
        ))}
      </Lines>
    </Container>
  );
}
