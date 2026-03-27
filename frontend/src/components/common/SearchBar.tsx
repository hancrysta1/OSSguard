import styled from "styled-components";

const Container = styled.div`
  display: flex;
  gap: 0.5rem;
  align-items: center;
`;

const Select = styled.select`
  padding: 0.6rem 0.8rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 6px;
  background: ${({ theme }) => theme.colors.surface};
  color: ${({ theme }) => theme.colors.text};
  font-size: 0.9rem;
`;

const Input = styled.input`
  flex: 1;
  padding: 0.6rem 1rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 6px;
  background: ${({ theme }) => theme.colors.surface};
  color: ${({ theme }) => theme.colors.text};
  font-size: 0.9rem;
  &:focus {
    border-color: ${({ theme }) => theme.colors.primary};
    outline: none;
  }
`;

const Button = styled.button`
  padding: 0.6rem 1.2rem;
  background: ${({ theme }) => theme.colors.primary};
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 0.9rem;
  &:hover { opacity: 0.9; }
`;

interface Props {
  category: string;
  onCategoryChange: (val: string) => void;
  value: string;
  onChange: (val: string) => void;
  onSubmit: () => void;
  placeholder?: string;
}

export default function SearchBar({ category, onCategoryChange, value, onChange, onSubmit, placeholder }: Props) {
  return (
    <Container>
      <Select value={category} onChange={(e) => onCategoryChange(e.target.value)}>
        <option value="github">GitHub</option>
        <option value="pypi">PyPI</option>
        <option value="npm">npm</option>
      </Select>
      <Input
        placeholder={placeholder || "검색..."}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && onSubmit()}
      />
      <Button onClick={onSubmit}>분석</Button>
    </Container>
  );
}
