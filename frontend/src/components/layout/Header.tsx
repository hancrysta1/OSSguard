import styled from "styled-components";

const HeaderBar = styled.header`
  height: 56px;
  padding: 0 1.5rem;
  display: flex;
  align-items: center;
  background: ${({ theme }) => theme.colors.headerBg};
  border-bottom: 1px solid ${({ theme }) => theme.colors.border};
`;

const MenuButton = styled.button`
  background: none;
  border: none;
  font-size: 1.5rem;
  cursor: pointer;
  color: ${({ theme }) => theme.colors.text};
  margin-right: 1rem;
  display: none;
  @media (max-width: 768px) {
    display: block;
  }
`;

const Title = styled.h1`
  font-size: 1rem;
  font-weight: 600;
  color: ${({ theme }) => theme.colors.text};
`;

interface Props {
  onToggleSidebar: () => void;
}

export default function Header({ onToggleSidebar }: Props) {
  return (
    <HeaderBar>
      <MenuButton onClick={onToggleSidebar}>&#9776;</MenuButton>
      <Title>OSSGuard - 오픈소스 공급망 보안 플랫폼</Title>
    </HeaderBar>
  );
}
