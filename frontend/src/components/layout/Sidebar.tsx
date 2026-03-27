import { useLocation, useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useTheme } from "../../context/ThemeContext";

const SidebarContainer = styled.nav`
  width: 230px;
  height: 100vh;
  background: ${({ theme }) => theme.colors.sidebarBg};
  display: flex;
  flex-direction: column;
  position: fixed;
  left: 0;
  top: 0;
`;

const Logo = styled.div`
  padding: 1.5rem 1rem;
  font-size: 1.4rem;
  font-weight: 700;
  color: white;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
`;

const Section = styled.div`
  padding: 0.75rem 0;
`;

const SectionTitle = styled.div`
  padding: 0.5rem 1rem;
  font-size: 0.7rem;
  text-transform: uppercase;
  letter-spacing: 0.1em;
  color: ${({ theme }) => theme.colors.sidebarText};
  opacity: 0.6;
`;

const NavItem = styled.div<{ $active?: boolean }>`
  padding: 0.6rem 1rem;
  margin: 0.15rem 0.5rem;
  border-radius: 6px;
  font-size: 0.9rem;
  cursor: pointer;
  color: ${({ $active, theme }) => ($active ? "white" : theme.colors.sidebarText)};
  background: ${({ $active, theme }) => ($active ? theme.colors.sidebarActive : "transparent")};
  transition: all 0.15s;
  &:hover {
    background: ${({ $active, theme }) => ($active ? theme.colors.sidebarActive : "rgba(255,255,255,0.05)")};
  }
`;

const Spacer = styled.div`
  flex: 1;
`;

const ThemeToggle = styled.div`
  padding: 1rem;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
`;

const ToggleBtn = styled.button`
  width: 100%;
  padding: 0.5rem;
  border: 1px solid rgba(255, 255, 255, 0.2);
  border-radius: 6px;
  background: transparent;
  color: ${({ theme }) => theme.colors.sidebarText};
  cursor: pointer;
  font-size: 0.85rem;
  &:hover { background: rgba(255, 255, 255, 0.05); }
`;

export default function Sidebar() {
  const location = useLocation();
  const navigate = useNavigate();
  const { isDark, toggleTheme } = useTheme();
  const path = location.pathname;
  const params = new URLSearchParams(location.search);
  const tab = params.get("tab") || "overview";

  const navTo = (path: string) => navigate(path);
  const navToTab = (t: string) => {
    const currentParams = new URLSearchParams(location.search);
    currentParams.set("tab", t);
    navigate(`/analysis?${currentParams.toString()}`);
  };

  const isAnalysis = path === "/analysis";

  return (
    <SidebarContainer>
      <Logo onClick={() => navTo("/")}>OSSGuard</Logo>

      <Section>
        <NavItem $active={path === "/"} onClick={() => navTo("/")}>
          Home
        </NavItem>
      </Section>

      {isAnalysis && (
        <Section>
          <SectionTitle>분석</SectionTitle>
          <NavItem $active={tab === "overview"} onClick={() => navToTab("overview")}>
            {"\uD83D\uDCCA"} 종합 분석
          </NavItem>
          <NavItem $active={tab === "sbom"} onClick={() => navToTab("sbom")}>
            {"\uD83D\uDCE6"} SBOM 분석
          </NavItem>
          <NavItem $active={tab === "vulnerability"} onClick={() => navToTab("vulnerability")}>
            {"\u26A0\uFE0F"} 취약점 분석
          </NavItem>
          <NavItem $active={tab === "update"} onClick={() => navToTab("update")}>
            {"\uD83D\uDD04"} 패키지 업데이트
          </NavItem>
          <NavItem $active={tab === "detection"} onClick={() => navToTab("detection")}>
            {"\uD83D\uDEE1\uFE0F"} 악성 코드 탐지
          </NavItem>
          <NavItem $active={tab === "ai"} onClick={() => navToTab("ai")}>
            {"\uD83E\uDD16"} AI 분석
          </NavItem>
        </Section>
      )}

      <Spacer />

      <ThemeToggle>
        <ToggleBtn onClick={toggleTheme}>
          {isDark ? "Light Mode" : "Dark Mode"}
        </ToggleBtn>
      </ThemeToggle>
    </SidebarContainer>
  );
}
