import { useState } from "react";
import { Outlet } from "react-router-dom";
import styled from "styled-components";
import Sidebar from "./Sidebar";
import Header from "./Header";

const LayoutWrapper = styled.div`
  display: flex;
  min-height: 100vh;
`;

const SidebarArea = styled.aside<{ $collapsed: boolean }>`
  width: ${({ $collapsed }) => ($collapsed ? "0" : "230px")};
  overflow: hidden;
  transition: width 0.2s;
  flex-shrink: 0;

  @media (max-width: 768px) {
    position: fixed;
    z-index: 100;
    height: 100vh;
  }
`;

const MainArea = styled.div`
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
`;

const ContentArea = styled.main`
  flex: 1;
  padding: 1.5rem;
  overflow-y: auto;
`;

export default function AppLayout() {
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  return (
    <LayoutWrapper>
      <SidebarArea $collapsed={sidebarCollapsed}>
        <Sidebar />
      </SidebarArea>
      <MainArea>
        <Header onToggleSidebar={() => setSidebarCollapsed((c) => !c)} />
        <ContentArea>
          <Outlet />
        </ContentArea>
      </MainArea>
    </LayoutWrapper>
  );
}
