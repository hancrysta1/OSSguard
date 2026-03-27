import { Component, ErrorInfo, ReactNode } from "react";
import styled from "styled-components";

const ErrorContainer = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 3rem;
  text-align: center;
`;

const ErrorTitle = styled.h2`
  font-size: 1.5rem;
  margin-bottom: 1rem;
  color: ${({ theme }) => theme.colors.error};
`;

const RetryButton = styled.button`
  padding: 0.5rem 1.5rem;
  background: ${({ theme }) => theme.colors.primary};
  color: white;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 1rem;
  margin-top: 1rem;
`;

interface Props {
  children: ReactNode;
  fallback?: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ErrorBoundary caught:", error, info);
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <ErrorContainer>
            <ErrorTitle>문제가 발생했습니다</ErrorTitle>
            <p>{this.state.error?.message}</p>
            <RetryButton onClick={this.handleRetry}>다시 시도</RetryButton>
          </ErrorContainer>
        )
      );
    }
    return this.props.children;
  }
}
