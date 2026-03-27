import React from "react";
import ReactDOM from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App";
import { ThemeContextProvider } from "./context/ThemeContext";
import { AnalysisProvider } from "./context/AnalysisContext";
import { WebSocketProvider } from "./context/WebSocketContext";
import { Toaster } from "react-hot-toast";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <BrowserRouter>
      <ThemeContextProvider>
        <AnalysisProvider>
          <WebSocketProvider>
            <App />
            <Toaster position="top-right" />
          </WebSocketProvider>
        </AnalysisProvider>
      </ThemeContextProvider>
    </BrowserRouter>
  </React.StrictMode>
);
