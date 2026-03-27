export interface Theme {
  name: string;
  colors: {
    bg: string;
    surface: string;
    surfaceHover: string;
    border: string;
    text: string;
    textSecondary: string;
    primary: string;
    primaryLight: string;
    sidebarBg: string;
    sidebarText: string;
    sidebarActive: string;
    headerBg: string;
    critical: string;
    high: string;
    medium: string;
    low: string;
    unknown: string;
    success: string;
    error: string;
  };
  shadows: {
    sm: string;
    md: string;
  };
}

export const lightTheme: Theme = {
  name: "light",
  colors: {
    bg: "#f5f7fa",
    surface: "#ffffff",
    surfaceHover: "#f0f4f8",
    border: "#e2e8f0",
    text: "#1a202c",
    textSecondary: "#718096",
    primary: "#2563eb",
    primaryLight: "#dbeafe",
    sidebarBg: "#1e293b",
    sidebarText: "#94a3b8",
    sidebarActive: "#3b82f6",
    headerBg: "#ffffff",
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#d97706",
    low: "#2563eb",
    unknown: "#6b7280",
    success: "#16a34a",
    error: "#dc2626",
  },
  shadows: {
    sm: "0 1px 3px rgba(0,0,0,0.1)",
    md: "0 4px 6px rgba(0,0,0,0.1)",
  },
};

export const darkTheme: Theme = {
  name: "dark",
  colors: {
    bg: "#0f172a",
    surface: "#1e293b",
    surfaceHover: "#334155",
    border: "#334155",
    text: "#f1f5f9",
    textSecondary: "#94a3b8",
    primary: "#3b82f6",
    primaryLight: "#1e3a5f",
    sidebarBg: "#0f172a",
    sidebarText: "#94a3b8",
    sidebarActive: "#3b82f6",
    headerBg: "#1e293b",
    critical: "#ef4444",
    high: "#f97316",
    medium: "#eab308",
    low: "#3b82f6",
    unknown: "#6b7280",
    success: "#22c55e",
    error: "#ef4444",
  },
  shadows: {
    sm: "0 1px 3px rgba(0,0,0,0.3)",
    md: "0 4px 6px rgba(0,0,0,0.3)",
  },
};
