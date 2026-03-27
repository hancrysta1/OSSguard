import { createContext, useContext, useState, useCallback, ReactNode } from "react";
import { ThemeProvider as SCThemeProvider } from "styled-components";
import { lightTheme, darkTheme, Theme } from "../styles/theme";
import GlobalStyles from "../styles/GlobalStyles";

interface ThemeCtx {
  theme: Theme;
  isDark: boolean;
  toggleTheme: () => void;
}

const ThemeCtxDefault: ThemeCtx = {
  theme: lightTheme,
  isDark: false,
  toggleTheme: () => {},
};

const ThemeContext = createContext<ThemeCtx>(ThemeCtxDefault);

export function ThemeContextProvider({ children }: { children: ReactNode }) {
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem("ossguard-theme");
    return saved === "dark";
  });

  const theme = isDark ? darkTheme : lightTheme;

  const toggleTheme = useCallback(() => {
    setIsDark((prev) => {
      const next = !prev;
      localStorage.setItem("ossguard-theme", next ? "dark" : "light");
      return next;
    });
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, isDark, toggleTheme }}>
      <SCThemeProvider theme={theme}>
        <GlobalStyles />
        {children}
      </SCThemeProvider>
    </ThemeContext.Provider>
  );
}

export const useTheme = () => useContext(ThemeContext);
