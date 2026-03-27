import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from "recharts";
import { SeverityDistribution } from "../../types/analysis";
import { useTheme } from "../../context/ThemeContext";

const COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#d97706",
  LOW: "#2563eb",
  UNKNOWN: "#6b7280",
};

interface Props {
  data: SeverityDistribution[];
}

export default function SeverityPieChart({ data }: Props) {
  const { theme } = useTheme();
  const filtered = data.filter((d) => d.count > 0);

  if (filtered.length === 0) {
    return <p style={{ color: theme.colors.textSecondary, textAlign: "center" }}>취약점 없음</p>;
  }

  return (
    <ResponsiveContainer width="100%" height={300}>
      <PieChart>
        <Pie
          data={filtered}
          dataKey="count"
          nameKey="level"
          cx="50%"
          cy="50%"
          outerRadius={100}
          label={({ level, count }) => `${level}: ${count}`}
        >
          {filtered.map((entry) => (
            <Cell key={entry.level} fill={COLORS[entry.level] || "#6b7280"} />
          ))}
        </Pie>
        <Tooltip />
        <Legend />
      </PieChart>
    </ResponsiveContainer>
  );
}
