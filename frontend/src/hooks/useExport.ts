import { useCallback } from "react";

export function useExport() {
  const exportCSV = useCallback((data: Record<string, unknown>[], filename: string) => {
    if (!data.length) return;
    const headers = Object.keys(data[0]);
    const csv = [
      headers.join(","),
      ...data.map((row) =>
        headers.map((h) => {
          const val = row[h];
          const str = typeof val === "object" ? JSON.stringify(val) : String(val ?? "");
          return `"${str.replace(/"/g, '""')}"`;
        }).join(",")
      ),
    ].join("\n");

    const blob = new Blob(["\uFEFF" + csv], { type: "text/csv;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${filename}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  const exportJSON = useCallback((data: unknown, filename: string) => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${filename}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, []);

  return { exportCSV, exportJSON };
}
