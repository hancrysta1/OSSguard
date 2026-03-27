import { useState, useMemo } from "react";
import styled from "styled-components";

const TableWrapper = styled.div`
  overflow-x: auto;
  border-radius: 8px;
  border: 1px solid ${({ theme }) => theme.colors.border};
`;

const StyledTable = styled.table`
  width: 100%;
  border-collapse: collapse;
`;

const Th = styled.th<{ $sortable?: boolean }>`
  padding: 0.75rem 1rem;
  text-align: left;
  background: ${({ theme }) => theme.colors.surfaceHover};
  color: ${({ theme }) => theme.colors.textSecondary};
  font-weight: 600;
  font-size: 0.85rem;
  cursor: ${({ $sortable }) => ($sortable ? "pointer" : "default")};
  user-select: none;
  white-space: nowrap;

  &:hover {
    background: ${({ theme, $sortable }) => ($sortable ? theme.colors.border : theme.colors.surfaceHover)};
  }
`;

const Td = styled.td`
  padding: 0.75rem 1rem;
  border-top: 1px solid ${({ theme }) => theme.colors.border};
  font-size: 0.9rem;
`;

const FilterInput = styled.input`
  width: 100%;
  padding: 0.5rem 0.75rem;
  margin-bottom: 0.75rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 6px;
  background: ${({ theme }) => theme.colors.surface};
  color: ${({ theme }) => theme.colors.text};
  font-size: 0.9rem;
`;

const Pagination = styled.div`
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 0.5rem;
  padding: 0.75rem;
`;

const PageButton = styled.button<{ $active?: boolean }>`
  padding: 0.35rem 0.75rem;
  border: 1px solid ${({ theme }) => theme.colors.border};
  border-radius: 4px;
  background: ${({ $active, theme }) => ($active ? theme.colors.primary : theme.colors.surface)};
  color: ${({ $active, theme }) => ($active ? "white" : theme.colors.text)};
  cursor: pointer;
  font-size: 0.85rem;
`;

interface Column<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  render?: (value: T[keyof T], row: T) => React.ReactNode;
}

interface Props<T> {
  data: T[];
  columns: Column<T>[];
  pageSize?: number;
  filterable?: boolean;
}

export default function DataTable<T extends Record<string, unknown>>({
  data,
  columns,
  pageSize = 10,
  filterable = true,
}: Props<T>) {
  const [sortKey, setSortKey] = useState<keyof T | null>(null);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");
  const [filter, setFilter] = useState("");
  const [page, setPage] = useState(1);

  const filtered = useMemo(() => {
    if (!filter) return data;
    const lower = filter.toLowerCase();
    return data.filter((row) =>
      columns.some((col) => String(row[col.key] ?? "").toLowerCase().includes(lower))
    );
  }, [data, filter, columns]);

  const sorted = useMemo(() => {
    if (!sortKey) return filtered;
    return [...filtered].sort((a, b) => {
      const aVal = String(a[sortKey] ?? "");
      const bVal = String(b[sortKey] ?? "");
      return sortDir === "asc" ? aVal.localeCompare(bVal) : bVal.localeCompare(aVal);
    });
  }, [filtered, sortKey, sortDir]);

  const totalPages = Math.ceil(sorted.length / pageSize);
  const pageData = sorted.slice((page - 1) * pageSize, page * pageSize);

  const handleSort = (key: keyof T) => {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  return (
    <div>
      {filterable && (
        <FilterInput
          placeholder="검색..."
          value={filter}
          onChange={(e) => { setFilter(e.target.value); setPage(1); }}
        />
      )}
      <TableWrapper>
        <StyledTable>
          <thead>
            <tr>
              {columns.map((col) => (
                <Th
                  key={String(col.key)}
                  $sortable={col.sortable}
                  onClick={() => col.sortable && handleSort(col.key)}
                >
                  {col.label}
                  {sortKey === col.key && (sortDir === "asc" ? " \u2191" : " \u2193")}
                </Th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageData.length === 0 ? (
              <tr><Td colSpan={columns.length} style={{ textAlign: "center" }}>데이터 없음</Td></tr>
            ) : (
              pageData.map((row, i) => (
                <tr key={i}>
                  {columns.map((col) => (
                    <Td key={String(col.key)}>
                      {col.render ? col.render(row[col.key], row) : String(row[col.key] ?? "")}
                    </Td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </StyledTable>
      </TableWrapper>
      {totalPages > 1 && (
        <Pagination>
          <PageButton onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}>
            이전
          </PageButton>
          {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
            const start = Math.max(1, Math.min(page - 2, totalPages - 4));
            const p = start + i;
            return p <= totalPages ? (
              <PageButton key={p} $active={p === page} onClick={() => setPage(p)}>
                {p}
              </PageButton>
            ) : null;
          })}
          <PageButton onClick={() => setPage((p) => Math.min(totalPages, p + 1))} disabled={page === totalPages}>
            다음
          </PageButton>
        </Pagination>
      )}
    </div>
  );
}
