import { useState, useEffect, useCallback } from "react";
import { emit, listen } from "@tauri-apps/api/event";
import { getCurrentWindow } from "@tauri-apps/api/window";
import type { StringRecordDto, StringXRef } from "../types/trace";

interface XRefsData {
  record: StringRecordDto;
  items: StringXRef[];
}

export default function StringXRefsPanel() {
  const [data, setData] = useState<XRefsData | null>(null);
  const [selectedSeq, setSelectedSeq] = useState<number | null>(null);

  // 先注册数据监听，再发送 ready 信号，确保不会丢失事件
  useEffect(() => {
    const unlisten = listen<XRefsData>("xrefs:init-data", (e) => {
      setData(e.payload);
    });
    // 通知父窗口：已准备好接收数据
    const winLabel = getCurrentWindow().label;
    emit(`xrefs:ready:${winLabel}`);
    return () => { unlisten.then(fn => fn()); };
  }, []);

  const handleJumpToSeq = useCallback((seq: number) => {
    setSelectedSeq(seq);
    emit("action:jump-to-seq", { seq });
  }, []);

  if (!data) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Loading...</span>
      </div>
    );
  }

  const { record, items } = data;

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* 信息栏 */}
      <div style={{
        padding: "6px 12px", fontSize: 11, fontFamily: "var(--font-mono)", flexShrink: 0,
        borderBottom: "1px solid var(--border-color)",
        display: "flex", gap: 16, flexWrap: "wrap",
      }}>
        <span>
          <span style={{ color: "var(--text-secondary)" }}>String: </span>
          <span style={{ color: "var(--syntax-string)" }}>
            "{record.content.length > 40 ? record.content.slice(0, 40) + "..." : record.content}"
          </span>
        </span>
        <span>
          <span style={{ color: "var(--text-secondary)" }}>Addr: </span>
          <span style={{ color: "var(--text-primary)" }}>{record.addr}</span>
        </span>
        <span>
          <span style={{ color: "var(--text-secondary)" }}>Total: </span>
          <span style={{ color: "var(--text-primary)" }}>{items.length}</span>
        </span>
      </div>

      {/* 表头 */}
      <div style={{
        display: "flex", padding: "4px 12px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: 11, color: "var(--text-secondary)", flexShrink: 0,
        fontFamily: "var(--font-mono)",
      }}>
        <span style={{ width: 70, flexShrink: 0 }}>Seq</span>
        <span style={{ width: 30, flexShrink: 0 }}>R/W</span>
        <span style={{ width: 110, flexShrink: 0 }}>Address</span>
        <span style={{ flex: 1 }}>Disasm</span>
      </div>

      {/* 列表 */}
      <div style={{ flex: 1, overflow: "auto" }}>
        {items.map((xref, i) => {
          const isSelected = xref.seq === selectedSeq;
          return (
            <div
              key={i}
              onClick={() => handleJumpToSeq(xref.seq)}
              style={{
                padding: "4px 12px", fontSize: 12, fontFamily: "var(--font-mono)",
                cursor: "pointer", borderBottom: "1px solid var(--border-subtle)",
                display: "flex", gap: 0,
                background: isSelected ? "var(--bg-selected)"
                  : i % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
              }}
              onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "rgba(255,255,255,0.04)"; }}
              onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = isSelected ? "var(--bg-selected)" : i % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
            >
              <span style={{ width: 70, flexShrink: 0, color: "var(--syntax-number)" }}>{xref.seq + 1}</span>
              <span style={{ width: 30, flexShrink: 0, color: xref.rw === "R" ? "var(--syntax-keyword)" : "var(--syntax-literal)" }}>{xref.rw}</span>
              <span style={{ width: 110, flexShrink: 0, color: "var(--text-secondary)" }}>{xref.insn_addr}</span>
              <span style={{ flex: 1, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{xref.disasm}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
