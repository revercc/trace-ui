import React, { useState, useEffect, useRef, useCallback } from "react";
import { invoke } from "@tauri-apps/api/core";
import { emit, emitTo, listen } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";
import { useVirtualScroll } from "../hooks/useVirtualScroll";
import { useResizableColumn } from "../hooks/useResizableColumn";
import VirtualScrollArea from "./VirtualScrollArea";
import Minimap, { MINIMAP_WIDTH } from "./Minimap";
import ContextMenu, { ContextMenuItem } from "./ContextMenu";
import type { StringRecordDto, StringsResult, StringXRef, TraceLine } from "../types/trace";
import type { ResolvedRow } from "../hooks/useFoldState";


const PAGE_SIZE = 500;
const ROW_HEIGHT = 22;
const HISTORY_KEY = "strings-search-history";
const MAX_HISTORY = 20;

interface Props {
  sessionId: string | null;
  isPhase2Ready: boolean;
  onJumpToSeq: (seq: number) => void;
  stringsScanning?: boolean;
}

export default function StringsPanel({ sessionId, isPhase2Ready, onJumpToSeq, stringsScanning }: Props) {
  const rwCol = useResizableColumn(36, "left", 28, "strings:rw");
  const seqCol = useResizableColumn(70, "right", 40, "strings:seq");
  const addrCol = useResizableColumn(156, "right", 50, "strings:addr");
  const encCol = useResizableColumn(56, "left", 30, "strings:enc");
  const lenCol = useResizableColumn(44, "left", 30, "strings:len");
  const xrefsCol = useResizableColumn(56, "left", 30, "strings:xrefs");

  const HANDLE_STYLE: React.CSSProperties = {
    width: 8, cursor: "col-resize", flexShrink: 0,
    display: "flex", alignItems: "center", justifyContent: "center",
  };

  const [total, setTotal] = useState(0);
  const [minLen, setMinLen] = useState(4);
  const [search, setSearch] = useState("");
  const [selectedIdx, setSelectedIdx] = useState<number | null>(null);
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; record: StringRecordDto } | null>(null);
  const [pageVersion, setPageVersion] = useState(0);
  const loading = total === 0 && pageVersion === 0;

  const [searchHistory, setSearchHistory] = useState<string[]>(() => {
    try { return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]"); } catch { return []; }
  });
  const [showHistory, setShowHistory] = useState(false);
  const searchWrapperRef = useRef<HTMLDivElement>(null);
  const searchTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const minLenTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  // ── 按页缓存（方案 C：index→seq 映射与详情分离） ──
  const pageCacheRef = useRef<Map<number, StringRecordDto[]>>(new Map());
  const loadingPagesRef = useRef<Set<number>>(new Set());

  const getRecordAtIndex = useCallback((index: number): StringRecordDto | undefined => {
    const page = Math.floor(index / PAGE_SIZE);
    const records = pageCacheRef.current.get(page);
    return records?.[index % PAGE_SIZE];
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageVersion]);

  const loadPage = useCallback(async (pageNum: number) => {
    if (pageCacheRef.current.has(pageNum) || loadingPagesRef.current.has(pageNum)) return;
    if (!sessionId || !isPhase2Ready) return;
    loadingPagesRef.current.add(pageNum);
    try {
      const result = await invoke<StringsResult>("get_strings", {
        sessionId,
        minLen,
        offset: pageNum * PAGE_SIZE,
        limit: PAGE_SIZE,
        search: search || null,
      });
      pageCacheRef.current.set(pageNum, result.strings);
      setTotal(result.total);
      setPageVersion(v => v + 1);
    } catch (e) {
      console.error("get_strings failed:", e);
    } finally {
      loadingPagesRef.current.delete(pageNum);
    }
  }, [sessionId, isPhase2Ready, minLen, search]);

  const ensureRange = useCallback((startIdx: number, endIdx: number) => {
    if (total === 0) return;
    const startPage = Math.floor(Math.max(0, startIdx) / PAGE_SIZE);
    const endPage = Math.floor(Math.min(endIdx, total - 1) / PAGE_SIZE);
    for (let p = startPage; p <= endPage; p++) {
      loadPage(p);
    }
  }, [total, loadPage]);

  // ── 初始加载 + 搜索/minLen 变化时重置缓存 ──
  useEffect(() => {
    pageCacheRef.current.clear();
    loadingPagesRef.current.clear();
    setPageVersion(v => v + 1);
    setTotal(0);
    loadPage(0);
  }, [loadPage]);

  // ── scanning 结束后自动刷新 ──
  const prevScanningRef = useRef(false);
  useEffect(() => {
    if (prevScanningRef.current && !stringsScanning) {
      pageCacheRef.current.clear();
      loadingPagesRef.current.clear();
      setPageVersion(v => v + 1);
      setTotal(0);
      loadPage(0);
    }
    prevScanningRef.current = !!stringsScanning;
  }, [stringsScanning, loadPage]);

  // ── 搜索 debounce ──
  const [searchInput, setSearchInput] = useState("");
  useEffect(() => {
    clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      setSearch(searchInput);
      // 记录搜索历史
      if (searchInput.trim()) {
        setSearchHistory(prev => {
          const next = [searchInput.trim(), ...prev.filter(h => h !== searchInput.trim())].slice(0, MAX_HISTORY);
          localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
          return next;
        });
      }
    }, 300);
    return () => clearTimeout(searchTimerRef.current);
  }, [searchInput]);

  // ── 搜索历史：点击外部关闭 ──
  useEffect(() => {
    if (!showHistory) return;
    const handler = (e: MouseEvent) => {
      if (searchWrapperRef.current && !searchWrapperRef.current.contains(e.target as Node)) {
        setShowHistory(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showHistory]);

  const removeHistoryItem = useCallback((item: string) => {
    setSearchHistory(prev => {
      const next = prev.filter(h => h !== item);
      localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
      return next;
    });
  }, []);

  const clearAllHistory = useCallback(() => {
    setSearchHistory([]);
    localStorage.removeItem(HISTORY_KEY);
    setShowHistory(false);
  }, []);

  const filteredHistory = searchInput.trim()
    ? searchHistory.filter(h => h !== searchInput.trim() && h.toLowerCase().includes(searchInput.toLowerCase()))
    : searchHistory;

  // ── minLen debounce ──
  const [minLenInput, setMinLenInput] = useState(4);
  useEffect(() => {
    clearTimeout(minLenTimerRef.current);
    minLenTimerRef.current = setTimeout(() => setMinLen(minLenInput), 200);
    return () => clearTimeout(minLenTimerRef.current);
  }, [minLenInput]);

  // ── 虚拟滚动 ──
  const vs = useVirtualScroll({ totalCount: total, rowHeight: ROW_HEIGHT, overscan: 20 });

  // ── 按需加载：可视范围变化时确保对应页已加载 ──
  useEffect(() => {
    if (total === 0) return;
    ensureRange(vs.startIdx, vs.endIdx);
  }, [vs.startIdx, vs.endIdx, total, ensureRange]);

  // ── Minimap 采样页预加载：逐页加载 minimap 需要的稀疏页 ──
  useEffect(() => {
    if (total === 0 || vs.containerHeight === 0) return;
    const mmRows = Math.floor(vs.containerHeight / 2); // MINIMAP_ROW_HEIGHT = 2
    if (mmRows === 0) return;
    const neededPages = new Set<number>();
    for (let i = 0; i < mmRows; i++) {
      const vi = Math.round(i * total / mmRows);
      if (vi >= total) break;
      neededPages.add(Math.floor(vi / PAGE_SIZE));
    }
    for (const p of neededPages) {
      if (!pageCacheRef.current.has(p) && !loadingPagesRef.current.has(p)) {
        loadPage(p);
        return; // 每次只加载一页，加载完成后 pageVersion 变化会重新触发此 effect
      }
    }
  }, [total, vs.containerHeight, pageVersion, loadPage]);

  // ── 点击行：选中 + 跳转 trace 表 ──
  const handleRowClick = useCallback((record: StringRecordDto) => {
    setSelectedIdx(record.idx);
    onJumpToSeq(record.seq);
  }, [onJumpToSeq]);

  // ── 双击行跳转到 trace 表对应汇编指令行 ──
  const handleRowDoubleClick = useCallback((record: StringRecordDto) => {
    onJumpToSeq(record.seq);
  }, [onJumpToSeq]);

  // ── 右键菜单（同时选中该行） ──
  const handleContextMenu = useCallback((e: React.MouseEvent, record: StringRecordDto) => {
    e.preventDefault();
    setSelectedIdx(record.idx);
    setContextMenu({ x: e.clientX, y: e.clientY, record });
  }, []);

  const handleCopyString = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.record.content);
    setContextMenu(null);
  }, [contextMenu]);

  const handleCopyAddr = useCallback(() => {
    if (contextMenu) navigator.clipboard.writeText(contextMenu.record.addr);
    setContextMenu(null);
  }, [contextMenu]);

  const handleViewInMemory = useCallback(() => {
    if (!contextMenu) return;
    const { addr, seq } = contextMenu.record;
    setContextMenu(null);
    emit("action:view-in-memory", { addr, seq });
  }, [contextMenu]);

  const handleViewDetail = useCallback(async () => {
    if (!contextMenu) return;
    const record = contextMenu.record;
    setContextMenu(null);
    const winLabel = `panel-string-detail-${Date.now()}`;
    const unlisten = await listen(`string-detail:ready:${winLabel}`, () => {
      emitTo(winLabel, "string-detail:init-data", record);
      unlisten();
    });
    new WebviewWindow(winLabel, {
      url: `index.html?panel=string-detail`,
      title: `String: ${record.content.slice(0, 40)}`,
      width: 588,
      minWidth: 588,
      maxWidth: 588,
      height: 580,
      decorations: false,
      transparent: true,
    });
  }, [contextMenu]);

  const handleShowXrefs = useCallback(async () => {
    if (!contextMenu || !sessionId) return;
    const record = contextMenu.record;
    setContextMenu(null);
    try {
      const items = await invoke<StringXRef[]>("get_string_xrefs", {
        sessionId,
        addr: record.addr,
        byteLen: record.byte_len,
      });
      const winLabel = `panel-string-xrefs-${Date.now()}`;
      // 先监听子窗口 ready 信号，收到后再发送数据
      const unlisten = await listen(`xrefs:ready:${winLabel}`, () => {
        emitTo(winLabel, "xrefs:init-data", { record, items });
        unlisten();
      });
      new WebviewWindow(winLabel, {
        url: `index.html?panel=string-xrefs`,
        title: `XRefs: ${record.content.slice(0, 30)}`,
        width: 520,
        height: 400,
        decorations: false,
        transparent: true,
      });
    } catch (e) {
      console.error("get_string_xrefs failed:", e);
    }
  }, [contextMenu, sessionId]);

  // ── Minimap 回调 ──
  const handleScrollbarScroll = useCallback((row: number) => {
    vs.scrollToRow(row);
  }, [vs.scrollToRow]);

  const resolveVirtualIndex = useCallback((vi: number): ResolvedRow => {
    const record = getRecordAtIndex(vi);
    return { type: "line", seq: record?.seq ?? -1 } as ResolvedRow;
  }, [getRecordAtIndex]);

  const getLines = useCallback(async (seqs: number[]): Promise<TraceLine[]> => {
    const seqMap = new Map<number, StringRecordDto>();
    for (const [, records] of pageCacheRef.current) {
      for (const r of records) seqMap.set(r.seq, r);
    }
    return seqs
      .map(seq => seqMap.get(seq))
      .filter((r): r is StringRecordDto => r !== undefined)
      .map(r => ({
        seq: r.seq,
        address: r.addr,
        so_offset: r.addr,
        so_name: null,
        disasm: r.content,
        changes: r.rw,
        reg_before: "",
        mem_rw: r.rw,
        mem_addr: null,
        mem_size: null,
        raw: "",
        call_info: null,
      }));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pageVersion]);

  const selectedSeq = selectedIdx != null
    ? getRecordAtIndex(
        // 找到 selectedIdx 对应的全局 index —— 向缓存中查找
        (() => {
          for (const [pageNum, records] of pageCacheRef.current) {
            const idx = records.findIndex(r => r.idx === selectedIdx);
            if (idx >= 0) return pageNum * PAGE_SIZE + idx;
          }
          return -1;
        })()
      )?.seq ?? null
    : null;

  if (!isPhase2Ready) {
    return (
      <div style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center" }}>
        <span style={{ color: "var(--text-secondary)", fontSize: 12 }}>Index not ready</span>
      </div>
    );
  }

  return (
    <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      {/* 工具栏 */}
      <div style={{
        display: "flex", alignItems: "center", gap: 8, padding: "4px 8px",
        borderBottom: "1px solid var(--border-color)", flexShrink: 0,
      }}>
        <div ref={searchWrapperRef} style={{ position: "relative", width: 420, flexShrink: 0 }}>
          <input
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            onFocus={() => setShowHistory(true)}
            placeholder="Search strings..."
            style={{
              width: "100%", background: "var(--input-bg)", border: "1px solid var(--border-color)",
              color: "var(--text-primary)", padding: "3px 24px 3px 8px", borderRadius: 3, fontSize: 12,
            }}
          />
          {searchInput && (
            <span
              onClick={() => { setSearchInput(""); setShowHistory(false); }}
              style={{
                position: "absolute", right: 4, top: "50%", transform: "translateY(-50%)",
                cursor: "pointer", color: "var(--text-secondary)", fontSize: 14, lineHeight: 1,
                width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center",
                borderRadius: "50%",
              }}
              onMouseEnter={e => (e.currentTarget.style.color = "var(--text-primary)")}
              onMouseLeave={e => (e.currentTarget.style.color = "var(--text-secondary)")}
            >×</span>
          )}
          {showHistory && filteredHistory.length > 0 && (
            <div style={{
              position: "absolute", top: "100%", left: 0, width: "100%", marginTop: 2,
              background: "var(--bg-dialog)", border: "1px solid var(--border-color)",
              borderRadius: 4, zIndex: 100, maxHeight: 200, overflowY: "auto",
              boxShadow: "0 4px 12px rgba(0,0,0,0.4)",
            }}>
              {filteredHistory.map(item => (
                <div
                  key={item}
                  style={{
                    display: "flex", alignItems: "center", padding: "4px 8px", fontSize: 12,
                    cursor: "pointer", color: "var(--text-primary)",
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = "var(--bg-selected)")}
                  onMouseLeave={e => (e.currentTarget.style.background = "transparent")}
                  onClick={() => { setSearchInput(item); setShowHistory(false); }}
                >
                  <span style={{ flex: 1, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{item}</span>
                  <span
                    onClick={e => { e.stopPropagation(); removeHistoryItem(item); }}
                    style={{
                      marginLeft: 4, color: "var(--text-secondary)", fontSize: 13, lineHeight: 1,
                      width: 16, height: 16, display: "flex", alignItems: "center", justifyContent: "center",
                      borderRadius: "50%", flexShrink: 0, cursor: "pointer",
                    }}
                    onMouseEnter={e => (e.currentTarget.style.color = "var(--text-primary)")}
                    onMouseLeave={e => (e.currentTarget.style.color = "var(--text-secondary)")}
                  >×</span>
                </div>
              ))}
              <div
                style={{
                  padding: "4px 8px", fontSize: 11, color: "var(--text-secondary)",
                  borderTop: "1px solid var(--border-color)", cursor: "pointer", textAlign: "center",
                }}
                onMouseEnter={e => { e.currentTarget.style.background = "var(--bg-selected)"; e.currentTarget.style.color = "var(--text-primary)"; }}
                onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = "var(--text-secondary)"; }}
                onClick={clearAllHistory}
              >Clear All</div>
            </div>
          )}
        </div>
        <span style={{ flex: 1 }} />
        <span style={{ color: "var(--text-tertiary)", fontSize: 11, whiteSpace: "nowrap" }}>
          {total.toLocaleString()} strings
        </span>
        <span style={{ color: "var(--text-secondary)", fontSize: 11, whiteSpace: "nowrap" }}>Min len:</span>
        <input
          type="range" min={2} max={32} value={minLenInput}
          onChange={e => setMinLenInput(Number(e.target.value))}
          style={{ width: 120 }}
        />
        <span style={{ color: "var(--text-secondary)", fontSize: 11, minWidth: 16 }}>{minLenInput}</span>
      </div>

      {/* 表头 */}
      <div style={{
        display: "flex", padding: "4px 8px",
        background: "var(--bg-secondary)",
        borderBottom: "1px solid var(--border-color)",
        fontSize: "var(--font-size-sm)", color: "var(--text-secondary)", flexShrink: 0,
      }}>
        <span style={{ width: rwCol.width, flexShrink: 0 }}>R/W</span>
        <div onMouseDown={rwCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: seqCol.width, flexShrink: 0 }}>Seq</span>
        <div onMouseDown={seqCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: addrCol.width, flexShrink: 0 }}>Address</span>
        <div onMouseDown={addrCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ flex: 1 }}>Content</span>
        <div onMouseDown={encCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: encCol.width, flexShrink: 0 }}>Enc</span>
        <div onMouseDown={lenCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: lenCol.width, flexShrink: 0 }}>Len</span>
        <div onMouseDown={xrefsCol.onMouseDown} style={HANDLE_STYLE}><div style={{ width: 1, height: "100%", background: "var(--border-color)" }} /></div>
        <span style={{ width: xrefsCol.width, flexShrink: 0 }}>XRefs</span>
        <span style={{ width: MINIMAP_WIDTH + 12, flexShrink: 0 }}></span>
      </div>

      {/* 虚拟滚动列表 */}
      <VirtualScrollArea
        containerRef={vs.containerRef}
        containerStyle={vs.containerStyle}
        containerHeight={vs.containerHeight}
        scrollbarProps={vs.scrollbarProps}
        gutterWidth={MINIMAP_WIDTH + 12}
        gutterContent={
          <Minimap
            virtualTotalRows={total}
            visibleRows={vs.visibleRows}
            currentRow={vs.currentRow}
            maxRow={vs.maxRow}
            height={vs.containerHeight}
            onScroll={handleScrollbarScroll}
            resolveVirtualIndex={resolveVirtualIndex}
            getLines={getLines}
            selectedSeq={selectedSeq}
            rightOffset={12}
            showSoName={false}
            showAbsAddress={false}
          />
        }
      >
        {Array.from({ length: Math.max(0, vs.endIdx - vs.startIdx + 1) }, (_, i) => {
          const index = vs.startIdx + i;
          const record = getRecordAtIndex(index);
          if (!record) {
            return (
              <div
                key={index}
                style={{
                  position: "absolute", top: 0, left: 0, width: "100%", height: ROW_HEIGHT,
                  transform: `translateY(${vs.getItemY(index)}px)`,
                  display: "flex", alignItems: "center", padding: "0 8px",
                  background: index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
                }}
              >
                <span style={{ color: "var(--text-disabled, #555)", fontSize: "var(--font-size-sm)" }}>Loading...</span>
              </div>
            );
          }
          const isSelected = record.idx === selectedIdx;
          return (
            <div
              key={index}
              onClick={() => handleRowClick(record)}
              onDoubleClick={() => handleRowDoubleClick(record)}
              onContextMenu={e => handleContextMenu(e, record)}
              style={{
                position: "absolute", top: 0, left: 0, width: "100%", height: ROW_HEIGHT,
                transform: `translateY(${vs.getItemY(index)}px)`,
                display: "flex", alignItems: "center", padding: "0 8px",
                cursor: "pointer", fontSize: "var(--font-size-sm)",
                background: isSelected ? "var(--bg-selected)"
                  : index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)",
              }}
              onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = "var(--bg-hover)"; }}
              onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = index % 2 === 0 ? "var(--bg-row-even)" : "var(--bg-row-odd)"; }}
            >
              <span style={{ width: rwCol.width, flexShrink: 0, color: record.rw === "R" ? "var(--syntax-keyword)" : "var(--syntax-number)" }}>{record.rw}</span>
              <span style={{ width: 8, flexShrink: 0 }} />
              <span style={{ width: seqCol.width, flexShrink: 0, color: "var(--syntax-number)" }}>{record.seq + 1}</span>
              <span style={{ width: 8, flexShrink: 0 }} />
              <span style={{ width: addrCol.width, flexShrink: 0, color: "var(--syntax-literal)" }}>{record.addr}</span>
              <span style={{ width: 8, flexShrink: 0 }} />
              <span style={{
                flex: 1, color: "var(--syntax-string)",
                overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
              }}>"{record.content}"</span>
              <span style={{ width: 8, flexShrink: 0 }} />
              <span style={{ width: encCol.width, flexShrink: 0, color: "var(--text-secondary)" }}>{record.encoding}</span>
              <span style={{ width: 8, flexShrink: 0 }} />
              <span style={{ width: lenCol.width, flexShrink: 0 }}>{record.byte_len}</span>
              <span style={{ width: 8, flexShrink: 0 }} />
              <span style={{ width: xrefsCol.width, flexShrink: 0, color: record.xref_count > 0 ? "var(--syntax-keyword)" : "var(--text-secondary)" }}>
                {record.xref_count}
              </span>
            </div>
          );
        })}
      </VirtualScrollArea>

      {loading && (
        <div style={{
          padding: "3px 8px", flexShrink: 0,
          borderTop: "1px solid var(--border-color)",
          background: "var(--bg-secondary)",
          fontSize: 11, color: "var(--text-secondary)",
        }}>
          Loading...
        </div>
      )}

      {stringsScanning && (
        <div style={{
          padding: "8px 12px",
          fontSize: 11,
          color: "var(--text-secondary)",
          textAlign: "center",
          borderTop: "1px solid var(--border-color)",
        }}>
          Scanning strings...
        </div>
      )}

      {/* 右键菜单 — Portal 到 body，避免祖先 overflow:hidden 裁剪 */}
      {contextMenu && (
        <ContextMenu x={contextMenu.x} y={contextMenu.y} onClose={() => setContextMenu(null)} minWidth={160}>
          <ContextMenuItem label="View Detail" onClick={handleViewDetail} />
          <ContextMenuItem label="View in Memory" onClick={handleViewInMemory} />
          <ContextMenuItem label="Show XRefs" onClick={handleShowXrefs} />
          <ContextMenuItem label="Copy String" onClick={handleCopyString} />
          <ContextMenuItem label="Copy Address" onClick={handleCopyAddr} />
        </ContextMenu>
      )}

    </div>
  );
}
