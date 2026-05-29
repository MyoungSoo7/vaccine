# Architecture

vaccine 는 *얇은 CLI* 와 *교체 가능한 소스 (source) + 결정자 (decision) + 알림자 (notifier)* 의 3 계층으로 구성된다.

```
                        ┌─────────────────────────────────────┐
                        │            cmd/vaccine              │
                        │  scan / netscan / procscan /        │
                        │  intel-sync / watch                 │
                        └────────────────┬────────────────────┘
                                         │
            ┌────────────────────────────┼────────────────────────────┐
            │                            │                            │
   ┌────────▼────────┐         ┌─────────▼─────────┐        ┌─────────▼─────────┐
   │   Sources       │         │    Decision       │        │    Notifiers      │
   │ (where data     │         │  (what is bad?)   │        │  (who hears?)     │
   │  comes from)    │         │                   │        │                   │
   │                 │         │                   │        │                   │
   │ • hash          │         │ • scanner         │        │ • notify          │
   │ • virustotal    │         │ • blocklist       │        │   (Telegram)      │
   │ • intel (URLhaus)│        │ • intel match     │        │ • stdout / json   │
   │ • netmon (psnet)│         │ • procmon rules   │        │                   │
   │ • procmon       │         │                   │        │                   │
   └─────────────────┘         └───────────────────┘        └───────────────────┘
                                         │
                                ┌────────▼────────┐
                                │   cache (24h)   │
                                │   ~/.vaccine/   │
                                └─────────────────┘
```

## 패키지

| 패키지 | 역할 | 의존 |
|---|---|---|
| `cmd/vaccine` | CLI 디스패처 | 모든 internal |
| `internal/config` | 환경 + 파일 설정 병합 | std |
| `internal/hash` | SHA256/SHA1/MD5 계산 | std |
| `internal/virustotal` | VT v3 REST 클라이언트 | std (net/http) |
| `internal/cache` | 디스크 캐시 (24h TTL) | std |
| `internal/blocklist` | 로컬 hash 차단 목록 | std |
| `internal/intel` | URLhaus CSV 다운로드 + 인덱싱 | std |
| `internal/scanner` | 파일 스캐너 (blocklist → cache → VT) | hash, vt, cache, blocklist |
| `internal/netmon` | 네트워크 connection + URLhaus 매칭 | gopsutil, intel |
| `internal/procmon` | 프로세스 cmdline 패턴 탐지 | gopsutil |
| `internal/notify` | Telegram 알림 | std (net/http) |

## 데이터 흐름

### `scan <path>`

```
파일 1 개
  ├─▶ hash.ComputeFile        ─ SHA256
  ├─▶ blocklist.Match         ─ 매칭 시 즉시 malicious (no API)
  ├─▶ cache.Get               ─ hit 시 결과 반환 (no API)
  └─▶ virustotal.LookupHash   ─ miss 시 API → cache.Put
```

*우선순위 = 비용 낮은 순*. VT API quota 보호.

### `netscan`

```
gopsutil.Connections (ESTABLISHED outbound)
  ▼
remote IP → URLhaus.MatchHost (bare IP)
         ↘ reverse DNS → URLhaus.MatchHost (hostname)
  ▼
findings: {connection, urlhaus entry}
```

### `procscan`

```
gopsutil.Processes (전체)
  ▼
각 process.Cmdline → 정규식 8 종 매칭
  ▼
findings: {process, pattern, reason}
```

### `watch <path>`

```
무한 루프 (interval=60min default)
  ▼
  [1] intel.URLhaus.Refresh
  [2] netmon.List + MatchAgainst → findings
  [3] procmon.List + Scan → findings
  [4] scanner.ScanPath (선택) → bad files
  ▼
요약 → stdout + (선택) Telegram
```

## 보안 / 권한 고려

- macOS — *현재 사용자의 *프로세스 + connection 만 *기본 권한으로* 보임. 시스템 전체 보려면 *Full Disk Access + sudo*.
- Linux — *non-root* 도 자기 프로세스는 보임. 시스템 전체는 *root* (또는 `cap_sys_ptrace`).
- *VT API 결과는 *전 세계 공유 DB* — 사적 파일을 직접 업로드하진 않음 (해시만 조회)
- *Telegram 토큰* 은 환경변수 / config 로 *코드에 안 박힘*

## 향후 (eBPF / EndpointSecurity 진입 지점)

Phase 2.5 ~ 3 의 *실시간 감시* 진입점:

- **Linux**: `cilium/ebpf` + tracepoint `sched_process_exec`, `connect`
- **macOS**: `EndpointSecurity.framework` via cgo (개발자 권한 필요)
- 두 곳 모두 *gopsutil → 자체 source* 로 *교체 가능* 한 구조로 설계됨.

## 의도적으로 *안 한 것*

- *signature DB 자체 구축* — VT/URLhaus 위임
- *실시간 차단 (kill/quarantine)* — 거짓 양성으로 사용자 데이터 손실 위험. 현 단계는 *알림만*
- *Windows 커널 드라이버* — 비용 대비 효과 낮음
- *YARA cgo 의존* — 빌드 단순화 위해 Phase 1.5 로 미룸
