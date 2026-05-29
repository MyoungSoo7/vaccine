# vaccine

> *macOS · Linux* 용 *경량 위협 탐지 도구* — **EDR-lite for personal endpoints**

기존 V3 / 알약처럼 *signature DB 를 *직접 *유지하지 않고*, *VirusTotal · YARA · eBPF · 알려진 IoC (Indicators of Compromise) 피드를 *조합* 해서 *개인 / 소규모 *환경에서 *''*무엇이 *수상한가""* 를 *알려주는 도구.

## 철학

- **재구축 (Reinvent) 금지** — 시그니처 DB 는 *VirusTotal / abuse.ch / OTX 같은 *전문 *피드* 를 *위임 사용*
- **모니터링 + 알람 우선** — 자동 격리 / 자동 삭제 *최소화*. 사용자에게 *결정권*
- **투명성** — 어떤 IoC, 어떤 룰로 매칭됐는지 *모두 공개*
- **경량** — *백그라운드 *상시 *프로세스가 *수십 MB 이하*

## 지원 플랫폼

| Platform | Status |
|---|---|
| macOS (Apple Silicon + Intel) | 1차 타겟 |
| Linux (Ubuntu/Debian/RHEL) | 1차 타겟 |
| Windows | 향후 (커널 드라이버 인증 부담으로 후순위) |
| Android | 별도 앱으로 검토 |
| iOS | 샌드박스 한계로 *지원 어려움* |

## 명령어 요약

```
vaccine scan       <path>   파일/디렉터리 스캔 (VT + 로컬 blocklist + 캐시)
vaccine netscan             활성 네트워크 connection 나열 + URLhaus 매칭
vaccine procscan            프로세스 cmdline 의심 패턴 탐지 (curl|bash 등)
vaccine intel-sync          URLhaus IoC feed 다운로드 + 캐시
vaccine watch      <path>   위 셋을 주기적으로 (cron 대체)
```

종료 코드: `0` 정상 / `2` 설정 오류 / `3` 위협 발견 — 자동화 hook 친화.

## 빠른 시작

```bash
# 빌드
make build
# 또는: go build -o vaccine ./cmd/vaccine

# VirusTotal API key 받기 (무료, 4 req/min, 500/day)
# https://www.virustotal.com/gui/my-apikey
export VACCINE_VT_API_KEY="your-api-key"

# (선택) Telegram 알람 — 발견 시 푸시
export VACCINE_TELEGRAM_BOT_TOKEN="..."
export VACCINE_TELEGRAM_CHAT_ID="..."

# 활용 ─────────────────────────

# 1) 파일 스캔
./vaccine scan ~/Downloads --only-bad

# 2) URLhaus 피드 동기화
./vaccine intel-sync

# 3) 네트워크 + 프로세스 점검
./vaccine netscan
./vaccine procscan

# 4) cron 대체 — 30 분마다 전체 점검 + Telegram 알람
./vaccine watch ~/Downloads --interval 30
```

## 설정 파일

`~/.vaccine/config.json` (선택). 환경변수가 *우선*.

```json
{
  "vt_api_key": "",
  "cache_dir": "/Users/me/.vaccine/cache",
  "cache_ttl_hours": 24,
  "blocklist_paths": ["/Users/me/.vaccine/my-bad-hashes.txt"],
  "whitelist_paths": ["/Users/me/Library"],
  "urlhaus_feed_url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
  "watch_interval_min": 60,
  "max_file_mb": 100,
  "vt_rate_seconds": 16
}
```

## 핵심 기능 (Roadmap)

### Phase 1 — *File Scanner* ✅
- [x] 파일 SHA256/SHA1/MD5 해시
- [x] VirusTotal API v3 조회
- [x] 디렉터리 재귀 스캔
- [x] 24h 디스크 캐시 (quota 절약)
- [x] 로컬 hash blocklist
- [x] Whitelist (스킵 경로)
- [x] JSON / table 출력
- [ ] YARA 룰 매칭 (Phase 1.5)

### Phase 2 — *Network Monitor* ✅ (passive)
- [x] 활성 connection 나열 (gopsutil)
- [x] URLhaus 피드 다운로드 + 매칭
- [x] 프로세스명 / PID 매핑
- [ ] eBPF 기반 실시간 감시 (Phase 2.5, Linux 전용)

### Phase 3 — *Process Monitor* ✅ (passive)
- [x] 프로세스 cmdline 의심 패턴 탐지 (curl|bash, base64|sh, rev-shell, miner)
- [ ] EndpointSecurity (macOS) / fanotify+audit (Linux) 기반 실시간 감시

### Phase 4 — *Daemon + Reporting* ✅ (basic)
- [x] `vaccine watch` 주기 실행
- [x] Telegram 알림
- [ ] Tauri 트레이 앱

### Phase 5 — *Threat Intel Integration*
- [x] URLhaus (abuse.ch) 피드
- [ ] MalwareBazaar 해시 피드
- [ ] AlienVault OTX
- [ ] SBOM 분석 (npm/pip 패키지 위험도)

## 의존성

```
github.com/shirou/gopsutil/v4   프로세스 / 네트워크 (cross-platform)
```

표준 라이브러리만으로도 80% 구현. 외부 의존 *최소화*.

## 비-목표 (Non-goals)

- *Windows 커널 드라이버* — 인증 비용 / 복잡도 너무 큼
- *자체 시그니처 DB* — VirusTotal 등 위임
- *유료 상용화* — 오픈소스 + 학습 목적
- *V3 / 알약 대체* — 그건 *50+ 명 팀의 영역*

## 라이선스

MIT — 개인 / 학술 / 상업 *자유 사용*.

## 면책

이 도구는 *''보조 알림기''* 이지 *''완전한 보안 솔루션''* 이 아닙니다. *Production 시스템 보호용* 으로는 *AhnLab V3, CrowdStrike, Microsoft Defender* 같은 *전문 제품을 함께 사용* 하세요.
