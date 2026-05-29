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

## 핵심 기능 (Roadmap)

### Phase 1 — *File Scanner* (MVP)
- [x] 파일 SHA256 해시 계산
- [x] VirusTotal API v3 조회
- [x] 디렉터리 재귀 스캔
- [x] JSON / table 형식 결과 출력
- [ ] YARA 룰 매칭 (로컬)
- [ ] 화이트리스트 / 캐시 (24h)

### Phase 2 — *Network Monitor*
- [ ] 활성 connection 모니터링 (`lsof -i` / `ss`)
- [ ] 알려진 악성 IP/도메인 매칭 (abuse.ch URLhaus, Spamhaus)
- [ ] DNS 쿼리 감시 (Linux: eBPF, macOS: NetworkExtension)
- [ ] 의심스러운 outbound C2 패턴 알림

### Phase 3 — *Process Monitor*
- [ ] 새 프로세스 실행 감지 (Linux: audit / fanotify, macOS: EndpointSecurity)
- [ ] 의심 패턴 탐지 (curl + bash pipe, base64 디코드 실행 등)
- [ ] 프로세스 트리 시각화

### Phase 4 — *Reporting & UI*
- [ ] Tauri 또는 SwiftUI 기반 트레이 앱
- [ ] 일/주간 리포트
- [ ] Telegram / 이메일 알림 연동

### Phase 5 — *Threat Intel Integration*
- [ ] AlienVault OTX 피드
- [ ] abuse.ch 피드 (URLhaus, MalwareBazaar)
- [ ] SBOM 분석 (특정 npm/pip 패키지 위험도)

## 빠른 시작

```bash
# 빌드
make build

# VirusTotal API key 설정 (https://www.virustotal.com/gui/my-apikey)
export VACCINE_VT_API_KEY="your-api-key"

# 단일 파일 스캔
./vaccine scan /path/to/suspicious-file

# 디렉터리 재귀 스캔
./vaccine scan ~/Downloads

# JSON 출력
./vaccine scan ~/Downloads --format json
```

## 비-목표 (Non-goals)

- *Windows 커널 *드라이버* — 인증 비용 / 복잡도 너무 큼
- *자체 *시그니처 DB* — VirusTotal 등 *전문 피드 *위임*
- *유료 *상용화* — *오픈소스 + 학습 목적*
- *''*V3 / 알약 *대체""* — *그건 *50+ 명 팀의 영역*

## 기술 스택

- **언어**: Go 1.26+
- **CLI**: Cobra
- **YARA**: go-yara
- **VirusTotal**: REST API v3
- **eBPF (Linux)**: cilium/ebpf (Phase 3)
- **EndpointSecurity (macOS)**: Cgo + ES framework (Phase 3)
- **UI**: Tauri (Phase 4)

## 라이선스

MIT — 개인 / 학술 / 상업 *자유 사용*.

## 면책

이 도구는 *''*보조 알림기""* 이지 *''*완전한 보안 *솔루션""* 이 아닙니다. *Production 시스템 *보호용* 으로는 *AhnLab V3, *CrowdStrike, *Microsoft Defender* 같은 *전문 *제품을 *함께 사용* 하세요.
