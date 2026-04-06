# OSSGuard — 오픈소스 공급망 보안 분석 플랫폼

> SBOM · SCA · 악성코드 탐지(YARA + LLM 2단계) · 타이포스쿼팅(4종 알고리즘) · 디펜던시 컨퓨전 · AI 보안 리포트
>
> 실제 보안 사고 사례(dYdX 공급망 공격, browser-cookies3 타이포스쿼팅)를 기반으로 탐지 엔진을 고도화한 프로젝트이다.



## 프로젝트 개요

| 항목 | 내용                                                          |
|------|-------------------------------------------------------------|
| 깃허브 | [github.com/TrustBOM](https://github.com/TrustBOM)          |
| 원본 개발 | 2025.01 ~ 2025.03 (3명 — 보안, 프론트, 백엔드 中 백엔드 담당)              |
| 출전 | 재단법인 미래와소프트웨어 제5회 아이디어 공모전                                  |
| 리팩토링 | 2026.01 ~ 2026.03 (1인, 백엔드 아키텍처 개선 + 보안 탐지 고도화 + 프론트엔드/인프라) |
| 리팩토링 방식 | 아키텍처 설계, 기술 선택, 결과 검증은 직접 수행. 코드 작성은 AI 도구 활용.              |



## 서비스 아키텍처

```
┌─────────────────────┐
│  Browser (React 19) │
└────────┬────────────┘
         │ ① REST API 요청 (분석 시작)
         ▼
┌──────────────────────────────────────────────────────────────────┐
│                     Docker Compose Cluster                       │
│                                                                  │
│  ┌─────────────────────────────────┐                             │
│  │  Frontend (Nginx :3000)         │ ── 정적 파일 서빙            │
│  └─────────────────────────────────┘                             │
│                                                                  │
│  ┌─────────────────────────────────┐      ┌───────────────────┐  │
│  │  API Gateway (FastAPI :8000)    │      │  Redis :6379      │  │
│  │    ├── /github   (저장소 분석)   │ ──②──▶ Celery 태스크 발행 │  │
│  │    ├── /pypi-npm (패키지 분석)   │      │  (메시지 브로커)   │  │
│  │    ├── /ai       (AI 분석)      │      │                   │  │
│  │    └── /ws       (WebSocket)    │ ◀─⑤── Pub/Sub 구독       │  │
│  └──────────────┬──────────────────┘      └──────┬────────────┘  │
│                 │                                 │               │
│                 │ ⑥ 캐시된 결과 조회              │               │
│                 └────────────────────────────────▶│               │
│                                                   │               │
│  ┌─────────────────────────────────┐              │               │
│  │  Worker (Celery ×4)            │ ◀─────③──────┘               │
│  │                                 │   태스크 수신 (브로커)        │
│  │    Clone                        │                              │
│  │     ↓                           │      ┌───────────────────┐  │
│  │    SBOM (Syft)                  │      │  Ollama :11434    │  │
│  │     ↓                           │      │  (LLM 서비스)     │  │
│  │    SCA (Trivy)                  │      └───────┬───────────┘  │
│  │     ↓                           │              │               │
│  │    MITRE ATT&CK (CVE 매핑)     │              │               │
│  │     ↓                           │              │               │
│  │    악성코드 (YARA + 키워드)     │              │               │
│  │     ↓                           │     ④ LLM 호출              │
│  │    LLM 2차 판단 ───────────────────────────────┘               │
│  │     ↓                           │                              │
│  │    타이포스쿼팅 (4종 알고리즘)   │                              │
│  │     ↓                           │                              │
│  │    디펜던시 컨퓨전              │                              │
│  │     ↓                           │      ┌───────────────────┐  │
│  │    AI 위험도 분석 ──────────────────────▶ Redis             │  │
│  │                                 │  ⑤   │ Pub/Sub (진행률)  │  │
│  │   각 단계마다 진행률 Publish ───────────▶ 캐시 (결과 저장)  │  │
│  └─────────────────────────────────┘      └───────────────────┘  │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
         │
         │ ⑤ WebSocket Push (실시간 진행률)
         │ ⑥ REST 응답 (캐시된 대시보드 데이터)
         ▼
┌─────────────────────┐
│  Browser (React 19) │
│  대시보드 렌더링      │
└─────────────────────┘

① 사용자가 GitHub URL 또는 패키지명 입력 → API Gateway로 REST 요청
② API Gateway가 Celery 태스크를 Redis 브로커에 발행
③ Worker가 Redis에서 태스크를 수신하여 분석 파이프라인 실행
④ 악성코드 탐지 시 Ollama LLM에 2차 판단 요청 (오탐 필터링)
⑤ 각 단계 완료 시 Redis Pub/Sub → API Gateway → WebSocket으로 진행률 Push
⑥ 분석 완료 후 결과를 Redis에 캐시 → 대시보드에서 조회
```

<br>

## 분석 파이프라인 상세
> [ANALYSIS_PIPELINE.md](docs/ANALYSIS_PIPELINE.md) — 각 단계의 탐지 방식, 구현 위치, 성과를 상세히 설명한다.

| 단계 | 도구 | 역할 |
|------|------|------|
| **SBOM** | Syft | 프로젝트 내 모든 패키지의 이름·버전·라이선스를 SPDX JSON으로 목록화 |
| **SCA** | Trivy | SBOM 기반으로 각 패키지의 알려진 CVE를 NVD/OSV에서 조회, 업데이트 권고 생성 |
| **MITRE ATT&CK** | cve.circl.lu API | CVE → CAPEC(공격 패턴) / CWE(취약점 유형) 매핑으로 위협 성격 식별 |
| **악성코드 1차** | YARA (13룰) + 키워드 | 위험 함수(`exec`, `eval`), 난독화(`base64`), 하드코딩 시크릿, 의심 파일명 탐지 |
| **악성코드 2차** | Ollama (LLM) | 1차 플래그를 LLM이 재판단 — 테스트 더미인지, 실제 악성인지 분류 (FP 81.8% 제거) |
| **타이포스쿼팅** | 4종 알고리즘 | Char Insertion · Char Swap · Levenshtein · SequenceMatcher로 100+개 인기 패키지 대조 |
| **디펜던시 컨퓨전** | 내부 패키지 대조 | 내부 패키지명이 공개 레지스트리에 등록되어 외부 패키지로 대체되는 공격 탐지 |
| **AI 위험도** | 가중 점수 산출 | CVE(60점) + 타이포(15점) + 디펜던시(15점) + 악성코드(10점) = 0~100점 등급화 |

<br>

## What is different?

### 원본
- 깃허브 링크 : [github.com/TrustBOM](https://github.com/TrustBOM)
- GitHub 분석(:8000), PyPI/npm 분석(:8001) FastAPI 서버를 각각 uvicorn으로 실행
- Celery 워커도 2개 분리 (github_tasks/github_vhost, pypi_npm_tasks/pypi_npm_vhost)
- MITRE ATT&CK 매핑 (mitreapi 라이브러리 직접 호출)
- CI/CD: Jenkins (Docker 컨테이너) + GitHub SSH 연동
- 배포: NCP (네이버 클라우드, Ubuntu 4GB) + Nginx (SSL 리버스 프록시) + Docker Compose
- 프론트엔드 배포: Vercel (ossguard.vercel.app)
- 배포 관련 글: [Docker Compose와 Jenkins로 CI/CD하기](https://velog.io/@hansjour/Docker-Compose%EC%99%80-Jenkins%EB%A1%9C-CICD%ED%95%98%EA%B8%B0)



### 리팩토링

**기능**

| | Before (2025, 팀) | After (리팩토링, 1인) |
|---|---|---|
| 악성코드 탐지 | 키워드가 있으면 무조건 위험 판정 (오탐 20%) | 키워드 탐지 후 LLM이 "진짜 위험한가?" 재판단 (오탐 10%) |
| 타이포스쿼팅 | 비교 대상 10개, 알고리즘 1개 (절반만 탐지) | 비교 대상 100+개, 알고리즘 4개 (91.7% 탐지) |
| MITRE ATT&CK | mitreapi 라이브러리로 직접 호출 | CVE → CAPEC/CWE 병렬 매핑 (파이프라인 내장) |
| 패키지 사전 검사 | 없음 (설치한 뒤에야 검사) | 설치 전에 먼저 검사 → 위험하면 설치 차단 |
| AI 분석 | 없음 | 위험도 점수, 수정 제안, 라이선스 검증, 챗봇 |
| 프론트엔드 | 페이지 구조만 존재, 더미 데이터 | 실제 API 연동, 차트/테이블/내보내기 완성 |
| 실시간 진행률 | 없음 | WebSocket으로 단계별 진행률 Push |

<br>

**아키텍처**

| | Before | After |
|---|---|---|
| 서버 | FastAPI 2개 (GitHub :8000, PyPI/npm :8001) | FastAPI 1개 (라우터로 분리) |
| Celery | 워커 2개 분리 (github_queue, pypi_npm_queue) | 워커 1개 (통합 파이프라인, concurrency=4) |
| 브로커 | RabbitMQ (vhost 분리: github_vhost, pypi_npm_vhost) | Redis (브로커 + 캐시 + Pub/Sub 통합) |
| MITRE ATT&CK | mitreapi 라이브러리 직접 호출 | CVE → CAPEC/CWE 매핑 (병렬 HTTP, 파이프라인 내장) |
| API | 탭별 개별 API 따로 호출 | `/g_dashboard` 한 번에 전체 반환 |
| 진행률 | task_id 폴링 | WebSocket Push (Redis Pub/Sub) |
| 프론트 연동 | 미연동 (더미 데이터) | REST API + WebSocket |
| CI/CD | Jenkins (NCP 서버에서 Docker 컨테이너로 실행) | — |
| 배포 | NCP + Nginx(SSL) + Docker Compose + Vercel(프론트) | Docker Compose 전체 서비스(5개) |
| LLM | 없음 | Ollama (Celery 파이프라인 내 자동 호출) |

<br>

**기술 스택**

| 영역 | Before | After |
|---|---|---|
| Backend | ![FastAPI](https://img.shields.io/badge/FastAPI-서버_2개-009688?logo=fastapi&logoColor=white) ![Celery](https://img.shields.io/badge/Celery-RabbitMQ-37814A?logo=celery&logoColor=white) ![Redis](https://img.shields.io/badge/Redis-Cache-DC382D?logo=redis&logoColor=white) ![RabbitMQ](https://img.shields.io/badge/RabbitMQ-Broker-FF6600?logo=rabbitmq&logoColor=white) | ![FastAPI](https://img.shields.io/badge/FastAPI-2.0-009688?logo=fastapi&logoColor=white) ![Celery](https://img.shields.io/badge/Celery-5.4-37814A?logo=celery&logoColor=white) ![Redis](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white) |
| Frontend | ![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black) (더미 데이터) | ![React](https://img.shields.io/badge/React-19-61DAFB?logo=react&logoColor=black) ![TypeScript](https://img.shields.io/badge/TypeScript-5.7-3178C6?logo=typescript&logoColor=white) ![Vite](https://img.shields.io/badge/Vite-6-646CFF?logo=vite&logoColor=white) |
| Security | ![Syft](https://img.shields.io/badge/Syft-SBOM-4B275F) ![Trivy](https://img.shields.io/badge/Trivy-SCA-1904DA) ![YARA](https://img.shields.io/badge/YARA-Malware-EE3124) ![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-ED1C24) | ![Syft](https://img.shields.io/badge/Syft-SBOM-4B275F) ![Trivy](https://img.shields.io/badge/Trivy-SCA-1904DA) ![YARA](https://img.shields.io/badge/YARA-Malware-EE3124) ![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-ED1C24) ![Ollama](https://img.shields.io/badge/Ollama-LLM_SAST-000000) |
| Infra | ![NCP](https://img.shields.io/badge/NCP-Naver_Cloud-03C75A?logo=naver&logoColor=white) ![Jenkins](https://img.shields.io/badge/Jenkins-CI%2FCD-D24939?logo=jenkins&logoColor=white) ![Nginx](https://img.shields.io/badge/Nginx-Reverse_Proxy-009639?logo=nginx&logoColor=white) ![RabbitMQ](https://img.shields.io/badge/RabbitMQ-Broker-FF6600?logo=rabbitmq&logoColor=white) ![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white) | ![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white) ![WebSocket](https://img.shields.io/badge/WebSocket-Real_Time-010101) |

<br>

## 주요 성과

| 영역 | 지표 | Before | After |
|------|------|--------|-------|
| 타이포스쿼팅 | Recall | 50.0% | **91.7%** |
| 타이포스쿼팅 | F1 Score | 66.7% | **95.7%** |
| 악성코드 탐지 (벤치마크) | FP Rate | 20.0% | **10.0%** |
| 악성코드 탐지 (벤치마크) | Precision | 83.3% | **90.9%** |
| 악성코드 탐지 (Flask 실적용) | 오탐 | 11건 | **2건 (81.8% 제거)** |
| 분석 성능 (Flask) | 총 소요시간 | 11분 42초 | **~3분 30초 (70% 단축)** |

<br>

## 시연

| 시연 항목 | 설명 |
|-----------|------|
| GitHub 분석 | GitHub URL 입력 → 실시간 진행률 → 대시보드 (SBOM, 취약점, 악성코드, 타이포스쿼팅) |
| PyPI/npm 분석 | 패키지명 입력 → 사전 타이포스쿼팅 검사 → 설치 → 분석 결과 |
| LLM 오탐 필터링 | 악성코드 탭에서 AI 판단 결과 표시 (safe/malicious 라벨) |
| AI 보안 리포트 | AI Insights 탭에서 위험도 점수, 우선순위, 수정 제안 확인 |

> 시연 영상/GIF 준비 후 교체 예정

<br>

## 기술적 의사결정 & 트러블슈팅

### 타이포스쿼팅 탐지 고도화
> [SECURITY_ENHANCEMENT.md](docs/SECURITY_ENHANCEMENT.md)

- 실제 악성 패키지 `browser-cookies3` (196회 다운로드, 비밀번호·Discord 토큰 탈취)를 기존 탐지 로직이 놓치는 것을 확인하였다.
- SequenceMatcher 1개 + 패키지 10개 → 4종 알고리즘(Levenshtein, Char Swap, Char Insertion, SequenceMatcher) + 100+개 패키지로 확장하였다.
- Recall 50% → 91.7%, F1 Score 66.7% → 95.7%로 개선되었다.

### 악성코드 LLM 2단계 필터링 & 성능 최적화
> [SECURITY_ENHANCEMENT.md](docs/SECURITY_ENHANCEMENT.md) · [malware-detection-optimization.md](docs/malware-detection-optimization.md)

- 키워드 매칭만으로는 테스트 코드의 `SECRET_KEY="test"`를 하드코딩 키로 오탐하는 문제가 있었다 (FP Rate 20%).
- LLM(Ollama) 2차 판단을 추가하여 "테스트 코드인지 실제 악성인지" 판별하도록 하였다 → FP Rate 10%로 개선.
- Flask 실적용 시 11건 오탐 중 9건을 제거하였다.
- YARA 룰 컴파일을 파일별 200회 → 1회로 최적화하고, LLM 호출을 `ThreadPoolExecutor(4)`로 병렬화하여 분석 시간을 11분 42초 → ~3분 30초로 단축하였다.

### 설치 전 타이포스쿼팅 사전 검사
> [SECURITY_ENHANCEMENT.md](docs/SECURITY_ENHANCEMENT.md)

- PyPI 패키지의 `setup.py`는 설치 시점에 자동 실행되므로 **설치 자체가 공격 벡터**이다.
- 삭제된 악성 패키지(`browser-cookies3`)는 `pip install` 실패 → 검사 자체가 수행되지 않는 문제가 있었다.
- 설치 전 사전 검사 API(`/pypi-npm/pre-check`)를 추가하여 패키지명만으로 타이포스쿼팅 여부를 판단하고, 의심 시 설치를 차단하도록 하였다.

### 프론트엔드-백엔드 데이터 정합성
> [SECURITY_ENHANCEMENT.md](docs/SECURITY_ENHANCEMENT.md)

- 백엔드 응답 키(`typosquatting_analysis`)와 프론트엔드 기대 키(`typosquatting_results`)가 불일치하여 대시보드 탭이 전부 0건으로 표시되는 문제를 해결하였다.
- `g_dashboard` 엔드포인트를 집계 API로 리팩토링하여 한 번의 호출로 모든 탭 데이터를 반환하도록 수정하였다.

### LLM 파이프라인 아키텍처 전환
> [SECURITY_ENHANCEMENT.md](docs/SECURITY_ENHANCEMENT.md)

- LLM 판단을 API 응답 시점에서 호출하면 대시보드 로딩에 5분 이상 소요되고, 매번 결과가 달라지는 문제가 있었다.
- LLM 호출을 Celery 백그라운드 파이프라인으로 이동하여 분석 시 한 번만 실행하고 Redis에 캐시하도록 전환하였다.

<br>

## 실행 방법

```bash
# 1. 전체 서비스 실행
docker-compose up -d

# 2. LLM 모델 다운로드 (최초 1회)
docker exec ossguard-ollama-1 ollama pull llama3.2:1b
```

| 서비스 | 포트 | 설명 |
|--------|------|------|
| Frontend | http://localhost:3000 | React 대시보드 |
| API Gateway | http://localhost:8000 | FastAPI 서버 |
| Ollama | http://localhost:11434 | LLM 서비스 |

### 환경변수

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `OSSGUARD_REDIS_HOST` | redis | Redis 호스트 |
| `OSSGUARD_OLLAMA_HOST` | http://ollama:11434 | Ollama 호스트 |
| `OSSGUARD_OLLAMA_MODEL` | llama3.2:1b | 사용할 LLM 모델 |

### 벤치마크

```bash
cd backend

# 타이포스쿼팅 Before/After
python3 tests/benchmark/run_typo_benchmark.py

# SAST Before/After
python3 tests/benchmark/run_benchmark.py

# LLM SAST Before/After (Ollama 필요)
bash tests/benchmark/run_llm_final.sh
```

<br>

## 프로젝트 구조

```
ossguard/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI 앱 (v2.0.0)
│   │   ├── config.py                  # 환경변수 설정
│   │   ├── routers/
│   │   │   ├── github.py              # GitHub 저장소 분석 API
│   │   │   ├── pypi_npm.py            # PyPI/npm 패키지 분석 + 사전검사
│   │   │   ├── ai.py                  # AI 보안 분석 (요약, 수정 제안, 챗봇)
│   │   │   └── ws.py                  # WebSocket 실시간 진행률
│   │   ├── services/
│   │   │   ├── sbom.py                # SBOM 생성 (Syft)
│   │   │   ├── sca.py                 # CVE 스캔 (Trivy)
│   │   │   ├── malware.py             # 악성코드 탐지 (키워드 + YARA)
│   │   │   ├── typosquatting.py       # 타이포스쿼팅 (4종 알고리즘)
│   │   │   ├── dependency_confusion.py # 디펜던시 컨퓨전
│   │   │   ├── mitre.py               # MITRE ATT&CK 매핑 (CVE → 공격기법)
│   │   │   └── ai/                    # AI 서비스 (llm_sast, risk_scorer 등)
│   │   └── workers/
│   │       ├── tasks.py               # Celery 분석 파이프라인
│   │       └── celery_app.py          # Celery 설정
│   ├── yara_rules/                    # YARA 룰 13개
│   └── tests/benchmark/              # 벤치마크 스크립트
├── frontend/
│   └── src/
│       ├── pages/                     # HomePage, AnalysisPage
│       ├── components/                # 차트, 테이블, 진행률 등
│       ├── services/                  # API 클라이언트
│       ├── contexts/                  # Analysis, Theme, WebSocket
│       └── hooks/                     # useAnalysis, useWebSocket 등
├── docs/                              # 기술 문서
├── docker-compose.yml                 # 5개 서비스 오케스트레이션
└── README.md
```

<br>

## 리팩토링을 통해 얻은 것

보안 도메인 전문성이 부족하더라도, AI를 활용해 실제 사고 사례에서 보완점을 찾고 벤치마크로 검증하며 탐지 품질을 개선할 수 있었다.
