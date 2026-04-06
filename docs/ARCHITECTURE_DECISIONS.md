# 아키텍처 의사결정

> 각 기술을 **왜 선택했고, 어떤 문제를 해결하는지** 설명한다.

---

## 1. 왜 Celery인가 — FastAPI와 분석 워커의 분리

### 문제

보안 분석 파이프라인은 CPU 바운드와 I/O 바운드 작업이 혼재되어 있다.

| 작업 | 유형 | 예시 |
|------|------|------|
| 패키지 다운로드/설치, git clone | I/O 바운드 | 디스크 접근, 네트워크 대기 |
| Trivy 취약점 스캔, YARA 시그니처 매칭 | CPU 바운드 | 정규식 비교, 패턴 매칭 반복 |
| Ollama LLM 호출 | I/O 바운드 (외부 서비스 대기) | HTTP 요청 후 응답 대기 |

이 작업들을 FastAPI 프로세스 안에서 동기적으로 처리하면:
- 분석 도중 다른 요청을 받을 수 없다 (응답 지연)
- Python GIL 제약으로 CPU 바운드 작업의 멀티스레드 병렬화가 불가능하다

### 결정

FastAPI는 **요청 수신 → task_id 즉시 반환**만 담당하고, 실제 분석은 Celery 워커가 백그라운드에서 처리하도록 분리하였다.

```
Browser → FastAPI (task_id 즉시 반환) → Redis (브로커) → Celery Worker (분석 수행)
```

### 효과

- 웹 서버는 가벼운 요청 처리에 집중, 워커가 병렬로 분석 수행
- GIL 제약을 프로세스 수준 분리로 극복 (Celery 워커는 별도 프로세스)
- 워커 수를 조절하여 수평 확장 가능

---

## 2. concurrency=4의 근거

### 문제

Celery `--concurrency` 값은 하나의 워커 프로세스가 동시에 처리할 수 있는 작업 수를 결정한다. 너무 높으면 Ollama(단일 인스턴스)가 병목이 되고, 너무 낮으면 I/O 대기 시간이 낭비된다.

### 결정

`--concurrency=4`로 설정하였다.

- 원본 프로젝트에서 `os.cpu_count() or 4`로 CPU 코어 수 기반 기본값을 사용
- LLM 오탐 필터링에서 `ThreadPoolExecutor(max_workers=4)`로 Ollama 병렬 호출
- Ollama 단일 인스턴스의 동시 처리 한계를 고려한 실용적 상한

### 구조

```
Celery Worker (concurrency=4)
  ├── Task 1: Flask 분석 중 (YARA 스캔 — CPU)
  ├── Task 2: Django 분석 중 (git clone 대기 — I/O)
  ├── Task 3: requests 분석 중 (LLM 판단 대기 — I/O)
  └── Task 4: numpy 분석 중 (Trivy 스캔 — CPU)
```

CPU 바운드 작업과 I/O 바운드 작업이 동시에 실행되므로, CPU가 유휴 상태인 I/O 대기 시간을 다른 작업이 활용할 수 있다.

---

## 3. 왜 Redis 1개로 3가지 역할을 통합했는가

### 원본 구조

| 역할 | 기술 |
|------|------|
| 메시지 브로커 | RabbitMQ (vhost 분리) |
| 결과 캐시 | Redis |

### 문제

- RabbitMQ + Redis 두 서비스를 운영해야 하는 관리 부담
- 원본에서 RabbitMQ는 Celery 브로커 역할만 수행 — 고급 기능(라우팅, 우선순위 큐 등)을 사용하지 않음
- 리팩토링에서 WebSocket 실시간 진행률을 위한 Pub/Sub이 추가로 필요

### 결정

Redis 1개로 3가지 역할을 통합하였다.

| 역할 | 용도 | 사용 방식 |
|------|------|----------|
| **브로커** | Celery 태스크 큐 | `celery_broker_url = redis://...` |
| **캐시** | 분석 결과 저장, 상태 조회 시 즉시 응답 | `redis_client.set(f"dashboard:{name}", ...)` |
| **Pub/Sub** | 분석 진행률 실시간 전달 | `redis_client.publish(f"analysis_progress:{task_id}", ...)` |

### 효과

- 인프라 단순화: 서비스 1개 감소 (RabbitMQ 제거)
- 상태 조회 시 DB/파일 접근 없이 메모리에서 즉시 응답 (레이턴시 최소화)
- Pub/Sub으로 WebSocket 실시간 진행률 구현 — 별도 메시지 브로커 불필요

### 트레이드오프

- Redis는 메시지 지속성(durability)이 RabbitMQ보다 약하다. 서버 재시작 시 미처리 태스크가 유실될 수 있다.
- 현재 규모(단일 서버, 분석 요청 수 제한적)에서는 Redis로 충분하며, 대규모 트래픽 시 브로커를 RabbitMQ로 분리하는 것을 검토할 수 있다.

---

## 4. 왜 Docker Compose인가 — 서비스 의존성과 실행 순서

### 문제

리팩토링 후 5개 프로세스가 필요하다:

| 프로세스 | 역할 | 의존성 |
|----------|------|--------|
| Redis | 브로커 + 캐시 + Pub/Sub | 없음 (가장 먼저 기동) |
| Backend (FastAPI) | HTTP 서버 | Redis 필요 |
| Worker (Celery) | 비동기 분석 | Redis 필요 |
| Ollama | LLM 서비스 | 없음 |
| Frontend (Nginx) | 정적 파일 + 리버스 프록시 | Backend 필요 |

Redis가 준비되기 전에 Backend/Worker가 시작되면 연결 실패로 크래시한다.
원본처럼 각 터미널에서 수동 실행하면 순서를 직접 관리해야 하고, 환경 변수도 일일이 설정해야 한다.

### 결정

Docker Compose의 `depends_on` + `healthcheck`로 실행 순서를 보장하였다.

```yaml
redis:
  healthcheck:
    test: ["CMD", "redis-cli", "ping"]  # Redis가 응답할 때까지 대기

backend:
  depends_on:
    redis:
      condition: service_healthy  # Redis healthcheck 통과 후 시작
```

### 효과

- `docker-compose up -d` 한 줄로 5개 서비스 순서대로 기동
- 환경 변수, 네트워크, 볼륨을 `docker-compose.yml` 하나로 관리
- 모놀리식 구조 유지 — Backend와 Worker는 동일한 `backend/` 코드베이스를 공유하며, 컨테이너 분리는 프로세스 역할(HTTP 서빙 vs 비동기 작업)을 나누기 위한 것

---

## 5. 서브태스크 타임아웃과 재시도 — 운영 안정성

### 문제

분석 파이프라인 중 일부 작업이 외부 의존성(GitHub clone, Ollama 응답)으로 인해 장시간 블로킹될 수 있다. 하나의 태스크가 멈추면 워커 슬롯을 점유하여 전체 처리량이 저하된다.

### 결정

- `subprocess.run(timeout=300)` — git clone, Trivy 등 외부 프로세스에 5분 타임아웃
- `options={"num_predict": 10}` — LLM 응답 길이를 제한하여 무한 생성 방지
- Celery 설정: `task_acks_late=True` (작업 완료 후 ACK), `worker_prefetch_multiplier=1` (한 번에 하나씩 가져옴)
- LLM 호출 실패 시 `llm_verdict = None`으로 설정하고 1차 결과만 반환 (graceful degradation)

### 효과

- 특정 태스크가 지연되어도 다른 분석 요청에 영향 없음
- Ollama 서비스 장애 시에도 LLM 단계를 건너뛰고 나머지 파이프라인은 정상 수행
