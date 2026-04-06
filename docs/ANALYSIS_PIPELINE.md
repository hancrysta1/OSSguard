# 분석 파이프라인 상세

> 각 단계가 **무엇을 탐지하고, 왜 필요한지** 설명한다.

- 원본 파이프라인 설계 문서 : https://thunder-banon-a5e.notion.site/196f7776fc46806fa281d46ad50b54b2?pvs=74
- **추가**: AI 위험도 점수, LLM 2차 오탐 필터링, 설치 전 사전검사, WebSocket 실시간 진행률                                                            
- **보완**: 타이포스쿼팅 (1종→4종 알고리즘, 10→100+개 패키지), 악성코드 탐지 성능 (YARA 1회 컴파일, 분석 70% 단축), MITRE ATT&CK (파이프라인 내장 + 병렬화)  

```
Clone → SBOM → SCA → MITRE 매핑 → 악성코드(YARA+LLM) → 타이포스쿼팅 → 디펜던시 컨퓨전 → AI 위험도
```

---

## 1. SBOM 생성 (Syft)

**Software Bill of Materials** — 프로젝트에 포함된 모든 오픈소스 패키지의 이름, 버전, 라이선스를 목록화한다.

- 출력 포맷: SPDX JSON
- 공급망 가시성 확보의 첫 단계. SBOM이 없으면 "어떤 패키지가 들어있는지"조차 알 수 없다.
- `requirements.txt`에 선언된 패키지와 SBOM을 대조하여 **누락된 패키지**(SBOM에 잡히지 않는 의존성)도 검출한다.

**구현**: `backend/app/services/sbom.py`

---

## 2. SCA — 취약점 분석 (Trivy)

**Software Composition Analysis** — SBOM을 기반으로 각 패키지의 알려진 취약점(CVE)을 NVD/OSV 데이터베이스에서 조회한다.

- 심각도 분류: CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
- 패치 가능한 버전이 있으면 업데이트 권고 목록 자동 생성
- 보안 개요(security_overview)에 전체 취약점 수, 심각도별 카운트, 영향받는 패키지 수를 집계

**구현**: `backend/app/services/sca.py`

---

## 3. MITRE ATT&CK 매핑

발견된 CVE를 실제 공격 기법과 연결한다. CVE 번호만으로는 "어떤 종류의 공격인지" 파악하기 어렵기 때문에, **CAPEC(공격 패턴)** 및 **CWE(취약점 유형)**를 매핑하여 위협의 성격을 명확히 한다.

- 예: `CVE-2023-XXXX` → CWE-79 (XSS) → CAPEC-86 (Cross-Site Scripting)
- 보안팀이 우선순위를 정할 때 "이 CVE가 실제로 어떤 공격 시나리오에 해당하는지" 판단하는 근거가 된다.
- 외부 API(`cve.circl.lu`)를 `ThreadPoolExecutor(4)`로 병렬 호출하여 다수의 CVE를 빠르게 매핑

**구현**: `backend/app/services/mitre.py`

---

## 4. 악성코드 탐지 (YARA + 키워드 + LLM 2단계)

소스코드에서 악의적 행위를 탐지한다. **2단계 구조**로 오탐을 최소화한다.

### 1차 — 정적 분석 (키워드 + YARA)

| 탐지 항목 | 대상 | 설명 |
|-----------|------|------|
| 위험 함수 | `exec()`, `eval()`, `subprocess.Popen()`, `os.system()` | 동적 코드 실행, 시스템 명령어 호출 |
| 난독화 패턴 | `base64`, `zlib` | 페이로드 인코딩으로 코드 은닉 시도 |
| 하드코딩 시크릿 | `API_KEY`, `SECRET_KEY` 패턴 | 코드에 직접 포함된 인증 정보 |
| YARA 룰 (13개) | APT 시그니처, PyPI 악성 패턴, PowerShell 페이로드 등 | 알려진 악성코드 패턴 매칭 |
| 의심 파일명 | `setup.py`, `install.py`, `bootstrap.py` 등 | 설치 시 자동 실행되는 파일 |

- YARA 룰은 디렉토리 스캔 시 **한 번만 컴파일**하여 파일별 반복 컴파일을 방지 (200회 → 1회)

### 2차 — LLM 오탐 필터링 (Ollama)

1차에서 플래그된 코드를 LLM에 전달하여 **"테스트 코드의 더미 키인지, 실제 악성인지"** 재판단한다.

- `SECRET_KEY="test"` 같은 개발용 설정을 오탐에서 제거
- 판단 결과: `safe` / `malicious` / `null`(판단 불가) 라벨 부여
- `ThreadPoolExecutor(4)` 병렬 호출로 속도 유지
- Ollama 서비스 미가동 시 LLM 단계를 건너뛰고 1차 결과만 반환 (graceful degradation)

**성과**:
- FP Rate: 20% → 10%
- Flask 실적용: 11건 오탐 → 2건 (81.8% 제거)
- 분석 시간: 11분 42초 → ~3분 30초 (70% 단축)

**구현**: `backend/app/services/malware.py`, `backend/app/workers/tasks.py` (`_llm_filter_malware`)

---

## 5. 타이포스쿼팅 탐지 (4종 알고리즘)

공격자가 인기 패키지와 **이름이 비슷한 악성 패키지**를 등록하여, 개발자의 오타를 노리는 공격을 탐지한다.

- 비교 대상: PyPI/npm 인기 패키지 **100+개**
- 임계값: 유사도 **85%** 이상 (SequenceMatcher 기준)

### 4종 알고리즘

| 알고리즘 | 탐지 대상 | 예시 |
|----------|----------|------|
| **Char Insertion** | 글자 1개 추가/삭제 | `browser-cookies3` → `browser-cookie3` |
| **Char Swap** | 인접 글자 순서 변경 | `djnago` → `django` |
| **Levenshtein Distance** | 편집 거리 1~2 이내 (4글자 이상) | `reqeusts` → `requests` |
| **SequenceMatcher** | 전체 유사도 85% 이상 | `python-dateutils` → `python-dateutil` |

하나라도 걸리면 의심 패키지로 플래그. 설치 전 사전 검사(`/pypi-npm/pre-check`)에서도 동일 로직을 사용하여 **설치 자체를 차단**할 수 있다.

### 실제 탐지 사례

`browser-cookies3` — PyPI에 196회 다운로드된 악성 패키지. 비밀번호와 Discord 토큰을 탈취하는 코드가 포함되어 있었으나, 기존 로직(SequenceMatcher 1개 + 패키지 10개)으로는 탐지하지 못했다. 4종 알고리즘 적용 후 Char Insertion 알고리즘으로 탐지 성공.

**성과**: Recall 50% → 91.7%, F1 Score 66.7% → 95.7%

**구현**: `backend/app/services/typosquatting.py`

---

## 6. 디펜던시 컨퓨전 탐지

기업 내부 패키지 이름과 동일한 이름의 패키지가 **공개 레지스트리(PyPI/npm)**에 등록되어 있을 때, 빌드 시스템이 외부 패키지를 우선 설치하는 공격을 탐지한다.

### 탐지 로직

1. `internal_deps.txt`에 정의된 내부 패키지 목록과 배포자(distributor)를 대조
2. 패키지명에 내부 키워드(`internal`, `corp`, `private`, `enterprise`, `inhouse`)가 포함되어 있는지 확인
3. 배포자가 신뢰 목록(`Official`, `TrustedOrg`, `PyPI`, `InternalRepo`)에 없으면 **위험 플래그**

### 공격 시나리오 (참고)

> 2021년 Alex Birsan이 Apple, Microsoft, PayPal 등 35개 기업의 내부 패키지명을 공개 레지스트리에 등록하여 내부 빌드 시스템에 침투한 사례. `pip install`이 내부 레지스트리보다 PyPI를 우선 참조하는 동작을 악용.

**구현**: `backend/app/services/dependency_confusion.py`

---

## 7. AI 위험도 점수 (Risk Scoring)

전체 분석 결과를 종합하여 **0~100점 위험도 점수**를 산출한다.

### 배점 기준

| 항목 | 배점 | 가중치 |
|------|------|--------|
| CVE 취약점 | 최대 60점 | CRITICAL ×15, HIGH ×8, MEDIUM ×3, LOW ×1 |
| 타이포스쿼팅 | 최대 15점 | 탐지 건당 5점 |
| 디펜던시 컨퓨전 | 최대 15점 | 탐지 건당 5점 |
| 악성코드 + YARA | 최대 10점 | 위험함수 2점, 난독화 1점, 시크릿 1점, YARA 히트 2점 |

### 등급 체계

| 점수 | 등급 | 대응 |
|------|------|------|
| 70~100 | **CRITICAL** | 즉시 대응 필요 |
| 50~69 | **HIGH** | 조속한 대응 권장 |
| 30~49 | **MEDIUM** | 계획적 패치 필요 |
| 10~29 | **LOW** | 모니터링 유지 |
| 0~9 | **SAFE** | 심각한 위험 없음 |

**구현**: `backend/app/services/ai/risk_scorer.py`
