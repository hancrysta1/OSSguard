# OSSGuard 보안 탐지 고도화 과정

## 배경

OSSGuard는 오픈소스 패키지의 보안 위협을 탐지하는 플랫폼이다. 웹사이트에서 패키지명을 입력하면 SBOM 생성, CVE 스캔, 악성코드 탐지, 타이포스쿼팅 검사를 자동으로 수행한다.

기능 자체는 잘 동작했지만, 실제 보안 사고 사례를 추적하면서 **두 가지 구조적 한계**를 발견하였다.

---

## 1. 타이포스쿼팅 탐지 고도화

### 1-1. 문제 발견 (동기)

Socket.dev의 보안 리서치팀이 PyPI에서 `browser-cookies3`라는 악성 패키지를 발견한 기사를 보게 되었다.

**정상 패키지 `browser-cookie3`란?**

`browser-cookie3`는 Chrome, Firefox 등 브라우저에 저장된 쿠키를 Python에서 읽을 수 있게 해주는 유틸리티 패키지이다. 2015년부터 유지되어 온 패키지로, **누적 다운로드 300만 회 이상**, 수천 명의 개발자가 사용하고 있다.

- PyPI: [https://pypi.org/project/browser-cookie3/](https://pypi.org/project/browser-cookie3/)
- GitHub: [https://github.com/borisbabic/browser_cookie3](https://github.com/borisbabic/browser_cookie3)

**악성 패키지 `browser-cookies3`란?**

공격자가 정상 패키지 이름에 **`s` 하나만 추가**한 `browser-cookies3`를 PyPI에 등록하였다. 개발자가 `pip install browser-cookies3`를 오타로 입력하면 악성 패키지가 설치되는 구조이다.

이 패키지의 `setup.py`에는 **설치 시 자동 실행되는 악성 코드**가 포함되어 있었고, 실행되면 다음 정보를 탈취한다:

- 브라우저 저장 비밀번호
- 스크린샷
- 웹캠 이미지
- Discord 인증 토큰

발견 전까지 **196회 다운로드**되었다. 즉, 196명이 오타 한 번으로 개인정보를 탈취당할 수 있었던 것이다.

- 출처: [Socket.dev - Typosquatting on PyPI: Malicious Package Mimics Popular 'browser-cookie3'](https://socket.dev/blog/typosquatting-on-pypi-malicious-package-mimics-popular-browser-cookie-library)
- Hacker News 토론: [https://news.ycombinator.com/item?id=41814614](https://news.ycombinator.com/item?id=41814614)

"OSSGuard로 이걸 잡을 수 있나?" 싶어서 테스트해보았다.

### 1-2. 기존 방식의 한계 분석

**테스트 결과 (Before):**

```
=======================================================
  Before: 기존 타이포스쿼팅 탐지
  패키지 목록: 10개 | 알고리즘: SequenceMatcher
  Threshold: 0.9
=======================================================

  [FN 놓침] browser-cookies3            (실제 악성 패키지, 196회 다운로드)
  [TP 탐지] requestss                 → requests
  [FN 놓침] djnago                      (글자 순서 변경)
  [FN 놓침] reqeusts                    (글자 위치 변경)
  [FN 놓침] nunpy                       (글자 탈락)

  Precision: 100.0%  Recall: 20.0%  F1: 33.3%
```

**`browser-cookies3`를 못 잡은 이유:**

기존 방식에는 두 가지 문제가 있었다.

**문제 1: 비교 대상이 10개뿐**

기존 코드에 하드코딩된 공식 패키지가 `requests`, `numpy`, `pandas` 등 **10개**뿐이었다. `browser-cookie3`는 목록에 없으니 **비교 자체를 하지 않았다.** PyPI에만 50만 개 이상의 패키지가 있는데, 10개만 보고 있던 것이다.

**문제 2: SequenceMatcher 알고리즘의 한계**

목록을 늘리면 해결될까? `djnago`(django 오타)의 경우, `browser-cookie3`가 목록에 있어도 SequenceMatcher의 특성상 **글자 순서 변경(transposition)에 유사도를 낮게 계산**하는 문제가 있었다.

그렇다고 threshold를 무작정 낮추면 `djangorest` 같은 정상 패키지도 `django`의 타이포로 잡히는 **Precision과 Recall 사이의 트레이드오프** 문제가 있다.

```
threshold 높이면 → 오탐 줄지만 놓치는 것 많아짐 (Recall ↓)
threshold 낮추면 → 더 잡지만 정상도 걸림 (Precision ↓)
```

### 1-3. 개선: 다중 유사도 알고리즘 도입

하나의 알고리즘으로는 한계가 있어서, **각각 다른 유형의 오타를 잡는 알고리즘 여러 개를 조합**하였다.

| 알고리즘 | 잡는 유형 | 예시 | 원리 |
|---------|----------|------|------|
| **Levenshtein Distance** | 글자 추가/삭제/변경 | `nunpy` → `numpy` (1글자 삭제) | 두 문자열 사이 최소 편집 횟수를 동적 프로그래밍(DP)으로 계산. `O(n*m)` 시간복잡도 |
| **Char Insertion 검사** | 글자 1개 삽입 | `browser-cookies3` → `browser-cookie3` (s 추가) | 긴 문자열에서 1글자를 빼면 짧은 문자열과 같아지는지 선형 탐색. `O(n)` |
| **Char Swap 검사** | 인접 글자 순서 변경 | `djnago` → `django` (a-n 위치 변경) | 두 문자열의 차이가 정확히 2개이고, 교차 일치하는지 확인. `O(n)` |
| **SequenceMatcher** | 전반적 유사도 | `flaask` → `flask` | 가장 긴 공통 부분 문자열 기반 비율 계산 (기존 방식, threshold 0.9→0.85로 조정) |

**왜 여러 개를 조합했는가:**

- Levenshtein Distance는 `browser-cookies3`(1글자 추가)을 잡지만, `reqeusts`(2글자 swap)에서 거리 2로 경계에 걸린다
- Char Swap은 `djnago`를 정확히 잡지만, `nunpy`(글자 삭제)는 길이가 달라서 못 잡는다
- SequenceMatcher는 전반적으로 무난하지만 단독으로는 threshold 설정이 어렵다

**각 알고리즘이 서로 다른 약점을 보완**하는 구조이다.

### 1-4. 결과 (After)

```
=======================================================
  After: 100+개 패키지, 다중 알고리즘
=======================================================

  [TP 탐지] browser-cookies3          → browser-cookie3 (Char Insertion)
  [TP 탐지] requestss                 → requests (Char Insertion)
  [TP 탐지] djnago                    → django (Levenshtein ≤2)
  [TP 탐지] reqeusts                  → requests (Levenshtein ≤2)
  [TP 탐지] nunpy                     → numpy (Levenshtein ≤2)

  Precision: 100.0%  Recall: 91.7%  F1: 95.7%
```

### 1-5. Before vs After 비교

| 지표 | Before | After | 변화 |
|------|--------|-------|------|
| **Recall** | 50.0% | **91.7%** | +41.7%p |
| **F1 Score** | 66.7% | **95.7%** | +29.0%p |
| Precision | 100% | 100% | 유지 |
| FP Rate | 0% | 0% | 유지 |

**Precision(오탐 0%)을 유지하면서 Recall을 50% → 91.7%로 끌어올렸다.**

---

## 2. 악성코드 탐지 고도화 (LLM 기반 SAST)

### 2-1. 문제 발견 (동기)

2026년 2월, dYdX 거래소의 **정식 PyPI 패키지에 악성 코드가 심어진 사건**을 보게 되었다.

> 공격자가 관리자 계정을 탈취해, 정상 패키지의 업데이트 버전에 암호화폐 지갑 탈취 코드를 삽입. **7개월간 128개 패키지, 121,539회 다운로드.**

- 출처: [The Hacker News - Compromised dYdX Packages](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)

이 사건의 악성 코드는 `base64` + `zlib`로 **100번 반복 난독화**되어 있었다. OSSGuard의 키워드 탐지는 `base64` 키워드를 잡긴 하지만, 여기서 문제가 드러났다.

### 2-2. 기존 방식의 한계 분석

**Before 벤치마크 (악성 10개 / 정상 10개):**

```
  TP (정탐): 10  |  FP (오탐): 2
  Precision: 83.3%  |  Recall: 100%  |  FP Rate: 20.0%

  오분류:
    [FP 오탐] base64_legit.py    ← 이미지 인코딩 코드인데 악성 판정
    [FP 오탐] subprocess_legit.py ← git 명령 실행 코드인데 악성 판정
```

**핵심 문제: 키워드만 보고는 코드의 '의도'를 알 수 없다.**

```python
# 정상: 이미지를 API로 보내기 위해 인코딩
encoded = base64.b64encode(image_file.read())

# 악성: 훔친 비밀번호를 외부 서버로 전송
encoded = base64.b64encode(password.encode())
```

둘 다 `base64`를 쓴다. 키워드는 **완전히 동일**하다.

키워드를 더 추가하면? `requests.post`를 추가하면 API 호출하는 정상 코드 전부 걸리고, `socket`을 추가하면 네트워크 코드 전부 걸린다. **키워드를 늘릴수록 오탐이 같이 늘어나는 구조**이다.

### 2-3. 개선: LLM 기반 2차 판단 도입

키워드 탐지를 1차 필터로 두고, 거기서 걸린 코드를 **LLM(Ollama llama3)에 넘겨서 코드의 목적을 판단**하는 2차 검증 단계를 추가하였다.

```
Before:  코드 → 키워드 있음? → Yes → 악성 판정 (끝)
After:   코드 → 키워드 있음? → Yes → LLM에 "이 코드 뭐 하는 거야?" → 판정
```

LLM에게 보내는 프롬프트:

```
키워드 [base64]가 탐지된 코드이다.
이 키워드가 정상적인 목적(이미지 처리, git 명령 등)이면 "safe",
악의적인 목적(데이터 탈취, 원격 코드 실행 등)이면 "malicious"로 판단하라.
```

**LLM이 `base64_legit.py`를 정확히 "safe"로 판단하여 오탐을 제거**하였다.

### 2-4. Before vs After 비교

| 지표 | Before | After | 변화 |
|------|--------|-------|------|
| **Precision** | 83.3% | **90.9%** | +7.6%p |
| **FP Rate** | 20.0% | **10.0%** | 절반 감소 |
| **F1 Score** | 90.9% | **95.2%** | +4.3%p |
| **Accuracy** | 90.0% | **95.0%** | +5.0%p |
| Recall | 100% | 100% | 유지 |

### 2-5. 실제 프로젝트 적용에서 발견된 추가 오탐 — Flask 사례

벤치마크에서 LLM 도입의 효과를 확인한 뒤, 실제 오픈소스 프로젝트(Flask)를 분석해보았다.

결과에서 **악성코드 의심 파일 11개**가 탐지되었는데, 전부 이런 내용이었다:

```
tests/conftest.py        → 하드코딩 API 키 탐지
tests/test_basic.py      → 하드코딩 API 키 탐지
tests/test_config.py     → 하드코딩 API 키 탐지
```

실제 코드를 보면:

```python
# tests/conftest.py (Flask 공식 테스트 코드)
SECRET_KEY="test key"
```

테스트 파일에 `SECRET_KEY`가 있는 건 당연하다. 테스트를 위한 더미 값이지 실제 비밀 키가 아니다. 하지만 키워드 탐지는 `SECRET_KEY`라는 문자열만 보고 "하드코딩된 시크릿"으로 판정한다.

이것은 벤치마크의 `base64_legit.py` 오탐과 **동일한 구조의 문제**이다:

| 벤치마크 오탐 | 실제 프로젝트 오탐 | 공통 원인 |
|---|---|---|
| 이미지 인코딩에 `base64` 사용 → "난독화 의심" | 테스트 코드에 `SECRET_KEY` 사용 → "하드코딩 키" | **코드의 목적을 모른 채 키워드만 매칭** |

LLM 2차 판단을 적용하면 "이 파일은 `tests/` 디렉토리의 테스트 코드이고, `SECRET_KEY`는 테스트용 더미 값이다 → safe" 판정이 가능하다.

LLM 2차 판단을 실제로 적용한 결과:

```
============================================================
  Flask 테스트 코드 오탐 Before/After (LLM)
============================================================

  Before: 키워드 탐지 단독
    [FP 오탐] tests/conftest.py        → SECRET_KEY 탐지
    [FP 오탐] tests/test_basic.py      → SECRET_KEY 탐지
    ... (총 11개 전부 오탐)

  After: 키워드 1차 → LLM 2차 판단
    [TN 정상] tests/conftest.py        → LLM: safe (오탐 제거!)
    [TN 정상] tests/test_basic.py      → LLM: safe (오탐 제거!)
    [TN 정상] tests/test_config.py     → LLM: safe (오탐 제거!)
    ... (11개 중 9개 오탐 제거)

  Before vs After
    오탐 파일 수:  11개 → 2개
    오탐률:        100% → 18.2%
    오탐 제거율:   81.8%
```

남은 2개는 경량 모델(1B)이 판단을 내리지 못한 것(unknown)이며, 악성으로 잘못 판단한 건 **0건**이다.

**벤치마크 샘플뿐 아니라 실제 프로젝트에서도 동일한 패턴의 오탐이 발생**하고, LLM 2차 판단으로 **81.8%의 오탐을 제거**할 수 있음을 확인하였다.

### 2-6. 실제 분석 파이프라인에 LLM 통합

벤치마크로 효과를 확인한 뒤, LLM 2차 판단을 **실제 분석 파이프라인에 통합**하였다.

#### 처음 시도 — API 응답 시점에서 LLM 호출 (실패)

처음에는 대시보드 API(`/g_dashboard`)가 결과를 반환할 때 실시간으로 LLM을 호출하는 방식으로 구현하였다.

```
사용자가 대시보드 열기 → API 호출 → 11개 파일 × LLM 판단 → 응답
```

**문제가 된 이유:**

LLM 추론은 **느린 작업**이다. 특히 Docker 환경에서 CPU로 돌리는 경량 모델(llama3.2 1B)도 파일 1개당 약 30~60초가 걸린다. 11개 파일이면 최소 5분 이상이다.

이를 API 응답 시점에서 수행하면:

1. **사용자가 대시보드를 열 때마다 5분 이상 대기** — 사용자 경험이 매우 나쁘다
2. **타임아웃으로 매번 결과가 다름** — 처음에 5개 판단 성공, 다음에 7개, 또 다음에 4개... 일관성이 없다
3. **같은 분석을 반복 수행** — 분석 대상이 바뀌지 않았는데 열 때마다 LLM을 다시 호출한다

근본적인 원인은 **"언제 LLM을 호출하느냐"의 설계 문제**이다. LLM 판단은 분석 대상 코드가 바뀔 때만 필요한 **일회성 작업**인데, 이를 사용자가 결과를 볼 때마다 반복 실행하고 있었다.

#### 수정 — 분석 시점(Celery 워커)에서 한 번만 실행

LLM 판단을 대시보드 API가 아니라, **백그라운드 분석 파이프라인(Celery 워커) 안에서 한 번만 실행**하고 결과를 Redis에 같이 저장하는 방식으로 변경하였다.

```
Before: clone → SBOM → SCA → malware 스캔 →              → Redis 저장
After:  clone → SBOM → SCA → malware 스캔 → LLM 2차 판단 → Redis 저장
                                                ↑ llm_verdict를 결과에 포함해서 저장
```

이렇게 하면:
- 분석은 어차피 백그라운드에서 비동기로 돌아가므로, **LLM이 느려도 사용자가 기다릴 필요가 없다**
- 결과가 Redis에 저장되므로, 대시보드 API는 **저장된 값을 읽기만** 하면 된다 → 빠르고 일관적이다
- 코드가 바뀌지 않으면 **재분석 전까지 같은 결과**를 보여준다

#### 프론트엔드 표시

- `llm_verdict: "safe"` → 초록색 뱃지 + "AI: safe (오탐 제거)" + 반투명 처리
- `llm_verdict: "malicious"` → 기존처럼 빨간색 유지
- `llm_verdict: null` → LLM이 판단 못 한 경우, 보수적으로 기존 탐지 결과 유지
- 악성 코드 탐지 섹션 헤더에 "N건 AI 오탐 제거" 카운트 표시

### 2-8. 남은 한계와 향후 개선

**1) `subprocess_legit.py` 오탐 미해결**

LLM 벤치마크에서 `base64_legit.py`의 오탐은 제거했지만, `subprocess_legit.py`(git 명령 실행 코드)는 경량 모델(llama3.2 1B)이 여전히 "malicious"로 판단한다. 코드의 문맥이 더 복잡한 경우 경량 모델의 추론 능력이 부족한 것으로, 더 큰 모델(llama3 8B 이상) 사용이나 프롬프트 개선으로 해결 가능하다.

**2) `pyproject.toml` 미지원**

Flask처럼 `pyproject.toml`을 사용하는 프로젝트는 타이포스쿼팅 의존성 검사가 동작하지 않는다. 현재 `requirements.txt`만 파싱하기 때문이다. 최근 Python 프로젝트는 대부분 `pyproject.toml` 또는 `setup.cfg`를 사용하므로, 이를 파싱하는 기능을 추가해야 실용성이 높아진다.

---

## 3. 활용 방식 개선: 웹사이트 → CI/CD 파이프라인

### 3-1. 문제

위 dYdX 사건이 보여주듯, 보안 위협은 **처음 설치할 때가 아니라 이후 업데이트에서** 들어오는 경우가 많다. 웹사이트에서 수동으로 검사하는 방식은 일회성이라 이런 위협을 놓친다.

CLI 모듈(`ossguard install flask`)을 만들어도 매번 개발할 때마다 실행하는 건 비현실적이고, 결국 안 쓰게 된다.

### 3-2. 개선

CI(Continuous Integration) 파이프라인에 테스트처럼 끼워넣는 방식으로 변경하였다. PR을 올리거나 배포할 때 **자동으로** 보안 검사가 실행된다.

```
기존 CI:    코드 푸시 → 빌드 → 테스트 → 린트 → 배포
개선 후:    코드 푸시 → 빌드 → 테스트 → 린트 → OSSGuard 보안 검사 → 배포
                                                  ↑ 문제 발견 시 배포 차단
```

---

## 4. 프론트엔드-백엔드 데이터 불일치 해결

### 4-1. 문제 발견

Flask 리포지토리(`https://github.com/pallets/flask`)를 분석했을 때, **종합 분석 탭에는 "취약점 13건"으로 표시**되는데 나머지 탭(취약점 분석, 악성 코드 탐지 등)에서는 **전부 0건**으로 나오는 현상이 발생하였다.

### 4-2. 원인 파악

Redis에 저장된 실제 백엔드 응답 데이터의 키 구조를 확인해본 결과, **프론트엔드가 기대하는 키 이름과 백엔드가 실제로 보내는 키 이름이 달랐다.**

```
# 프론트엔드가 읽는 키          →  백엔드가 보내는 키
typosquatting_results           →  typosquatting_analysis
dependency_confusion_results    →  dependency_confusion_analysis
severity_distribution (array)   →  security_overview.severity_count (dict)
```

또한 악성코드 데이터 구조에서도 불일치가 있었다. 프론트엔드는 `entry.dangerous_functions`를 직접 읽는데, 백엔드는 `entry.result.dangerous_functions`로 한 단계 감싸서 보내고 있었다.

```json
// 프론트엔드가 기대하는 구조
{ "file": "test.py", "dangerous_functions": ["exec"] }

// 백엔드가 실제로 보내는 구조
{ "file": "test.py", "result": { "dangerous_functions": ["exec"], ... } }
```

### 4-3. 해결

**1) 키 이름 호환 처리**

타이포스쿼팅, 의존성 혼동 데이터를 읽을 때 백엔드 키(`_analysis`)와 프론트 키(`_results`) 모두를 참조하도록 수정하였다.

```typescript
// MalwareDetection.tsx - Before
const typoResults = analysisData?.typosquatting_results || [];

// MalwareDetection.tsx - After (양쪽 키 모두 대응)
const typoResults = analysisData?.typosquatting_analysis
                 || analysisData?.typosquatting_results || [];
```

**2) 악성코드 데이터 래핑 처리**

백엔드의 `result` 래핑 구조에 대응하는 헬퍼를 추가하였다.

```typescript
// result 안에 감싸져 있으면 풀어서 읽음
const getResult = (e: any) => e.result || e;

const hasDanger = getResult(entry).dangerous_functions?.length
              || getResult(entry).obfuscation_detected;
```

**3) 심각도 분포 데이터 변환**

백엔드는 `severity_count`를 `{ "CRITICAL": 0, "HIGH": 1, ... }` dict로 보내는데, 프론트의 파이차트는 `[{ level: "CRITICAL", count: 0 }, ...]` 배열을 기대한다. dict → 배열 변환 로직을 추가하였다.

```typescript
// Overview.tsx - severity_count dict를 배열로 변환
const severity = analysisData.severity_distribution?.length
  ? analysisData.severity_distribution
  : Object.entries(overview?.severity_count || {}).map(([level, count]) => ({
      level,
      count: count as number,
    }));
```

### 4-4. 교훈

백엔드와 프론트엔드를 별도로 개발할 때, **API 응답의 키 네이밍 컨벤션을 사전에 맞추지 않으면** 통합 단계에서 이런 문제가 발생한다. 데이터는 정상적으로 있지만 이름이 달라서 화면에 안 보이는 — 디버깅하기 어려운 유형의 버그이다.

Redis CLI로 실제 저장된 데이터를 직접 확인하는 방식으로 원인을 특정할 수 있었다.

---

## 5. 대시보드 API 응답 누락 해결

### 5-1. 문제 발견

키 이름 불일치를 수정한 뒤에도 **여전히 SBOM 분석, 취약점 분석, 패키지 업데이트 탭이 전부 0건**으로 표시되었다.

### 5-2. 원인 파악

API 응답을 직접 확인해보았다.

```bash
curl -s http://localhost:8000/github/g_dashboard \
  -H "Content-Type: application/json" \
  -d '{"github_url":"https://github.com/pallets/flask"}'
```

결과: `packages`, `vulnerabilities`, `malicious_code_analysis` 등이 **응답에 아예 포함되지 않았다.**

백엔드의 `/github/g_dashboard` 엔드포인트 코드를 확인한 결과, 이 엔드포인트는 `security_overview`와 `top_vulnerabilities`**만** 반환하고 있었다. 나머지 데이터는 `/github/packages`, `/github/vulnerabilities`, `/github/malicious_code` 등 **별도 엔드포인트**로 분리되어 있었다.

```python
# 기존: g_dashboard가 반환하는 데이터
return {
    "repository": ...,
    "security_overview": ...,
    "severity_distribution": ...,
    "top_vulnerabilities": ...,   # ← 여기까지만
    # packages, vulnerabilities, malicious_code 등 없음
}
```

그런데 프론트엔드는 `g_dashboard` **한 번 호출**로 모든 탭의 데이터를 받아오는 구조였다. 각 탭이 별도 API를 호출하는 방식이 아니라, `AnalysisContext`에 한 번에 저장하고 각 탭이 꺼내 쓰는 구조이다.

즉, **백엔드는 데이터를 여러 API로 분산시켰는데 프론트는 한 API에서 전부 기대하는** 설계 불일치였다.

### 5-3. 해결

`/github/g_dashboard` 엔드포인트에서 Redis에 캐시된 전체 분석 결과를 **한 번에 변환하여 반환**하도록 수정하였다.

추가된 데이터:

| 필드 | 변환 내용 |
|------|----------|
| `packages` | SPDX 원본 구조(`name`, `versionInfo`, `externalRefs`) → 프론트 구조(`package_name`, `version`, `download_link`) |
| `vulnerabilities` | 그대로 전달 |
| `malicious_code_analysis` | `entry.result` 래핑을 풀어서 평탄화 |
| `yara_analysis` | 동일하게 래핑 해제 |
| `typosquatting_results` | `typosquatting_analysis`에서 변환 |
| `dependency_confusion_results` | `dependency_confusion_analysis`에서 변환 |
| `updates` | dict 구조(`{패키지명: {...}}`) → 배열 구조(`[{package_name, ...}]`) |

수정 후 API 응답 검증:

```
packages: 122개
vulnerabilities: 13개
malicious_code: 83개
yara: 83개
updates: 3개
```

### 5-4. 교훈

프론트엔드와 백엔드 사이의 **API 호출 패턴**이 일치하는지 확인해야 한다. 백엔드가 데이터를 분산 엔드포인트로 제공하더라도, 프론트가 한 번의 호출로 전체 데이터를 기대한다면 **집계 엔드포인트(aggregate endpoint)**가 필요하다. 이 문제는 단순히 "키 이름이 다르다"보다 한 단계 위의 — **API 설계 수준의 불일치**였다.

---

## 6. 설치 전 타이포스쿼팅 사전 검사 추가

### 6-1. 왜 이 기능이 필요한가

PyPI/npm 패키지의 `setup.py`(Python) 또는 `postinstall` 스크립트(npm)는 **패키지를 설치하는 순간 자동으로 실행**된다. 즉, `pip install browser-cookies3`를 치는 것만으로 악성 코드가 실행될 수 있다.

실제로 `browser-cookies3` 사건이 정확히 이 방식이었다. 공격자가 `setup.py`에 악성 코드를 넣어두고, 개발자가 설치하는 순간 비밀번호/웹캠/Discord 토큰을 탈취하는 구조였다. **설치 = 감염**인 것이다.

이런 케이스들이 계속 발생하고 있다:

| 사건 | 공격 방식 | 피해 |
|------|----------|------|
| `browser-cookies3` (2024) | `setup.py` 설치 시 자동 실행 | 비밀번호, 웹캠, Discord 토큰 탈취 (196회 다운로드) |
| `aiocpa` (2024.11) | 정상 패키지 업데이트에 악성 코드 삽입 | 암호화폐 지갑 정보 → 텔레그램 전송 (12,100회 다운로드) |
| dYdX (2026.02) | 관리자 계정 탈취 → 정식 패키지에 악성 버전 배포 | 지갑 탈취 + RAT (121,539회 다운로드) |

공통점은 **설치하는 순간 이미 늦다**는 것이다. 따라서 **설치 전에** 패키지명이 안전한지 먼저 확인하는 사전 검사가 필수이다.

### 6-2. 문제 발견

위 필요성을 인지하고 `browser-cookies3`를 OSSGuard의 PyPI 분석에 넣어보았다. 이 패키지는 이미 PyPI에서 삭제되었기 때문에 `pip install`이 실패한다.

문제는, **설치가 실패하면 분석 자체가 시작되지 않는다**는 것이었다. 기존 흐름이:

```
패키지명 입력 → pip install → 설치된 파일 SBOM 생성 → CVE 스캔 → 타이포스쿼팅 검사
```

이렇게 **설치가 성공해야만 타이포스쿼팅 검사까지 도달**하는 구조였다. 삭제된 악성 패키지, 존재하지 않는 패키지는 설치 단계에서 막혀서 아무런 경고 없이 "설치 실패"로 끝난다.

하지만 타이포스쿼팅 검사는 **패키지명만 있으면 할 수 있는 검사**이다. 설치 성공 여부와 무관하게, 패키지명이 정식 패키지와 비슷한지 판단하는 데는 파일이 필요하지 않다.

### 6-3. 해결: 설치 전 사전 검사 (Pre-check)

패키지 설치를 시도하기 **전에** 타이포스쿼팅 검사를 먼저 수행하는 사전 검사 엔드포인트를 추가하였다.

**백엔드** — `/pypi-npm/pre-check` 엔드포인트 추가:

```python
@router.post("/pre-check")
async def pre_check_package(req: PackageRequest):
    from app.services.typosquatting import detect_typosquatting
    is_typo, official = detect_typosquatting(req.package_name)
    return {
        "package_name": req.package_name,
        "typosquatting": {
            "detected": is_typo,
            "official_package": official,
            "warning": f"'{req.package_name}'은(는) '{official}'의 타이포스쿼팅 의심" if is_typo else None,
        },
    }
```

**프론트엔드** — 설치 전 사전 검사 호출:

```typescript
// 설치 전 타이포스쿼팅 사전 검사
const preCheck = await preCheckPackage(manager, name);
if (preCheck.typosquatting?.detected) {
  toast.error(`타이포스쿼팅 의심: '${name}'은(는) '${official}'의 유사 패키지입니다.`);
  return; // 설치 중단
}
```

**변경된 흐름:**

```
Before: 패키지명 입력 → pip install (실패) → 끝 (경고 없음)
After:  패키지명 입력 → 사전 검사 → 타이포스쿼팅 탐지! → 설치 차단 + 경고
```

### 6-4. 검증

```bash
# browser-cookies3 사전 검사
curl -s http://localhost:8000/pypi-npm/pre-check \
  -H "Content-Type: application/json" \
  -d '{"package_manager":"pypi","package_name":"browser-cookies3","package_version":""}'
```

```json
{
  "package_name": "browser-cookies3",
  "typosquatting": {
    "detected": true,
    "official_package": "browser-cookie3",
    "warning": "'browser-cookies3'은(는) 정식 패키지 'browser-cookie3'의 타이포스쿼팅 의심 패키지입니다."
  }
}
```

실제로 삭제된 악성 패키지 `browser-cookies3`를 **설치 없이, 패키지명만으로 탐지**하고 설치를 차단한다.

### 6-5. 교훈

보안 검사는 가능한 한 **파이프라인 앞단에서** 수행해야 한다. 설치 후에 검사하는 것은 이미 악성 코드가 실행된 뒤일 수 있다. 특히 PyPI 패키지의 `setup.py`는 **설치 시점에 자동 실행**되기 때문에, 설치 자체가 공격 벡터가 된다. `browser-cookies3`도 정확히 이 방식으로 설치 시 `setup.py`에서 악성 코드가 실행되는 구조였다.

---

## 벤치마크 실행 방법

```bash
cd ossguard/backend

# Before 버전만 (캡처용)
python3 tests/benchmark/run_before_only.py

# SAST Before/After (키워드 단독)
python3 tests/benchmark/run_benchmark.py

# SAST LLM Before/After (Ollama 필요)
bash tests/benchmark/run_llm_final.sh

# 타이포스쿼팅 Before/After
python3 tests/benchmark/run_typo_benchmark.py
```

---

## 전체 성과 요약

| 영역 | 지표 | Before | After |
|------|------|--------|-------|
| 타이포스쿼팅 | Recall | 50.0% | **91.7%** |
| 타이포스쿼팅 | F1 Score | 66.7% | **95.7%** |
| 악성코드 탐지 (SAST) | FP Rate | 20.0% | **10.0%** |
| 악성코드 탐지 (SAST) | Precision | 83.3% | **90.9%** |
| 악성코드 탐지 (SAST) | F1 Score | 90.9% | **95.2%** |

---

## 참고 자료

- [Socket.dev - browser-cookies3 타이포스쿼팅](https://socket.dev/blog/typosquatting-on-pypi-malicious-package-mimics-popular-browser-cookie-library)
- [The Hacker News - dYdX 공급망 공격 (2026.02)](https://thehackernews.com/2026/02/compromised-dydx-npm-and-pypi-packages.html)
- [The Hacker News - PyPI 신규 가입 중단 사태 (2024.03)](https://thehackernews.com/2024/03/pypi-halts-sign-ups-amid-surge-of.html)
- [Sonatype - 오픈소스 악성코드 156% 증가 (2024)](https://www.globenewswire.com/news-release/2024/10/10/2961239/0/en/Sonatype-s-10th-Annual-State-of-the-Software-Supply-Chain-Report-Reveals-156-Surge-in-Open-Source-Malware.html)
- [Synopsys OSSRA 2024 - 코드베이스 74%에서 고위험 취약점](https://news.synopsys.com/2024-02-27-New-Synopsys-Report-Finds-74-of-Codebases-Contained-High-Risk-Open-Source-Vulnerabilities,-Surging-54-Since-Last-Year)
- [KISA - SW 공급망 보안 가이드라인 1.0 (2024.05)](https://www.kisa.or.kr/2060204/form?postSeq=15&page=1)