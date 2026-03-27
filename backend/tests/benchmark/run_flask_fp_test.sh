#!/bin/bash
# Flask 테스트 코드 오탐 Before/After 비교
# 실제 Flask 분석 결과에서 "하드코딩 키"로 오탐된 11개 파일을 LLM으로 재판단

OLLAMA="http://localhost:11434/api/generate"
MODEL="llama3.2:1b"

echo "============================================================"
echo "  Flask 테스트 코드 오탐 Before/After (LLM)"
echo "============================================================"

# Flask 분석에서 하드코딩 키 탐지된 파일들 (실제 결과 기반)
FILES=(
  "tests/conftest.py|SECRET_KEY=\"test key\""
  "tests/test_basic.py|app.secret_key = None"
  "tests/test_reqctx.py|SECRET_KEY=\"testing\""
  "tests/test_config.py|SECRET_KEY=\"devkey\""
  "examples/tutorial/flaskr/__init__.py|SECRET_KEY=\"dev\""
  "tests/test_templating.py|SECRET_KEY=\"testing\""
  "tests/test_testing.py|SECRET_KEY=\"testing\""
  "tests/test_views.py|SECRET_KEY=\"testing\""
  "examples/tutorial/tests/conftest.py|SECRET_KEY=\"test\""
  "tests/test_json_tag.py|SECRET_KEY=\"testing\""
  "tests/test_signals.py|SECRET_KEY=\"testing\""
)

BEFORE_FP=0
AFTER_FP=0
AFTER_TN=0

echo ""
echo "=== Before: 키워드 탐지 단독 ==="
echo ""

for entry in "${FILES[@]}"; do
  IFS='|' read -r file code <<< "$entry"
  BEFORE_FP=$((BEFORE_FP+1))
  echo "  [FP 오탐] $file → SECRET_KEY 탐지"
done

echo ""
echo "  오탐: ${BEFORE_FP}개 / 전체: ${BEFORE_FP}개"
echo "  ※ 전부 테스트 코드의 더미 값인데 '하드코딩 시크릿'으로 판정"
echo ""

echo "=== After: 키워드 1차 → LLM 2차 판단 ==="
echo "(LLM 호출 중...)"
echo ""

LLM_DETAILS=""

for entry in "${FILES[@]}"; do
  IFS='|' read -r file code <<< "$entry"

  # 따옴표 제거 + 짧은 프롬프트
  clean_code=$(echo "$code" | tr -d '"')
  prompt="Is ${clean_code} in file ${file} safe or malicious? One word:"

  # python으로 JSON 생성 (따옴표 escape 안전)
  resp=$(python3 -c "
import json, urllib.request
body = json.dumps({'model':'$MODEL','prompt':'$prompt','stream':False,'options':{'temperature':0.1,'num_predict':10}}).encode()
req = urllib.request.Request('$OLLAMA', data=body, headers={'Content-Type':'application/json'})
try:
    r = urllib.request.urlopen(req, timeout=180)
    print(r.read().decode())
except: print('{}')
" 2>/dev/null)

  verdict=$(echo "$resp" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    r=d.get('response','').lower()
    if 'malicious' in r: print('malicious')
    elif 'safe' in r: print('safe')
    else: print('unknown')
except: print('error')
" 2>/dev/null)

  if [ "$verdict" = "safe" ]; then
    AFTER_TN=$((AFTER_TN+1))
    echo "  [TN 정상] $file → LLM: safe (오탐 제거!)"
  else
    AFTER_FP=$((AFTER_FP+1))
    echo "  [FP 오탐] $file → LLM: $verdict"
  fi
done

echo ""
echo "  오탐: ${AFTER_FP}개 / 전체: ${#FILES[@]}개 (제거: ${AFTER_TN}개)"

echo ""
echo "============================================================"
echo "  Before vs After 비교"
echo "============================================================"
echo ""

BEFORE_FPR=$(python3 -c "print(f'{$BEFORE_FP/$BEFORE_FP*100:.1f}%')")
TOTAL=${#FILES[@]}
AFTER_FPR=$(python3 -c "fp=$AFTER_FP;t=$TOTAL;print(f'{fp/t*100:.1f}%')")
REMOVED=$(python3 -c "print(f'{$AFTER_TN/$TOTAL*100:.1f}%')")

printf "  %-20s %10s %10s\n" "지표" "Before" "After"
echo "  ----------------------------------------"
printf "  %-20s %10s %10s\n" "오탐 파일 수" "${BEFORE_FP}개" "${AFTER_FP}개"
printf "  %-20s %10s %10s\n" "오탐률" "$BEFORE_FPR" "$AFTER_FPR"
printf "  %-20s %10s %10s\n" "오탐 제거율" "-" "$REMOVED"
echo ""
