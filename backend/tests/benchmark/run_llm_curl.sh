#!/bin/bash
# LLM 벤치마크 - curl 기반 (Python 백그라운드 문제 우회)

OLLAMA="http://localhost:11434/api/chat"
MODEL="llama3.2:1b"
RESULTS_FILE="tests/benchmark/benchmark_llm_results.json"

echo "============================================================"
echo "  OSSGuard LLM SAST 벤치마크 (curl 기반)"
echo "============================================================"

# 카운터
BEFORE_TP=0; BEFORE_FP=0; BEFORE_TN=0; BEFORE_FN=0
AFTER_TP=0; AFTER_FP=0; AFTER_TN=0; AFTER_FN=0

check_keywords() {
    local file="$1"
    grep -qE '\b(exec|eval|subprocess\.Popen|os\.system)\b' "$file" && return 0
    grep -qE '(base64|zlib)' "$file" && return 0
    grep -qiE '(API_KEY|apikey|secret_key|SECRET)' "$file" && return 0
    return 1
}

ask_llm() {
    local file="$1"
    local flags="$2"
    local code
    code=$(head -30 "$file" | sed 's/"/\\"/g' | tr '\n' ' ')

    local payload
    payload=$(cat <<ENDJSON
{"model":"$MODEL","messages":[{"role":"user","content":"Keywords [$flags] detected. Is this code SAFE (image processing, git, API) or MALICIOUS (data theft, RCE, reverse shell)? JSON only: {\"verdict\":\"safe or malicious\",\"reason\":\"1 sentence\"}. Code: $code"}],"stream":false,"options":{"temperature":0.1,"num_predict":100}}
ENDJSON
)

    local resp
    resp=$(curl -s --max-time 60 "$OLLAMA" -d "$payload" 2>/dev/null)
    local verdict
    verdict=$(echo "$resp" | python3 -c "
import sys,json,re
try:
    d=json.load(sys.stdin)
    c=d.get('message',{}).get('content','')
    m=re.search(r'\"verdict\"\s*:\s*\"(safe|malicious)\"',c)
    print(m.group(1) if m else 'unknown')
except: print('unknown')
" 2>/dev/null)
    echo "$verdict"
}

echo ""
echo "=== Before: 키워드 탐지 단독 ==="
echo ""

# Malicious files
for f in tests/benchmark/fixtures/malicious/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then
        BEFORE_TP=$((BEFORE_TP+1))
        echo "  [TP] $fname"
    else
        BEFORE_FN=$((BEFORE_FN+1))
        echo "  [FN] $fname"
    fi
done

# Benign files
for f in tests/benchmark/fixtures/benign/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then
        BEFORE_FP=$((BEFORE_FP+1))
        echo "  [FP] $fname  ← 오탐"
    else
        BEFORE_TN=$((BEFORE_TN+1))
        echo "  [TN] $fname"
    fi
done

echo ""
echo "  TP: $BEFORE_TP  FP: $BEFORE_FP  FN: $BEFORE_FN  TN: $BEFORE_TN"

# Before metrics
BEFORE_PREC=$(python3 -c "tp=$BEFORE_TP;fp=$BEFORE_FP;print(f'{tp/(tp+fp)*100:.1f}%' if tp+fp>0 else '0%')")
BEFORE_REC=$(python3 -c "tp=$BEFORE_TP;fn=$BEFORE_FN;print(f'{tp/(tp+fn)*100:.1f}%' if tp+fn>0 else '0%')")
BEFORE_FPR=$(python3 -c "fp=$BEFORE_FP;tn=$BEFORE_TN;print(f'{fp/(fp+tn)*100:.1f}%' if fp+tn>0 else '0%')")
echo "  Precision: $BEFORE_PREC  Recall: $BEFORE_REC  FP Rate: $BEFORE_FPR"

echo ""
echo "=== After: 키워드 1차 → LLM 2차 판단 ==="
echo "(각 샘플당 LLM 호출 중... 시간이 걸립니다)"
echo ""

# Malicious files with LLM
for f in tests/benchmark/fixtures/malicious/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then
        # 키워드 탐지됨 → LLM에 물어봄
        flags=$(grep -oE '\b(exec|eval|subprocess|os\.system|base64|zlib)\b' "$f" | sort -u | tr '\n' ',' | sed 's/,$//')
        verdict=$(ask_llm "$f" "$flags")
        if [ "$verdict" = "safe" ]; then
            AFTER_FN=$((AFTER_FN+1))
            echo "  [FN] $fname ← LLM이 safe 판정 (잘못된 판단)"
        else
            AFTER_TP=$((AFTER_TP+1))
            echo "  [TP] $fname ← LLM: $verdict"
        fi
    else
        AFTER_FN=$((AFTER_FN+1))
        echo "  [FN] $fname ← 키워드 없음"
    fi
done

# Benign files with LLM
for f in tests/benchmark/fixtures/benign/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then
        # 키워드 탐지됨 → LLM에 물어봄
        flags=$(grep -oE '\b(exec|eval|subprocess|os\.system|base64|zlib)\b' "$f" | sort -u | tr '\n' ',' | sed 's/,$//')
        verdict=$(ask_llm "$f" "$flags")
        if [ "$verdict" = "safe" ]; then
            AFTER_TN=$((AFTER_TN+1))
            echo "  [TN] $fname ← LLM이 safe 판정 (오탐 제거!)"
        else
            AFTER_FP=$((AFTER_FP+1))
            echo "  [FP] $fname ← LLM: $verdict"
        fi
    else
        AFTER_TN=$((AFTER_TN+1))
        echo "  [TN] $fname"
    fi
done

echo ""
echo "  TP: $AFTER_TP  FP: $AFTER_FP  FN: $AFTER_FN  TN: $AFTER_TN"

AFTER_PREC=$(python3 -c "tp=$AFTER_TP;fp=$AFTER_FP;print(f'{tp/(tp+fp)*100:.1f}%' if tp+fp>0 else '0%')")
AFTER_REC=$(python3 -c "tp=$AFTER_TP;fn=$AFTER_FN;print(f'{tp/(tp+fn)*100:.1f}%' if tp+fn>0 else '0%')")
AFTER_FPR=$(python3 -c "fp=$AFTER_FP;tn=$AFTER_TN;print(f'{fp/(fp+tn)*100:.1f}%' if fp+tn>0 else '0%')")
echo "  Precision: $AFTER_PREC  Recall: $AFTER_REC  FP Rate: $AFTER_FPR"

echo ""
echo "============================================================"
echo "  Before vs After 비교"
echo "============================================================"
echo "  지표          Before      After"
echo "  ---------------------------------"
echo "  Precision     $BEFORE_PREC       $AFTER_PREC"
echo "  Recall        $BEFORE_REC      $AFTER_REC"
echo "  FP Rate       $BEFORE_FPR       $AFTER_FPR"
echo ""
