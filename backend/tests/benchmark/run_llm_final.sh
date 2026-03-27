#!/bin/bash
# OSSGuard LLM SAST 벤치마크 - /api/generate 사용
OLLAMA="http://localhost:11434/api/generate"
MODEL="llama3.2:1b"

echo "============================================================"
echo "  OSSGuard SAST 벤치마크: Before vs After (LLM)"
echo "  샘플: 악성 10개 / 정상 10개"
echo "============================================================"

BEFORE_TP=0; BEFORE_FP=0; BEFORE_TN=0; BEFORE_FN=0
AFTER_TP=0; AFTER_FP=0; AFTER_TN=0; AFTER_FN=0

check_keywords() {
    grep -qE '\b(exec|eval|subprocess\.Popen|os\.system)\b' "$1" && return 0
    grep -qE '(base64|zlib)' "$1" && return 0
    grep -qiE '(API_KEY|apikey|secret_key|SECRET)' "$1" && return 0
    return 1
}

ask_llm() {
    local file="$1"
    local flags="$2"
    local code
    code=$(head -15 "$file" | tr '\n' '; ' | sed 's/"/\\"/g' | cut -c1-500)

    local prompt="Keywords [$flags] found in code. Is this SAFE(image,git,API) or MALICIOUS(theft,RCE,shell)? Answer ONE word: safe or malicious. Code: $code"

    local resp
    resp=$(curl -s --max-time 300 "$OLLAMA" \
        -d "{\"model\":\"$MODEL\",\"prompt\":\"$prompt\",\"stream\":false,\"options\":{\"temperature\":0.1,\"num_predict\":15}}" 2>/dev/null)

    local answer
    answer=$(echo "$resp" | python3 -c "
import sys,json
try:
    d=json.load(sys.stdin)
    r=d.get('response','').lower()
    if 'malicious' in r: print('malicious')
    elif 'safe' in r: print('safe')
    else: print('unknown')
except: print('error')
" 2>/dev/null)
    echo "$answer"
}

echo ""
echo "=== Before: 키워드 탐지 단독 ==="
echo ""

for f in tests/benchmark/fixtures/malicious/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then BEFORE_TP=$((BEFORE_TP+1)); echo "  [TP] $fname"
    else BEFORE_FN=$((BEFORE_FN+1)); echo "  [FN] $fname"; fi
done
for f in tests/benchmark/fixtures/benign/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then BEFORE_FP=$((BEFORE_FP+1)); echo "  [FP] $fname ← 오탐"
    else BEFORE_TN=$((BEFORE_TN+1)); echo "  [TN] $fname"; fi
done

echo ""
echo "  TP:$BEFORE_TP FP:$BEFORE_FP FN:$BEFORE_FN TN:$BEFORE_TN"
echo ""

echo "=== After: 키워드 1차 → LLM 2차 판단 ==="
echo "(LLM 호출 중... 샘플당 약 1-2분 소요)"
echo ""

LLM_DETAILS=""

for f in tests/benchmark/fixtures/malicious/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then
        flags=$(grep -oE '\b(exec|eval|subprocess|os\.system|base64|zlib)\b' "$f" | sort -u | tr '\n' ',' | sed 's/,$//')
        echo -n "  [$fname] LLM 호출 중... "
        verdict=$(ask_llm "$f" "$flags")
        if [ "$verdict" = "safe" ]; then
            AFTER_FN=$((AFTER_FN+1))
            echo "[FN] LLM: safe (놓침)"
            LLM_DETAILS="$LLM_DETAILS\n  [FN] $fname → LLM이 safe로 잘못 판단"
        else
            AFTER_TP=$((AFTER_TP+1))
            echo "[TP] LLM: $verdict"
            LLM_DETAILS="$LLM_DETAILS\n  [TP] $fname → LLM: $verdict"
        fi
    else
        AFTER_FN=$((AFTER_FN+1))
        echo "  [FN] $fname ← 키워드 없음"
    fi
done

for f in tests/benchmark/fixtures/benign/*.py; do
    fname=$(basename "$f")
    if check_keywords "$f"; then
        flags=$(grep -oE '\b(exec|eval|subprocess|os\.system|base64|zlib)\b' "$f" | sort -u | tr '\n' ',' | sed 's/,$//')
        echo -n "  [$fname] LLM 호출 중... "
        verdict=$(ask_llm "$f" "$flags")
        if [ "$verdict" = "safe" ]; then
            AFTER_TN=$((AFTER_TN+1))
            echo "[TN] LLM: safe (오탐 제거!)"
            LLM_DETAILS="$LLM_DETAILS\n  [TN] $fname → LLM이 safe로 정확히 판단 (오탐 제거)"
        else
            AFTER_FP=$((AFTER_FP+1))
            echo "[FP] LLM: $verdict"
            LLM_DETAILS="$LLM_DETAILS\n  [FP] $fname → LLM: $verdict"
        fi
    else
        AFTER_TN=$((AFTER_TN+1))
        echo "  [TN] $fname"
    fi
done

echo ""
echo "  TP:$AFTER_TP FP:$AFTER_FP FN:$AFTER_FN TN:$AFTER_TN"

# 메트릭 계산
BEFORE_PREC=$(python3 -c "tp=$BEFORE_TP;fp=$BEFORE_FP;print(f'{tp/(tp+fp)*100:.1f}' if tp+fp>0 else '0')")
BEFORE_REC=$(python3 -c "tp=$BEFORE_TP;fn=$BEFORE_FN;print(f'{tp/(tp+fn)*100:.1f}' if tp+fn>0 else '0')")
BEFORE_F1=$(python3 -c "p=$BEFORE_PREC;r=$BEFORE_REC;p=float(p);r=float(r);print(f'{2*p*r/(p+r):.1f}' if p+r>0 else '0')")
BEFORE_FPR=$(python3 -c "fp=$BEFORE_FP;tn=$BEFORE_TN;print(f'{fp/(fp+tn)*100:.1f}' if fp+tn>0 else '0')")
BEFORE_ACC=$(python3 -c "print(f'{($BEFORE_TP+$BEFORE_TN)/($BEFORE_TP+$BEFORE_FP+$BEFORE_FN+$BEFORE_TN)*100:.1f}')")

AFTER_PREC=$(python3 -c "tp=$AFTER_TP;fp=$AFTER_FP;print(f'{tp/(tp+fp)*100:.1f}' if tp+fp>0 else '0')")
AFTER_REC=$(python3 -c "tp=$AFTER_TP;fn=$AFTER_FN;print(f'{tp/(tp+fn)*100:.1f}' if tp+fn>0 else '0')")
AFTER_F1=$(python3 -c "p=$AFTER_PREC;r=$AFTER_REC;p=float(p);r=float(r);print(f'{2*p*r/(p+r):.1f}' if p+r>0 else '0')")
AFTER_FPR=$(python3 -c "fp=$AFTER_FP;tn=$AFTER_TN;print(f'{fp/(fp+tn)*100:.1f}' if fp+tn>0 else '0')")
AFTER_ACC=$(python3 -c "print(f'{($AFTER_TP+$AFTER_TN)/($AFTER_TP+$AFTER_FP+$AFTER_FN+$AFTER_TN)*100:.1f}')")

echo ""
echo "============================================================"
echo "  Before vs After 비교"
echo "============================================================"
echo ""
printf "  %-15s %10s %10s %10s\n" "지표" "Before" "After" "변화"
echo "  ------------------------------------------------"
printf "  %-15s %9s%% %9s%%\n" "Precision" "$BEFORE_PREC" "$AFTER_PREC"
printf "  %-15s %9s%% %9s%%\n" "Recall" "$BEFORE_REC" "$AFTER_REC"
printf "  %-15s %9s%% %9s%%\n" "F1 Score" "$BEFORE_F1" "$AFTER_F1"
printf "  %-15s %9s%% %9s%%\n" "FP Rate" "$BEFORE_FPR" "$AFTER_FPR"
printf "  %-15s %9s%% %9s%%\n" "Accuracy" "$BEFORE_ACC" "$AFTER_ACC"
echo ""
echo "=== LLM 판단 상세 ==="
echo -e "$LLM_DETAILS"
echo ""
