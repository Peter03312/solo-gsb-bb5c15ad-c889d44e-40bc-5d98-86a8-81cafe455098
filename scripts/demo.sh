#!/usr/bin/env bash
# 端到端调用示例：对运行中的服务执行一次完整的换发核验流程。
# 用法: ./scripts/demo.sh [BASE_URL]   （默认 http://localhost:8000）
set -euo pipefail

BASE="${1:-http://localhost:8000}/api/v1"
JQ="python3 -m json.tool"

echo "==> 0. 健康检查"
curl -s "${BASE%/api/v1}/healthz" | $JQ

echo "==> 1. 查看信任根版本（种子数据已导入 demo-root-v1 并激活）"
curl -s "$BASE/trust-roots" | $JQ

echo "==> 2. 查看已导入证书（取第一张证书的指纹）"
curl -s "$BASE/certificates" | $JQ
FP=$(curl -s "$BASE/certificates" | python3 -c "import json,sys;print(json.load(sys.stdin)['items'][0]['fingerprint_sha256'])")
echo "   fingerprint = $FP"

echo "==> 3. 查看 demo.example.com 的服务窗口"
curl -s "$BASE/service-windows?domain=demo.example.com" | $JQ

echo "==> 4. 创建换发计划并评估（窗口首尾相接 → 无断档）"
curl -s -X POST "$BASE/plans" -H 'Content-Type: application/json' -d '{
  "domain": "demo.example.com",
  "eval_start": "2026-01-01T00:00:00Z",
  "eval_end":   "2027-01-01T00:00:00Z"
}' | $JQ

echo "==> 5. 查看种子计划 #1（已批准，含冻结判定）"
curl -s "$BASE/plans/1" | $JQ

echo "==> 6. 断档计划 #2 尝试批准（应 409 拒绝）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/plans/2/approve"

echo "==> 7. 错误处理示例"
echo "-- 7.1 PEM 格式错误（应 400）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/certificates" \
  -H 'Content-Type: application/json' -d '{"pem":"not-a-pem"}'
echo "-- 7.2 未知信任根版本（应 404）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/plans" \
  -H 'Content-Type: application/json' -d '{"domain":"demo.example.com","eval_start":"2026-01-01T00:00:00Z","eval_end":"2027-01-01T00:00:00Z","trust_root_version":"v999"}'
echo "-- 7.3 无效时间窗口（应 400）"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/service-windows" \
  -H 'Content-Type: application/json' -d "{\"domain\":\"demo.example.com\",\"certificate_fingerprint\":\"$FP\",\"role\":\"planned\",\"start\":\"2027-01-01T00:00:00Z\",\"end\":\"2026-01-01T00:00:00Z\"}"

echo "==> 8. 服务窗口变动 → 已批准计划转待复核"
curl -s -X POST "$BASE/service-windows" -H 'Content-Type: application/json' -d "{
  \"domain\": \"demo.example.com\",
  \"certificate_fingerprint\": \"$FP\",
  \"role\": \"planned\",
  \"start\": \"2027-01-01T00:00:00Z\",
  \"end\":   \"2027-07-01T00:00:00Z\"
}" | $JQ
curl -s "$BASE/plans/1" | python3 -c "import json,sys;d=json.load(sys.stdin);print('plan 1 status =', d['status'])"

echo "==> 9. 复核：重新评估并再次批准"
curl -s -X POST "$BASE/plans/1/evaluate" | python3 -c "import json,sys;d=json.load(sys.stdin);print('has_gaps =', d['has_gaps'])"
curl -s -X POST "$BASE/plans/1/approve" | python3 -c "import json,sys;d=json.load(sys.stdin);print('re-approved, status =', d['plan']['status'])"

echo "==> 10. 批准历史（历史判定全部保留）"
curl -s "$BASE/plans/1/approvals" | $JQ

echo "==> 11. 离线撤销快照（CRL）"
echo "-- 11.1 列出快照（种子数据导入了 demo-crl-2026Q1 / -revoked）"
curl -s "$BASE/crl-snapshots" | $JQ
curl -s "$BASE/crl-snapshots/demo-crl-2026Q1-revoked" | $JQ

echo "-- 11.2 选择无撤销快照创建计划（CRL 覆盖整个评估区间 → 无断档）"
CRL_PLAN=$(curl -s -X POST "$BASE/plans" -H 'Content-Type: application/json' -d '{
  "domain": "demo.example.com",
  "eval_start": "2026-01-01T00:00:00Z",
  "eval_end":   "2027-01-01T00:00:00Z",
  "crl_snapshot_version": "demo-crl-2026Q1"
}')
echo "$CRL_PLAN" | $JQ
CPID=$(echo "$CRL_PLAN" | python3 -c "import json,sys;print(json.load(sys.stdin)['plan']['id'])")

echo "-- 11.3 重评切换到含撤销的快照（现用证书 2026-03-01 起撤销 → 出现断档，逐证书原因）"
curl -s -X POST "$BASE/plans/$CPID/evaluate" -H 'Content-Type: application/json' \
  -d '{"crl_snapshot_version":"demo-crl-2026Q1-revoked"}' \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('has_gaps =', d['has_gaps']);print('gaps =', d['gaps']);print('reasons =', d['certificates'][0]['reasons'])"

echo "-- 11.4 切回无撤销快照（可重新批准；历史评估与冻结批准各自保留快照版本）"
curl -s -X POST "$BASE/plans/$CPID/evaluate" -H 'Content-Type: application/json' \
  -d '{"crl_snapshot_version":"demo-crl-2026Q1"}' >/dev/null
curl -s -X POST "$BASE/plans/$CPID/approve" \
  | python3 -c "import json,sys;d=json.load(sys.stdin);print('approved, snapshot =', d['approval']['crl_snapshot_version'])"
curl -s "$BASE/plans/$CPID/evaluations" \
  | python3 -c "import json,sys;print('evaluation snapshots =', [e['crl_snapshot_version'] for e in json.load(sys.stdin)['items']])"

echo "-- 11.5 非法 CRL（400）与重复快照版本（409）被拒"
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/crl-snapshots" \
  -H 'Content-Type: application/json' -d '{"version":"bad","pem":"not-a-crl"}'
GOOD_PEM=$(curl -s "$BASE/crl-snapshots/demo-crl-2026Q1" >/dev/null; \
  python3 - <<'PYEOF'
import json, os, sqlite3
conn = sqlite3.connect(os.environ.get("TLS_CHECKER_DB", "/data/tls_checker.db"))
pem = conn.execute(
    "SELECT pem FROM crl_snapshots WHERE version='demo-crl-2026Q1'"
).fetchone()[0]
print(json.dumps({"version": "demo-crl-2026Q1", "pem": pem}))
PYEOF
)
printf '%s' "$GOOD_PEM" | curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/crl-snapshots" \
  -H 'Content-Type: application/json' -d @-

echo "==> 12. 域名级窗口变更：预演 → 原子提交"
CUR_WIN=$(curl -s "$BASE/service-windows?domain=demo.example.com" \
  | python3 -c "import json,sys;print([w['id'] for w in json.load(sys.stdin)['items'] if w['role']=='current'][0])")
CUR_FP=$(curl -s "$BASE/service-windows?domain=demo.example.com" \
  | python3 -c "import json,sys;print([w['certificate_fingerprint'] for w in json.load(sys.stdin)['items'] if w['role']=='current'][0])")

echo "-- 12.1 预演：只撤下 current 窗口（已批准计划将断档 → 阻断；预演只读）"
PREV=$(curl -s -X POST "$BASE/window-changes/preview" -H 'Content-Type: application/json' \
  -d "{\"domain\":\"demo.example.com\",\"delete_window_ids\":[$CUR_WIN]}")
echo "$PREV" | python3 -c "
import json,sys
d=json.load(sys.stdin)
print('would_block =', d['would_block'])
print('blocking    =', d['blocking_reasons'])
for p in d['plans']:
    print(f\"  plan #{p['plan_id']} ({p['status']}): before gaps={p['before']['gaps']} after gaps={p['after']['gaps']}\")"

echo "-- 12.2 直接提交该变更（应 409 整组拒绝，窗口无变化）"
TOKEN=$(echo "$PREV" | python3 -c "import json,sys;print(json.load(sys.stdin)['change_token'])")
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/window-changes/commit" \
  -H 'Content-Type: application/json' \
  -d "{\"domain\":\"demo.example.com\",\"change_token\":\"$TOKEN\",\"delete_window_ids\":[$CUR_WIN]}"

echo "-- 12.3 预演：撤下旧窗口并登记等价接替窗口 → 提交（原子应用，已批准计划转待复核）"
PREV=$(curl -s -X POST "$BASE/window-changes/preview" -H 'Content-Type: application/json' -d "{
  \"domain\":\"demo.example.com\",
  \"delete_window_ids\":[$CUR_WIN],
  \"add_windows\":[{\"certificate_fingerprint\":\"$CUR_FP\",\"role\":\"current\",
                    \"start\":\"2026-01-01T00:00:00Z\",\"end\":\"2026-07-01T00:00:00Z\"}]}")
echo "$PREV" | python3 -c "import json,sys;print('would_block =', json.load(sys.stdin)['would_block'])"
TOKEN=$(echo "$PREV" | python3 -c "import json,sys;print(json.load(sys.stdin)['change_token'])")
curl -s -X POST "$BASE/window-changes/commit" -H 'Content-Type: application/json' -d "{
  \"domain\":\"demo.example.com\",
  \"change_token\":\"$TOKEN\",
  \"delete_window_ids\":[$CUR_WIN],
  \"add_windows\":[{\"certificate_fingerprint\":\"$CUR_FP\",\"role\":\"current\",
                    \"start\":\"2026-01-01T00:00:00Z\",\"end\":\"2026-07-01T00:00:00Z\"}]}" | $JQ
curl -s "$BASE/plans/1" | python3 -c "import json,sys;print('plan 1 status =', json.load(sys.stdin)['status'])"

echo "-- 12.4 预演后计划状态/判定依据变化 → 旧标识提交应 409（过期预演）"
CUR_WIN=$(curl -s "$BASE/service-windows?domain=demo.example.com" \
  | python3 -c "import json,sys;print([w['id'] for w in json.load(sys.stdin)['items'] if w['role']=='current'][0])")
TOKEN=$(curl -s -X POST "$BASE/window-changes/preview" -H 'Content-Type: application/json' \
  -d "{\"domain\":\"demo.example.com\",\"delete_window_ids\":[$CUR_WIN],\"add_windows\":[{\"certificate_fingerprint\":\"$CUR_FP\",\"role\":\"current\",\"start\":\"2026-01-01T00:00:00Z\",\"end\":\"2026-07-01T00:00:00Z\"}]}" \
  | python3 -c "import json,sys;print(json.load(sys.stdin)['change_token'])")
# 预演后复核并重新批准计划（状态变化）→ 标识失效
curl -s -X POST "$BASE/plans/1/evaluate" > /dev/null
curl -s -X POST "$BASE/plans/1/approve" > /dev/null
curl -s -w "\nHTTP %{http_code}\n" -X POST "$BASE/window-changes/commit" \
  -H 'Content-Type: application/json' \
  -d "{\"domain\":\"demo.example.com\",\"change_token\":\"$TOKEN\",\"delete_window_ids\":[$CUR_WIN],\"add_windows\":[{\"certificate_fingerprint\":\"$CUR_FP\",\"role\":\"current\",\"start\":\"2026-01-01T00:00:00Z\",\"end\":\"2026-07-01T00:00:00Z\"}]}"

echo "demo done."
