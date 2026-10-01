# TLS 证书换发核验服务（tls-cert-checker）

面向运维团队的**离线** TLS 证书换发核验服务。导入 PEM 证书链与分版本的本地信任根，
为域名登记现用（current）/拟启用（planned）证书的服务窗口，按 X.509 规则校验
签名链、CA 约束、域名 SAN 与有效期，并评估指定区间内是否存在证书覆盖断档；
仅无断档的计划可批准，批准即冻结判定依据。

- 技术栈：Python 3.11 · FastAPI · SQLite（标准库 sqlite3）· cryptography
- 全部计算在本地完成，不依赖任何外部服务，可离线运行

## 快速启动

### Docker Compose（一键启动并初始化）

```bash
docker compose up --build
```

启动后自动建库并写入演示数据（演示 CA、两个域名的证书/窗口/计划，详见下文），
服务地址：**http://localhost:8000**，交互式 API 文档：**http://localhost:8000/docs**。

### 本地运行

```bash
pip install -r requirements.txt
SEED_DEMO=1 python -m scripts.seed_demo          # 可选：写入演示数据
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

### 运行测试

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## 配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `TLS_CHECKER_DB` | 容器内 `/data/tls_checker.db`，本地 `./data/tls_checker.db` | SQLite 数据库文件路径 |
| `SEED_DEMO` | `1` | 启动时是否写入演示数据（幂等，已初始化则跳过） |
| `HOST` / `PORT` | `0.0.0.0` / `8000` | 监听地址与端口 |

## 概念与规则

- **信任根版本**：每个版本是一组 PEM 根证书；首个导入的版本自动激活，
  `POST /trust-roots/{version}/activate` 切换在用版本。
- **证书链**：导入的 PEM 中第一个块为叶子证书，其余为中间证书；
  以叶子证书 DER 的 SHA-256 为指纹，全局唯一。
- **服务窗口**：域名 + 证书指纹 + 角色（current/planned）+ UTC 半开区间
  `[start, end)`；前一窗口的 `end` 与后一窗口的 `start` 相接**不算断档**。
- **X.509 校验**：签名链必须逐级验证至在用版本信任根；链上每个签发者必须
  `basicConstraints CA=TRUE`、不超出 `pathLength`、`keyUsage` 含 `keyCertSign`；
  叶子证书 SAN 须匹配域名（支持 `*.example.com` 单标签通配）；
  评估时刻须落在整条链的有效期交集内。
- **断档评估**：在 `[eval_start, eval_end)` 内，每一时刻至少一张证书
  「处于服务窗口且验证通过」。返回全部断档区间与每张证书的不可用原因。
- **批准与冻结**：仅无断档计划可批准；批准时冻结证书指纹集合、信任根版本、
  撤销快照版本与判定结果。
- **待复核**：信任根换版、撤销快照切换或服务窗口增删后，相关已批准计划自动
  转为 `pending_review`；历史评估与历史批准（含冻结判定）全部保留，
  重新评估无断档后可再次批准。
- **按域名成组窗口变更（换发演练）**：换发证书时，可按**单个域名**把「撤下旧
  窗口」与「登记新窗口」组成一次变更，分两步进行：先**预演**（基于候选窗口
  集合，按每个相关计划当前选定的信任根版本与可选 CRL 快照重算，返回各计划
  变更前后的断档区间与阻断原因，并签发提交令牌；预演不改动窗口、评估或批准
  历史），再携带该令牌**提交**。提交时若域名窗口、相关计划状态或判定依据在
  预演后发生变化，令牌过期被拒（409，需重新预演）；候选状态使任一**当前已
  批准**计划出现断档时，**整组拒绝、不产生部分变更**（409）；否则在同一
  事务内原子应用全部增删，相关已批准计划转 `pending_review`，冻结批准历史
  完整保留。预演/提交不产生新的评估记录；既有单窗口增删与计划接口语义不变。
- **离线撤销快照（可选）**：换发计划可选择一个不可变的带版本 PEM CRL 快照。
  导入时逐张验证签名（须由已导入的 CA 证书签署且带 `cRLSign`），拒绝重复版本、
  同一签发者的冲突列表与无法解析的内容。选择快照的计划在每次评估中，须为
  证书链每张**非根证书**找到由其签发者签署的 CRL；证书仅在
  `[thisUpdate, nextUpdate)` 内且**尚未到撤销生效时刻**的时段可用，缺失、
  过期或已撤销的时段计入断档，并返回逐证书原因。撤销可用区间还须与原有服务
  窗口、证书有效期和评估区间求交；端点相接不算断档。重评可切换快照
  （显式传 `null` 取消），切换会使已批准计划先转待复核；历史评估与冻结批准
  保留各自的快照版本与判定。**未选择快照的既有计划保持原评估与响应语义。**
  非法 CRL、未知快照或不完整的撤销证据不会被静默判为安全。
- **拒绝规则**：PEM 格式错误 → 400；无效时间窗口/评估区间 → 400；
  非法/未签名/未知签发者 CRL → 400；未知信任根版本/证书指纹/快照版本 → 404；
  重复信任根版本/证书指纹 → 409；快照版本重复、同一签发者冲突/重复 CRL → 409；
  时间戳缺时区 → 422。
  成组窗口变更额外规则：变更为空、新窗口区间无效、跨域引用窗口或重复删除
  → 400；未知窗口 ID / 未知证书指纹 → 404；提交令牌缺失或签名非法 → 400；
  提交参数与预演不一致、预演后域名窗口或相关计划状态/判定依据已变化
  （预演过期）→ 409；候选状态使任一当前已批准计划出现断档 → 409（整组拒绝、
  无部分变更）。

## API 一览（前缀 `/api/v1`）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/healthz` | 健康检查 |
| POST | `/trust-roots` | 导入信任根版本（PEM bundle） |
| GET | `/trust-roots` | 列出版本 |
| POST | `/trust-roots/{version}/activate` | 切换在用版本（触发待复核） |
| POST | `/crl-snapshots` | 导入带版本的 PEM CRL 快照（验签/拒绝冲突） |
| GET | `/crl-snapshots` / `/crl-snapshots/{version}` | 列出/查询快照（含逐签发者有效期） |
| POST | `/certificates` | 导入 PEM 证书链 |
| GET | `/certificates` / `/certificates/{fp}` | 查询证书 |
| POST | `/service-windows` | 登记服务窗口 |
| GET | `/service-windows?domain=` | 查询窗口 |
| DELETE | `/service-windows/{id}` | 删除窗口（触发待复核） |
| POST | `/domains/{domain}/window-change/preview` | 按域名成组换发预演（撤旧+登新，重算各计划前后断档，返回提交令牌；不落库） |
| POST | `/domains/{domain}/window-change/commit` | 携带令牌原子提交成组增删（断档整组拒绝；成功则相关已批准计划转待复核） |
| POST | `/plans` | 创建计划并立即评估（可带 `crl_snapshot_version`） |
| GET | `/plans` / `/plans/{id}` | 查询计划（含最新评估与批准） |
| POST | `/plans/{id}/evaluate` | 重新评估（可换信任根版本/快照；省略沿用，null 取消快照） |
| POST | `/plans/{id}/approve` | 批准（仅无断档，冻结快照版本） |
| GET | `/plans/{id}/evaluations` | 评估历史 |
| GET | `/plans/{id}/approvals` | 批准历史（冻结判定） |

## 调用示例

以下示例假设服务运行于 `http://localhost:8000` 且已写入演示数据
（`SEED_DEMO=1`，演示计划 #1 已批准、计划 #2 有断档）。
完整可执行脚本见 `scripts/demo.sh`：`./scripts/demo.sh`。

### 1. 导入信任根版本

```bash
jq -n --arg v "root-2026Q3" --rawfile pem root-ca.pem '{version: $v, pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/trust-roots \
      -H 'Content-Type: application/json' -d @-
# 201 → {"version":"root-2026Q3","cert_count":1,"is_active":false,...}
# 版本重复 → 409；PEM 错误 → 400
```

### 2. 导入证书链（叶子在前，中间证书随后）

```bash
jq -n --arg pem "$(cat leaf-and-intermediate.pem)" '{label: "api.example.com-2026", pem: $pem}' \
  | curl -s -X POST http://localhost:8000/api/v1/certificates \
      -H 'Content-Type: application/json' -d @-
# 201 → {"fingerprint_sha256":"ab12...","san_dns":["api.example.com"],...}
# 指纹重复 → 409
```

### 3. 登记服务窗口（现用 + 拟启用，端点相接）

```bash
FP=<上一步返回的 fingerprint_sha256>
curl -s -X POST http://localhost:8000/api/v1/service-windows \
  -H 'Content-Type: application/json' -d "{
    \"domain\": \"api.example.com\",
    \"certificate_fingerprint\": \"$FP\",
    \"role\": \"current\",
    \"start\": \"2026-01-01T00:00:00Z\",
    \"end\":   \"2026-07-01T00:00:00Z\"}"
# 再为拟启用证书登记 [2026-07-01, 2027-01-01) 的 planned 窗口……
```

### 4. 创建计划并评估

```bash
curl -s -X POST http://localhost:8000/api/v1/plans \
  -H 'Content-Type: application/json' -d '{
    "domain": "demo-gap.example.com",
    "eval_start": "2026-01-01T00:00:00Z",
    "eval_end":   "2027-01-01T00:00:00Z"}'
```

响应（节选，演示数据中存在 14 天断档）：

```json
{
  "plan": {"id": 3, "status": "pending", "trust_root_version": "demo-root-v1", ...},
  "evaluation": {
    "has_gaps": true,
    "gaps": [{"start": "2026-06-01T00:00:00.000Z", "end": "2026-06-15T00:00:00.000Z"}],
    "certificates": [
      {"role": "current",  "usable_intervals": [{"start": "2026-01-01T00:00:00.000Z", "end": "2026-06-01T00:00:00.000Z"}], "reasons": []},
      {"role": "planned",  "usable_intervals": [{"start": "2026-06-15T00:00:00.000Z", "end": "2027-01-01T00:00:00.000Z"}], "reasons": []}
    ]
  }
}
```

证书不可用原因示例：`SAN ['x'] does not match domain '...'`、
`signature chain incomplete: ...`、`CA constraint violation: ... CA=FALSE`、
`certificate chain expires at ..., before window end ...`。

### 5. 批准计划（仅无断档）

```bash
curl -s -X POST http://localhost:8000/api/v1/plans/1/approve
# 200 → approval 中冻结 cert_fingerprints / trust_root_version / verdict
curl -s -X POST http://localhost:8000/api/v1/plans/2/approve
# 409 → {"detail":"plan has 1 coverage gap(s); only gap-free plans can be approved"}
```

### 6. 信任根换版 → 待复核 → 复核

```bash
curl -s -X POST http://localhost:8000/api/v1/trust-roots/root-2026Q4/activate
# → {"plans_marked_pending_review": N}，冻结版本不一致的已批准计划转为 pending_review
curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"trust_root_version": "root-2026Q4"}'
curl -s -X POST http://localhost:8000/api/v1/plans/1/approve     # 无断档后重新批准
curl -s http://localhost:8000/api/v1/plans/1/approvals           # 历史判定全部保留
```

### 7. 导入离线撤销快照（PEM CRL）

```bash
jq -n --arg v "crl-2026Q3" --rawfile crl ca-2026Q3.crl '{version: $v, pem: $crl}' \
  | curl -s -X POST http://localhost:8000/api/v1/crl-snapshots \
      -H 'Content-Type: application/json' -d @-
# 201 → {"version":"crl-2026Q3","crl_count":1,"items":[{"issuer":"CN=Root CA",
#          "this_update":"...","next_update":"...","revoked_count":0}]}
# 重复版本/同一签发者冲突列表 → 409；PEM 无法解析 → 400；
# 签名验证失败/签发者 CA 未导入/无 cRLSign → 400
```

### 8. 创建选择快照的计划

```bash
curl -s -X POST http://localhost:8000/api/v1/plans \
  -H 'Content-Type: application/json' -d '{
    "domain": "api.example.com",
    "eval_start": "2026-01-01T00:00:00Z",
    "eval_end":   "2027-01-01T00:00:00Z",
    "crl_snapshot_version": "crl-2026Q3"}'
```

响应中每张证书新增 `revocation`（链上每张非根证书一项），包含命中的
CRL（`this_update`/`next_update`/`revoked`）与逐证书原因；`usable_intervals`
已与 CRL 可用区间求交。例如 CRL 在评估期内过期：

```json
{"role": "current",
 "usable_intervals": [{"start": "2026-01-01T00:00:00.000Z",
                       "end":   "2026-10-01T00:00:00.000Z"}],
 "revocation": [{"subject": "CN=api.example.com",
                 "issuer": "CN=Root CA",
                 "crl": {"this_update": "2025-12-01T00:00:00.000Z",
                         "next_update": "2026-10-01T00:00:00.000Z",
                         "revoked": null},
                 "reasons": ["CN=api.example.com: CRL from issuer 'CN=Root CA'"
                             + " expires at 2026-10-01..., coverage missing after that"]}],
 "reasons": ["CN=api.example.com: CRL from issuer ... coverage missing after that"]}
```

其他典型原因：`no CRL signed by issuer '...' found in snapshot`（缺失）、
`CRL ... expired at ..., before window start ...`、
`certificate ... revoked at 2026-06-01T00:00:00.000Z`。

### 9. 重评切换快照与待复核

```bash
# 切换到另一个快照版本（未知版本 → 404，绝不静默放行）
curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"crl_snapshot_version": "crl-2026Q4"}'
# 已批准计划立即转为 pending_review，旧冻结批准置 superseded 但完整保留

curl -s -X POST http://localhost:8000/api/v1/plans/1/evaluate \
  -H 'Content-Type: application/json' -d '{"crl_snapshot_version": null}'   # 取消快照
# 省略该字段则沿用计划当前选择；取消后回到无快照的原始评估与响应语义
```

### 10. 按域名成组换发：预演 → 原子提交

换发证书时，把「撤下旧窗口」与「登记新窗口」组成**单域名**的一次变更。
先预演（只读，不改动任何数据），再用返回的 `commit_token` 提交。

**第 1 步：预演。** `delete_window_ids` 为待撤下的旧窗口 ID（可多个），
`add_windows` 为待登记的新窗口（证书指纹、角色、带时区起止时间）：

```bash
curl -s -X POST \
  http://localhost:8000/api/v1/domains/demo.example.com/window-change/preview \
  -H 'Content-Type: application/json' -d '{
    "domain": "demo.example.com",
    "delete_window_ids": [1],
    "add_windows": [{
      "certificate_fingerprint": "ab12…（新证书指纹）",
      "role": "current",
      "start": "2026-01-01T00:00:00Z",
      "end":   "2026-07-01T00:00:00Z"
    }]
  }'
```

响应（节选）：每个相关计划都给出 `before` / `after` 的断档区间与阻断原因；
任一**当前已批准**计划变更后出现断档时顶层 `blocked=true`，并返回
`commit_token`：

```json
{
  "domain": "demo.example.com",
  "delete_window_ids": [1],
  "add_windows": [{"temporary_id": "new-1", "...": "..."}],
  "candidate_windows": [{"id": 2, "...": "..."}, {"id": "new-1", "...": "..."}],
  "blocked": false,
  "plans": [{
    "plan_id": 1, "status": "approved", "approved": true, "would_block": false,
    "trust_root_version": "demo-root-v1", "crl_snapshot_version": null,
    "before": {"has_gaps": false, "gaps": [], "blocking_reasons": []},
    "after":  {"has_gaps": false, "gaps": [], "blocking_reasons": []}
  }],
  "commit_token": "eyJkIjoi….<<HMAC-SHA256 签名>>"
}
```

**第 2 步：携带同一令牌提交**（变更参数须与预演完全一致）：

```bash
TOKEN='<上一步返回的 commit_token>'
curl -s -X POST \
  http://localhost:8000/api/v1/domains/demo.example.com/window-change/commit \
  -H 'Content-Type: application/json' -d "{
    \"domain\": \"demo.example.com\",
    \"delete_window_ids\": [1],
    \"add_windows\": [{
      \"certificate_fingerprint\": \"ab12…（新证书指纹）\",
      \"role\": \"current\",
      \"start\": \"2026-01-01T00:00:00Z\",
      \"end\":   \"2026-07-01T00:00:00Z\"
    }],
    \"commit_token\": \"$TOKEN\"
  }"
```

成功响应：`applied=true`，`deleted_windows` / `added_windows` 为本次原子
增删，`plans_marked_pending_review` 为转待复核的已批准计划数（冻结批准
历史保留、置 `superseded`），`plans` 给出各计划提交后的状态与断档。

**关键行为与报错**：

- 预演是只读的：窗口、评估历史、批准历史、计划状态均不改变，也不写评估记录；
  重算时各计划沿用其**当前选定**的信任根版本与可选 CRL 快照。
- `blocked=true` 时提交被**整组拒绝（409）**，不产生任何部分变更，例如：
  `window change rejected: candidate state leaves 1 currently approved plan(s) with coverage gaps: …`。
- 提交令牌缺失/签名非法 → 400；参数与预演不一致 → 409；预演后域名窗口或相关
  计划状态/判定依据（信任根版本、CRL 快照、评估区间、计划增删）已变化 →
  409 `stale window change … re-run preview`（令牌用过一次即失效）。
- 变更为空、新窗口 `start >= end`、引用其他域名的窗口、重复的删除 ID → 400；
  未知窗口 ID / 未知证书指纹 → 404；时间戳不带时区 → 422。
- 仅增（`delete_window_ids` 为空）或仅删（`add_windows` 为空）也允许；
  断档只会阻断**已批准**计划的提交，`pending` / `pending_review` 计划的断档
  仅在响应中报告。

## 项目结构

```
app/
  main.py       FastAPI 路由
  service.py    业务逻辑（导入/窗口/CRL 快照/评估/批准/待复核）
  certutils.py  PEM 解析、签名链构建、CA 约束与 SAN 校验
  crlutils.py   PEM CRL 解析、签发者匹配与签名验证
  coverage.py   半开区间断档与求交计算
  db.py         SQLite 连接、建表与轻量迁移
  models.py     请求模型（时区强制、域名归一化）
scripts/
  seed_demo.py  离线生成演示 CA/证书/CRL 并初始化演示数据（幂等）
  demo.sh       端到端 curl 调用示例
  docker-entrypoint.sh
tests/          pytest 测试（84 例，覆盖全部拒绝规则、CRL 证据、复核流程与成组换发预演/提交）
Dockerfile / docker-compose.yml
```
