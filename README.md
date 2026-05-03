# semantic-redaction-ko

> **마스킹은 단어를 숨기지만, 의미 보존 가명화는 추론 상태를 보존합니다.**

`semantic-redaction-ko`는 외부 LLM을 쓰고 싶지만 개인신용정보를 유출할 수 없는 한국 금융회사를 위한 Qwen 기반 킬러 데모입니다.

이 프로젝트는 국내 금융회사가 **혁신금융서비스** 및 금융망 분리 예외를 검토할 때 필요한 구조를 보여줍니다. Qwen 같은 open-weight LLM을 내부 폐쇄망에서 실행해 원문 고객 맥락을 먼저 이해하고, 외부 LLM에는 의미가 보존된 가명 decision state만 전달합니다.

```text
Private Raw Input
  -> Local Qwen Semantic Redactor
  -> Deterministic Policy & Privacy Gate
  -> External LLM Payload
  -> Safe Internal Rehydration
```

외부 LLM은 개인신용정보가 아니라, 답변에 필요한 안전한 추론 맥락만 받습니다.

## 무엇이 다른가

기존 redaction:

```text
스타벅스 강남2호점 / 6,800원 / 승인
SBUX GANGNAM STN / 6,800원 / 취소
  -> MERCHANT_1 / AMOUNT_1 / STATUS_1
```

이 방식은 안전해 보이지만 LLM이 중요한 의미를 잃습니다. 두 거래가 같은 커피전문점 승인/취소 흐름인지, 중복 청구인지, 반복결제인지 판단할 수 없습니다.

Semantic redaction:

```json
{
  "merchant_taxonomy": "coffee_chain",
  "location_granularity": "same_commercial_area",
  "amount_relation": "same_amount",
  "temporal_relation": "near_time_duplicate_within_2_minutes",
  "authorization_lifecycle": ["approved", "cancelled"],
  "billing_interpretation": "approved_and_cancelled_pair_likely_single_final_charge",
  "required_action": "explain_transactions_without_raw_merchant_names"
}
```

LLM은 상황을 설명할 수 있지만, 원 가맹점명, 카드번호 일부, 상세 위치, 원장 데이터는 보지 못합니다.

## 고급 가명화 전략

이 데모는 두 단계 전략을 사용합니다.

1. **Local Qwen draft**
   - Qwen 모델을 금융회사 내부 폐쇄망에서 실행합니다.
   - 의도, 후보, 판단 근거, 충돌 정보, 불확실성, 필요한 조치를 초안으로 만듭니다.

2. **Deterministic semantic policy engine**
   - Qwen 초안에 남은 민감정보를 제거합니다.
   - 외부 LLM에 전달해도 되는 목적 제한 의미정보를 보강합니다.
   - 어떤 의미를 보존했고 어떤 원문 필드를 숨겼는지 감사 로그에 남깁니다.

구현된 기법:

| 기법 | 보존하는 의미 | 숨기는 정보 |
|---|---|---|
| 토큰화된 엔티티 바인딩 | `TX_A`, `CLAIM_A`, `DEBT_B` 같은 안정적 참조 | 이름, 원 가맹점명, 기관명, 증권번호 |
| 도메인 택소노미 승격 | `coffee_chain`, `diagnostic_imaging_mri`, `card_loan` | 원 가맹점명, 병원명, 발급기관명 |
| 관계 인코딩 | 동일 금액, 근접 시간 중복, 고금리 우선 상환 | 정확 시각, 정확 잔액, 원 거래 설명 |
| 라이프사이클 추상화 | 승인/취소 쌍, 청구 가능성, 상환 우선순위 | 전체 원장과 계약 식별자 |
| 밴딩/일반화 | 금리 구간, 잔액 구간, 의료기관 종류 | 정확 잔액, 정확 병원명 |
| 불확실성 계약 | 확정/추정/충돌/서류 필요 상태 | 숨겨진 과잉확신 |
| 목적 제한 최소화 | LLM 업무에 필요한 사실만 전달 | 답변과 무관한 사적 맥락 |
| **쿼리 관련성 필터** | 질문과 직접 관련된 의미 차원 보존 강화 | 질문과 무관한 PII 억제 강화 |

### 보안 계층

의미 보존 유틸리티를 낮추지 않으면서 프라이버시를 강화하는 4개의 추가 보안 계층:

| 계층 | 역할 |
|---|---|
| **확장된 FORBIDDEN_PATTERNS** | 주민등록번호, 카드 16자리, 사업자등록번호, 이메일, 카드사·증권사·보험사·캐피탈명, 병원·의원명, 만원/억원 단위 금액 탐지 |
| **Dict key 스캔** | Qwen 출력의 value뿐 아니라 key도 민감정보 검사 대상 |
| **Outbound 필터** | 외부 LLM 응답을 재결합 전에 한 번 더 검사·정제 |
| **교차 참조 탐지** | 동일 엔티티에 대한 반복 쿼리에서 의미 차원 누적을 추적해 재식별 위험 경고 (차단이 아닌 탐지) |

## 한국 규제 및 시장 맥락

이 프로젝트는 국내 금융권 AI 도입 흐름에서 출발했습니다.

- 금융규제 샌드박스의 **혁신금융서비스**
- 은행, 카드, 보험, 증권, 핀테크의 외부 생성형 AI 활용
- 외부 AI 모델에 가명정보를 입력할 수 있는지에 대한 보안·컴플라이언스 요구
- 개인정보보호위원회 `가명정보 처리 가이드라인(2026.03.)`의 핵심 원칙:
  - 처리 목적을 달성할 수 있을 만큼 데이터 유용성을 보존해야 합니다.
  - 재식별 위험은 막연히 없다고 주장하는 것이 아니라 통제 가능한 수준으로 관리해야 합니다.
  - 추가정보와 매핑테이블은 분리 보관하고 접근권한을 통제해야 합니다.
  - 적정성 검토와 잔존 위험 모니터링이 필요합니다.

이 저장소는 법률 자문이 아니라 기술 데모입니다. AI/데이터/보안팀이 혁신금융서비스 신청 또는 운영 전에 더 안전한 외부 LLM 연계 구조를 논의할 수 있게 만드는 것이 목적입니다.

참고 공개자료:

- [금융규제 샌드박스](https://sandbox.fintech.or.kr/)
- [KB국민카드: 생성형 AI 카드생활 메이트](https://sandbox.fintech.or.kr/business/enterprise.do?id=479&lang=ko)
- [카카오페이: 자산관리 AI 금융 에이전트](https://sandbox.fintech.or.kr/business/enterprise.do?id=805&lang=ko)
- [아이지넷: 보장분석 대화형 서비스](https://sandbox.fintech.or.kr/business/enterprise.do?id=683&lang=ko)

## 데모 시나리오

```bash
semantic-redaction demo card
semantic-redaction demo insurance
semantic-redaction demo debt
semantic-redaction demo all
semantic-redaction audit last-run --format md
```

시나리오:

- 카드 거래내역 미스터리: `지난주 강남 스벅 두 번 긁힌 거 뭐야? 하나는 취소된 거 아냐?`
- 보험 청구 상담: `아버지 무릎 MRI 찍은 거 서울아산병원에서 한 건 실손 청구돼?`
- 부채 최적화: `신한 마통보다 카드론 먼저 갚는 게 나아, 자동차 할부 먼저 갚는 게 나아?`

각 실행은 다음을 출력합니다.

1. 원문 private input
2. Qwen draft
3. Policy gate findings
4. 의미 보존 가명화 기법
5. 외부 LLM payload
6. 내부 재결합 최종 응답
7. Privacy audit (2026 위험 등급 + 교차 참조 경고 포함)

## 설치

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Ollama로 Qwen을 로컬 실행하려면:

```bash
ollama pull qwen3:30b-a3b
semantic-redaction demo all --model qwen3:30b-a3b
```

Ollama나 Qwen이 없어도 mock Qwen draft로 전체 파이프라인이 실행됩니다.

vLLM/SGLang 방식의 OpenAI-compatible 로컬 서버를 사용할 수도 있습니다.

```bash
OPENAI_COMPATIBLE_BASE_URL=http://localhost:8000/v1 \
semantic-redaction demo card --runtime openai-compatible --model Qwen/Qwen3-30B-A3B
```

---

# English

> **Masking hides words. Semantic redaction preserves reasoning.**

`semantic-redaction-ko` is a Qwen-powered killer demo for Korean financial companies that want to use external LLMs without leaking personal credit information.

It models the architecture many Korean financial institutions need for **Innovative Financial Services** and financial network separation exceptions: a local open-weight LLM such as Qwen runs inside the closed/private network, understands the raw customer context, and converts it into a meaning-preserving pseudonymized decision state before anything reaches an external LLM.

```text
Private Raw Input
  -> Local Qwen Semantic Redactor
  -> Deterministic Policy & Privacy Gate
  -> External LLM Payload
  -> Safe Internal Rehydration
```

The external LLM receives useful reasoning context, not personal credit data.

## Why This Is Different

Traditional redaction:

```text
스타벅스 강남2호점 / 6,800원 / 승인
SBUX GANGNAM STN / 6,800원 / 취소
  -> MERCHANT_1 / AMOUNT_1 / STATUS_1
```

This is private, but the LLM loses the important meaning: these two records may be the same coffee-chain authorization lifecycle, where one transaction was approved and one was cancelled.

Semantic redaction:

```json
{
  "merchant_taxonomy": "coffee_chain",
  "location_granularity": "same_commercial_area",
  "amount_relation": "same_amount",
  "temporal_relation": "near_time_duplicate_within_2_minutes",
  "authorization_lifecycle": ["approved", "cancelled"],
  "billing_interpretation": "approved_and_cancelled_pair_likely_single_final_charge",
  "required_action": "explain_transactions_without_raw_merchant_names"
}
```

The LLM can still explain the situation, but it never sees the raw merchant names, card number fragments, detailed location, or original ledger records.

## Advanced Redaction Strategy

This demo uses a two-layer strategy:

1. **Local Qwen draft**
   - A self-hosted Qwen model runs inside the private financial network.
   - It drafts intent, candidates, reasons, conflicts, uncertainty, and required action.

2. **Deterministic semantic policy engine**
   - It removes sensitive leaks from the Qwen draft.
   - It adds testable, purpose-bound meaning that is safe for the external LLM.
   - It records which meaning was preserved and which private fields were suppressed.

Implemented techniques:

| Technique | Preserves | Suppresses |
|---|---|---|
| Tokenized entity binding | Stable references such as `TX_A`, `CLAIM_A`, `DEBT_B` | Names, raw merchants, institutions, policy numbers |
| Domain taxonomy lifting | `coffee_chain`, `diagnostic_imaging_mri`, `card_loan` | Raw merchant, hospital, issuer strings |
| Relation encoding | Same amount, near-time duplicate, high-rate-first priority | Exact timestamps, exact balances, raw descriptions |
| Lifecycle abstraction | Approved/cancelled pair, possible claim, repayment priority | Full ledgers and contract identifiers |
| Banding/generalization | Rate bands, balance bands, provider class | Exact balances, exact hospital names |
| Uncertainty contract | Confirmed/likely/conflicting/needs-documents states | Hidden overconfidence |
| Purpose-bound minimization | Only facts needed for the LLM task | Extra unrelated private context |
| **Query-relevance filter** | Finer-grained semantic facts for query-relevant PII | More aggressive suppression of query-irrelevant PII |

### Security Layers

Four additional security layers that strengthen privacy without reducing semantic utility:

| Layer | Role |
|---|---|
| **Extended FORBIDDEN_PATTERNS** | Detects Korean RRN, 16-digit card numbers, business registration numbers, emails, card/securities/insurance/capital company names, hospital/clinic names, and Korean unit amounts (만원/억원) |
| **Dict key scanning** | Scans both keys and values in Qwen output — not just values |
| **Outbound filter** | Inspects and sanitizes external LLM responses before rehydration |
| **Cross-reference detection** | Tracks cumulative semantic dimension exposure across repeated queries on the same entity; warns (does not block) when re-identification risk increases |

## Korean Regulatory Context

This project is inspired by the Korean financial AI adoption pattern around:

- **Innovative Financial Services** under the Korean financial regulatory sandbox.
- External generative AI usage by banks, card companies, insurers, securities firms, and fintechs.
- The recurring need to control whether pseudonymized information is sent to external AI models.
- The Korean `가명정보 처리 가이드라인(2026.03.)`, especially:
  - Utility must be preserved enough to achieve the processing purpose.
  - Re-identification risk must be controlled, not hand-waved away.
  - Additional information and mapping tables must be separated and access-controlled.
  - Suitability review and residual-risk monitoring are part of the process.

This is a technical demo, not legal advice. It is designed to help AI/data/security teams discuss a safer architecture before applying for or operating an AI-powered Innovative Financial Service.

Relevant public context:

- [Korean Financial Regulatory Sandbox](https://sandbox.fintech.or.kr/)
- [KB Kookmin Card: generative AI card-life mate](https://sandbox.fintech.or.kr/business/enterprise.do?id=479&lang=ko)
- [KakaoPay: asset-management AI financial agent](https://sandbox.fintech.or.kr/business/enterprise.do?id=805&lang=ko)
- [Aijinet: insurance coverage analysis conversational service](https://sandbox.fintech.or.kr/business/enterprise.do?id=683&lang=ko)

## Demo Scenarios

```bash
semantic-redaction demo card
semantic-redaction demo insurance
semantic-redaction demo debt
semantic-redaction demo all
semantic-redaction audit last-run --format md
```

Scenarios:

- Card transaction mystery: `지난주 강남 스벅 두 번 긁힌 거 뭐야? 하나는 취소된 거 아냐?`
- Insurance claim guidance: `아버지 무릎 MRI 찍은 거 서울아산병원에서 한 건 실손 청구돼?`
- Debt optimization: `신한 마통보다 카드론 먼저 갚는 게 나아, 자동차 할부 먼저 갚는 게 나아?`

Each run prints:

1. Raw private input
2. Qwen draft
3. Policy gate findings
4. Meaning-preserving techniques
5. External LLM payload
6. Final rehydrated response
7. Privacy audit (2026 risk tier assessment + cross-reference warnings)

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

For local Qwen inference with Ollama:

```bash
ollama pull qwen3:30b-a3b
semantic-redaction demo all --model qwen3:30b-a3b
```

If Ollama or Qwen is unavailable, the demo falls back to mock Qwen drafts so the full pipeline still runs.

For vLLM/SGLang-style local serving:

```bash
OPENAI_COMPATIBLE_BASE_URL=http://localhost:8000/v1 \
semantic-redaction demo card --runtime openai-compatible --model Qwen/Qwen3-30B-A3B
```

## License

Apache-2.0
