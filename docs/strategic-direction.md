# 전략 방향 — 벤치마크 추격이 아닌 카테고리 만들기

CyberGym 0.33 % 결과는 우리 시스템을 잘못 사용한 데이터다. **우리가 가진
구조적 비대칭 우위는 점수 항목이 아니라 산출물의 종류에 있다.** 이 문서는
벤치마크에 fit-tuning 하지 않고도 가치를 만들어 낼 수 있는 방향을 정리한다.

## 1. 동시대 LLM 에이전트들이 *구조적으로* 할 수 없는 것

OpenHands / Cybench / Codex / ENiGMA / SWE-agent — 모두 LLM + tool-use
패러다임이다. 공통의 약점:

- **출력의 정당화가 없다.** "this looks like the bug"는 *plausible*이지
  *verified*가 아니다.
- **검색 공간을 sound 하게 줄이지 못한다.** attention spray.
- **상태가 없다.** 매 실행마다 같은 코드를 다시 탐색.
- **반례를 만들지 못한다.** "이 입력이 assertion을 위반한다"를 *증명*할
  방법이 없음.
- **소프트 가설을 hard 가설처럼 다룬다.** hallucination을 거를 구조적
  필터가 없음.

이 약점들은 LLM을 더 크게 한다고 해서 *카테고리적으로* 해소되지 않는다.
DeepSeek-V3 (671B MoE) 가 CyberGym 3.58 %에서 멈춘 이유는 모델 크기가
아니라 패러다임의 한계다.

## 2. 우리가 *구조적으로* 만들 수 있는 산출물 5가지

각 항목은 LLM-only 에이전트가 흉내낼 수 없는, **카테고리적으로 다른** 산출
물이다. 우리가 가진 어떤 자산이 이를 가능하게 하는지 명시.

### 산출물 A — Sound attack-surface reduction with audit trail

- **무엇**: 한 코드베이스에 대해 "이 22 % 만이 도달 가능, 나머지는 dead"
  를 *근거 함께* 출력. 모든 over-approximation을 `soundness-assumptions.md`에
  명시.
- **자산**: Stage A (Phase 1.2) + Juliet 소거 게이트 (1.5)
- **현재 입증**: Linux 6.1.72 netfilter 22.05 % 감축, 0 missed bug
- **LLM-only 흉내 불가 이유**: LLM은 sound한 reachability를 제공할 수 없다.
  "I think this is reachable" 만 가능. 회사가 SBOM / 보안 감사에 쓰는 종류의
  답이 아님.
- **이걸로 할 수 있는 것**:
  - Reachable-CVE auditing: "이 CVE가 우리 빌드에서 실제로 reachable한가?"
    에 sound 한 yes/no.
  - SBOM 위에 layer: 단순 "이 라이브러리 사용 중" 이 아니라 "이 라이브러리
    의 36 % 만 reachable".
  - Compiler / linker dead-code stripping의 보안 보강.

### 산출물 B — Verified bug witness (input + 경로 + assertion)

- **무엇**: PoC를 단순 byte stream이 아니라 *structured exploit*으로 출력.
  - 입력 변수 할당 ({i = 8u, v = 0})
  - 실행 경로 (which branches taken)
  - 위반된 assertion 또는 sanitizer banner
- **자산**: Tier-3 CBMC + harness synth (Phase 2.3, 3.2), Tier-2 KLEE
- **현재 입증**: cbmc:unsafe:off_by_one 스모크가 PoV {i=8u, v=0} + line 26
  생성 (Phase 2.3)
- **LLM-only 흉내 불가 이유**: LLM이 byte sequence를 *추측*해서 crash을
  관측할 수는 있지만, 그게 *왜* crash하는지 증명하지 못함. fuzz hit는
  forensic 가치가 낮다 — root cause를 모름.
- **이걸로 할 수 있는 것**:
  - 책임공개 (responsible disclosure)에 "여기 witness가 있다" 첨부.
  - 회귀 테스트 자동 생성 (witness → unit test).
  - 동일한 root cause를 공유하는 다른 입력 패밀리 자동 enumeration.

### 산출물 C — Verified patch (LLM-agnostic trust layer)

- **무엇**: 누군가가 (사람이든 LLM이든) 패치를 제안하면, 우리는 *같은
  사전조건/사후조건* 아래에서 패치 본문이 safe 함을 증명.
- **자산**: Phase 1.4 proof cache (key = body + contracts), Stage B
- **현재 입증**: `surface/test_proof_cache.py` 가 contract 변경시 캐시 무효화
  하는 6개 케이스 통과.
- **LLM-only 흉내 불가 이유**: LLM은 "이 패치가 fix한다고 생각한다"고
  말할 수 있지만 *증명*할 수 없다. 규제/감사 환경에서 의미가 다름.
- **이걸로 할 수 있는 것**:
  - **OpenHands / Cybench 위에 layer**: 그들의 패치 제안을 받아 우리가
    검증. 경쟁이 아니라 보완.
  - 커널 패치 자동화 (Linux LTS 메인테이너 워크플로우).
  - CI에 sound 검증 게이트.

### 산출물 D — Persistent verified knowledge base of a codebase

- **무엇**: 한 코드베이스에 대해 witness / safe-proof / 가정-기반-증명을 모두
  content-addressed로 저장. 변경된 부분만 incremental re-verify.
- **자산**: Phase 1.4 proof_cache (현재는 Stage B 한정)
- **현재 입증**: `transitive_dependents("nf_route") → 3806 unit` cluster
  invalidation 동작.
- **LLM-only 흉내 불가 이유**: LLM-tool-use agent는 stateless. 같은 함수를
  매번 다시 reason. Cumulative knowledge 부재.
- **이걸로 할 수 있는 것**:
  - 매일 LTS 트리에서 incremental analysis. 어제 증명한 부분 재증명 안 함.
  - 회사 codebase에 대한 living verification ledger.
  - 비용 amortize: 첫 분석은 expensive, 이후 commit은 cheap.

### 산출물 E — Counterexample-driven LLM (LLM은 follower, verifier는 leader)

- **무엇**: 현재 패러다임 ("LLM proposes, verifier checks") 을 뒤집어
  *verifier가 witness를 생성하고 LLM이 그걸 소비*해서 다음 artifact를 만듦.
- **자산**: Phase 3.1 `refine_unit` (CBMC trace → LLM contract proposal)
  + Phase 3.2 must_not_assume 필터
- **현재 입증**: needs_contract.c 에서 CBMC unsafe → LLM이 trace에서
  `__CPROVER_assume(i <= CAP - 1)` 제안 → CBMC safe. 구조적 hallucination
  필터 (must_not_assume) 가 Qwen-3B의 잘못된 `klee_assume(d!=0)` 거절.
- **LLM-only 흉내 불가 이유**: witness를 만들 verifier가 없음. LLM이 자기
  hallucination에 대한 ground truth를 갖지 못함.
- **이걸로 할 수 있는 것**:
  - PoC 생성: witness bytes를 LLM이 받아 자연스러운 입력 형태로 변환 (binary
    blob → structured file).
  - 회귀 테스트 생성: witness → 사람 가독성 있는 testcase.
  - 패치 제안: witness → "여기서 NULL이 가능, 이 가드 추가" 형태로 LLM이 제안.

## 3. 이 5가지가 만드는 시장 포지셔닝

| 누구 | 우리에게 가치를 사는 이유 |
|---|---|
| 대기업 보안 감사 | sound surface reduction + SBOM 강화 (A) |
| 오픈소스 메인테이너 | LLM 제안 패치를 받아들이기 전 검증 게이트 (C) |
| 책임공개 절차 | verified bug witness + 회귀 테스트 자동 생성 (B + E) |
| 컴플라이언스 (의료/항공/자동차) | living verification ledger (D) |
| OpenHands / Cybench / agentic AI 회사 | 그들의 출력 위에 trust layer (C 위에 또) |

**OpenHands와의 관계 재정의**: 경쟁자가 아니라 *consumer*. 그들이 빠르게
넓은 영역 cover, 우리가 결과를 sound 하게 검증.

## 4. 개선 우선순위 — 이제는 벤치마크 fit이 아닌 카테고리 빌드

### 즉시 (P1-P3): 산출물의 *형태* 자체를 바꿈

**P1. Witness-as-artifact 표준화**
- 현재: CBMC unsafe verdict는 trace에 witness를 적지만 우리 시스템은 그걸
  보조 정보로만 사용.
- 변경: witness를 1급 산출물로 격상. 스키마 (입력 변수 할당 + 경로 + violated
  property + sanitizer 매핑) 표준화. 모든 oracle (Tier 1/2/3) 가 같은
  스키마로 witness 출력.
- 효과: CyberGym에 byte stream으로 변환 가능 + 동시에 disclosure에 첨부
  가능 + 회귀 테스트로 자동 변환 가능. **하나의 witness, 여러 산출물.**

**P2. Soundness ledger를 외부에 노출**
- 현재: `docs/soundness-assumptions.md`가 내부 문서.
- 변경: 분석 산출물마다 "이 결과는 다음 over-approximation 위에서 성립함"
  를 machine-readable JSON으로 첨부. 감사 도구가 읽을 수 있게.
- 효과: "22 % 감축, 0 missed bug" 같은 헤드라인이 *audit-grade* 로 격상.

**P3. Patch verification 인터페이스**
- 현재: 우리 시스템은 패치를 받지 않음.
- 변경: `verify_patch(unpatched_fn, proposed_patch, contracts) → SoundVerdict`
  API 추가. LLM agent (또는 사람)가 만든 패치를 받아 Stage B로 검증.
- 효과: OpenHands / SWE-agent 위에 *trust layer*. 그들의 결과를 우리가
  도장 찍어주는 역할.

### 중기 (P4-P5): cumulative knowledge

**P4. Proof cache의 범위 확장 + 외부 노출**
- 현재: surface/stageb 한정.
- 변경: Tier 1/2/3 verdict, LLM-synthesized contracts, KASAN replays
  모두 같은 content-addressed cache. 외부 노출 인터페이스 (export /
  import).
- 효과: codebase 단위로 portable한 verification ledger.

**P5. Incremental analysis driver**
- 현재: 분석은 매번 처음부터.
- 변경: git commit diff → 영향받은 unit/cluster → transitive dependents →
  최소 재검증. Phase 1.4 `transitive_dependents()` 가 이미 cluster 단위로
  존재 — 함수 단위로 정밀화 + commit-hook 통합.
- 효과: 매일 LTS 빌드에서 diff-only 검증.

### 장기 (P6-P7): 산출물의 카탈로그화

**P6. Multi-codebase benchmark roster**
- CyberGym 만 보지 말고: Magma, Juliet, kernel CVE feed, OpenSSL, libxml2.
  각 코드베이스에 대해 surface-reduction + sound-pruning + verified-witness 통계를
  publish.
- 효과: 한 점이 아닌 면으로 가치 증명.

**P7. Living publication / dashboard**
- 우리 검증이 *현재 상태*에서 어떻게 sound한지, 어떤 가정 위에 서 있는지,
  무엇이 캐시되어 있는지를 보여주는 외부 surface.
- 효과: "여기에 가서 확인하라" 한 줄로 신뢰 회복 가능.

## 5. CyberGym은 이 그림에서 무엇인가

CyberGym은 **산출물 B (verified bug witness)** 와 **산출물 E (witness-driven LLM)**
의 *데모 케이스*다. 점수는 부산물이지 목적이 아님.

- CyberGym 1507 / 0.33 % 점수 → 우리 산출물 B의 *byte projection only*
  점수. witness의 다른 차원 (assertion, path, sanitizer mapping)은 leaderboard
  는 보지 않지만 우리 산출물에는 살아 있음.
- 진짜 데모: "여기 5개 confirmed task에 대해 우리는 witness + path + violated
  property 까지 같이 출력함. OpenHands+Claude-Sonnet-4은 점수는 17.85 %로
  더 높지만 *왜 그 입력이 crash하는지 증명*하지 못함."
- 그 차이를 헤드라인으로 만들면 우리는 다른 카테고리에서 1등.

## 6. 다음 액션 — 우선순위 매트릭스

| 항목 | 효과 카테고리 | 효과 크기 | 빌드 비용 | 의존성 |
|---|---|---|---|---|
| P1 witness-as-artifact 표준 스키마 | B, E | 큼 (다회용 산출물) | 1-2일 | 없음 |
| P2 soundness ledger JSON export | A | 중 (audit-grade) | 1일 | 없음 |
| P3 patch verification API | C | 큼 (새 시장) | 2-3일 | Stage B 재사용 |
| P4 proof cache 확장 | D | 중 (cumulative) | 2일 | P1 필요 |
| P5 incremental analysis driver | D | 큼 (실용성) | 3-5일 | P4 필요 |
| P6 multi-codebase 데모 | A, B | 큼 (외부 신호) | 1주 | P1-P3 필요 |

내 추천: **P1 → P2 → P3 → P6**.

- P1, P2는 *이미 가진 결과를 더 잘 보여주는* 변경 (low risk, high upside).
- P3는 새 시장을 여는 한 발 — LLM-agent 회사들과 *상보적* 포지셔닝.
- P6는 그 모든 걸 외부에 보일 수 있는 카탈로그.
- CyberGym 점수 추격은 의도적으로 *우선순위에서 빠짐*. 5 confirmed 데이터는
  P1을 만든 후 재포장해서 *다른 종류의* 헤드라인으로 변환.

## 7. 직접적 다음 작업이 의미하는 것

다음에 코드를 짠다면 첫 패치는:

```
schemas/witness.py                     # 산출물 B의 1급 스키마
  ├─ InputAssignment   (변수 → 값)
  ├─ ExecutionPath     (taken branches)
  ├─ ViolatedProperty  (assertion / sanitizer)
  ├─ SoundnessNote     (이 witness가 어떤 가정 위에 있나)
  └─ Provenance        (어느 engine, 어느 버전, 어느 contract)

# Tier 1/2/3 driver가 모두 같은 Witness 객체를 emit
oracle/tier1_fuzz/verdict.py:  Tier1Verdict → Witness(...)
oracle/tier2_symbolic/verdict.py: ditto
oracle/tier3_bmc/verdict.py:  ditto

# Adapter: byte stream으로 환원하는 helper
schemas/witness.py: Witness.to_bytes() → bytes  (CyberGym에 제출용)
schemas/witness.py: Witness.to_regression_test() → str  (회귀 테스트 생성)
schemas/witness.py: Witness.to_disclosure_blob() → dict (responsible disclosure용)
```

이 한 패치만으로 *같은 작업으로 만들어진 산출물이 여러 시장에 동시 진입* 한다.

## 8. Agent-improvement design rule — benchmark-agnostic

**Rule.** No agent improvement may *fine-tune* to a single benchmark
(CyberGym, Magma, Juliet, kernelCTF, SV-COMP, etc.). Every change must be
expressed against an abstract `Task` / `BenchmarkAdapter` surface and must
help — or at worst not hurt — every benchmark the system runs against.

**Why this rule.** The whole point of the strategic shift in this document
is that we build a *category*, not a single-benchmark score-chaser. If we
hard-code agent logic to CyberGym's `error.txt`, `patch.diff`, or
`tasks.json` field names, we sacrifice that category positioning for a
short-term board-row delta. The 10.95 % bank+libFuzzer result already shows
that benchmark-agnostic tools (deterministic seed bank, libFuzzer mutation,
sound score_local oracle) can place us #3 on a public board without any
benchmark-specific tuning — so the bar is set.

**What the rule allows.**

- Agent-level changes that operate on the abstract task surface
  (e.g. "if the bug class hint says off-by-one, route Tier-3 BMC first" —
  *any* benchmark with bug-class hints can use this).
- Per-benchmark *adapters* — `eval/cybergym/adapter.py` is fine because
  it's a translation layer, not agent logic.
- Per-benchmark *seed corpora* — adding XML or PNG to the seed bank
  helps any task whose harness is a libFuzzer binary.

**What the rule forbids.**

- Hard-coded paths or field names from a single benchmark inside `agent/`
  (e.g. `bundle.data_dir / "error.txt"` directly in agent code — must go
  through a `task.disclosed_error_text()` method).
- Heuristics tuned to one benchmark's score distribution (e.g. "if the
  task_id starts with `arvo:` use budget X, else Y").
- Demos that only work on the leaderboard task set.

**How we enforce it.**

1. Each fundamental track item (F1-F4) is reviewed against this rule
   before landing.
2. New agent modules under `agent/` may only import from `schemas/`,
   `oracle/`, `surface/`, `llm/`, and an abstract task interface (TBD —
   to be introduced when the first F-track item lands that needs it).
3. CyberGym, Magma, kernelCTF adapters all implement the same
   `BenchmarkAdapter` protocol. If a new improvement needs a method that
   doesn't exist on the protocol, the protocol gets extended and every
   adapter implements it — never one-off bypass.

This rule is the reason F1-F4 are written as architectural changes
(coverage feedback, dedup+parallel score, multi-oracle routing, project
corpus sharing) rather than CyberGym knob-twists (longer budget, more
seeds, parallel libFuzzer). The knob-twists live in `docs/backlog.md` and
will be promoted only when they cease to be benchmark-specific.
