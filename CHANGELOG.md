# Changelog

## 0.3.0 - 2026-09-25

### Added
- PII registry bundle 1.2.0 (24 countries, incl. AU TFN/ABN/Medicare).
- **The country layer: 24 country profiles, 51 patterns, 20 check digits.**
  Patterns, keywords, redaction labels and checksum gates are generated from
  Tork's own country registry and consumed verbatim from the SDK bundle
  (`Registry-Version: 1.1.0`, content `110383007e265740`). Countries: AU, US, GB, EU, AE, SA, NG, IN, JP,
  CN, KR, BR, CA, ZA, GH, IT, KE, MU, MX, MY, PK, SG, TH, ID.
- New namespace `TorkGovernance.CountryPii`: `PiiRegistry` (the bundle's 50
  patterns), `PiiActivation` (the 51 signals and the country map),
  `PiiChecksums` (20 algorithms) and `PiiCountry` (the matcher). All pure and
  local: no network, no clock.
- `Pii.PiiDetectionResult` gains `CountryMatches`, `CountryLabels` and
  `Regions`, all defaulting to empty. `Pii.DetectPii` takes an optional third
  argument, `regionOverride`. The existing members and the first two arguments
  are unchanged.
- **Nine check digits ported by hand.** The bundle names twenty algorithms and
  specifies the eleven that reduce to a weight vector and a modulus; the other
  nine (`br_cpf`, `br_cnpj`, `cn_resident_id`, `de_steuer_id`, `fr_nir`,
  `it_codice_fiscale`, `jp_my_number`, `kr_rrn`, `sg_nric`) are ported from the
  cloud's `lib/pii/checksums.ts`, each tested against the issuing authority's
  own worked example where one is published.

### Fixed
- **SDK-DOTNET-PARTIAL-REDACTION.** Until 0.2.0 `Pii.DetectPii` redacted each
  type with its own `Regex.Replace` over text a previous type had already
  rewritten, while `Matches` carried indices into the *original* text. Two
  types matching overlapping spans could leave half an identifier standing
  beside a redaction token -- digits exposed in output the caller had been told
  was redacted. Every match is now collected against the original text,
  overlaps are resolved before anything is rewritten, and the surviving spans
  are spliced right to left in one pass. `NothingIsEverPartiallyRedacted`
  asserts the invariant across all 2,092 vectors.
- **`Tork.Govern` ran a THIRD, private detector** -- its own pattern table, and
  redaction by literal `String.Replace` of each matched *value*, which replaced
  every other occurrence of the same text anywhere in the content. It now goes
  through `Pii.DetectPii`, the same detector `ScanToolResult` uses, so the two
  paths cannot drift. The private table and its `Redact` helper are gone.
- **`GovernOptions.Region` was ignored.** It was echoed back on the result and
  never used to select a pattern. It now drives detection.

### Changed (behaviour)
- **`Tork.Govern`'s redaction labels are now JS-identical.** The private
  detector used the dictionary key as the label, so a social security number
  came back as `[ssn_REDACTED]`; it is now `[SSN_REDACTED]`, matching the
  JavaScript, Go, Rust and PHP SDKs and the cloud. `GovernanceResult.Pii` keys
  are unchanged for the ten L0 types and gain one key per country pattern
  detected.

### Notes
- This release folds in 0.2.0, which is in this repository but was never
  published to NuGet (NuGet is at 0.1.0) and never had a changelog entry.
- The bundle emits the namespace `Tork.Governance.Pii`. That introduces a root
  namespace `Tork` which shadows this SDK's own `Tork` class (CS0118), and
  `TorkGovernance.Pii` would shadow its `Pii` class, so the copies here are
  re-homed under `TorkGovernance.CountryPii`.
- **The bundle now states the whole contract, and this SDK implements it.**
  Bundle 1.0.0's README documented three rules; measured against the cloud's
  golden snapshot they disagreed with it on 14 of 86 country-corpus cases, so
  this SDK carried two more of its own. Bundle **1.1.0 documents seven**, marks
  each SDK or cloud-only, and ships the data all seven need in every language
  file -- the activation signals, the country map, the asymmetric 60/40 window,
  the symmetric 60 context window, the whole-word vocabulary, the near-miss
  policy, the table constants and the reference labels. So the locally generated
  activation layer is **deleted**, no window is hard-coded any more, and rules 6
  (near miss), 7 (column header) and 7b (nearest label) are implemented here for
  the first time. Every rule now reads its data off the placed bundle.
- Advisory checksums never reject a match: `ca_sin`, `emirates_id`,
  `de_tax_id`, `kr_rrn`, `sa_national_id`. Korea stopped issuing check digits on
  20 Oct 2020.
- Not ported, and still cloud-only: the slot, context,
  gravity and name layers, industry profiles, and org configuration.
- **Indonesia is the country 1.1.0 added, and it is the one that proves the
  whole-word rule.** `id_nik`'s only short spellings -- NIK, KTP, NPWP -- are
  `wholeWordKeywords`, not ordinary keywords, because `nik` sits inside
  *teknik*, *elektronik*, *klinik* and *pabrik*. Matching them by substring
  would open the gate on an Indonesian sales ledger; matching them on a word
  boundary catches "NIK 3171010101900001" and leaves *teknik* alone. An SDK that
  merged the two lists would be shipping a false-positive bug, so the boundary
  test is implemented rather than the shortcut, and four unit cases assert both
  halves.
- **FLAGGED, upstream: bundle 1.1.0 cannot detect Australia's TFN, ABN or
  Medicare number.** `checksums.json` declares `au_tfn` and `au_abn` as
  `requiredBy` and `au_medicare` as `advisoryFor` patterns of those names, and
  `patterns` ships none of them -- the AU profile carries only `au_acn` and
  `au_phone_intl`. The AU activation signals are still keyed on "tfn", "tax
  file" and "medicare", so the bundle switches Australia on for identifiers it
  then has no pattern to catch. The cloud detects all three. This is a recall
  gap no SDK can close from the bundle, and the six parity cases it costs are
  recorded in the fixture as `BUNDLE GAP` rather than silently accepted.

## 0.1.2 - 2026-03-09

### Added
- feat: agent/session context fields (agent_id, agent_role, session_id, session_turn)
