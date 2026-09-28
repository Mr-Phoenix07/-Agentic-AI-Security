-- AEGIS persistence schema (SQLite dialect; portable to Postgres with minor edits).
-- Every assessment is fully reconstructable from these tables: raw probes and
-- responses, derived observations, adjudicated findings, metrics, and the
-- structured memory / regression baselines used for continuous validation.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assessments (
    id           TEXT PRIMARY KEY,
    engagement   TEXT NOT NULL,
    status       TEXT NOT NULL DEFAULT 'running',   -- running|completed|aborted
    config_json  TEXT NOT NULL,
    started_at   REAL NOT NULL,
    finished_at  REAL
);

CREATE TABLE IF NOT EXISTS targets (
    id             TEXT NOT NULL,
    assessment_id  TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL,
    mode           TEXT NOT NULL,
    model          TEXT,
    endpoint       TEXT,
    metadata_json  TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (assessment_id, id)
);

CREATE TABLE IF NOT EXISTS probes (
    id             TEXT PRIMARY KEY,
    assessment_id  TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    seed_id        TEXT,
    category       TEXT NOT NULL,
    mode           TEXT NOT NULL,
    objective      TEXT,
    payload_json   TEXT NOT NULL,
    provenance_json TEXT NOT NULL DEFAULT '[]',
    content_hash   TEXT NOT NULL,
    created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_probes_assessment ON probes(assessment_id);
CREATE INDEX IF NOT EXISTS idx_probes_hash ON probes(content_hash);

CREATE TABLE IF NOT EXISTS results (
    id             TEXT PRIMARY KEY,
    probe_id       TEXT NOT NULL REFERENCES probes(id) ON DELETE CASCADE,
    assessment_id  TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    target_id      TEXT NOT NULL,
    status         TEXT NOT NULL,
    response_json  TEXT NOT NULL,
    latency_ms     REAL NOT NULL DEFAULT 0,
    tokens_json    TEXT NOT NULL DEFAULT '{}',
    error          TEXT,
    created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_results_assessment ON results(assessment_id);
CREATE INDEX IF NOT EXISTS idx_results_probe ON results(probe_id);

CREATE TABLE IF NOT EXISTS evidence (
    id                TEXT PRIMARY KEY,
    result_id         TEXT REFERENCES results(id) ON DELETE CASCADE,
    assessment_id     TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    target_id         TEXT,
    kind              TEXT NOT NULL,
    summary           TEXT,
    payload_json      TEXT NOT NULL DEFAULT '{}',
    reproduction_json TEXT NOT NULL DEFAULT '{}',
    created_at        REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_assessment ON evidence(assessment_id);

CREATE TABLE IF NOT EXISTS observations (
    id             TEXT PRIMARY KEY,
    assessment_id  TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    target_id      TEXT,
    dimension      TEXT NOT NULL,
    metric         TEXT NOT NULL,
    value          REAL NOT NULL,
    unit           TEXT NOT NULL DEFAULT 'ratio',
    direction      TEXT NOT NULL DEFAULT 'higher_is_better',
    confidence_json TEXT NOT NULL DEFAULT '{}',
    evidence_ids_json TEXT NOT NULL DEFAULT '[]',
    context_json   TEXT NOT NULL DEFAULT '{}',
    created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_assessment ON observations(assessment_id);
CREATE INDEX IF NOT EXISTS idx_obs_dimension ON observations(dimension);

CREATE TABLE IF NOT EXISTS findings (
    id                  TEXT PRIMARY KEY,
    assessment_id       TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    target_id           TEXT,
    title               TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL,
    mode                TEXT NOT NULL,
    confidence_json     TEXT NOT NULL DEFAULT '{}',
    summary             TEXT,
    root_cause          TEXT,
    impact              TEXT,
    frameworks_json     TEXT NOT NULL DEFAULT '{}',
    mitigations_json    TEXT NOT NULL DEFAULT '[]',
    regression_tests_json TEXT NOT NULL DEFAULT '[]',
    evidence_ids_json   TEXT NOT NULL DEFAULT '[]',
    observation_ids_json TEXT NOT NULL DEFAULT '[]',
    created_at          REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(assessment_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);

CREATE TABLE IF NOT EXISTS metrics (
    id             TEXT PRIMARY KEY,
    assessment_id  TEXT NOT NULL REFERENCES assessments(id) ON DELETE CASCADE,
    target_id      TEXT,
    name           TEXT NOT NULL,
    value          REAL NOT NULL,
    created_at     REAL NOT NULL
);

-- Generic structured memory (assessment history, prompt variants, notes).
CREATE TABLE IF NOT EXISTS memory (
    id          TEXT PRIMARY KEY,
    namespace   TEXT NOT NULL,
    key         TEXT NOT NULL,
    value_json  TEXT NOT NULL,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_memory_ns_key ON memory(namespace, key);

-- Regression baselines for continuous validation: a metric's accepted value for
-- a (target, dimension, metric) tuple, used to detect drift across runs.
CREATE TABLE IF NOT EXISTS baselines (
    id          TEXT PRIMARY KEY,
    target_key  TEXT NOT NULL,      -- stable identity, e.g. provider+model
    dimension   TEXT NOT NULL,
    metric      TEXT NOT NULL,
    value       REAL NOT NULL,
    tolerance   REAL NOT NULL DEFAULT 0.1,
    created_at  REAL NOT NULL,
    UNIQUE (target_key, dimension, metric)
);

-- Immutable audit trail for external tool invocations (spec §21/§26/§34).
-- Every attempt — allowed, refused, or errored — is recorded here. Rows are
-- append-only by convention; the platform never updates or deletes them.
CREATE TABLE IF NOT EXISTS tool_runs (
    id             TEXT PRIMARY KEY,
    assessment_id  TEXT,                 -- nullable: runs may precede an assessment
    tool           TEXT NOT NULL,
    binary         TEXT NOT NULL,
    target         TEXT NOT NULL,
    engagement     TEXT,
    requested_by   TEXT,
    reason         TEXT,
    argv_json      TEXT NOT NULL,
    scope_allowed  INTEGER NOT NULL,     -- 0/1
    scope_reason   TEXT,
    risk_level     TEXT,
    approved       INTEGER NOT NULL,     -- 0/1
    dry_run        INTEGER NOT NULL,     -- 0/1
    executed       INTEGER NOT NULL,     -- 0/1
    exit_code      INTEGER,
    duration_s     REAL,
    outcome        TEXT NOT NULL,        -- allowed|executed|refused|errored
    detail         TEXT,
    created_at     REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tool_runs_assessment ON tool_runs(assessment_id);
CREATE INDEX IF NOT EXISTS idx_tool_runs_outcome ON tool_runs(outcome);
