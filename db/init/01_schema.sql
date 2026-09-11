-- ===========================================================================
-- Schema for the Guardrailed Agentic AI Framework
-- Runs once, on first PostgreSQL start (mounted into docker-entrypoint-initdb.d).
--
-- Tables:
--   audit_log   append-only record of everything (accountability + evaluation)
--   proposals   actions the agent has proposed, and their guardrail verdicts
--   decisions   human approve/reject decisions
--   agent_memory (OPTIONAL, disabled by default) verified facts for future use
--
-- LangGraph creates its own checkpoint tables automatically when the Postgres
-- checkpointer is initialised by the backend - not defined here.
-- ===========================================================================

CREATE EXTENSION IF NOT EXISTS vector;      -- pgvector, for optional retrieval

-- ---------------------------------------------------------------------------
-- proposals: one row per action the agent proposes
-- ---------------------------------------------------------------------------
CREATE TABLE proposals (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    action        JSONB        NOT NULL,          -- the structured action object
    reasoning     TEXT,                            -- agent's narrative (description only)
    evidence      JSONB        NOT NULL DEFAULT '[]',  -- list of Wazuh event ids
    risk_tier     TEXT         NOT NULL,           -- 'auto' | 'human' | 'elevated'
    guardrail_ok  BOOLEAN      NOT NULL,           -- did it pass the gauntlet?
    guardrail_reason TEXT,                         -- why it failed, if it did
    status        TEXT         NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','approved','rejected','auto_approved','executed','blocked')),
    thread_id     TEXT
);
CREATE INDEX idx_proposals_status ON proposals (status);
CREATE INDEX idx_proposals_created ON proposals (created_at DESC);

-- ---------------------------------------------------------------------------
-- decisions: human approve/reject (or the policy auto-approval) per proposal
-- ---------------------------------------------------------------------------
CREATE TABLE decisions (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    proposal_id   BIGINT       NOT NULL REFERENCES proposals(id),
    decided_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    decision      TEXT         NOT NULL CHECK (decision IN ('approved','rejected','auto_approved')),
    decided_by    TEXT         NOT NULL,           -- analyst username, or 'policy:auto'
    justification TEXT,                             -- required for elevated actions
    second_approver TEXT                            -- for actions above severity threshold
);
CREATE INDEX idx_decisions_proposal ON decisions (proposal_id);

-- ---------------------------------------------------------------------------
-- audit_log: APPEND-ONLY. The source of truth for accountability + Chapter 5.
-- Update and delete are blocked by a trigger below.
-- ---------------------------------------------------------------------------
CREATE TABLE audit_log (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ts            TIMESTAMPTZ  NOT NULL DEFAULT now(),
    event_type    TEXT         NOT NULL,   -- proposal|guardrail|decision|execution|alert
    proposal_id   BIGINT,                  -- nullable link back to a proposal
    autonomous    BOOLEAN      NOT NULL DEFAULT false,  -- was this the auto lane?
    payload       JSONB        NOT NULL    -- full detail of the event
);
CREATE INDEX idx_audit_ts   ON audit_log (ts DESC);
CREATE INDEX idx_audit_type ON audit_log (event_type);

-- Enforce append-only: reject any UPDATE or DELETE on audit_log.
CREATE OR REPLACE FUNCTION audit_log_immutable() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_log is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE OR DELETE ON audit_log
    FOR EACH ROW EXECUTE FUNCTION audit_log_immutable();

-- ---------------------------------------------------------------------------
-- agent_memory (OPTIONAL - future enhancement, left empty by default)
-- Only VERIFIED, grounded facts may ever be written here. Never raw log text
-- and never raw model output, or you create a persistent prompt-injection
-- channel (poisoned memory). See the thesis discussion.
-- ---------------------------------------------------------------------------
CREATE TABLE agent_memory (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    fact        TEXT        NOT NULL,        -- e.g. 'IP 203.0.113.47 blocked, analyst-confirmed'
    source      TEXT        NOT NULL,        -- must trace to a verified origin
    embedding   vector(768)                  -- for semantic retrieval (optional)
);
