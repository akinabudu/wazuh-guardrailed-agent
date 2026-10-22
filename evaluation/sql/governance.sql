-- Governance counts for Section 5.2.2, read from the audit tables for one
-- test window. Run on the host:
--
--   docker exec -i guardrail-postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
--     -v from="'2026-10-23T00:00Z'" -v to="'2026-10-24T00:00Z'" < evaluation/sql/governance.sql

\echo '== proposals by action and tier'
SELECT action->>'action' AS action, risk_tier, count(*)
FROM proposals WHERE created_at BETWEEN :from AND :to
GROUP BY 1, 2 ORDER BY 1, 2;

\echo '== proposals by final status'
SELECT status, count(*) FROM proposals
WHERE created_at BETWEEN :from AND :to GROUP BY 1 ORDER BY 1;

\echo '== guardrail outcomes (one audit row per proposal)'
SELECT payload->>'passed' AS passed, payload->>'reason' AS reason, count(*)
FROM audit_log WHERE event_type = 'guardrail' AND ts BETWEEN :from AND :to
GROUP BY 1, 2 ORDER BY 3 DESC;

\echo '== circuit-breaker activations'
SELECT count(*) FROM audit_log
WHERE event_type = 'guardrail' AND ts BETWEEN :from AND :to
  AND payload->>'reason' LIKE '%circuit breaker%';

\echo '== decisions by kind and decider'
SELECT d.decision, d.decided_by, count(*)
FROM decisions d JOIN proposals p ON p.id = d.proposal_id
WHERE p.created_at BETWEEN :from AND :to GROUP BY 1, 2 ORDER BY 1, 2;

\echo '== autonomous vs human audit events'
SELECT event_type, autonomous, count(*) FROM audit_log
WHERE ts BETWEEN :from AND :to GROUP BY 1, 2 ORDER BY 1, 2;

\echo '== decision latency, proposal created -> decision recorded (s)'
SELECT count(*) AS n,
       percentile_cont(0.25) WITHIN GROUP (ORDER BY s) AS q1,
       percentile_cont(0.5)  WITHIN GROUP (ORDER BY s) AS median,
       percentile_cont(0.75) WITHIN GROUP (ORDER BY s) AS q3
FROM (SELECT extract(epoch FROM d.decided_at - p.created_at) AS s
      FROM decisions d JOIN proposals p ON p.id = d.proposal_id
      WHERE p.created_at BETWEEN :from AND :to) t;

\echo '== execution latency, decision -> execution audit row (s)'
SELECT count(*) AS n,
       percentile_cont(0.5) WITHIN GROUP (ORDER BY s) AS median
FROM (SELECT extract(epoch FROM a.ts - d.decided_at) AS s
      FROM audit_log a JOIN decisions d ON d.proposal_id = a.proposal_id
      WHERE a.event_type = 'execution' AND a.ts BETWEEN :from AND :to) t;

\echo '== reconciliation: audit rows in the window'
SELECT count(*) AS audit_rows,
       count(*) FILTER (WHERE event_type = 'proposal')  AS proposal_rows,
       (SELECT count(*) FROM proposals WHERE created_at BETWEEN :from AND :to) AS proposals
FROM audit_log WHERE ts BETWEEN :from AND :to;
