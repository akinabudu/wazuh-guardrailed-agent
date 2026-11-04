"""Thesis v2 figures 3.1-3.7, drawn to match the rewritten text. Reuses the helpers in
docs/figures/make_figures.py (read-only) and writes SVG + 2x PNG to this folder."""
import subprocess, sys
from pathlib import Path

sys.path.insert(0, r"C:\Users\akinb\Documents\Dev\wazuh-guardrailed-agent\docs\figures")
from make_figures import Fig, KIND, INK, MUTED, RED, browser  # noqa: E402

OUT = Path(__file__).resolve().parent


def tag(f, x, y, s):
    f.parts.append(f'<circle cx="{x}" cy="{y}" r="11" fill="#FFFFFF" stroke="{RED}" stroke-width="1.5"/>')
    f.text(x, y + 4, s, 10.5, 700, RED)


def fig_3_1():
    f = Fig(1000, 300)
    steps = [("1. Problem", ["Section 1.2"], "infra"), ("2. Objectives", ["Section 1.3, Tables 3.1-3.2"], "human"),
             ("3. Design and", ["development", "Sections 3.3-3.5, Ch. 4"], "ai"),
             ("4. Demonstration", ["end-to-end trace", "Section 4.5"], "safety"),
             ("5. Evaluation", ["laboratory run", "Chapter 5"], "action"), ("6. Communication", ["this report and", "the repository"], "infra")]
    x = 12
    for i, (a, b, k) in enumerate(steps):
        f.box(x, 30, 148, 84, a, b, k, size=15)
        if i:
            f.arrow([(x - 15, 72), (x - 2, 72)])
        x += 164
    f.arrow([(750, 114), (750, 150), (414, 150), (414, 118)],
            "development results fed back into design", at=(582, 168))
    f.box(110, 200, 360, 62, "Development corpus", ["used while building and tuning; never reported"], "plain", size=14)
    f.box(530, 200, 360, 62, "Evaluation corpus and rubric", ["checksummed before the first trial; reported"], "plain", size=14)
    f.text(500, 288, "Activities after Peffers et al. (2007); evaluation criteria after Hevner et al. (2004).", 12.5, 400, MUTED, italic=True)
    return f


def fig_3_2():
    f = Fig(1000, 820)
    f.box(30, 60, 220, 80, "wazuh-lab-endpoint", ["Wazuh agent 4.14.9", "auditd · FIM · sshd · nginx"], "infra", size=14)
    f.box(30, 190, 220, 90, "Attacker-influenced fields", ["SSH user names · user agents", "request paths · file names"], "plain", size=14)
    f.arrow([(140, 190), (140, 142)], "written into logs", at=(148, 170), lanchor="start")
    f.box(330, 60, 260, 80, "Wazuh 4.14.9 manager + indexer", ["alerts · rules · ATT&CK labels", "active-response API"], "infra", size=14)
    f.arrow([(250, 112), (328, 112)], "events", at=(290, 106))
    f.arrow([(330, 76), (252, 76)])
    f.text(290, 70, "firewall-drop", 11, 400, MUTED, italic=True)
    tag(f, 290, 44, "B6")
    # backend
    f.parts.append('<rect x="282" y="170" width="326" height="545" rx="12" fill="none" stroke="#6A93CF" '
                   'stroke-width="1.4" stroke-dasharray="4 4"/>')
    f.text(294, 706, "FastAPI backend (guardrail-backend container)", 12.5, 700, "#4A6FA5", anchor="start")
    f.box(300, 192, 290, 66, "hunt_and_propose", ["four recorded retrieval steps · the only model call"], "ai", size=14)
    f.arrow([(445, 140), (445, 190)], "context, as data", at=(453, 168), lanchor="start")
    tag(f, 425, 166, "B1")
    f.box(650, 192, 230, 66, "Amazon Bedrock", ["Claude Opus 4.6", "IAM role: this model only"], "ai", size=14)
    f.arrow([(590, 225), (648, 225)], both=True)
    tag(f, 619, 210, "B2")
    f.box(300, 300, 290, 82, "Policy engine (code)", ["schema · allowlist · target · blast radius", "evidence re-read from the indexer", "then the circuit breaker"], "safety", size=14)
    f.arrow([(445, 258), (445, 298)], "proposal, untrusted", at=(453, 282), lanchor="start")
    tag(f, 425, 280, "B3")
    f.box(60, 404, 180, 62, "Blocked", ["logged; ends here"], "blocked", size=14)
    f.arrow([(300, 342), (150, 342), (150, 402)])
    f.text(140, 384, "check or breaker fails", 12, 400, MUTED, anchor="end", italic=True)
    f.box(300, 410, 290, 52, "Tier router", ["conditional edge"], "safety", size=14)
    f.arrow([(445, 382), (445, 408)])
    f.box(300, 500, 135, 70, "auto_approve", ["enrich:", "records only"], "safety", size=14)
    f.box(455, 500, 135, 70, "human_gate", ["interrupt()", "waits for analyst"], "human", size=14)
    f.arrow([(367, 462), (367, 498)], "auto", at=(360, 484), lanchor="end")
    f.arrow([(522, 462), (522, 498)], "human / elevated", at=(530, 484), lanchor="start")
    f.box(300, 620, 290, 66, "execute", ["approved block_ip, run with", "the analyst's own Wazuh token"], "action", size=14)
    f.arrow([(367, 570), (367, 618)])
    f.arrow([(522, 570), (522, 618)], "approved", at=(530, 598), lanchor="start")
    f.box(650, 300, 230, 70, "PostgreSQL 16", ["audit_log · decisions", "LangGraph checkpoints"], "infra", size=14)
    f.arrow([(590, 335), (648, 335)])
    f.box(650, 470, 230, 86, "Dashboard plugin (server)", ["analyst named from the", "Wazuh session · HMAC-signed", "requests to the backend"], "human", size=14)
    f.arrow([(590, 530), (648, 530)], both=True)
    tag(f, 619, 515, "B4")
    f.box(650, 610, 230, 62, "Analyst (browser)", ["Wazuh dashboard login"], "human", size=14)
    f.arrow([(765, 610), (765, 558)], "decides", at=(773, 588), lanchor="start")
    f.text(765, 694, "the browser has no route to the backend", 12, 400, MUTED, italic=True)
    f.arrow([(300, 653), (268, 653), (268, 130), (328, 130)])
    tag(f, 268, 590, "B5")
    f.text(258, 620, "active response with", 11.5, 400, MUTED, anchor="end", italic=True)
    f.text(258, 635, "the analyst's token", 11.5, 400, MUTED, anchor="end", italic=True)
    f.text(500, 752, "B1-B6: trust boundaries described in Section 3.3. Bedrock is outside the VPC, in the same AWS account.",
           12.5, 400, RED, italic=True)
    f.legend(795, ("ai", "safety", "human", "action", "infra", "blocked"))
    return f


def fig_3_3():
    f = Fig(1000, 430)
    f.text(500, 28, "The model runs only in hunt_and_propose. Every other step is deterministic code.", 15, 700, INK)
    f.text(500, 50, "A PostgreSQL checkpointer saves the state at interrupt(), so a paused investigation survives a restart.",
           13, 400, MUTED, italic=True)
    f.box(20, 150, 170, 70, "hunt_and_propose", ["retrieval + model call"], "ai")
    f.box(225, 150, 190, 70, "guardrail", ["five checks, then breaker"], "safety")
    f.box(450, 155, 150, 60, "route", ["conditional edge"], "plain", dashed=True, size=14)
    f.box(650, 60, 150, 62, "auto_approve", ["enrich only"], "safety", size=14)
    f.box(650, 190, 150, 62, "human_gate", ["interrupt()"], "human", size=14)
    f.box(845, 60, 135, 62, "execute", ["active response"], "action", size=14)
    f.parts.append('<ellipse cx="912" cy="340" rx="62" ry="26" fill="#F3F4F7" stroke="#8C93A3" stroke-width="1.6"/>')
    f.text(912, 345, "END", 15, 700, INK)
    f.arrow([(190, 185), (223, 185)])
    f.arrow([(415, 185), (448, 185)])
    f.arrow([(600, 170), (625, 170), (625, 91), (648, 91)], "auto", at=(618, 84), lanchor="end")
    f.arrow([(600, 200), (625, 200), (625, 221), (648, 221)], "human / elevated", at=(620, 240), lanchor="end", lsize=11.5)
    f.arrow([(525, 215), (525, 340), (848, 340)], "blocked by a check or the breaker: logged, no analyst", at=(690, 332))
    f.arrow([(800, 91), (843, 91)])
    f.arrow([(800, 221), (822, 221), (822, 111), (843, 111)], "approved", at=(830, 172), lanchor="start")
    f.text(830, 186, "(resume once)", 11, 400, MUTED, anchor="start", italic=True)
    f.arrow([(725, 252), (725, 300), (858, 326)], "rejected", at=(717, 285), lanchor="end")
    f.arrow([(912, 122), (912, 312)], "executed or execution_failed", at=(904, 270), lanchor="end", lsize=11.5)
    f.text(500, 410, "Elevated actions (disable_account) need a second approver, which is not implemented, so they cannot be approved.",
           12.5, 400, RED, italic=True)
    return f


def fig_3_4():
    stages = [
        ("1. Schema", ["strict type: action, target, reason (up to 2,000 characters),",
                       "evidence ids, affected hosts, optional ATT&CK technique"], 92),
        ("2. Allowlist", ["enrich · escalate · block_ip · kill_process · isolate_host · disable_account"], 80),
        ("3. Target", ["block_ip: IP address · kill_process: process id · disable_account: user name",
                       "isolate_host, escalate: host · enrich: address, host or hash (never a URL)"], 92),
        ("4. Blast radius", ["not a protected address · not the monitored endpoint",
                             "not a listed critical asset · at most five hosts"], 92),
        ("5. Evidence", ["1-20 cited events; each exists in the indexer, is on the investigated",
                         "agent and inside the window; one mentions the target",
                         "indexer unreachable: fail closed · ATT&CK mismatch: note only"], 112),
        ("Circuit breaker", ["automatic tier only: at most 10 passing proposals per sliding hour"], 80),
    ]
    f = Fig(880, 1000)
    f.box(220, 20, 400, 56, "Proposal (from the model)", [], "ai", size=16)
    y = 108
    for title, sub, h in stages:
        f.box(120, y, 600, h, title, sub, "safety", size=16)
        f.arrow([(420, y - 30), (420, y - 2)])
        f.arrow([(720, y + h / 2), (752, y + h / 2), (752, 520), (765, 520)])
        y += h + 30
    f.box(767, 480, 105, 80, "Blocked", ["logged", "no analyst"], "blocked", size=15)
    f.arrow([(420, y - 30), (420, y - 2)])
    f.box(120, y, 600, 76, "Tier router", ["auto (enrich) · human (analyst approval) · elevated (fails closed)"], "action", size=16)
    f.text(440, y + 104, "Each stage is applied in order; the first failure stops the proposal and is recorded as the deciding stage.",
           13, 400, MUTED, italic=True)
    f.h = int(y + 125)
    return f


def fig_3_5():
    lanes = ["Analyst (browser)", "Plugin server", "FastAPI backend", "Bedrock Opus 4.6", "PostgreSQL", "Wazuh (indexer, mgr)"]
    kinds = ["human", "human", "safety", "ai", "infra", "action"]
    f = Fig(1000, 640)
    xs = [85 + i * 166 for i in range(6)]
    for x, name, k in zip(xs, lanes, kinds):
        f.box(x - 72, 14, 144, 46, name, [], k, size=13.5)
        f.parts.append(f'<line x1="{x}" y1="60" x2="{x}" y2="610" stroke="#C3C8D3" stroke-width="1.4" stroke-dasharray="5 5"/>')
    L = dict(zip("APBODW", xs))
    msgs = [
        ("B", "W", "1. four recorded queries: trigger, same rule, shared indicator, window"),
        ("B", "O", "2. prompt: <alert> and <context>, marked as data"),
        ("O", "B", "3. one proposal as schema-constrained JSON"),
        ("B", "B", "4. five checks (cited events re-read), then the breaker"),
        ("B", "D", "5. proposal and guardrail rows; checkpoint at interrupt()"),
        ("A", "P", "6. opens the queue in the Wazuh dashboard"),
        ("P", "B", "7. GET /queue, HMAC-signed, analyst named from the session"),
        ("A", "P", "8. Approve + justification"),
        ("P", "B", "9. POST /approve: signed, timestamp + one-time nonce, analyst's Wazuh token"),
        ("B", "D", "10. compare-and-set pending to approved; decision row"),
        ("B", "W", "11. PUT /active-response firewall-drop, with the analyst's token"),
        ("W", "B", "12. affected_items / failed_items"),
        ("B", "D", "13. execution row, or execution_failed"),
    ]
    y = 96
    for a, b, label in msgs:
        if a == b:
            x = L[a]
            f.arrow([(x, y - 6), (x + 34, y - 6), (x + 34, y + 10), (x + 3, y + 10)])
            f.text(x + 42, y + 6, label, 12.5, 400, INK, anchor="start")
        else:
            x1, x2 = L[a], L[b]
            f.arrow([(x1, y + 4), (x2 + (-3 if x2 > x1 else 3), y + 4)])
            f.text(min(x1, x2) + 8, y - 3, label, 12.5, 400, INK, anchor="start")
        y += 39
    f.text(500, 630, "A stopped proposal ends after step 5. A forged, replayed, stale or second decision is refused at step 9 or 10.",
           12.5, 400, RED, italic=True)
    return f


def fig_3_6():
    f = Fig(1000, 690)
    f.frame(10, 10, 980, 540, "AWS VPC, us-east-1 (WazuhLabStack): no inbound access from the internet; administration over SSM only")
    f.parts.append('<rect x="30" y="48" width="600" height="485" rx="12" fill="#F7F8FB" stroke="#B9C0CE" stroke-width="1.5"/>')
    f.text(330, 70, "wazuh-lab-host · EC2 t3.xlarge spot · 4 vCPU · 16 GiB · 120 GB encrypted · Ubuntu 24.04", 13.5, 700, INK)
    f.parts.append('<rect x="48" y="86" width="270" height="290" rx="10" fill="none" stroke="#6A93CF" stroke-width="1.3" stroke-dasharray="4 4"/>')
    f.text(183, 104, "Docker · Wazuh 4.14.9 single-node", 12.5, 700, "#4A6FA5")
    f.box(64, 116, 238, 62, "wazuh.manager", ["API 55000 · agents 1514/1515"], "infra", size=14)
    f.box(64, 192, 238, 62, "wazuh.indexer", ["OpenSearch"], "infra", size=14)
    f.box(64, 268, 238, 92, "wazuh.dashboard", ["OpenSearch Dashboards 2.19.6", "+ wazuhGuardrail plugin", "443 on 127.0.0.1"], "human", size=14)
    f.parts.append('<rect x="336" y="86" width="276" height="204" rx="10" fill="none" stroke="#6A93CF" stroke-width="1.3" stroke-dasharray="4 4"/>')
    f.text(474, 104, "Docker · application tier", 12.5, 700, "#4A6FA5")
    f.box(352, 116, 244, 74, "guardrail-backend", ["FastAPI 0.115 · LangGraph 0.2.76", "guardrails · 127.0.0.1:8000"], "safety", size=14)
    f.box(352, 204, 244, 74, "guardrail-postgres", ["PostgreSQL 16 + pgvector", "audit · checkpoints"], "infra", size=14)
    f.box(336, 322, 276, 72, "Instance IAM role", ["bedrock:InvokeModel on the", "Opus 4.6 inference profile only"], "safety", size=14)
    f.arrow([(596, 153), (622, 153), (622, 358), (614, 358)])
    f.box(336, 572, 276, 66, "Amazon Bedrock", ["Claude Opus 4.6 · US inference profile", "same AWS account, outside the VPC"], "ai", size=14)
    f.arrow([(612, 380), (621, 380), (621, 605), (614, 605)])
    f.text(632, 600, "HTTPS, signed", 12, 400, MUTED, anchor="start", italic=True)
    f.text(632, 616, "with the role", 12, 400, MUTED, anchor="start", italic=True)
    f.arrow([(318, 150), (350, 150)], both=True)
    f.box(48, 416, 564, 48, "8 GB swap · all service ports bound to 127.0.0.1", ["created by setup.sh"], "plain", size=14)
    f.text(330, 488, "setup.sh installs everything on first boot; dashboard-plugin/install.sh deploys the plugin", 12.5, 400, MUTED, italic=True)
    f.text(330, 508, "the backend joins the Wazuh Docker network to reach the manager and indexer", 12.5, 400, MUTED, italic=True)
    f.box(680, 86, 290, 132, "wazuh-lab-endpoint", ["EC2 t3.small spot · Ubuntu 24.04", "Wazuh agent 4.14.9 · auditd · real-time FIM",
                                                     "sshd · nginx · Atomic Red Team"], "infra", size=15)
    f.box(680, 300, 290, 104, "wazuh-lab-attacker", ["EC2 t3.micro spot · Ubuntu 24.04", "SSH and HTTP attacks;", "injection payloads"], "plain", size=15)
    f.arrow([(678, 200), (650, 200), (650, 306), (326, 306), (326, 168), (304, 168)])
    f.text(474, 302, "agent traffic 1514/1515 · security group: endpoint only", 11, 400, MUTED, italic=True)
    f.arrow([(825, 298), (825, 220)], "SSH 22 · HTTP 80", at=(835, 262), lanchor="start")
    f.box(680, 440, 290, 80, "Operator workstation", ["SSM port-forward to dashboard 443", "(no public port)"], "human", size=14)
    f.arrow([(678, 480), (636, 480), (636, 405), (183, 405), (183, 362)], dashed=True)
    f.legend(668)
    return f


def table(f, x, y, w, name, cols, note=None):
    rh = 26
    h = rh * (len(cols) + 1)
    f.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#FFFFFF" stroke="#8C93A3" stroke-width="1.5"/>')
    f.parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{rh}" rx="6" fill="#E8EBF2" stroke="#8C93A3" stroke-width="1.5"/>')
    f.text(x + w / 2, y + 18, name, 14.5, 700, INK)
    for i, (typ, col, key) in enumerate(cols, 1):
        yy = y + rh * i
        if i % 2 == 0:
            f.parts.append(f'<rect x="{x + 1}" y="{yy}" width="{w - 2}" height="{rh}" fill="#F5F6F9"/>')
        f.text(x + 10, yy + 18, col, 13, 700 if key else 400, INK, anchor="start")
        f.text(x + w - 44, yy + 18, typ, 12, 400, MUTED, anchor="end")
        if key:
            f.text(x + w - 10, yy + 18, key, 11.5, 700, "#4A6FA5", anchor="end")
    if note:
        f.text(x + w / 2, y + h + 18, note, 12, 400, MUTED, italic=True)
    return h


def fig_3_7():
    f = Fig(1000, 560)
    table(f, 30, 30, 300, "proposals", [
        ("bigint", "id", "PK"), ("timestamptz", "created_at", ""), ("jsonb", "action", ""), ("text", "reasoning", ""),
        ("jsonb", "evidence", ""), ("text", "risk_tier", ""), ("boolean", "guardrail_ok", ""), ("text", "guardrail_reason", ""),
        ("text", "guardrail_check", ""), ("text", "status", ""), ("text", "thread_id", ""), ("text", "agent_id", ""),
        ("text", "requested_by", "")], "status changes from pending only by compare-and-set")
    table(f, 420, 30, 270, "decisions", [
        ("bigint", "id", "PK"), ("bigint", "proposal_id", "FK"), ("timestamptz", "decided_at", ""), ("text", "decision", ""),
        ("text", "decided_by", ""), ("text", "justification", ""), ("text", "second_approver", "")],
        "at most one decision per proposal")
    table(f, 420, 290, 270, "audit_log", [
        ("bigint", "id", "PK"), ("timestamptz", "ts", ""), ("text", "event_type", ""), ("bigint", "proposal_id", ""),
        ("boolean", "autonomous", ""), ("jsonb", "payload", "")], "trigger rejects UPDATE and DELETE")
    table(f, 750, 30, 230, "agent_memory", [
        ("bigint", "id", "PK"), ("timestamptz", "created_at", ""), ("text", "fact", ""), ("text", "source", ""),
        ("vector(768)", "embedding", "")], "not used in the evaluated build")
    f.arrow([(330, 120), (375, 120), (375, 108), (418, 108)], "FK", at=(374, 98))
    f.arrow([(330, 300), (375, 300), (375, 394), (418, 394)], dashed=True)
    f.text(374, 420, "proposal_id,", 12, 400, MUTED, italic=True)
    f.text(374, 435, "no constraint", 12, 400, MUTED, italic=True)
    f.text(500, 540, "LangGraph's own checkpoint tables are not shown.", 12.5, 400, MUTED, italic=True)
    return f


FIGS = {"fig-3-1": fig_3_1, "fig-3-2": fig_3_2, "fig-3-3": fig_3_3, "fig-3-4": fig_3_4,
        "fig-3-5": fig_3_5, "fig-3-6": fig_3_6, "fig-3-7": fig_3_7}

if __name__ == "__main__":
    exe = browser()
    for name, make in FIGS.items():
        fig = make()
        svg = OUT / f"{name}.svg"
        svg.write_text(fig.svg(), encoding="utf-8")
        subprocess.run([exe, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--force-device-scale-factor=2",
                        f"--window-size={fig.w},{fig.h}", f"--screenshot={OUT / (name + '.png')}", svg.as_uri()],
                       check=True, capture_output=True, timeout=60)
        print(name, fig.w, fig.h)
