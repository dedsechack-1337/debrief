// Pure, offline, pattern-based log analysis. No network call, no API key.
// This is intentionally a first-pass triage tool, not a replacement for the
// AI-enhanced mode or a human analyst — see the "notes" field it returns.

const IP_REGEX = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
const HASH_REGEX = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g;
const URL_REGEX = /\bhttps?:\/\/[^\s'")]+/g;
const USER_REGEX = /(?:for (?:invalid user )?|user[= ])([a-zA-Z][\w.-]{1,31})\b/gi;
const HOST_REGEX = /\b([a-zA-Z0-9_-]+)\s+(?:sshd|sudo|kernel|crontab|auditd|systemd|CROND|fw\d*|nginx|apache2?)\b/g;
const TIMESTAMP_REGEX = /^(\d{4}-\d{2}-\d{2}T[\d:.]+Z?|[A-Z][a-z]{2}\s+\d{1,2}\s+[\d:]{8})/;

const RULES = [
  {
    key: "bruteForce",
    weight: 2,
    test: /failed password|authentication failure|invalid user/i,
    minHits: 4,
    label: "Brute-force login attempts",
    action: "Block or rate-limit the source IP(s) at the firewall or fail2ban.",
  },
  {
    key: "successAfterBrute",
    weight: 3,
    test: /accepted password|accepted publickey|session opened/i,
    minHits: 1,
    requires: "bruteForce",
    label: "Successful login following failed attempts",
    action: "Force a password reset for the account and confirm MFA is enforced.",
  },
  {
    key: "privEsc",
    weight: 3,
    test: /sudo:.*(shadow|passwd|useradd|usermod|su -|\bid\b)|USER=root/i,
    minHits: 1,
    label: "Privilege escalation activity",
    action: "Audit the sudo commands run on this host; confirm they were authorized.",
  },
  {
    key: "remoteDownloadExec",
    weight: 4,
    test: /\b(curl|wget)\b.*(https?:\/\/|\.sh\b)|\|\s*(bash|sh)\b/i,
    minHits: 1,
    label: "Remote payload download and execution",
    action: "Isolate the host now; preserve the downloaded file for analysis before deleting it.",
  },
  {
    key: "suspiciousPort",
    weight: 3,
    test: /\b(DPT|DST)=?\s*[:=]?\s*(4444|31337|1337|6666|12345|8888)\b|port\s+(4444|31337|1337|6666)/i,
    minHits: 1,
    label: "Traffic on a known reverse-shell port",
    action: "Block outbound traffic to the flagged host/port and investigate for a reverse shell.",
  },
  {
    key: "persistence",
    weight: 3,
    test: /crontab.*replace|new ssh key|authorized_keys|useradd|systemd.*enable/i,
    minHits: 1,
    label: "Persistence mechanism established",
    action: "Review and remove unauthorized cron jobs or SSH keys; rotate the account's credentials.",
  },
  {
    key: "portScan",
    weight: 1,
    test: /\bDROP\b.*(repeated|scan)|nmap|masscan/i,
    minHits: 1,
    label: "Port scanning activity",
    action: "Correlate the scanning source against threat intel and consider a perimeter block.",
  },
  {
    key: "fileIntegrity",
    weight: 2,
    test: /modified by uid|auditd.*(passwd|shadow)|file integrity/i,
    minHits: 1,
    label: "Sensitive file modification",
    action: "Verify the modified system files against a known-good baseline.",
  },
];

function countMatches(lines, regex) {
  let count = 0;
  const matchedLines = [];
  for (const line of lines) {
    if (regex.test(line)) {
      count++;
      matchedLines.push(line);
    }
    regex.lastIndex = 0;
  }
  return { count, matchedLines };
}

function extractUnique(text, regex, limit = 12) {
  const found = new Set();
  let m;
  const re = new RegExp(regex.source, regex.flags.includes("g") ? regex.flags : regex.flags + "g");
  while ((m = re.exec(text)) !== null) {
    const val = m[1] || m[0];
    if (val) found.add(val);
    if (found.size >= limit) break;
  }
  return Array.from(found);
}

function extractTimestamp(line) {
  const m = line.match(TIMESTAMP_REGEX);
  return m ? m[0] : "";
}

export function analyzeLogHeuristically(logText, logType) {
  const lines = logText.split(/\r?\n/).filter((l) => l.trim());
  const matchedRules = [];

  for (const rule of RULES) {
    if (rule.requires && !matchedRules.find((r) => r.key === rule.requires)) continue;
    const { count, matchedLines } = countMatches(lines, rule.test);
    if (count >= rule.minHits) {
      matchedRules.push({ ...rule, count, matchedLines });
    }
  }

  const score = matchedRules.reduce((sum, r) => sum + r.weight, 0);
  let severity = "info";
  if (score >= 9) severity = "critical";
  else if (score >= 6) severity = "high";
  else if (score >= 3) severity = "medium";
  else if (score >= 1) severity = "low";

  const title =
    matchedRules.length > 0
      ? matchedRules
          .slice(0, 2)
          .map((r) => r.label)
          .join(" + ")
      : "No suspicious patterns detected";

  const summary =
    matchedRules.length > 0
      ? `Local pattern analysis flagged ${matchedRules.length} indicator${matchedRules.length > 1 ? "s" : ""} of concern: ${matchedRules
          .map((r) => r.label.toLowerCase())
          .join(", ")}. This is a rule-based first pass, not a full investigation.`
      : "No known suspicious patterns (brute force, privilege escalation, remote payload execution, persistence, etc.) were matched in this excerpt by local rules. This doesn't guarantee the log is clean, especially for attack techniques these rules don't cover.";

  // Build a timeline from lines that matched any rule, in original order, capped at 8.
  const flaggedLineSet = new Set();
  matchedRules.forEach((r) => r.matchedLines.forEach((l) => flaggedLineSet.add(l)));
  const timeline = lines
    .filter((l) => flaggedLineSet.has(l))
    .slice(0, 8)
    .map((l) => ({ time: extractTimestamp(l), event: l.replace(TIMESTAMP_REGEX, "").trim().slice(0, 160) }));

  const iocs = {
    ips: extractUnique(logText, IP_REGEX),
    users: extractUnique(logText, USER_REGEX).filter((u) => !["root", "the", "for", "user"].includes(u.toLowerCase())),
    hosts: extractUnique(logText, HOST_REGEX),
    hashes: extractUnique(logText, HASH_REGEX),
    urls: extractUnique(logText, URL_REGEX),
  };

  const recommended_actions = matchedRules
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 6)
    .map((r) => r.action);

  return {
    severity,
    title,
    summary,
    timeline,
    iocs,
    recommended_actions,
    notes:
      "Generated locally by pattern-matching rules — no data left your browser and no API key was used. For nuanced or novel attack patterns, try AI-enhanced mode.",
    truncated: false,
    mode: "offline",
  };
}
