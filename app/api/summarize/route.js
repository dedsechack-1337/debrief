import { NextResponse } from "next/server";

const MAX_CHARS = 30000; // keep the request well inside a reasonable context budget

function sampleLog(text) {
  if (text.length <= MAX_CHARS) return { sample: text, truncated: false };
  const headLen = Math.floor(MAX_CHARS * 0.6);
  const tailLen = MAX_CHARS - headLen;
  const head = text.slice(0, headLen);
  const tail = text.slice(text.length - tailLen);
  const omitted = text.length - MAX_CHARS;
  return {
    sample: `${head}\n\n...[${omitted.toLocaleString()} characters omitted]...\n\n${tail}`,
    truncated: true,
  };
}

export async function POST(req) {
  let body;
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "Invalid request body." }, { status: 400 });
  }

  const { logText, logType, fileName, apiKey: clientKey } = body || {};
  const apiKey = (clientKey && clientKey.trim()) || process.env.ANTHROPIC_API_KEY;

  if (!apiKey) {
    return NextResponse.json(
      {
        error:
          "No Anthropic API key available. Add your own key in Settings, or use Offline mode — it needs no key at all.",
      },
      { status: 401 }
    );
  }

  if (!logText || !logText.trim()) {
    return NextResponse.json({ error: "No log content provided." }, { status: 400 });
  }

  const { sample, truncated } = sampleLog(logText);

  const prompt = `You are a security operations analyst. Analyze the following log excerpt${
    logType ? ` from a ${logType} source` : ""
  }${fileName ? ` (file: ${fileName})` : ""} and produce an incident summary for a human analyst.

LOG EXCERPT:
"""
${sample}
"""
${truncated ? "Note: this excerpt was truncated from a longer file; only the beginning and end are shown above." : ""}

Respond with ONLY a JSON object, no markdown fences, no preamble, in exactly this shape:
{
  "severity": "critical" | "high" | "medium" | "low" | "info",
  "title": "short incident title, under 10 words",
  "summary": "2-4 sentence plain-language summary of what happened and why it matters",
  "timeline": [{"time": "timestamp or relative marker from the log, empty string if none is present", "event": "short description of what happened at this point"}],
  "iocs": {"ips": [], "users": [], "hosts": [], "hashes": [], "urls": []},
  "recommended_actions": ["short, concrete, actionable step"],
  "notes": "caveats: e.g. insufficient data, ambiguous evidence, log was truncated, or nothing suspicious found"
}

Rules:
- Base your analysis only on what's actually present in the excerpt. Never invent IPs, users, or events that aren't there.
- If there's no clear evidence of a security incident, say so plainly in the summary and set severity to "info".
- Limit "timeline" to at most 8 entries and "recommended_actions" to at most 6.
- Leave any "iocs" sub-array empty ([]) if that type of indicator doesn't appear in the excerpt.`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-sonnet-5",
        max_tokens: 1200,
        messages: [{ role: "user", content: prompt }],
      }),
    });

    if (!response.ok) {
      const text = await response.text();
      const hint = response.status === 401 ? " Check that your API key is correct." : "";
      return NextResponse.json(
        { error: `Anthropic API error (${response.status}): ${text.slice(0, 300)}${hint}` },
        { status: 502 }
      );
    }

    const data = await response.json();
    const raw = (data.content || [])
      .map((block) => (block.type === "text" ? block.text : ""))
      .join("")
      .trim();

    let parsed;
    try {
      const cleaned = raw.replace(/^```json\s*|```$/g, "").trim();
      parsed = JSON.parse(cleaned);
    } catch {
      return NextResponse.json(
        { error: "The model's response couldn't be parsed as JSON. Try again." },
        { status: 502 }
      );
    }

    return NextResponse.json({ ...parsed, truncated, mode: "ai" });
  } catch (err) {
    return NextResponse.json({ error: `Request failed: ${err.message}` }, { status: 500 });
  }
}
