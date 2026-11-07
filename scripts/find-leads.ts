/**
 * Lead discovery for Mont Agent Gateway.
 *
 *   npx tsx scripts/find-leads.ts [--days 30] [--out leads.csv] [--max-repos 80] [--no-reddit] [--include-email]
 *   GITHUB_TOKEN=ghp_... npx tsx scripts/find-leads.ts      (recommended: higher limits + package.json code search)
 *
 * 1. GitHub: repositories pushed in the last N days that combine an AI stack
 *    (@modelcontextprotocol/sdk, langchain, openai, anthropic, ai-sdk) with a commerce/web stack
 *    (express, shopify, stripe, webhook).
 *      - With GITHUB_TOKEN: code search over package.json for both dependencies (precise).
 *      - Without:           repository search over name/description/README/topics (approximate).
 * 2. Owner profile: name, company, blog, X/Twitter, bio (+ public email only with --include-email).
 * 3. Reddit public JSON (r/mcp, r/AI_Agents, r/shopify, r/node, r/LangChain): recent posts about agent
 *    security, rate limits, human-in-the-loop, or production API failures.
 * 4. Writes a de-duplicated CSV with a short, specific 3-sentence opener per lead.
 *
 * Use responsibly:
 *   - GitHub's Acceptable Use Policy prohibits using data from GitHub (including public emails) for
 *     spam or unsolicited bulk email. Emails are therefore off by default. Prefer replying where the
 *     person already talks in public (an issue/discussion on their repo, their X account, the Reddit thread).
 *   - Reddit asks automated clients to identify themselves and stay within rate limits; set
 *     REDDIT_USER_AGENT to something like "mont-lead-finder/1.1 (by u/yourname)".
 *   - Every message is a draft for a human to review and personalise before sending.
 */
import fs from "fs";
import path from "path";
import { parseArgs } from "util";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------
const { values: args } = parseArgs({
  options: {
    days: { type: "string", default: "30" },
    out: { type: "string", default: "leads.csv" },
    "max-repos": { type: "string", default: "80" },
    "no-reddit": { type: "boolean", default: false },
    "include-email": { type: "boolean", default: false },
  },
  strict: true,
});

const DAYS = Math.max(1, Math.min(365, Number(args.days) || 30));
const OUT = path.resolve(args.out ?? "leads.csv");
const MAX_REPOS = Math.max(1, Math.min(500, Number(args["max-repos"]) || 80));
const INCLUDE_EMAIL = args["include-email"] === true;
const WITH_REDDIT = args["no-reddit"] !== true;
const TOKEN = process.env.GITHUB_TOKEN?.trim() || "";
const REDDIT_UA = process.env.REDDIT_USER_AGENT?.trim() || "mont-lead-finder/1.1 (agent-gateway-sdk research script)";
const SINCE = new Date(Date.now() - DAYS * 24 * 60 * 60_000);
const SINCE_DAY = SINCE.toISOString().slice(0, 10);

interface Term {
  id: string;
  label: string;
  /** Exact dependency string for package.json code search. */
  dep: string;
  /** Keyword for repository search. */
  keyword: string;
}

const AI_TERMS: Term[] = [
  { id: "mcp", label: "MCP", dep: '"@modelcontextprotocol/sdk"', keyword: "modelcontextprotocol" },
  { id: "langchain", label: "LangChain", dep: '"langchain"', keyword: "langchain" },
  { id: "openai", label: "OpenAI", dep: '"openai"', keyword: "openai" },
  { id: "anthropic", label: "Anthropic", dep: '"@anthropic-ai/sdk"', keyword: "anthropic" },
  { id: "ai-sdk", label: "Vercel AI SDK", dep: '"@ai-sdk/', keyword: "ai-sdk" },
];
const WEB_TERMS: Term[] = [
  { id: "express", label: "Express", dep: '"express"', keyword: "express" },
  { id: "shopify", label: "Shopify", dep: '"@shopify/', keyword: "shopify" },
  { id: "stripe", label: "Stripe", dep: '"stripe"', keyword: "stripe" },
  { id: "webhook", label: "webhooks", dep: "webhook", keyword: "webhook" },
];

const SUBREDDITS = ["mcp", "AI_Agents", "shopify", "node", "LangChain"];
const REDDIT_QUERY = '"rate limit" OR "human in the loop" OR approval OR "prompt injection" OR security OR guardrails OR "in production" OR runaway';
const REDDIT_TOPICS: Array<{ id: string; re: RegExp }> = [
  { id: "prompt-injection", re: /prompt[\s-]?injection|jailbreak|malicious (?:prompt|instruction)/i },
  { id: "rate-limit", re: /rate[\s-]?limit|429|throttl|runaway|infinite loop|loop(?:ing)? (?:agent|calls)|too many requests/i },
  { id: "human-in-the-loop", re: /human[\s-]in[\s-]the[\s-]loop|\bhitl\b|approval|approve|confirm(?:ation)? before/i },
  { id: "security", re: /secur|guardrail|permission|least privilege|access control|api key|auth/i },
  { id: "production-failure", re: /in production|prod(?:uction)? (?:incident|outage|bug)|broke|went wrong|disaster|refund(?:ed)? .*by mistake|deleted/i },
];

// ---------------------------------------------------------------------------
// HTTP helpers with rate-limit handling
// ---------------------------------------------------------------------------
const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const log = (...a: unknown[]): void => console.error("[find-leads]", ...a);

const SEARCH_GAP_MS = TOKEN ? 2_200 : 6_500; // search API: 30/min authenticated, 10/min anonymous
const CODE_SEARCH_GAP_MS = 6_500; // code search: 10/min
let lastSearchAt = 0;

async function github<T>(url: string, kind: "search" | "code" | "core" = "core"): Promise<T | null> {
  if (kind !== "core") {
    const gap = kind === "code" ? CODE_SEARCH_GAP_MS : SEARCH_GAP_MS;
    const wait = lastSearchAt + gap - Date.now();
    if (wait > 0) await sleep(wait);
    lastSearchAt = Date.now();
  }
  for (let attempt = 1; attempt <= 4; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        headers: {
          accept: "application/vnd.github+json",
          "x-github-api-version": "2022-11-28",
          "user-agent": "mont-lead-finder",
          ...(TOKEN ? { authorization: `Bearer ${TOKEN}` } : {}),
        },
        signal: AbortSignal.timeout(20_000),
      });
    } catch (err) {
      log(`network error (${attempt}/4) for ${url}:`, (err as Error).message);
      await sleep(2_000 * attempt);
      continue;
    }
    if (res.ok) return (await res.json()) as T;

    const remaining = res.headers.get("x-ratelimit-remaining");
    const reset = Number(res.headers.get("x-ratelimit-reset"));
    const retryAfter = Number(res.headers.get("retry-after"));
    if (res.status === 403 || res.status === 429) {
      let waitMs = 60_000;
      if (Number.isFinite(retryAfter) && retryAfter > 0) waitMs = retryAfter * 1000;
      else if (remaining === "0" && Number.isFinite(reset)) waitMs = Math.max(1_000, reset * 1000 - Date.now() + 1_000);
      if (waitMs > 5 * 60_000) {
        log(`GitHub rate limit resets in ${Math.round(waitMs / 60_000)} min; skipping ${url}. Set GITHUB_TOKEN for higher limits.`);
        return null;
      }
      log(`GitHub rate limited; waiting ${Math.round(waitMs / 1000)}s...`);
      await sleep(waitMs);
      continue;
    }
    if (res.status === 401) {
      log("GITHUB_TOKEN was rejected (401). Check the token or unset it.");
      return null;
    }
    if (res.status === 422 || res.status === 404) return null;
    log(`GitHub HTTP ${res.status} for ${url}`);
    await sleep(1_500 * attempt);
  }
  return null;
}

// ---------------------------------------------------------------------------
// GitHub discovery
// ---------------------------------------------------------------------------
interface GhRepo {
  full_name: string;
  name: string;
  html_url: string;
  description: string | null;
  stargazers_count: number;
  pushed_at: string;
  fork: boolean;
  archived: boolean;
  topics?: string[];
  language: string | null;
  owner: { login: string; type: string };
}
interface GhUser {
  login: string;
  type: string;
  name: string | null;
  company: string | null;
  blog: string | null;
  twitter_username: string | null;
  email: string | null;
  bio: string | null;
  html_url: string;
  followers: number;
}

interface RepoHit {
  repo: GhRepo;
  ai: Set<string>;
  web: Set<string>;
}

async function discoverRepos(): Promise<Map<string, RepoHit>> {
  const hits = new Map<string, RepoHit>();
  const add = (repo: GhRepo, ai: Term, web: Term): void => {
    if (repo.fork || repo.archived) return;
    if (new Date(repo.pushed_at) < SINCE) return;
    const hit = hits.get(repo.full_name) ?? { repo, ai: new Set<string>(), web: new Set<string>() };
    hit.ai.add(ai.label);
    hit.web.add(web.label);
    hits.set(repo.full_name, hit);
  };

  const combos = AI_TERMS.flatMap((ai) => WEB_TERMS.map((web) => ({ ai, web })));
  for (const { ai, web } of combos) {
    if (hits.size >= MAX_REPOS) break;
    if (TOKEN) {
      // Precise: both strings in the same package.json. Code search cannot filter on push date,
      // so each candidate repo is fetched and filtered by pushed_at.
      const q = `${ai.dep} ${web.dep} filename:package.json`;
      const data = await github<{ items: Array<{ repository: { full_name: string } }> }>(
        `https://api.github.com/search/code?q=${encodeURIComponent(q)}&per_page=30`,
        "code"
      );
      const names = [...new Set((data?.items ?? []).map((i) => i.repository.full_name))];
      log(`code search ${ai.id} + ${web.id}: ${names.length} candidate repos`);
      for (const name of names) {
        if (hits.size >= MAX_REPOS) break;
        const existing = hits.get(name);
        if (existing) {
          existing.ai.add(ai.label);
          existing.web.add(web.label);
          continue;
        }
        const repo = await github<GhRepo>(`https://api.github.com/repos/${name}`);
        if (repo) add(repo, ai, web);
      }
    } else {
      const q = `${ai.keyword} ${web.keyword} pushed:>=${SINCE_DAY} fork:false archived:false`;
      const data = await github<{ items: GhRepo[] }>(
        `https://api.github.com/search/repositories?q=${encodeURIComponent(q)}&sort=updated&order=desc&per_page=30`,
        "search"
      );
      log(`repo search ${ai.id} + ${web.id}: ${(data?.items ?? []).length} repos`);
      for (const repo of data?.items ?? []) add(repo, ai, web);
    }
  }
  return hits;
}

// ---------------------------------------------------------------------------
// Reddit discovery
// ---------------------------------------------------------------------------
interface RedditPost {
  author: string;
  title: string;
  selftext: string;
  permalink: string;
  subreddit: string;
  created_utc: number;
  score: number;
  num_comments: number;
  over_18: boolean;
}

async function discoverReddit(): Promise<RedditPost[]> {
  const out: RedditPost[] = [];
  for (const sub of SUBREDDITS) {
    const url = `https://www.reddit.com/r/${sub}/search.json?q=${encodeURIComponent(REDDIT_QUERY)}&restrict_sr=1&sort=new&t=month&limit=50&raw_json=1`;
    let posts: RedditPost[] = [];
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        const res = await fetch(url, { headers: { "user-agent": REDDIT_UA, accept: "application/json" }, signal: AbortSignal.timeout(20_000) });
        if (res.status === 429) {
          const wait = Number(res.headers.get("retry-after")) || 10 * attempt;
          log(`Reddit rate limited on r/${sub}; waiting ${wait}s`);
          await sleep(wait * 1000);
          continue;
        }
        if (!res.ok) {
          log(`Reddit HTTP ${res.status} for r/${sub} (Reddit may block anonymous clients; set REDDIT_USER_AGENT or use OAuth). Skipping.`);
          break;
        }
        const data = (await res.json()) as { data?: { children?: Array<{ data: RedditPost }> } };
        posts = (data.data?.children ?? []).map((c) => c.data);
        break;
      } catch (err) {
        log(`Reddit network error for r/${sub}:`, (err as Error).message);
        await sleep(3_000 * attempt);
      }
    }
    const recent = posts.filter(
      (p) =>
        p.created_utc * 1000 >= SINCE.getTime() &&
        !p.over_18 &&
        p.author &&
        !["[deleted]", "AutoModerator"].includes(p.author) &&
        REDDIT_TOPICS.some((t) => t.re.test(`${p.title}\n${p.selftext}`))
    );
    log(`r/${sub}: ${recent.length} relevant posts`);
    out.push(...recent);
    await sleep(2_500); // stay well under Reddit's anonymous limits
  }
  return out;
}

// ---------------------------------------------------------------------------
// Message generation: specific, short, no hype, easy to ignore
// ---------------------------------------------------------------------------
function pick<T>(seed: string, options: T[]): T {
  let h = 0;
  for (const ch of seed) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return options[h % options.length];
}

function trimSentence(text: string, max = 90): string {
  const clean = text.replace(/\s+/g, " ").trim().replace(/[.!]+$/, "");
  return clean.length > max ? `${clean.slice(0, max - 1).replace(/\s+\S*$/, "")}…` : clean;
}

const WEB_RISK: Record<string, string> = {
  Stripe: "once an agent can reach Stripe-backed endpoints, a single injected instruction can turn into a burst of refunds or charges",
  Shopify: "once an agent can touch Shopify orders or refunds, one injected instruction in a ticket or product review can act on the whole store",
  webhooks: "webhook-triggered agent actions are a common place for an injected payload to slip straight into a write call",
  Express: "every Express route the agent can call becomes something a prompt injection can call too",
};

const CTA = [
  "I'm building Mont, a small self-hosted gateway that puts payload rules (e.g. amount > $100 needs a human), rate limits and one-tap phone approvals in front of those calls; happy to send a 60-second demo if it's useful, and no worries if not.",
  "I've been working on Mont, a self-hosted gateway that sits in front of agent tool calls with payload-level rules, loop protection and phone approvals; glad to share a short demo if that's relevant, otherwise feel free to ignore this.",
];

function githubMessage(hit: RepoHit, user: GhUser | null): string {
  const first = (user?.name ?? "").split(" ")[0] || hit.repo.owner.login;
  const ai = [...hit.ai].join(" + ");
  const web = [...hit.web];
  const desc = hit.repo.description ? ` (${trimSentence(hit.repo.description, 80)})` : "";
  const s1 = `Hi ${first}, I came across ${hit.repo.name}${desc} while looking at ${ai} projects that wire agents into ${web.join("/")}.`;
  const risk = WEB_RISK[web.find((w) => WEB_RISK[w]) ?? "Express"];
  const s2 = `Curious how you're handling guardrails there, since ${risk}.`;
  return `${s1} ${s2} ${pick(hit.repo.full_name, CTA)}`;
}

const REDDIT_ANGLE: Record<string, string> = {
  "prompt-injection": "The part that stuck with me is that the model can't reliably refuse injected instructions, so the last line of defence has to be outside the model, at the API call itself.",
  "rate-limit": "Runaway loops seem to be one of the most common ways agents hurt in production, and a per-endpoint limit at the gateway is usually cheaper than fixing it in every tool.",
  "human-in-the-loop": "Approvals are only as good as what the approver sees, so showing the actual payload (amount, recipient, email) instead of just the endpoint name matters a lot.",
  security: "Scoping what an agent may call (and with which payloads) at a gateway tends to be easier to reason about than prompt-level guardrails.",
  "production-failure": "Incidents like that are exactly why a deterministic, fail-closed check in front of write endpoints is worth having.",
};

function redditMessage(p: RedditPost): string {
  const topic = REDDIT_TOPICS.find((t) => t.re.test(`${p.title}\n${p.selftext}`))?.id ?? "security";
  const s1 = `Saw your post "${trimSentence(p.title, 80)}" in r/${p.subreddit}.`;
  return `${s1} ${REDDIT_ANGLE[topic]} ${pick(p.permalink, CTA)}`;
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------
interface Lead {
  source: "github" | "reddit";
  handle: string;
  name: string;
  company: string;
  website: string;
  twitter: string;
  email: string;
  bio: string;
  account_type: string;
  repo: string;
  repo_url: string;
  repo_stars: number | "";
  repo_description: string;
  stack: string;
  last_activity: string;
  post_title: string;
  post_url: string;
  topics: string;
  outreach_message: string;
}

const COLUMNS: (keyof Lead)[] = [
  "source", "handle", "name", "company", "website", "twitter", "email", "bio", "account_type",
  "repo", "repo_url", "repo_stars", "repo_description", "stack", "last_activity",
  "post_title", "post_url", "topics", "outreach_message",
];

function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : String(v);
  s = s.replace(/\r?\n/g, " ").trim();
  // Spreadsheet formula injection guard: data from the internet must never execute in Excel/Sheets.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function normaliseUrl(u: string | null | undefined): string {
  if (!u) return "";
  const t = u.trim();
  if (!t) return "";
  return /^https?:\/\//i.test(t) ? t : `https://${t}`;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main(): Promise<void> {
  log(`Looking back ${DAYS} days (since ${SINCE_DAY}); GitHub ${TOKEN ? "authenticated (code search)" : "anonymous (repo search)"}.`);
  if (INCLUDE_EMAIL) {
    log("NOTE: --include-email is on. GitHub's Acceptable Use Policy forbids using these emails for spam or unsolicited bulk email.");
  }

  const leads = new Map<string, Lead>();

  // ---- GitHub ----
  const hits = await discoverRepos();
  log(`${hits.size} repos matched; fetching owner profiles...`);
  const users = new Map<string, GhUser | null>();
  // Strongest repo per owner first, so the message references their most notable project.
  const ordered = [...hits.values()].sort((a, b) => b.repo.stargazers_count - a.repo.stargazers_count);
  for (const hit of ordered) {
    const login = hit.repo.owner.login;
    const key = `github:${login.toLowerCase()}`;
    if (leads.has(key)) {
      const lead = leads.get(key)!;
      const stack = new Set(lead.stack.split(" + ").filter(Boolean));
      [...hit.ai, ...hit.web].forEach((s) => stack.add(s));
      lead.stack = [...stack].join(" + ");
      continue;
    }
    if (!users.has(login)) users.set(login, await github<GhUser>(`https://api.github.com/users/${encodeURIComponent(login)}`));
    const user = users.get(login) ?? null;
    if (user?.type === "Bot" || /\[bot\]$/i.test(login)) continue;
    leads.set(key, {
      source: "github",
      handle: login,
      name: user?.name ?? "",
      company: user?.company ?? "",
      website: normaliseUrl(user?.blog),
      twitter: user?.twitter_username ? `https://x.com/${user.twitter_username}` : "",
      email: INCLUDE_EMAIL ? user?.email ?? "" : "",
      bio: user?.bio ?? "",
      account_type: user?.type ?? hit.repo.owner.type,
      repo: hit.repo.full_name,
      repo_url: hit.repo.html_url,
      repo_stars: hit.repo.stargazers_count,
      repo_description: hit.repo.description ?? "",
      stack: [...hit.ai, ...hit.web].join(" + "),
      last_activity: hit.repo.pushed_at,
      post_title: "",
      post_url: "",
      topics: (hit.repo.topics ?? []).join(" "),
      outreach_message: githubMessage(hit, user),
    });
  }

  // ---- Reddit ----
  if (WITH_REDDIT) {
    const posts = await discoverReddit();
    posts.sort((a, b) => b.score + b.num_comments - (a.score + a.num_comments));
    for (const p of posts) {
      const key = `reddit:${p.author.toLowerCase()}`;
      if (leads.has(key)) continue;
      leads.set(key, {
        source: "reddit",
        handle: `u/${p.author}`,
        name: "",
        company: "",
        website: "",
        twitter: "",
        email: "",
        bio: "",
        account_type: "RedditUser",
        repo: "",
        repo_url: "",
        repo_stars: "",
        repo_description: "",
        stack: "",
        last_activity: new Date(p.created_utc * 1000).toISOString(),
        post_title: p.title,
        post_url: `https://www.reddit.com${p.permalink}`,
        topics: REDDIT_TOPICS.filter((t) => t.re.test(`${p.title}\n${p.selftext}`)).map((t) => t.id).join(" "),
        outreach_message: redditMessage(p),
      });
    }
  }

  const rows = [...leads.values()];
  const csv = [COLUMNS.join(","), ...rows.map((r) => COLUMNS.map((c) => csvCell(r[c])).join(","))].join("\n");
  // BOM so Excel opens the UTF-8 file correctly (quotes, ellipses, non-Latin names).
  fs.writeFileSync(OUT, `﻿${csv}\n`, "utf8");
  const gh = rows.filter((r) => r.source === "github").length;
  log(`Wrote ${rows.length} leads (${gh} GitHub, ${rows.length - gh} Reddit) to ${OUT}`);
  log("Review and personalise every message before sending; do not bulk-send.");
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
