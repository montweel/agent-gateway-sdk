/**
 * Social lead discovery for Mont: non-technical founders, e-commerce owners and agency operators
 * talking publicly about AI agent / automation mistakes on Hacker News and Reddit.
 *
 *   npx tsx scripts/find-social-leads.ts [--days 90] [--out leads-social.csv] [--no-reddit] [--no-hn]
 *
 * - Hacker News: Algolia search API (stories + comments), no auth needed.
 * - Reddit: public search.json with a descriptive User-Agent (Reddit's API rules require one that
 *   identifies the app and a contact). Override with REDDIT_USER_AGENT.
 *
 * Output columns: Source, Date, Title, Snippet/Content, URL. Cells are neutralised against
 * spreadsheet formula injection. Every row is a conversation to read, not an address to bulk-message.
 */
import fs from "fs";
import path from "path";
import { parseArgs } from "util";

const { values: args } = parseArgs({
  options: {
    days: { type: "string", default: "90" },
    out: { type: "string", default: "leads-social.csv" },
    "no-reddit": { type: "boolean", default: false },
    "no-hn": { type: "boolean", default: false },
  },
  strict: true,
});

const DAYS = Math.max(1, Math.min(365, Number(args.days) || 90));
const OUT = path.resolve(args.out ?? "leads-social.csv");
const SINCE_MS = Date.now() - DAYS * 24 * 60 * 60_000;
const REDDIT_UA =
  process.env.REDDIT_USER_AGENT?.trim() || "MontweelSocialTracker/1.0 (contact: admin@montweel.com)";

/**
 * Owner-centric pain-point queries. `reddit` is sent as-is (Reddit search understands AND/OR and
 * quoted phrases). Algolia (HN) has no boolean operators and exact phrases there return ~nothing,
 * so `hn` holds looser keyword searches (all words must match; quotes still force a phrase).
 */
const QUERIES: Array<{ id: string; reddit: string; hn: string[] }> = [
  {
    id: "refund-discount",
    reddit: '"AI bot refunded" OR "AI gave discount"',
    hn: ["AI agent refund", "chatbot discount customer"],
  },
  {
    id: "hallucination-cost",
    reddit: '"AI agent hallucinated" AND ("money" OR "cost")',
    hn: ["AI agent mistake cost"],
  },
  {
    id: "stop-agent",
    reddit: '"how to stop AI agent from"',
    hn: [],
  },
  {
    id: "human-in-the-loop",
    reddit: '"human in the loop" AND "AI automation"',
    hn: ['"human in the loop" automation'],
  },
  {
    id: "shopify-stripe-mistake",
    reddit: '"Shopify bot mistake" OR "Stripe AI mistake"',
    hn: ["Shopify AI mistake"],
  },
];

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
const log = (...a: unknown[]): void => console.error("[find-social-leads]", ...a);

interface Lead {
  Source: "HN" | "Reddit";
  Date: string;
  Title: string;
  "Snippet/Content": string;
  URL: string;
}

function decodeEntities(s: string): string {
  return s
    .replace(/&#x([0-9a-f]+);/gi, (_, h: string) => String.fromCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d: string) => String.fromCodePoint(Number(d)))
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

function snippet(raw: string | null | undefined, max = 400): string {
  const text = decodeEntities((raw ?? "").replace(/<[^>]+>/g, " ")).replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1).replace(/\s+\S*$/, "")}…` : text;
}

async function getJson<T>(url: string, headers: Record<string, string>, label: string): Promise<T | null> {
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, { headers: { accept: "application/json", ...headers }, signal: AbortSignal.timeout(20_000) });
      if (res.status === 429) {
        const wait = Number(res.headers.get("retry-after")) || 10 * attempt;
        log(`${label}: rate limited; waiting ${wait}s`);
        await sleep(wait * 1000);
        continue;
      }
      if (!res.ok) {
        log(`${label}: HTTP ${res.status}; skipping.`);
        return null;
      }
      return (await res.json()) as T;
    } catch (err) {
      log(`${label}: network error (${attempt}/3):`, (err as Error).message);
      await sleep(2_000 * attempt);
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Hacker News (Algolia)
// ---------------------------------------------------------------------------
interface HnHit {
  objectID: string;
  created_at_i: number;
  title: string | null;
  story_title: string | null;
  story_text: string | null;
  comment_text: string | null;
  url: string | null;
  story_id: number | null;
}

async function searchHn(): Promise<Lead[]> {
  const out: Lead[] = [];
  const since = Math.floor(SINCE_MS / 1000);
  for (const q of QUERIES) {
    for (const query of q.hn) {
      for (const tag of ["story", "comment"] as const) {
        const url =
          `https://hn.algolia.com/api/v1/search_by_date?query=${encodeURIComponent(query)}` +
          `&tags=${tag}&numericFilters=${encodeURIComponent(`created_at_i>${since}`)}` +
          `&advancedSyntax=true&hitsPerPage=50`;
        const data = await getJson<{ hits: HnHit[] }>(url, {}, `HN ${tag} ${query}`);
        const hits = data?.hits ?? [];
        log(`HN ${tag} [${q.id}] ${query}: ${hits.length}`);
        for (const h of hits) {
          const isComment = tag === "comment";
          out.push({
            Source: "HN",
            Date: new Date(h.created_at_i * 1000).toISOString(),
            Title: (isComment ? h.story_title : h.title) ?? "",
            "Snippet/Content": snippet(isComment ? h.comment_text : h.story_text || h.url),
            URL: `https://news.ycombinator.com/item?id=${h.objectID}`,
          });
        }
        await sleep(500);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Reddit
// ---------------------------------------------------------------------------
interface RedditPost {
  title: string;
  selftext: string;
  permalink: string;
  created_utc: number;
  over_18: boolean;
  author: string;
}

function redditTimeWindow(): string {
  if (DAYS <= 1) return "day";
  if (DAYS <= 7) return "week";
  if (DAYS <= 31) return "month";
  return "year";
}

async function searchReddit(): Promise<Lead[]> {
  const out: Lead[] = [];
  for (const q of QUERIES) {
    const url =
      `https://www.reddit.com/search.json?q=${encodeURIComponent(q.reddit)}` +
      `&sort=new&t=${redditTimeWindow()}&limit=100&raw_json=1`;
    const data = await getJson<{ data?: { children?: Array<{ data: RedditPost }> } }>(
      url,
      { "user-agent": REDDIT_UA },
      `Reddit [${q.id}]`
    );
    const posts = (data?.data?.children ?? [])
      .map((c) => c.data)
      .filter((p) => !p.over_18 && p.created_utc * 1000 >= SINCE_MS && !["[deleted]", "AutoModerator"].includes(p.author));
    log(`Reddit [${q.id}]: ${posts.length}`);
    for (const p of posts) {
      out.push({
        Source: "Reddit",
        Date: new Date(p.created_utc * 1000).toISOString(),
        Title: p.title,
        "Snippet/Content": snippet(p.selftext),
        URL: `https://www.reddit.com${p.permalink}`,
      });
    }
    await sleep(2_500); // stay well under Reddit's unauthenticated limits
  }
  return out;
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------
const COLUMNS: (keyof Lead)[] = ["Source", "Date", "Title", "Snippet/Content", "URL"];

function csvCell(v: unknown): string {
  let s = v === null || v === undefined ? "" : String(v);
  s = s.replace(/[\r\n]+/g, " ").trim();
  // Formula-injection guard: text from the internet must never execute in Excel/Sheets.
  if (/^[=+\-@\t\r|%]/.test(s)) s = `'${s}`;
  return /[",]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

async function main(): Promise<void> {
  log(`Looking back ${DAYS} days.`);
  const all: Lead[] = [];
  if (args["no-hn"] !== true) all.push(...(await searchHn()));
  if (args["no-reddit"] !== true) all.push(...(await searchReddit()));

  const byUrl = new Map<string, Lead>();
  for (const l of all) if (!byUrl.has(l.URL)) byUrl.set(l.URL, l);
  const rows = [...byUrl.values()].sort((a, b) => b.Date.localeCompare(a.Date));

  const csv = [COLUMNS.join(","), ...rows.map((r) => COLUMNS.map((c) => csvCell(r[c])).join(","))].join("\n");
  fs.writeFileSync(OUT, `﻿${csv}\n`, "utf8");
  const hn = rows.filter((r) => r.Source === "HN").length;
  log(`Wrote ${rows.length} rows (${hn} HN, ${rows.length - hn} Reddit) to ${OUT}`);
}

main().catch((err: unknown) => {
  console.error(err);
  process.exit(1);
});
