#!/usr/bin/env node
// Refreshes docs/data/versions.json with the latest patch release of every PHP
// branch, using the official php.net releases API. Support dates and the CVE
// list are curated by hand and kept as-is. If php.net is unreachable or returns
// nothing usable, the existing file is left untouched.
import { readFile, writeFile } from 'node:fs/promises';

const FILE = new URL('../docs/data/versions.json', import.meta.url);
const MAJORS = [8, 7, 5, 4];

const cmp = (a, b) => {
  const pa = a.split('.').map(Number), pb = b.split('.').map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d;
  }
  return 0;
};

async function releasesFor(major) {
  const url = `https://www.php.net/releases/index.php?json&version=${major}&max=1000`;
  const res = await fetch(url, { headers: { 'User-Agent': 'php-exposed-versions-updater' } });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  const body = await res.json();
  return Object.keys(body).filter(v => /^\d+\.\d+\.\d+$/.test(v));
}

const data = JSON.parse(await readFile(FILE, 'utf8'));
const latest = {};
for (const major of MAJORS) {
  try {
    for (const v of await releasesFor(major)) {
      const branch = v.split('.').slice(0, 2).join('.');
      if (!latest[branch] || cmp(v, latest[branch]) > 0) latest[branch] = v;
    }
  } catch (err) {
    console.warn(`warn: ${err.message}`);
  }
}

if (!Object.keys(latest).length) {
  console.warn('No release data fetched; keeping existing versions.json');
  process.exit(0);
}

let changed = false;
for (const b of data.branches) {
  if (latest[b.branch] && cmp(latest[b.branch], b.latest) > 0) {
    console.log(`${b.branch}: ${b.latest} -> ${latest[b.branch]}`);
    b.latest = latest[b.branch];
    changed = true;
  }
}

// A new branch (e.g. 8.6) shows up here before anyone curates its dates;
// list it with unknown support dates so it at least appears on the site.
for (const [branch, v] of Object.entries(latest)) {
  if (!data.branches.some(b => b.branch === branch)) {
    console.log(`new branch ${branch} (${v}) — add support dates by hand`);
    data.branches.push({ branch, released: null, activeUntil: null, securityUntil: null, latest: v });
    changed = true;
  }
}
data.branches.sort((a, b) => cmp(b.branch, a.branch));

data.generatedAt = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
data.source = 'php.net releases API';
await writeFile(FILE, JSON.stringify(data, null, 2) + '\n');
console.log(changed ? 'versions.json updated' : 'versions.json already current (timestamp refreshed)');
if (process.env.GITHUB_OUTPUT) {
  const { appendFile } = await import('node:fs/promises');
  await appendFile(process.env.GITHUB_OUTPUT, `changed=${changed}\n`);
}
