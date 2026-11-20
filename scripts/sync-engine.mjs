import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TARGET = 'src/vendor/wide-engine';

const rootDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const rulesRoot = process.env.WIDE_RULES_DIST_DIR
  ? resolve(rootDir, process.env.WIDE_RULES_DIST_DIR, '..')
  : resolve(rootDir, '../wide-rules');
const srcDir = resolve(rulesRoot, 'engine/src');
const outDir = resolve(rootDir, TARGET);
const checkOnly = process.argv.includes('--check');

if (!existsSync(srcDir)) {
  console.error(`Missing wide-rules engine sources in ${srcDir}.`);
  process.exit(1);
}

const wanted = new Map();
for (const name of readdirSync(srcDir).filter((f) => f.endsWith('.ts')).sort()) {
  wanted.set(name, readFileSync(resolve(srcDir, name), 'utf8').replace(/\r\n/g, '\n'));
}
const present = existsSync(outDir) ? readdirSync(outDir).filter((f) => f.endsWith('.ts')) : [];

if (checkOnly) {
  const problems = [];
  for (const [name, text] of wanted) {
    const target = resolve(outDir, name);
    if (!existsSync(target)) problems.push(`missing ${name}`);
    else if (readFileSync(target, 'utf8').replace(/\r\n/g, '\n') !== text) problems.push(`stale ${name}`);
  }
  for (const name of present) if (!wanted.has(name)) problems.push(`orphan ${name}`);
  if (problems.length > 0) {
    console.error(`${TARGET} differs from wide-rules engine: ${problems.join(', ')}. Run npm run sync:engine.`);
    process.exit(1);
  }
  console.log(`${TARGET} matches wide-rules engine (${wanted.size} modules).`);
  process.exit(0);
}

mkdirSync(outDir, { recursive: true });
for (const name of present) if (!wanted.has(name)) rmSync(resolve(outDir, name));
for (const [name, text] of wanted) writeFileSync(resolve(outDir, name), text);
console.log(`Synced ${wanted.size} wide-rules engine modules into ${TARGET}.`);
