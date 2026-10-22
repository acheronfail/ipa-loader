import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { afterEach, test } from "node:test";

const root = new URL("../", import.meta.url).pathname;
const directories = [];
afterEach(() => {
  for (const path of directories.splice(0))
    rmSync(path, { recursive: true, force: true });
});
const fakeTool = `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const tool = path.basename(process.argv[1]);
const args = process.argv.slice(2);
const op = args.slice(0, 2).join(' ');
const log = (value) => fs.appendFileSync(process.env.FAKE_LOG, JSON.stringify(value) + '\\n');
log({ tool, args, operation: tool === 'xcrun' ? op : args[0], passwordInEnvironment: !!process.env.APPLE_NOTARY_PASSWORD });
if (tool === 'codesign') process.exit(process.env.FAKE_SIGNATURE_FAILURE ? 1 : 0);
if (tool === 'xcrun') {
  if (op === 'notarytool store-credentials') process.exit(0);
  if (op === 'notarytool submit') {
    if (process.env.FAKE_STATUS === 'malformed') { console.log('bad json'); process.exit(1); }
    console.log(JSON.stringify({ id: process.env.FAKE_SUBMISSION_ID || '12345678-1234-1234-1234-123456789012', status: process.env.FAKE_STATUS }));
    process.exit(process.env.FAKE_SUBMIT_FAILURE || process.env.FAKE_STATUS === 'In Progress' ? 69 : 0);
  }
  if (op === 'notarytool log') {
    fs.writeFileSync(args[args.length - 1], JSON.stringify({ issues: [{ code: 4000, message: 'Rejected test signature' }] }));
    process.exit(0);
  }
  if (op === 'stapler staple') {
    if (process.env.FAKE_STAPLE_FAILURE) process.exit(1);
    const counter = path.join(process.env.RUNNER_TEMP, 'staple-attempts');
    const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) + 1 : 1;
    fs.writeFileSync(counter, String(attempt));
    if (attempt <= Number(process.env.FAKE_STAPLE_LOOKUP_FAILURES || 0)) process.exit(68);
    fs.writeFileSync(path.join(args[2], '.ticket'), 'ticket');
    process.exit(0);
  }
  if (op === 'stapler validate') {
    if (process.env.FAKE_VALIDATE_FAILURE) process.exit(65);
    const counter = path.join(process.env.RUNNER_TEMP, 'validate-attempts');
    const attempt = fs.existsSync(counter) ? Number(fs.readFileSync(counter, 'utf8')) + 1 : 1;
    fs.writeFileSync(counter, String(attempt));
    if (attempt <= Number(process.env.FAKE_VALIDATE_LOOKUP_FAILURES || 0)) process.exit(68);
    process.exit(fs.existsSync(path.join(args[2], '.ticket')) ? 0 : 1);
  }
}
if (tool === 'ditto') {
  const source = args[args.length - 2];
  fs.writeFileSync(args[args.length - 1], fs.existsSync(path.join(source, '.ticket')) ? 'archive-with-ticket' : 'archive-without-ticket');
  process.exit(0);
}
if (tool === 'spctl') process.exit(process.env.FAKE_GATEKEEPER_FAILURE ? 1 : 0);
if (tool === 'unzip') process.exit(process.env.FAKE_ARCHIVE_FAILURE ? 1 : 0);
if (tool === 'sleep') process.exit(0);
if (tool === 'security') {
  if (args[0] === 'import' && fs.readFileSync(args[1], 'utf8') !== 'test') process.exit(1);
  if (args[0] === 'list-keychains' && args.length === 3) console.log('  "/tmp/original.keychain-db"');
  if (args[0] === 'find-identity') console.log('  1) AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "' + process.env.FAKE_IDENTITY + '"');
  process.exit(0);
}
if (tool === 'probe') {
  console.log(JSON.stringify({ identity: process.env.CODE_SIGN_IDENTITY, hasKeychain: !!process.env.CODE_SIGN_KEYCHAIN,
    leakedCertificateSecret: !!process.env.APPLE_CODE_SIGN_P12_BASE64 || !!process.env.APPLE_CODE_SIGN_P12_PASSWORD }));
  process.exit(0);
}
throw new Error('Unexpected fake tool invocation: ' + tool + ' ' + op);
`;
function fixture() {
  const path = mkdtempSync(join(tmpdir(), "ipa-loader-notary-test-"));
  directories.push(path);
  const bin = join(path, "bin");
  mkdirSync(bin);
  for (const name of [
    "xcrun",
    "codesign",
    "ditto",
    "spctl",
    "unzip",
    "security",
    "probe",
    "sleep",
  ]) {
    const file = join(bin, name);
    writeFileSync(file, fakeTool);
    chmodSync(file, 0o755);
  }
  const app = join(path, "IPA Loader.app");
  mkdirSync(app);
  const output = join(path, "IPA-Loader.zip");
  writeFileSync(output, "previous-successful-download");
  const log = join(path, "operations.jsonl");
  const env = {
    ...process.env,
    PATH: bin + delimiter + process.env.PATH,
    RUNNER_TEMP: path,
    APPLE_TEAM_ID: "TESTTEAM01",
    GITHUB_ACTIONS: "false",
    FAKE_LOG: log,
    FAKE_STATUS: "Accepted",
  };
  const operations = () =>
    existsSync(log)
      ? readFileSync(log, "utf8")
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line))
      : [];
  return { path, app, output, env, operations };
}
function runNotary(item, extra = {}) {
  return spawnSync(
    "bash",
    [
      join(root, "app/scripts/notarize-macos-release.sh"),
      item.app,
      item.output,
    ],
    {
      env: { ...item.env, ...extra },
      encoding: "utf8",
      timeout: 10_000,
    },
  );
}

test("notarization staples before rebuilding the downloadable ZIP", () => {
  const item = fixture();
  const result = runNotary(item);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, "utf8"), "archive-with-ticket");
  const operations = item.operations().map((x) => `${x.tool} ${x.operation}`);
  assert.ok(
    operations.indexOf("xcrun stapler validate") <
      operations.indexOf("spctl --assess"),
  );
  assert.equal(operations.filter((x) => x === "ditto -c").length, 2);
  assert.equal(
    item
      .operations()
      .some((x) => x.operation === "notarytool store-credentials"),
    false,
  );
});
for (const status of ["Invalid", "Rejected", "In Progress", "malformed"]) {
  test(`notarization ${status} preserves the previous download and never staples`, () => {
    const item = fixture();
    const result = runNotary(item, { FAKE_STATUS: status });
    assert.notEqual(result.status, 0);
    assert.equal(
      readFileSync(item.output, "utf8"),
      "previous-successful-download",
    );
    assert.equal(
      item.operations().some((x) => x.operation === "stapler staple"),
      false,
    );
  });
}
test("stapling failure does not replace the previous download", () => {
  const item = fixture();
  assert.notEqual(runNotary(item, { FAKE_STAPLE_FAILURE: "1" }).status, 0);
  assert.equal(
    readFileSync(item.output, "utf8"),
    "previous-successful-download",
  );
  assert.equal(item.operations().filter(x => x.operation === "stapler staple").length, 1);
  assert.equal(item.operations().some(x => x.tool === "sleep"), false);
});
test("transient ticket lookup failures retry stapling without resubmitting", () => {
  const item = fixture();
  const result = runNotary(item, { FAKE_STAPLE_LOOKUP_FAILURES: "2" });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(readFileSync(item.output, "utf8"), "archive-with-ticket");
  const calls = item.operations();
  assert.equal(calls.filter(x => x.operation === "stapler staple").length, 3);
  assert.equal(calls.filter(x => x.operation === "notarytool submit").length, 1);
  assert.deepEqual(calls.filter(x => x.tool === "sleep").map(x => x.operation), ["5", "10"]);
});
test("persistent ticket lookup failure stops after four attempts and preserves the download", () => {
  const item = fixture();
  const result = runNotary(item, { FAKE_STAPLE_LOOKUP_FAILURES: "4" });
  assert.equal(result.status, 68, result.stderr);
  assert.equal(readFileSync(item.output, "utf8"), "previous-successful-download");
  const calls = item.operations();
  assert.equal(calls.filter(x => x.operation === "stapler staple").length, 4);
  assert.deepEqual(calls.filter(x => x.tool === "sleep").map(x => x.operation), ["5", "10", "15"]);
  assert.equal(calls.some(x => x.operation === "stapler validate"), false);
  assert.equal(calls.some(x => x.tool === "spctl"), false);
  assert.equal(calls.filter(x => x.tool === "ditto").length, 1);
});
for (const [failures, expectedStatus, attempts] of [["2", 0, 3], ["4", 68, 4]]) {
  test(`validation lookup failures ${expectedStatus === 0 ? "recover" : "stop after four attempts"}`, () => {
    const item = fixture();
    const result = runNotary(item, { FAKE_VALIDATE_LOOKUP_FAILURES: failures });
    assert.equal(result.status, expectedStatus, result.stderr);
    const calls = item.operations();
    assert.equal(calls.filter(x => x.operation === "stapler validate").length, attempts);
    assert.equal(calls.filter(x => x.operation === "stapler staple").length, 1);
    assert.equal(calls.filter(x => x.operation === "notarytool submit").length, 1);
    assert.equal(calls.some(x => x.tool === "spctl"), expectedStatus === 0);
    assert.equal(readFileSync(item.output, "utf8"), expectedStatus === 0 ? "archive-with-ticket" : "previous-successful-download");
    assert.deepEqual(calls.filter(x => x.tool === "sleep").map(x => x.operation), expectedStatus === 0 ? ["5", "10"] : ["5", "10", "15"]);
  });
}
test("invalid ticket validation fails immediately and preserves the download", () => {
  const item = fixture();
  assert.equal(runNotary(item, { FAKE_VALIDATE_FAILURE: "1" }).status, 65);
  assert.equal(readFileSync(item.output, "utf8"), "previous-successful-download");
  assert.equal(item.operations().filter(x => x.operation === "stapler validate").length, 1);
  assert.equal(item.operations().some(x => x.tool === "sleep" || x.tool === "spctl"), false);
});
test("invalid signing identity fails before submission", () => {
  const item = fixture();
  assert.notEqual(runNotary(item, { FAKE_SIGNATURE_FAILURE: "1" }).status, 0);
  assert.equal(
    item.operations().some((x) => x.operation === "notarytool submit"),
    false,
  );
});
test("Gatekeeper failure preserves the previous download after stapling", () => {
  const item = fixture();
  assert.notEqual(runNotary(item, { FAKE_GATEKEEPER_FAILURE: "1" }).status, 0);
  assert.equal(
    readFileSync(item.output, "utf8"),
    "previous-successful-download",
  );
  assert.equal(item.operations().filter((x) => x.tool === "ditto").length, 1);
});
test("CI stores notarization credentials only in its disposable keychain", () => {
  const item = fixture();
  const result = runNotary(item, {
    GITHUB_ACTIONS: "true",
    CODE_SIGN_KEYCHAIN: join(item.path, "temporary.keychain-db"),
    APPLE_NOTARY_APPLE_ID: "test@example.invalid",
    APPLE_NOTARY_PASSWORD: "secret-sentinel",
  });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  assert.equal(
    calls.find((x) => x.operation === "notarytool store-credentials")
      .passwordInEnvironment,
    true,
  );
  assert.equal(
    calls.find((x) => x.operation === "notarytool submit")
      .passwordInEnvironment,
    false,
  );
  assert.doesNotMatch(result.stdout + result.stderr, /secret-sentinel/);
});
for (const [identity, accepted] of [
  ["Developer ID Application: Test Person (TESTTEAM01)", true],
  ["Developer ID Application: Other Person (OTHERTEAM1)", false],
  ["IPA Loader Self Signed", false],
  ["Apple Distribution: Test Person (TESTTEAM01)", false],
]) {
  test(`CI import ${accepted ? "accepts selected team" : "rejects"}: ${identity}`, () => {
    const item = fixture();
    const result = spawnSync(
      "bash",
      [join(root, "app/scripts/with-apple-signing-identity.sh"), "probe"],
      {
        env: {
          ...item.env,
          GITHUB_ACTIONS: "true",
          RUNNER_ENVIRONMENT: "github-hosted",
          RUNNER_OS: "macOS",
          APPLE_CODE_SIGN_P12_BASE64: "dGVzdA==",
          APPLE_CODE_SIGN_P12_PASSWORD: "certificate-secret",
          FAKE_IDENTITY: identity,
        },
        encoding: "utf8",
        timeout: 10_000,
      },
    );
    assert.equal(result.status === 0, accepted, result.stderr);
    assert.equal(
      item.operations().some((x) => x.operation === "add-trusted-cert"),
      false,
    );
    assert.equal(
      item.operations().some((x) => x.operation === "delete-keychain"),
      true,
    );
    if (accepted)
      assert.deepEqual(JSON.parse(result.stdout), {
        identity: "A".repeat(40),
        hasKeychain: true,
        leakedCertificateSecret: false,
      });
  });
}
test("CI import refuses a developer workstation", () => {
  const item = fixture();
  const result = spawnSync(
    "bash",
    [join(root, "app/scripts/with-apple-signing-identity.sh"), "probe"],
    {
      env: item.env,
      encoding: "utf8",
      timeout: 10_000,
    },
  );
  assert.notEqual(result.status, 0);
  assert.deepEqual(item.operations(), []);
});

test("CI import rejects malformed base64 before importing a certificate", () => {
  const item = fixture();
  const result = spawnSync(
    "bash",
    [join(root, "app/scripts/with-apple-signing-identity.sh"), "probe"],
    {
      env: {
        ...item.env,
        GITHUB_ACTIONS: "true",
        RUNNER_ENVIRONMENT: "github-hosted",
        RUNNER_OS: "macOS",
        APPLE_CODE_SIGN_P12_BASE64: "!!!!",
        APPLE_CODE_SIGN_P12_PASSWORD: "certificate-secret",
      },
      encoding: "utf8",
      timeout: 10_000,
    },
  );
  assert.notEqual(result.status, 0);
  assert.equal(item.operations().some((x) => x.operation === "import"), false);
});

for (const extra of [
  { FAKE_SUBMIT_FAILURE: "1" },
  { FAKE_SUBMISSION_ID: "not-a-submission-id" },
  { FAKE_STATUS: "Unknown" },
  { FAKE_ARCHIVE_FAILURE: "1" },
]) {
  test(`failed submission or archive verification preserves output: ${JSON.stringify(extra)}`, () => {
    const item = fixture();
    const result = runNotary(item, extra);
    assert.notEqual(result.status, 0);
    assert.equal(readFileSync(item.output, "utf8"), "previous-successful-download");
    if (!extra.FAKE_ARCHIVE_FAILURE)
      assert.equal(item.operations().some(x => x.operation === "stapler staple"), false);
  });
}

test("release signs with hardened runtime and timestamp before notarizing", () => {
  const item = fixture();
  const bin = join(item.app, "Contents", "MacOS");
  mkdirSync(bin, { recursive: true });
  const executable = join(bin, "ipa-loader");
  writeFileSync(executable, '#!/bin/sh\n[ "$1" = --check-runtime ]\n');
  chmodSync(executable, 0o755);
  const result = spawnSync("bash", [join(root, "app/scripts/sign-and-notarize-macos.sh"), item.app, item.output], {
    env: { ...item.env, CODE_SIGN_IDENTITY: "A".repeat(40), CODE_SIGN_KEYCHAIN: join(item.path, "temporary.keychain-db") },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  const calls = item.operations();
  const signing = calls.find(x => x.tool === "codesign" && x.operation === "--force");
  assert.ok(signing.args.includes("--timestamp"));
  assert.ok(signing.args.includes("runtime"));
  assert.ok(signing.args.includes("--keychain"));
  assert.equal(signing.args.includes("--deep"), false);
  assert.ok(calls.indexOf(signing) < calls.findIndex(x => x.operation === "notarytool submit"));
  assert.equal(readFileSync(item.output, "utf8"), "archive-with-ticket");
});

test("CI deletes its signing keychain when the wrapped command fails", () => {
  const item = fixture();
  const result = spawnSync("bash", [join(root, "app/scripts/with-apple-signing-identity.sh"), "bash", "-c", "exit 42"], {
    env: { ...item.env, GITHUB_ACTIONS: "true", RUNNER_ENVIRONMENT: "github-hosted", RUNNER_OS: "macOS",
      APPLE_CODE_SIGN_P12_BASE64: "dGVzdA==", APPLE_CODE_SIGN_P12_PASSWORD: "certificate-secret",
      FAKE_IDENTITY: "Developer ID Application: Person (TESTTEAM01)" },
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 42, result.stderr);
  assert.ok(item.operations().some(x => x.operation === "delete-keychain"));
  assert.ok(item.operations().some(x => x.operation === "list-keychains" && x.args.includes("/tmp/original.keychain-db") && x.args.length === 5));
});
