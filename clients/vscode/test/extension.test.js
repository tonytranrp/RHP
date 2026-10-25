'use strict';
// extension.js against a stand-in for the `vscode` module and a fake runner (node + a script that
// prints the runner's JSON events): discovery, the listing, a run with a pass / a failure with a
// diff / output, and coverage.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Module = require('node:module');

const workspace = fs.mkdtempSync(path.join(os.tmpdir(), 'rhp-ext-'));
fs.mkdirSync(path.join(workspace, 'specs'));
fs.writeFileSync(path.join(workspace, 'specs', 'a_spec.lua'), '-- a spec\n');
fs.writeFileSync(path.join(workspace, 'fake_runner.js'), `
const args = process.argv.slice(2);
const out = (e) => process.stdout.write(JSON.stringify(e) + '\\n');
if (args.includes('--list')) {
    out({ event: 'list', file: 'specs/a_spec.lua', errors: [], tests: [
        { id: 'specs/a_spec.lua::d passes', name: 'd passes', line: 2, tags: [], skipped: false },
        { id: 'specs/a_spec.lua::d fails', name: 'd fails', line: 5, tags: [], skipped: false } ] });
    process.exit(0);
}
const filtered = args.includes('--filter');
out({ event: 'run_start', seed: 1, files: 1 });
out({ event: 'test_start', id: 'specs/a_spec.lua::d passes', file: 'specs/a_spec.lua', name: 'd passes' });
out({ event: 'test_end', file: 'specs/a_spec.lua', name: 'd passes', line: 2, status: 'passed', message: '', ms: 1,
      output: ['hello'], cost: { instructions: 10, peak: 64, allocations: 1 } });
if (!filtered) {
    out({ event: 'test_start', id: 'specs/a_spec.lua::d fails', file: 'specs/a_spec.lua', name: 'd fails' });
    out({ event: 'test_end', file: 'specs/a_spec.lua', name: 'd fails', line: 5, status: 'failed', message: 'Expected objects to be equal.',
          fail_file: 'specs/a_spec.lua', fail_line: 6, traceback: '', ms: 1, expected: '8', actual: '7', output: [] });
}
out({ event: 'file_end', file: 'specs/a_spec.lua', ms: 2, errors: [] });
out({ event: 'run_end', passed: 1, failed: filtered ? 0 : 1, coverage: args.includes('--coverage') ? [{ file: 'scripts/m.lua', lines: [[1, 1], [2, 0]] }] : [] });
process.exit(filtered ? 0 : 1);
`);

// ---- a stand-in for the parts of the vscode API the extension uses ----
const calls = [];
class Uri {
    constructor(fsPath) { this.fsPath = fsPath; }
    static file(p) { return new Uri(p); }
    toString() { return `file://${this.fsPath}`; }
}
class Collection {
    constructor() { this.map = new Map(); }
    add(i) { this.map.set(i.id, i); }
    delete(id) { this.map.delete(id); }
    get(id) { return this.map.get(id); }
    forEach(f) { [...this.map.values()].forEach(f); }
    get size() { return this.map.size; }
}
const profiles = {};
const vscode = {
    Uri,
    Range: class { constructor(l) { this.line = l; } },
    Position: class { constructor(l, c) { this.line = l; this.character = c; } },
    Location: class { constructor(uri, pos) { this.uri = uri; this.pos = pos; } },
    RelativePattern: class { constructor(base, pattern) { this.base = base; this.pattern = pattern; } },
    MarkdownString: class { constructor(v) { this.value = v; } },
    TestMessage: class {
        constructor(m) { this.message = m; }
        static diff(m, e, a) { const t = new vscode.TestMessage(m); t.expectedOutput = e; t.actualOutput = a; return t; }
    },
    TestRunProfileKind: { Run: 1, Debug: 2, Coverage: 3 },
    FileCoverage: class { constructor(uri, count) { this.uri = uri; this.count = count; } },
    TestCoverageCount: class { constructor(c, t) { this.covered = c; this.total = t; } },
    StatementCoverage: class { constructor(h, p) { this.executed = h; this.location = p; } },
    TestRunRequest: class { constructor(include, exclude) { this.include = include; this.exclude = exclude; } },
    CancellationTokenSource: class { constructor() { this.token = { isCancellationRequested: false, onCancellationRequested() {} }; } },
    workspace: {
        workspaceFolders: [{ uri: new Uri(workspace), name: 'w', index: 0 }],
        getConfiguration: () => ({
            get: (key, d) => ({ command: [process.execPath, path.join(workspace, 'fake_runner.js')] }[key] ?? d),
        }),
        findFiles: async () => [new Uri(path.join(workspace, 'specs', 'a_spec.lua'))],
        createFileSystemWatcher: () => ({ onDidCreate() {}, onDidChange() {}, onDidDelete() {}, dispose() {} }),
    },
    commands: { registerCommand: () => ({ dispose() {} }) },
    tests: {
        createTestController: () => {
            const ctrl = {
                items: new Collection(),
                createTestItem: (id, label, uri) => ({ id, label, uri, children: new Collection() }),
                createRunProfile: (label, kind, handler) => { profiles[label] = { handler }; return profiles[label]; },
                createTestRun: () => {
                    const r = {};
                    for (const m of ['enqueued', 'started', 'passed', 'failed', 'errored', 'skipped', 'appendOutput', 'addCoverage', 'end']) {
                        r[m] = (...a) => calls.push([m, ...a]);
                    }
                    return r;
                },
                dispose() {},
            };
            return ctrl;
        },
    },
};
const load = Module._load;
Module._load = function (request, ...rest) {
    return request === 'vscode' ? vscode : load.call(this, request, ...rest);
};
const extension = require('../extension');

test('lists, runs and covers', async () => {
    const context = { subscriptions: [] };
    extension.activate(context);
    const ctrl = context.subscriptions[0];
    await ctrl.resolveHandler(undefined);
    assert.equal(ctrl.items.size, 1);
    const file = [...ctrl.items.map.values()][0];
    assert.equal(file.rel, 'specs/a_spec.lua');
    await ctrl.resolveHandler(file);
    assert.deepEqual([...file.children.map.keys()], ['specs/a_spec.lua::d passes', 'specs/a_spec.lua::d fails']);
    assert.equal(file.children.get('specs/a_spec.lua::d fails').range.line, 4);

    const token = { isCancellationRequested: false, onCancellationRequested() {} };
    await profiles.Run.handler(new vscode.TestRunRequest(), token);
    const passed = calls.find((c) => c[0] === 'passed');
    assert.equal(passed[1].id, 'specs/a_spec.lua::d passes');
    const failed = calls.find((c) => c[0] === 'failed');
    assert.equal(failed[2].expectedOutput, '8');
    assert.equal(failed[2].actualOutput, '7');
    assert.equal(failed[2].location.pos.line, 5);
    assert.ok(calls.some((c) => c[0] === 'appendOutput' && c[1] === 'hello\r\n'));
    assert.ok(!calls.some((c) => c[0] === 'errored'));

    calls.length = 0;
    const one = file.children.get('specs/a_spec.lua::d passes');
    await profiles.Coverage.handler(new vscode.TestRunRequest([one]), token);
    assert.equal(calls.filter((c) => c[0] === 'passed').length, 1);
    assert.ok(!calls.some((c) => c[0] === 'failed'));
    const cov = calls.find((c) => c[0] === 'addCoverage')[1];
    assert.equal(cov.count.covered, 1);
    assert.equal(cov.count.total, 2);
    const lines = await profiles.Coverage.loadDetailedCoverage(null, cov);
    assert.deepEqual(lines.map((l) => [l.location.line, l.executed]), [[0, 1], [1, 0]]);
});

test.after(() => fs.rmSync(workspace, { recursive: true, force: true }));
