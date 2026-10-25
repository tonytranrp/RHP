'use strict';
// The protocol against a real test executable: RHP_TEST_RUNNER is its path, RHP_TEST_EXAMPLE the
// Examples/lua_tests folder (ctest sets both: vscode.protocol). Skipped without them.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { spawnSync } = require('node:child_process');
const p = require('../lib/protocol');

const runner = process.env.RHP_TEST_RUNNER;
const example = process.env.RHP_TEST_EXAMPLE;
const skip = !runner || !example ? 'RHP_TEST_RUNNER / RHP_TEST_EXAMPLE not set' : false;

function run(args) {
    const r = spawnSync(runner, args, { cwd: example, encoding: 'utf8' });
    return { status: r.status, out: r.stdout, err: r.stderr };
}

test('the listing names every test with its line', { skip }, () => {
    const r = run(p.listArgs({ files: ['tests/rules_spec.lua'], root: example, extra: ['-s', 'scripts'] }));
    assert.equal(r.status, 0, r.err);
    const files = p.parseList(r.out);
    assert.equal(files.length, 1);
    assert.equal(files[0].file, 'tests/rules_spec.lua');
    const total = files[0].tests.find((t) => t.name === 'total adds the prices of a basket');
    assert.ok(total);
    assert.equal(total.line, 5);
    assert.equal(total.id, p.testId('tests/rules_spec.lua', 'total adds the prices of a basket'));
});

test('a run of one test streams its events, with coverage', { skip }, () => {
    const name = 'checkout charges the customer';
    const r = run(p.runArgs({ files: ['tests/rules_spec.lua'], root: example, tests: [name], coverage: true, extra: ['-s', 'scripts'] }));
    assert.equal(r.status, 0, r.err);
    const events = [];
    const s = p.lineSplitter((l) => {
        const e = p.parseEvent(l);
        if (e) {
            events.push(e);
        }
    });
    s.push(r.out);
    s.end();
    const ends = events.filter((e) => e.event === 'test_end' && e.status !== 'skipped');
    assert.deepEqual(ends.map((e) => e.name), [name]);
    assert.equal(p.outcomeOf(ends[0]).state, 'passed');
    const runEnd = events.find((e) => e.event === 'run_end');
    const rules = p.coverageOf(runEnd).find((f) => f.file === path.posix.join('scripts', 'shop', 'rules.lua'));
    assert.ok(rules);
    assert.ok(rules.covered > 0 && rules.covered < rules.total);
});

test('a failure carries its place and values', { skip }, () => {
    const fs = require('node:fs');
    const os = require('node:os');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rhp-vscode-'));
    try {
        fs.writeFileSync(path.join(dir, 'x_spec.lua'), 'it("adds", function()\n  assert.equals(3, 1 + 1)\nend)\n');
        const r = spawnSync(runner, p.runArgs({ files: ['x_spec.lua'], root: dir }), { cwd: dir, encoding: 'utf8' });
        assert.equal(r.status, 1);
        const end = r.stdout.split('\n').map(p.parseEvent).find((e) => e && e.event === 'test_end');
        const o = p.outcomeOf(end);
        assert.equal(o.state, 'failed');
        assert.deepEqual(o.location, { file: 'x_spec.lua', line: 2 });
        assert.equal(o.expected, '3');
        assert.equal(o.actual, '2');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
