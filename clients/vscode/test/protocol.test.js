'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const p = require('../lib/protocol');

test('regex escaping keeps names literal', () => {
    const name = 'combat (ok) costs 1.5 [x] a/b #fast';
    const re = new RegExp(`^${p.escapeRegex(name)}$`);
    assert.ok(re.test(name));
    assert.ok(!re.test('combat (ok) costs 105 [x] a/b #fast'));
});

test('list and run command lines', () => {
    assert.deepEqual(p.listArgs({ files: ['a_spec.lua'], root: '/w', extra: ['-s', 'scripts'] }), [
        '--list', '--reporter', 'json', '--no-color', '--root', '/w', '-s', 'scripts', 'a_spec.lua',
    ]);
    assert.deepEqual(p.runArgs({ files: ['a_spec.lua'], root: '/w', tests: ['d it (ok)'], coverage: true, updateSnapshots: true }), [
        '--reporter', 'json', '--no-color', '--root', '/w', '--filter', '/^d it \\(ok\\)$/', '--coverage', 'summary', '--update-snapshots', 'a_spec.lua',
    ]);
});

test('lines come whole whatever the chunks', () => {
    const lines = [];
    const s = p.lineSplitter((l) => lines.push(l));
    s.push('{"a":1}\r\n{"b"');
    s.push(':2}\n\n');
    s.push('{"c":3}');
    s.end();
    assert.deepEqual(lines, ['{"a":1}', '{"b":2}', '{"c":3}']);
});

test('events are recognized, other output is not', () => {
    assert.deepEqual(p.parseEvent('{"event":"run_start","seed":1,"files":2}'), { event: 'run_start', seed: 1, files: 2 });
    assert.equal(p.parseEvent('hello from print'), null);
    assert.equal(p.parseEvent('{"no":"event"}'), null);
    assert.equal(p.parseEvent('{broken'), null);
});

test('a listing gives files and tests', () => {
    const text = [
        '{"event":"list","file":"specs/a_spec.lua","tests":[{"id":"specs/a_spec.lua::d one","name":"d one","line":3,"tags":[],"skipped":false}],"errors":[]}',
        '{"event":"list","file":"specs/b_spec.lua","tests":[],"errors":["the test file failed to load: x"]}',
    ].join('\n');
    const files = p.parseList(text);
    assert.equal(files.length, 2);
    assert.equal(files[0].tests[0].line, 3);
    assert.deepEqual(files[1].errors, ['the test file failed to load: x']);
});

test('test_end events become outcomes', () => {
    const failed = p.outcomeOf({
        event: 'test_end', file: 'specs/a_spec.lua', name: 'd one', line: 3, status: 'failed', message: 'Expected objects to be equal.',
        fail_file: 'specs/a_spec.lua', fail_line: 7, traceback: 'specs/a_spec.lua:7: in function', ms: 0.5, expected: '8', actual: '7', notes: ['slow'],
    });
    assert.equal(failed.state, 'failed');
    assert.deepEqual(failed.location, { file: 'specs/a_spec.lua', line: 7 });
    assert.equal(failed.expected, '8');
    assert.match(failed.message, /in function\nnote: slow$/);
    assert.equal(p.outcomeOf({ status: 'error', file: 'f', line: 2 }).state, 'errored');
    assert.equal(p.outcomeOf({ status: 'pending', file: 'f', line: 2 }).state, 'skipped');
    assert.deepEqual(p.outcomeOf({ status: 'passed', file: 'f', line: 2 }).location, { file: 'f', line: 2 });
});

test('coverage of run_end', () => {
    const cov = p.coverageOf({ coverage: [{ file: 'scripts/game/combat.lua', lines: [[2, 1], [5, 0], [7, 3]] }] });
    assert.deepEqual(cov, [{ file: 'scripts/game/combat.lua', covered: 2, total: 3, lines: [{ line: 2, hits: 1 }, { line: 5, hits: 0 }, { line: 7, hits: 3 }] }]);
    assert.deepEqual(p.coverageOf({}), []);
});

test('ids and cost lines', () => {
    assert.equal(p.testId('specs/a_spec.lua', 'd one'), 'specs/a_spec.lua::d one');
    assert.equal(p.costLine({ name: 't', cost: { instructions: 10, peak: 64, allocations: 2 } }), 't: 10 instructions, peak 64 B, 2 allocations');
});
