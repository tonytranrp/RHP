'use strict';
// The runner's side of the extension, without VS Code: command lines for `--list` and runs, and the
// JSON event stream (`--reporter json`, one event per line) turned into results. Unit-tested with
// `node --test` (test/*.test.js).

/** Escapes text for use inside a regular expression. */
function escapeRegex(text) {
    return text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/**
 * Arguments that list the tests of some files: `--list -r json <files>`.
 * @param {{files: string[], root: string, extra?: string[]}} o
 */
function listArgs(o) {
    return ['--list', '--reporter', 'json', '--no-color', '--root', o.root, ...(o.extra || []), ...o.files];
}

/**
 * Arguments that run tests. `tests` (full names) narrows the run to those tests, each matched
 * exactly; `coverage` collects line coverage (it comes back in the run_end event).
 * @param {{files: string[], root: string, tests?: string[], coverage?: boolean, updateSnapshots?: boolean, extra?: string[]}} o
 */
function runArgs(o) {
    const args = ['--reporter', 'json', '--no-color', '--root', o.root];
    for (const name of o.tests || []) {
        args.push('--filter', `/^${escapeRegex(name)}$/`);
    }
    if (o.coverage) {
        args.push('--coverage', 'summary');
    }
    if (o.updateSnapshots) {
        args.push('--update-snapshots');
    }
    args.push(...(o.extra || []), ...o.files);
    return args;
}

/**
 * Splits a stream of text into complete lines; feed it chunks, it calls `onLine` for each line.
 * @param {(line: string) => void} onLine
 */
function lineSplitter(onLine) {
    let pending = '';
    return {
        push(chunk) {
            pending += chunk;
            let at;
            while ((at = pending.indexOf('\n')) >= 0) {
                const line = pending.slice(0, at).replace(/\r$/, '');
                pending = pending.slice(at + 1);
                if (line.length > 0) {
                    onLine(line);
                }
            }
        },
        end() {
            const line = pending.replace(/\r$/, '');
            pending = '';
            if (line.length > 0) {
                onLine(line);
            }
        },
    };
}

/** One JSON event, or null for a line that isn't one (a program's own output, say). */
function parseEvent(line) {
    if (!line.startsWith('{')) {
        return null;
    }
    try {
        const v = JSON.parse(line);
        return v && typeof v.event === 'string' ? v : null;
    } catch {
        return null;
    }
}

/**
 * The tests of `--list --reporter json` output: [{file, tests: [{id, name, line, tags, skipped}], errors}].
 * @param {string} text
 */
function parseList(text) {
    const files = [];
    for (const line of text.split(/\r?\n/)) {
        const e = parseEvent(line);
        if (e && e.event === 'list') {
            files.push({ file: e.file, tests: e.tests || [], errors: e.errors || [] });
        }
    }
    return files;
}

/**
 * What a test_end event says about the test, in the terms of VS Code's TestRun:
 * {state: 'passed' | 'failed' | 'errored' | 'skipped', message, location: {file, line} | null,
 *  expected, actual, duration}.
 */
function outcomeOf(e) {
    const state = { passed: 'passed', failed: 'failed', error: 'errored', pending: 'skipped', skipped: 'skipped' }[e.status] || 'errored';
    const file = e.fail_file || e.file;
    const line = e.fail_line || e.line || 0;
    let message = e.message || '';
    if (e.traceback) {
        message += `\n${e.traceback}`;
    }
    if (Array.isArray(e.notes) && e.notes.length > 0) {
        message += `\n${e.notes.map((n) => `note: ${n}`).join('\n')}`;
    }
    return {
        state,
        message,
        location: file ? { file, line } : null,
        expected: e.expected,
        actual: e.actual,
        duration: typeof e.ms === 'number' ? e.ms : undefined,
    };
}

/** A one-line summary of what a passing test cost, for the test's output. */
function costLine(e) {
    const c = e.cost || {};
    const parts = [];
    if (typeof c.instructions === 'number') {
        parts.push(`${c.instructions} instructions`);
    }
    if (typeof c.peak === 'number') {
        parts.push(`peak ${c.peak} B`);
    }
    if (typeof c.allocations === 'number') {
        parts.push(`${c.allocations} allocations`);
    }
    return `${e.name}: ${parts.join(', ')}`;
}

/**
 * Coverage of the run_end event as [{file, covered, total, lines: [{line, hits}]}].
 * @param {{coverage?: {file: string, lines: number[][]}[]}} runEnd
 */
function coverageOf(runEnd) {
    return (runEnd.coverage || []).map((f) => {
        const lines = f.lines.map(([line, hits]) => ({ line, hits }));
        return { file: f.file, covered: lines.filter((l) => l.hits > 0).length, total: lines.length, lines };
    });
}

/**
 * The program to start for a command: a path (relative to the workspace folder) as it is; a bare
 * name looked up on PATH (Windows: with PATHEXT's executable extensions, never .bat / .cmd, which
 * only a shell can run). Unresolved names come back unchanged (the spawn reports them).
 */
function resolveProgram(command, cwd, env, platform) {
    const path = require('node:path');
    const fs = require('node:fs');
    const isFile = (f) => {
        try {
            return fs.statSync(f).isFile();
        } catch {
            return false;
        }
    };
    if (command.includes('/') || command.includes('\\')) {
        return path.resolve(cwd, command);
    }
    const dirs = (env.PATH || env.Path || '').split(platform === 'win32' ? ';' : ':').filter(Boolean);
    const exts = platform === 'win32' ? ['', '.exe', '.com'] : [''];
    for (const dir of dirs) {
        for (const ext of exts) {
            const candidate = path.join(dir, command + ext);
            if ((platform !== 'win32' || /\.(exe|com)$/i.test(candidate)) && isFile(candidate)) {
                return candidate;
            }
        }
    }
    return command;
}

/** The id the runner gives a test: "<file relative to the root>::<full name>". */
function testId(file, name) {
    return `${file}::${name}`;
}

module.exports = { escapeRegex, listArgs, runArgs, lineSplitter, parseEvent, parseList, outcomeOf, costLine, coverageOf, testId, resolveProgram };
