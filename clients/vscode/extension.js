'use strict';
// RHP Lua tests in VS Code's Test Explorer: lists the tests of every spec file (runner --list), runs
// them (one runner process per file), shows failures where they happened with expected / actual
// diffs, the output scripts printed, what each test cost, and line coverage.
const vscode = require('vscode');
const cp = require('node:child_process');
const path = require('node:path');
const p = require('./lib/protocol');

/** @type {vscode.TestController} */
let ctrl;
/** test id ("<file>::<name>") or file key ("<folder>|<file>") -> item */
const items = new Map();
/** FileCoverage -> its lines, for the detailed view */
const details = new WeakMap();

function config(folder) {
    const c = vscode.workspace.getConfiguration('rhpTests', folder.uri);
    return {
        command: c.get('command', ['rhp-cli', 'test']),
        args: c.get('args', []),
        include: c.get('include', '**/{*_spec,*.spec,*_test,test_*}.lua'),
        exclude: c.get('exclude', '**/{node_modules,build,out,.git}/**'),
    };
}

function relative(folder, uri) {
    return path.relative(folder.uri.fsPath, uri.fsPath).split(path.sep).join('/');
}

function fileItem(folder, uri) {
    const rel = relative(folder, uri);
    const key = `${folder.uri.toString()}|${rel}`;
    let item = items.get(key);
    if (!item) {
        item = ctrl.createTestItem(key, rel, uri);
        item.canResolveChildren = true;
        item.folder = folder;
        item.rel = rel;
        items.set(key, item);
        ctrl.items.add(item);
    }
    return item;
}

function testItem(file, name, line) {
    const id = p.testId(file.rel, name);
    let item = items.get(id);
    if (!item) {
        item = ctrl.createTestItem(id, name, file.uri);
        item.testName = name;
        item.file = file;
        items.set(id, item);
        file.children.add(item);
    }
    if (line > 0) {
        item.range = new vscode.Range(line - 1, 0, line - 1, 0);
    }
    return item;
}

// Runs the runner; resolves with its exit status, calling onLine for every line it prints.
function spawn(folder, args, onLine, token) {
    const c = config(folder);
    const [program, ...lead] = c.command;
    return new Promise((resolve) => {
        const child = cp.spawn(program, [...lead, ...args], { cwd: folder.uri.fsPath, shell: process.platform === 'win32' && !program.includes('\\') && !program.includes('/') });
        const out = p.lineSplitter(onLine);
        let err = '';
        child.stdout.setEncoding('utf8');
        child.stderr.setEncoding('utf8');
        child.stdout.on('data', (d) => out.push(d));
        child.stderr.on('data', (d) => { err += d; });
        child.on('error', (e) => resolve({ status: -1, err: String(e) }));
        child.on('close', (status) => {
            out.end();
            resolve({ status, err });
        });
        if (token) {
            token.onCancellationRequested(() => child.kill());
        }
    });
}

async function listFile(item) {
    const folder = item.folder;
    const c = config(folder);
    let text = '';
    const r = await spawn(folder, p.listArgs({ files: [item.rel], root: folder.uri.fsPath, extra: c.args }), (l) => { text += `${l}\n`; });
    const files = p.parseList(text);
    item.error = undefined;
    if (r.status !== 0 && files.length === 0) {
        item.error = new vscode.MarkdownString(`The runner failed: \`${c.command.join(' ')}\`\n\n${r.err}`);
        return;
    }
    const seen = new Set();
    for (const f of files) {
        if (f.errors.length > 0) {
            item.error = f.errors.join('\n');
        }
        for (const t of f.tests) {
            seen.add(testItem(item, t.name, t.line).id);
        }
    }
    item.children.forEach((child) => {
        if (!seen.has(child.id)) {
            item.children.delete(child.id);
            items.delete(child.id);
        }
    });
}

async function discover() {
    for (const folder of vscode.workspace.workspaceFolders || []) {
        const c = config(folder);
        const uris = await vscode.workspace.findFiles(new vscode.RelativePattern(folder, c.include), new vscode.RelativePattern(folder, c.exclude));
        for (const uri of uris) {
            fileItem(folder, uri);
        }
    }
}

function watch(context) {
    for (const folder of vscode.workspace.workspaceFolders || []) {
        const w = vscode.workspace.createFileSystemWatcher(new vscode.RelativePattern(folder, config(folder).include));
        w.onDidCreate((uri) => listFile(fileItem(folder, uri)));
        w.onDidChange((uri) => listFile(fileItem(folder, uri)));
        w.onDidDelete((uri) => {
            const key = `${folder.uri.toString()}|${relative(folder, uri)}`;
            ctrl.items.delete(key);
            items.delete(key);
        });
        context.subscriptions.push(w);
    }
}

// Groups a request into one runner call per file: a whole file, or some of its tests.
function plan(request) {
    const files = new Map(); // file item -> null (all) | Set(names)
    const add = (item) => {
        if (request.exclude && request.exclude.includes(item)) {
            return;
        }
        if (item.file) {
            const set = files.get(item.file);
            if (set !== null) {
                files.set(item.file, (set || new Set()).add(item.testName));
            }
        } else {
            files.set(item, null);
        }
    };
    if (request.include) {
        request.include.forEach(add);
    } else {
        ctrl.items.forEach(add);
    }
    return files;
}

async function run(request, token, coverage, updateSnapshots) {
    const testRun = ctrl.createTestRun(request);
    const files = plan(request);
    for (const [file, names] of files) {
        if (token.isCancellationRequested) {
            break;
        }
        const folder = file.folder;
        const c = config(folder);
        const root = folder.uri.fsPath;
        const at = (rel, line) => new vscode.Location(vscode.Uri.file(path.join(root, rel)), new vscode.Position(Math.max(line - 1, 0), 0));
        file.children.forEach((t) => {
            if (!names || names.has(t.testName)) {
                testRun.enqueued(t);
            }
        });
        const args = p.runArgs({ files: [file.rel], root, tests: names ? [...names] : [], coverage, updateSnapshots, extra: c.args });
        const r = await spawn(folder, args, (line) => {
            const e = p.parseEvent(line);
            if (!e) {
                testRun.appendOutput(`${line}\r\n`);
                return;
            }
            if (e.event === 'test_start') {
                testRun.started(testItem(file, e.name, 0));
            } else if (e.event === 'test_end') {
                const item = testItem(file, e.name, e.line);
                const o = p.outcomeOf(e);
                for (const out of e.output || []) {
                    testRun.appendOutput(`${out}\r\n`, at(e.file, e.line), item);
                }
                if (o.state === 'passed') {
                    testRun.appendOutput(`${p.costLine(e)}\r\n`, undefined, item);
                    testRun.passed(item, o.duration);
                } else if (o.state === 'skipped') {
                    testRun.skipped(item);
                } else {
                    const message = o.expected !== undefined && o.actual !== undefined
                        ? vscode.TestMessage.diff(o.message, o.expected, o.actual)
                        : new vscode.TestMessage(o.message);
                    if (o.location) {
                        message.location = at(o.location.file, o.location.line);
                    }
                    if (o.state === 'failed') {
                        testRun.failed(item, message, o.duration);
                    } else {
                        testRun.errored(item, message, o.duration);
                    }
                }
            } else if (e.event === 'file_end' && e.errors.length > 0) {
                for (const err of e.errors) {
                    const m = new vscode.TestMessage(`${err.message}\n${err.traceback || ''}`);
                    m.location = at(err.file || file.rel, err.line || 1);
                    testRun.errored(file, m);
                }
            } else if (e.event === 'run_end' && coverage) {
                for (const f of p.coverageOf(e)) {
                    const fc = new vscode.FileCoverage(vscode.Uri.file(path.join(root, f.file)), new vscode.TestCoverageCount(f.covered, f.total));
                    details.set(fc, f.lines);
                    testRun.addCoverage(fc);
                }
            }
        }, token);
        if (r.status !== 0 && r.status !== 1) {
            testRun.errored(file, new vscode.TestMessage(`The runner failed (${r.status}): ${c.command.join(' ')}\n${r.err}`));
        }
    }
    testRun.end();
}

function activate(context) {
    ctrl = vscode.tests.createTestController('rhpLuaTests', 'RHP Lua tests');
    context.subscriptions.push(ctrl);
    ctrl.resolveHandler = async (item) => {
        if (!item) {
            await discover();
        } else {
            await listFile(item);
        }
    };
    ctrl.refreshHandler = async () => {
        await discover();
        const all = [];
        ctrl.items.forEach((i) => all.push(listFile(i)));
        await Promise.all(all);
    };
    ctrl.createRunProfile('Run', vscode.TestRunProfileKind.Run, (req, token) => run(req, token, false, false), true);
    const cov = ctrl.createRunProfile('Coverage', vscode.TestRunProfileKind.Coverage, (req, token) => run(req, token, true, false), true);
    cov.loadDetailedCoverage = async (_run, fileCoverage) =>
        (details.get(fileCoverage) || []).map((l) => new vscode.StatementCoverage(l.hits, new vscode.Position(l.line - 1, 0)));
    context.subscriptions.push(vscode.commands.registerCommand('rhpTests.updateSnapshots', async () => {
        const source = new vscode.CancellationTokenSource();
        await run(new vscode.TestRunRequest(), source.token, false, true);
    }));
    watch(context);
}

function deactivate() {}

module.exports = { activate, deactivate };
