const assert = require('node:assert/strict');
const vm = require('node:vm');
const fs = require('node:fs');
const path = require('node:path');
const {webcrypto} = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, '../tools/router/browser-diagnostics.js'), 'utf8');

async function test(kind, cancel, networkFailure = false) {
  const calls = [];
  let active = 0, peak = 0;
  const created = [];
  const element = () => {
    const item = {classList: {add() {}}, style: {}, append() {}, textContent: ''};
    created.push(item);
    return item;
  };
  const targets = Array.from({length: 5}, (_, i) => ({name: 'fixture' + i, url: 'https://example.com/' + i}));
  const context = vm.createContext({
    AbortController, Uint8Array, crypto: webcrypto, performance, setTimeout, clearTimeout,
    document: {getElementById: element, createElement: element},
    diagnosticWatch: null, diagnosticControls() {}, busy() {},
    api: async url => {
      assert.ok(['/api/diagnostics/status', '/api/diagnostics/targets', '/api/route/status', '/api/tuner/status'].includes(url));
      return url.endsWith('status') ? {active: false} : {standard: targets, dpi: targets};
    },
    fetch: (url, options) => new Promise((resolve, reject) => {
      // Model Fetch's browser validation, missed by the original mock.
      if (options.mode === 'no-cors' && options.redirect !== 'follow') {
        reject(new TypeError('no-cors requires redirect follow'));
        return;
      }
      calls.push({url, options});
      if (networkFailure) {
        reject(new TypeError('fixture browser network error'));
        return;
      }
      active++; peak = Math.max(peak, active);
      options.signal.addEventListener('abort', () => {active--; reject(new Error('aborted'));}, {once: true});
      if (!cancel) setTimeout(() => {active--; resolve({type: 'opaque'});}, 2);
    }),
  });
  vm.runInContext(source, context);
  const running = context.runBrowserDiagnostic(kind);
  if (cancel) {
    await new Promise(resolve => setTimeout(resolve, 10));
    vm.runInContext('browserDiagnosticRun.controller.abort()', context);
  }
  await running;
  assert.ok(peak <= 3);
  assert.equal(active, 0);
  assert.equal(calls.length, cancel ? 3 : targets.length * (kind === 'dpi' ? 2 : 1));
  for (const {url, options} of calls) {
    assert.ok(url.startsWith('https://example.com/'));
    assert.equal(options.credentials, 'omit');
    assert.equal(options.referrerPolicy, 'no-referrer');
    assert.equal(options.redirect, 'follow');
    if (options.method === 'POST') assert.equal(options.body.length, 65536);
  }
  assert.equal(vm.runInContext('browserDiagnosticRun', context), null);
  if (networkFailure) assert.ok(created.some(item => item.textContent.includes('fixture browser network error')));
}
(async () => {
  await test('standard', false);
  await test('dpi', false);
  await test('standard', true);
  await test('standard', false, true);
  console.log('browser-diagnostics-tests-ok');
})().catch(error => {console.error(error); process.exitCode = 1;});
