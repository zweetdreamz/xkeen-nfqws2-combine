// Browser UI tests for the web panel (Chromium via Playwright).
//
// The page is served by tests/panel_mock_server.py with canned API answers;
// nothing touches a router. Without Playwright the test is skipped (exit 0)
// unless REQUIRE_PANEL_UI_TESTS=1, which CI sets.
"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");
const assert = require("node:assert/strict");

function loadPlaywright() {
  for (const name of [process.env.PLAYWRIGHT_MODULE, "playwright", "playwright-core"]) {
    if (!name) continue;
    try {
      return require(name);
    } catch (_) {
      // try the next candidate
    }
  }
  return null;
}

const playwright = loadPlaywright();
if (!playwright) {
  if (process.env.REQUIRE_PANEL_UI_TESTS === "1") {
    console.error("playwright is required for the panel UI tests");
    process.exit(1);
  }
  console.log("panel-ui-tests-skipped (playwright not installed)");
  process.exit(0);
}

const PORT = 18000 + (process.pid % 1000);
const BASE = `http://127.0.0.1:${PORT}`;

function startServer() {
  const server = spawn("python3", [path.join(__dirname, "panel_mock_server.py"), String(PORT)], {
    stdio: ["ignore", "pipe", "inherit"],
  });
  return new Promise((resolve, reject) => {
    server.on("error", reject);
    server.stdout.on("data", (chunk) => {
      if (String(chunk).includes("ready")) resolve(server);
    });
  });
}

async function setMock(change) {
  const response = await fetch(`${BASE}/__mock/set`, {
    method: "POST",
    body: JSON.stringify(change),
  });
  assert.equal(response.status, 200);
}

async function setResponse(apiPath, body) {
  await setMock({ path: apiPath, body });
}

async function stats() {
  return (await fetch(`${BASE}/__mock/stats`)).json();
}

async function waitForCall(endpoint, n, timeout = 4000) {
  const deadline = Date.now() + timeout;
  while (((await stats())[`GET ${endpoint}`]?.count || 0) < n) {
    assert.ok(Date.now() < deadline, `request did not start: ${endpoint}`);
    await new Promise(resolve => setTimeout(resolve, 20));
  }
}

async function openPanel(browser, errors, { clock = false } = {}) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  // Install before application timers are created; only polling tests advance it.
  if (clock) await page.clock.install();
  page.on("pageerror", (error) => errors.push(String(error)));
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto(`${BASE}/`);
  await page.waitForFunction(() => document.querySelector('[data-service="youtube"] .current').textContent !== "—");
  assert.equal(await page.locator('#openDiagnostics').count(),0);
  assert.equal(await page.getByRole('heading',{name:'Проверка после применения',exact:true}).count(),0);
  assert.equal(await page.getByRole('heading',{name:'Проверить в приложении',exact:true}).count(),0);
  assert.equal(await page.locator('#automation .field-hint').count(),0);
  assert.ok(await page.locator('#postApplyStatus').evaluate(x=>x.hidden&&!!x.closest('#diagnostics')));
  return page;
}

async function finishXkeenAction(page) {
  await page.click('[data-action="restart"]');
  await page.waitForFunction(() => document.getElementById("log").textContent.includes("mock"));
  // busy(false) runs in the finally block after the status refresh.
  await page.waitForFunction(() => !document.querySelector('[data-action="restart"]').disabled);
}

async function pollingChecks(browser, errors) {
  const count = (data, endpoint) => data[`GET ${endpoint}`]?.count || 0;
  const settle = page => page.waitForFunction(() => pendingReads.size === 0 && !tunerRequest);
  const heavy = ["/api/vpn-nodes", "/api/imported", "/api/profile-versions", "/api/updates",
    "/api/automation", "/api/tuner/sources", "/api/tuner/voice-endpoint"];
  await setMock({ reset_stats: true });
  let page = await openPanel(browser, errors);
  await settle(page);
  let data = await stats();
  for (const endpoint of heavy) assert.equal(count(data, endpoint), 0, `hidden startup: ${endpoint}`);
  for (const endpoint of ["/api/status", "/api/history", "/api/tuner/status", "/api/diagnostics/status", "/api/route/status", "/api/dns"])
    assert.equal(count(data, endpoint), 1, `startup discovery: ${endpoint}`);
  // Post-operation list refreshes are deferred too; validators/jobs are not gated.
  await page.evaluate(() => Promise.all([refreshVpnNodes(), refreshProfiles(), refreshVersions(),
    refreshUpdates(), refreshAutomation(), refreshTunerSources(), refreshVoiceEndpoint()]));
  data = await stats();
  for (const endpoint of heavy) assert.equal(count(data, endpoint), 0, `hidden refresh: ${endpoint}`);
  await page.click('.tab[data-tab="import"]');
  await settle(page);
  assert.equal(count(await stats(), "/api/imported"), 1);
  assert.equal(count(await stats(), "/api/profile-versions"), 1);
  await page.click('.tab[data-tab="import"]'); // already selected: no reload storm
  await settle(page);
  assert.equal(count(await stats(), "/api/imported"), 1);
  await page.click('.tab[data-tab="control"]');
  await settle(page);
  await page.click('.tab[data-tab="import"]');
  await settle(page);
  assert.equal(count(await stats(), "/api/imported"), 2, "reopening must read fresh state");

  // Only concurrent GETs share a request; completed/error responses are not cached.
  await setMock({ path: "/api/updates", delay: 0.3 });
  await setMock({ reset_stats: true });
  await page.evaluate(() => Promise.all(Array.from({ length: 12 }, () => api("/api/updates"))));
  data = await stats();
  assert.equal(count(data, "/api/updates"), 1);
  assert.equal(data["GET /api/updates"].max_in_flight, 1);
  await page.evaluate(() => api("/api/updates"));
  assert.equal(count(await stats(), "/api/updates"), 2, "no response cache");
  await setMock({ path: "/api/updates", sequence: [
    { status: 500, body: { ok: false, error: "read failed" } },
    { ok: true, status: "never_downloaded" },
  ] });
  const rejected = await page.evaluate(() => Promise.allSettled(
    Array.from({ length: 5 }, () => api("/api/updates"))).then(results => results.every(r => r.status === "rejected")));
  assert.equal(rejected, true);
  assert.equal(count(await stats(), "/api/updates"), 3);
  await page.evaluate(() => api("/api/updates"));
  assert.equal(count(await stats(), "/api/updates"), 4, "retry after shared failure");
  await setResponse("/api/updates", { ok: true, status: "never_downloaded" });
  // No sharing of writes, or of a read started before a write/rollback boundary.
  await setMock({ reset_stats: true });
  await page.evaluate(async () => {
    const old = api("/api/updates");
    await Promise.all([api("/api/import/validate", { method: "POST", body: "{}" }),
      api("/api/import/validate", { method: "POST", body: "{}" })]);
    await Promise.all([old, api("/api/updates")]);
  });
  data = await stats();
  assert.equal(count(data, "/api/updates"), 2, "write invalidates in-flight sharing");
  assert.equal(data["POST /api/import/validate"].count, 2, "POST must never be coalesced");
  await setMock({ path: "/api/updates", delay: 0 });
  // An older read (including a late error) must not overwrite a newer render
  // after a write. The mock captures its payload before delaying the response.
  const statusBody = await (await fetch(`${BASE}/api/status`)).json();
  const vpnBody = await (await fetch(`${BASE}/api/vpn-nodes`)).json();
  await page.click('.tab[data-tab="vpn-nodes"]');
  await settle(page);
  const freshVpn = { ...vpnBody, nodes: [{ id: "current", name: "fresh node", active: true,
    protocol: "vless", endpoint: "example:443", network: "tcp", security: "reality", health: null,
    flow: "xtls-rprx-vision", fingerprint: "firefox", sni: "front.example" }] };
  for (const [endpoint, refreshName, fresh, old] of [
    ["/api/status", "refresh", statusBody, { ...statusBody, xkeen_runtime: "stopped" }],
    ["/api/vpn-nodes", "refreshVpnNodes", freshVpn, { ...freshVpn, nodes: [{ ...freshVpn.nodes[0], name: "old node" }] }],
  ]) {
    for (const failed of [false, true]) {
      await setMock({ path: endpoint, sequence: [failed ? { status: 500, body: { ok: false, error: "old failure" } } : old, fresh] });
      await setMock({ path: endpoint, delay: 0.4 });
      const n = count(await stats(), endpoint);
      await page.evaluate(name => { window.oldRead = window[name](); }, refreshName);
      await waitForCall(endpoint, n + 1);
      await setMock({ path: endpoint, delay: 0 });
      await page.evaluate(async name => {
        await api("/api/import/validate", { method: "POST", body: "{}" });
        await window[name]();
        await window.oldRead;
      }, refreshName);
      if (endpoint === "/api/status") assert.equal(await page.textContent("#statusText"), "XKeen работает");
      else {
        assert.match(await page.textContent("#vpnNodesList"), /fresh node/);
        assert.doesNotMatch(await page.textContent("#vpnNodesList"), /old node/);
        assert.equal(await page.locator('#vpnNodesList .vpn-node-endpoint').textContent(), 'example:443');
        assert.deepEqual(await page.locator('#vpnNodesList .vpn-node-tag').allTextContents(),
          ['VLESS','TCP','REALITY','xtls-rprx-vision','firefox','front.example']);
      }
    }
  }
  await setResponse("/api/status", statusBody);
  await setResponse("/api/vpn-nodes", vpnBody);
  await page.close();

  // Automation polling belongs to its visible tab, preserves unsaved inputs,
  // and a manual refresh burst cannot overlap status calls.
  const automation = await (await fetch(`${BASE}/api/automation`)).json();
  await setResponse("/api/automation", { ...automation, active: true });
  await setMock({ reset_stats: true });
  page = await openPanel(browser, errors, { clock: true });
  await settle(page);
  assert.equal(count(await stats(), "/api/automation"), 0);
  await page.click('.tab[data-tab="automation"]');
  await settle(page);
  await page.locator("#autoTimes").fill("04:15");
  await setMock({ path: "/api/automation", delay: 0.3 });
  const autoBefore = count(await stats(), "/api/automation");
  await page.evaluate(() => Promise.all(Array.from({ length: 8 }, () => refreshAutomation())));
  data = await stats();
  assert.equal(count(data, "/api/automation"), autoBefore + 1);
  assert.equal(data["GET /api/automation"].max_in_flight, 1);
  await setMock({ path: "/api/automation", delay: 0 });
  await page.click('.tab[data-tab="control"]');
  const autoHidden = count(await stats(), "/api/automation");
  await page.clock.runFor(3300);
  await page.clock.resume();
  await settle(page);
  assert.equal(count(await stats(), "/api/automation"), autoHidden, "hidden automation keeps polling");
  await page.click('.tab[data-tab="automation"]');
  await settle(page);
  assert.equal(count(await stats(), "/api/automation"), autoHidden + 1);
  assert.equal(await page.locator("#autoTimes").inputValue(), "04:15", "poll overwrote an unsaved schedule");
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  const background = count(await stats(), "/api/automation");
  await page.clock.runFor(3300);
  await page.clock.resume();
  await settle(page);
  assert.equal(count(await stats(), "/api/automation"), background, "background document keeps polling");
  await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event("visibilitychange")); });
  await settle(page);
  assert.equal(count(await stats(), "/api/automation"), background + 1);
  assert.equal(await page.locator("#autoTimes").inputValue(), "04:15");
  await page.close();
  await setResponse("/api/automation", automation);

  // Tuner discovery is global for the route locks. A hidden browser suspends
  // polling, not the router job; foregrounding reads fresh state immediately.
  await setResponse("/api/tuner/status", { ok: true, status: "running", active: true, service: "youtube" });
  page = await openPanel(browser, errors, { clock: true });
  await settle(page);
  await page.evaluate(() => {
    Object.defineProperty(document, "hidden", { configurable: true, value: true });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  const tunerHidden = count(await stats(), "/api/tuner/status");
  await page.clock.runFor(2200);
  await page.clock.resume();
  await settle(page);
  assert.equal(count(await stats(), "/api/tuner/status"), tunerHidden);
  assert.ok((await page.$$eval(".mode", buttons => buttons.map(b => b.disabled))).every(Boolean));
  await setResponse("/api/tuner/status", { ok: true, status: "idle", active: false });
  await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event("visibilitychange")); });
  await settle(page);
  assert.equal(count(await stats(), "/api/tuner/status"), tunerHidden + 1);
  assert.ok((await page.$$eval(".mode", buttons => buttons.map(b => b.disabled))).every(value => !value));
  assert.equal((await stats())["POST /api/tuner/cancel"]?.count || 0, 0, "visibility must not cancel the router job");
  await page.close();
  console.log("panel-polling-tests-ok (startup: 6 GETs including DNS, hidden heavy lists: 0)");
}

async function inspectionChecks(browser, errors) {
  const identityA={node_id:"node-a",source_digest:"a".repeat(64)},identityB={node_id:"node-b",source_digest:"b".repeat(64)};
  const monitor=identity=>({ok:true,active:false,identity,expected:{ipv4:["1.1.1.1"]},verdict:"unapproved",config:{enabled:false,interval_minutes:5,families:["ipv4"],nodes:{}},state:{history:[]},detail:""});
  await setResponse("/api/vpn-monitor",monitor(identityA));
  const page=await openPanel(browser,errors);
  await page.click('.tab[data-tab="vpn-nodes"]');
  await page.waitForFunction(()=>document.getElementById("vpnMonitorSummary").textContent.includes("node-a"));
  await page.fill("#vpnExpected4","8.8.8.8");
  await setResponse("/api/vpn-monitor",monitor(identityB));
  await page.click('.tab[data-tab="diagnostics"]');
  await page.waitForFunction(()=>document.getElementById("vpnMonitorSummary").textContent.includes("node-b"));
  assert.equal(await page.inputValue("#vpnExpected4"),"8.8.8.8");
  assert.equal(await page.isDisabled("#vpnMonitorSave"),true,"dirty IP form must stay bound to node A");
  await page.click('.tab[data-tab="vpn-nodes"]');
  await page.click("#vpnMonitorReload");
  await page.waitForFunction(()=>!document.getElementById("vpnMonitorSave").disabled);
  let saved=null;
  await page.route("**/api/vpn-monitor/save",async route=>{saved=route.request().postDataJSON();await route.fulfill({json:monitor(identityB)})});
  await page.fill("#vpnExpected4","8.8.8.8");
  await page.click("#vpnMonitorSave");
  await page.waitForFunction(()=>document.getElementById("vpnExpected4").value==="1.1.1.1");
  assert.deepEqual(saved.identity,identityB);
  assert.deepEqual(saved.changes.expected.ipv4,["8.8.8.8"]);
  const jobId="0123456789abcdef";
  await setResponse("/api/inspection/status",{ok:true,status:"idle",active:false,results:{}});
  let query=null;
  await page.route("**/api/inspection/check/route",async route=>{
    query=route.request().postDataJSON();
    await setResponse("/api/inspection/status",{ok:true,status:"completed",active:false,job_id:jobId,results:{route:{status:"completed",routes:[{ip:"1.1.1.1",outbound:"direct",path:"direct"}],scope:"Xray TestRoute"}}});
    await route.fulfill({status:202,json:{ok:true,job_id:jobId,kind:"route",active:true,status:"running"}});
  });
  await page.click('.tab[data-tab="diagnostics"]');
  await page.fill("#inspectDomain","example.org");
  await page.selectOption("#inspectNetwork","udp");
  await page.click("#inspectRoute");
  await page.waitForFunction(()=>document.getElementById("inspectRouteResult").textContent.includes("→ direct"));
  assert.equal(query.domain,"example.org");assert.equal(query.network,"udp");
  await page.close();
  await setResponse("/api/vpn-monitor",monitor({}));
  console.log("inspection-ui-tests-ok (route context and dirty node/IP binding)");
}

async function importValidationChecks(browser, errors) {
  const page = await openPanel(browser, errors);
  await page.click('.tab[data-tab="import"]');
  const pending = [];
  const applied = [];
  const confirmations = [];
  page.on('dialog', dialog => confirmations.push(dialog.message()));
  await page.route('**/api/import/validate', route => { pending.push(route); });
  await page.route('**/api/import/apply', async route => {
    applied.push(route.request().postDataJSON());
    await route.fulfill({ json: { ok: false, error: 'offline apply captured' }, status: 400 });
  });
  const report = id => ({ service: 'youtube', found: { service: 'youtube', candidate_id: id,
    source_name: 'fixture.bat', family: 'fixture', args: ['--filter-tcp=443'] } });
  async function select(value) {
    await page.locator('#reportFile').setInputFiles({ name: 'report.json', mimeType: 'application/json',
      buffer: Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)) });
  }
  async function start(name) {
    await page.evaluate(name => { window[name] = validateReport(); }, name);
    while (!pending.length) await new Promise(resolve => setTimeout(resolve, 10));
    return pending.shift();
  }
  async function answer(route, value, name, failed = false) {
    await route.fulfill({ json: failed ? { ok: false, error: 'stale rejection' } : { ok: true, profile: value.found },
      status: failed ? 400 : 200 });
    await page.evaluate(name => window[name], name);
  }
  const a = report('aaaaaaaaaaaa'), b = report('bbbbbbbbbbbb');
  await select(a);
  await answer(await start('validationA'), a, 'validationA');
  assert.equal(await page.locator('#candidateId').textContent(), a.found.candidate_id);
  // Selection alone invalidates the old preview, before another validation starts.
  await select(b);
  assert.equal(await page.locator('#applyImport').isDisabled(), true, 'changed file may still apply A');
  assert.equal(await page.locator('#candidate').evaluate(x => x.classList.contains('visible')), false);
  const pendingB = await start('validationB');
  await page.evaluate(() => { busy(false); return applyImport(); });
  assert.equal(applied.length, 0, 'pending B must not submit B using the descriptor for A');
  assert.equal(await page.locator('#applyImport').isDisabled(), true, 'busy(false) reopened pending apply');
  await answer(pendingB, b, 'validationB');
  await page.click('#applyImport');
  await page.waitForFunction(() => document.getElementById('log').textContent.includes('offline apply captured'));
  assert.deepEqual(applied, [b], 'apply payload must match the displayed descriptor');
  assert.match(confirmations.at(-1), /bbbbbbbbbbbb/, 'confirmation must identify the submitted report');
  await page.waitForFunction(() => !document.getElementById('validate').disabled);

  // Both stale success and stale failure must leave the newest validated pair intact.
  for (const [failed, sameFile] of [[false, false], [true, false], [true, true]]) {
    await select(sameFile ? b : a);
    const old = await start('olderValidation');
    if (!sameFile) await select(b);
    const current = await start('currentValidation');
    await answer(current, b, 'currentValidation');
    await answer(old, a, 'olderValidation', failed);
    assert.equal(await page.locator('#candidateId').textContent(), b.found.candidate_id);
    assert.equal(await page.locator('#candidate').evaluate(x => x.classList.contains('visible')), true);
    assert.equal(await page.locator('#applyImport').isEnabled(), true);
    await page.evaluate(() => applyImport());
    assert.deepEqual(applied.at(-1), b, 'late validation replaced the submitted report');
  }
  // A late response must not resurrect a preview after a file change or parse error.
  for (const parse of [false, true]) {
    await select(a);
    const old = await start('beforeInvalidation');
    await select('{broken-json');
    if (parse) await page.evaluate(() => validateReport());
    await answer(old, a, 'beforeInvalidation');
    assert.equal(await page.locator('#candidate').evaluate(x => x.classList.contains('visible')), false);
    assert.equal(await page.locator('#applyImport').isDisabled(), true);
    const before = applied.length;
    await page.evaluate(() => applyImport());
    assert.equal(applied.length, before);
  }
  await page.close();
  console.log('import-validation-ui-tests-ok (file changes, pending checks, reverse responses and payload)');
}

async function main() {
  setTimeout(()=>{console.error("panel UI test timeout");process.exit(1)},120000).unref();
  const server = await startServer();
  const launchOptions = {};
  if (process.env.PLAYWRIGHT_CHROMIUM_PATH) {
    launchOptions.executablePath = process.env.PLAYWRIGHT_CHROMIUM_PATH;
  }
  const browser = await playwright.chromium.launch(launchOptions);
  const errors = [];
  try {
    await importValidationChecks(browser, errors);
    await pollingChecks(browser, errors);
    await inspectionChecks(browser, errors);
    // Four independent route cards with their current modes.
    let page = await openPanel(browser, errors);
    const cards = await page.$$eval(".service", (items) =>
      items.map((item) => [item.dataset.service, item.querySelector(".current").textContent])
    );
    assert.deepEqual(cards, [
      ["discord-tcp", "ZAPRET"],
      ["discord-voice", "DIRECT"],
      ["youtube", "VPN"],
      ["telegram", "ВЫКЛ"],
    ]);
    // Telegram alone has the "off" mode; it is active while unmanaged. Zapret was
    // removed for Telegram (the ISP blocks it by IP).
    assert.deepEqual(
      await page.$$eval('[data-service="telegram"] .mode', (buttons) =>
        buttons.map((button) => [button.dataset.mode, button.classList.contains("active")])
      ),
      [["direct", false], ["vpn", false], ["ws", false], ["unmanaged", true]]
    );
    assert.equal(await page.$$eval('.mode[data-mode="unmanaged"]', (buttons) => buttons.length), 1);
    // 2x2 grid on a desktop width; the four Telegram buttons share one row.
    const tops = await page.$$eval(".service", (items) => items.map((item) => Math.round(item.getBoundingClientRect().top)));
    assert.equal(tops[0], tops[1]);
    assert.equal(tops[2], tops[3]);
    assert.ok(tops[2] > tops[0]);
    const telegramButtonTops = await page.$$eval('[data-service="telegram"] .mode', (buttons) =>
      new Set(buttons.map((button) => Math.round(button.getBoundingClientRect().top))).size
    );
    assert.equal(telegramButtonTops, 1);
    // On a phone the four Telegram buttons form a 2x2 grid.
    await page.setViewportSize({ width: 390, height: 844 });
    const phoneRows = await page.$$eval('[data-service="telegram"] .mode', (buttons) =>
      buttons.map((button) => Math.round(button.getBoundingClientRect().top))
    );
    assert.equal(new Set(phoneRows).size, 2);
    assert.equal(phoneRows[0], phoneRows[1]);
    assert.equal(phoneRows[2], phoneRows[3]);
    await page.setViewportSize({ width: 1280, height: 900 });

    // The autotuner offers only the services with an nfqws2 profile.
    assert.deepEqual(
      await page.$$eval("#tunerService option", (options) => options.map((option) => option.value)),
      ["youtube", "discord-tcp", "discord-voice"]
    );

    // The search seed is generated by the router, not entered in the form.
    assert.equal(await page.$("#tunerSeed"), null);

    // The LAN IPv4 field belongs to Discord Voice only.
    await page.click('.tab[data-tab="autotune"]');
    await page.waitForFunction(() => pendingReads.size === 0 && !tunerRequest);
    assert.equal(await page.isHidden("#clientIpField"), true);
    await page.selectOption("#tunerService", "discord-voice");
    assert.equal(await page.isVisible("#clientIpField"), true);

    // Voice check modes: traffic by default; the router probe needs a learned server.
    assert.equal(await page.isVisible("#voiceAutoField"), true);
    assert.equal(await page.$eval("#tunerVoiceCheck", (select) => select.value), "traffic");
    assert.match(await page.textContent("#voiceAutoHint"), /оставайтесь в нём/);
    assert.equal(await page.$eval('#tunerVoiceCheck option[value="probe"]', (option) => option.disabled), true);
    await page.selectOption("#tunerService", "youtube");
    assert.equal(await page.isHidden("#voiceAutoField"), true);
    await setResponse("/api/tuner/voice-endpoint", {
      ok: true,
      endpoint: { ip: "162.159.130.234", port: 50007, learned_utc: "2026-10-20T10:00:00Z" },
    });
    await page.evaluate(() => refreshVoiceEndpoint());
    await page.selectOption("#tunerService", "discord-voice");
    assert.equal(await page.$eval('#tunerVoiceCheck option[value="probe"]', (option) => option.disabled), false);
    await page.selectOption("#tunerVoiceCheck", "probe");
    assert.match(await page.textContent("#voiceAutoHint"), /162\.159\.130\.234:50007/);
    await page.selectOption("#tunerVoiceCheck", "traffic");
    await setResponse("/api/tuner/voice-endpoint", { ok: true, endpoint: null });

    // Success is stated first; known harmless lines are explained before the raw output.
    const text = await page.evaluate(() => resultText(
      "Discord Voice: профиль f3de2c222df9 применён",
      "WARNING: XKeen IPv6 support is on, but no usable IPv6 WAN route exists.\nseccomp: Invalid argument\nStarted NFQWS2 service"
    ));
    const lines = text.split("\n");
    assert.equal(lines[0], "Готово: Discord Voice: профиль f3de2c222df9 применён");
    assert.match(lines[1], /IPv6 безвредно/);
    assert.match(lines[2], /seccomp безвредна/);
    assert.ok(text.endsWith("Полный вывод:\nWARNING: XKeen IPv6 support is on, but no usable IPv6 WAN route exists.\nseccomp: Invalid argument\nStarted NFQWS2 service"));
    assert.equal(await page.evaluate(() => resultText("xkeen -restart", "")), "Готово: xkeen -restart");

    // busy() must not disable navigation.
    await page.evaluate(() => busy(true));
    assert.equal(await page.$eval('.tab[data-tab="control"]', (tab) => tab.disabled), false);
    await page.evaluate(() => busy(false));

    // Idle: after any operation the "stop" buttons stay disabled.
    await page.click('.tab[data-tab="control"]');
    await finishXkeenAction(page);
    assert.equal(await page.$eval("#cancelTuner", (button) => button.disabled), true);
    assert.equal(await page.$eval("#cancelDiagnostic", (button) => button.disabled), true);
    await page.close();

    // A running tuner keeps route buttons locked and its stop button usable.
    await setResponse("/api/tuner/status", { ok: true, status: "running", active: true, service: "youtube" });
    page = await openPanel(browser, errors);
    await page.waitForFunction(() => !document.getElementById("cancelTuner").disabled);
    // Any other operation ends with busy(false), e.g. a history refresh error.
    await page.evaluate(() => { busy(true); busy(false); });
    assert.equal(await page.$eval("#cancelTuner", (button) => button.disabled), false);
    assert.equal(await page.$eval("#startTuner", (button) => button.disabled), true);
    const modes = await page.$$eval(".mode", (buttons) => buttons.map((button) => button.disabled));
    assert.ok(modes.every(Boolean), `mode buttons must stay disabled: ${modes}`);
    await page.close();
    await setResponse("/api/tuner/status", { ok: true, status: "idle", active: false });

    // B8/D8: a dead job's state (here voice_watch with active=false) never locks the page.
    await setResponse("/api/tuner/status", { ok: true, status: "voice_watch", active: false, service: "discord-voice" });
    page = await openPanel(browser, errors);
    await page.waitForFunction(() => document.getElementById("tunerStatus").textContent.includes("голосовым"));
    assert.equal(await page.$eval("#startTuner", (button) => button.disabled), false);
    assert.equal(await page.$eval("#cancelTuner", (button) => button.disabled), true);
    assert.ok((await page.$$eval(".mode", (buttons) => buttons.map((button) => button.disabled))).every((value) => !value));
    await page.close();

    // Tuner polling never overlaps: the next request waits for the previous answer.
    await setResponse("/api/tuner/status", { ok: true, status: "running", active: true, service: "youtube" });
    await setMock({ path: "/api/tuner/status", delay: 2.5 });
    await setMock({ reset_stats: true });
    page = await openPanel(browser, errors);
    await waitForCall("/api/tuner/status", 2, 10000);
    await page.waitForFunction(() => !tunerRequest);
    const tunerStats = (await stats())["GET /api/tuner/status"];
    assert.ok(tunerStats.count >= 2, `tuner polling stopped: ${JSON.stringify(tunerStats)}`);
    assert.equal(tunerStats.max_in_flight, 1, `overlapping tuner polls: ${JSON.stringify(tunerStats)}`);
    await page.close();
    await setMock({ path: "/api/tuner/status", delay: 0 });
    await setResponse("/api/tuner/status", { ok: true, status: "idle", active: false });

    // D3: every successful nfqws2 change ends with the post-apply check (and fresh
    // route badges); a failed change does not run it.
    await setResponse("/api/checks/config", {
      ok: true,
      all_ok: false,
      checks: [
        { name: "Xray", ok: true, status: "ok", detail: "процесс запущен" },
        { name: "nfqws2: порты профилей в очереди", ok: false, status: "error", detail: "профиль 2 (youtube.list): UDP 443 нет в UDP_PORTS" },
        { name: "NFQUEUE: переходы", ok: true, status: "warn", detail: "POSTROUTING → nfqws_post: 2 раз(а)" },
      ],
    });
    await setResponse("/api/tuner/status", {
      ok: true, status: "found", active: false, service: "youtube", result_available: true,
      found: { candidate_id: "aaaaaaaaaaaa", family: "fixture", source_name: "general.bat", args: ["--filter-tcp=443"] },
    });
    page = await openPanel(browser, errors);
    await page.route('**/api/import/validate', route => route.fulfill({
      json: { ok: true, profile: route.request().postDataJSON().found },
    }));
    const versionId = "20261020T100000Z-aaaaaaaaaaaa-applied-1";
    const operations = [
      ["applyImport", "/api/import/apply", async () => {
        const report = { service: "youtube", found: { service: "youtube", candidate_id: "aaaaaaaaaaaa",
          source_name: "fixture.bat", family: "fixture", args: ["--filter-tcp=443"] } };
        const files = new DataTransfer();
        files.items.add(new File([JSON.stringify(report)], 'report.json', { type: 'application/json' }));
        const input = document.getElementById('reportFile');
        input.files = files.files;
        input.dispatchEvent(new Event('change'));
        await validateReport();
        return applyImport();
      }],
      ["clearImport", "/api/import/clear/youtube", () => clearImport("youtube")],
      ["rollbackImport", "/api/import/rollback", () => rollbackImport()],
      ["applyVersion", `/api/profiles/apply/youtube/${versionId}`, (id) => applyVersion("youtube", id)],
      ["applyTunerResult", "/api/tuner/apply", () => applyTunerResult()],
      ["xkeenAction", "/api/xkeen/restart", () => xkeenAction("restart")],
      ["checkVpnNode", "/api/vpn-nodes/check/current", () => checkVpnNode("current")],
      ["addVpnNode", "/api/vpn-nodes/add", () => {
        document.getElementById("vpnNodeName").value="node1";
        document.getElementById("vpnNodeSource").value="vless://fixture";
        return addVpnNode();
      }],
    ];
    const jobId="0123456789abcdef";
    for (const [name, apiPath, operation] of operations) {
      for (const fails of [false, true]) {
        const kind=name==="xkeenAction"?"xkeen":name==="checkVpnNode"?"vpn-check":name==="addVpnNode"?"vpn-add":"apply-profile";
        const queued={ok:true,job_id:jobId,operation:kind,status:"queued",active:true,output:"",service:"youtube"};
        const done={...queued,status:fails?"failed":"completed",active:false,result_ok:!fails,code:fails?1:0,output:fails?"engine failed":"full result output"};
        if(name==="checkVpnNode")done.health={ok:true,latency_ms:1,http_code:204};
        if(name==="addVpnNode")done.node={id:"node1",health:{ok:true}};
        await setMock({method:"POST",path:apiPath,status:202,body:queued});
        await setMock({path:"/api/route/status",sequence:[queued,{...done,output:"short status"}]});
        await setResponse("/api/route/result",done);
        await page.evaluate(() => { const root = document.getElementById("postApplyStatus"); root.textContent = "—"; root.className = "hint"; });
        const before = await stats();
        await page.evaluate(operation, versionId);
        const after = await stats();
        const checksCalls = (after["GET /api/checks/config"] || { count: 0 }).count - (before["GET /api/checks/config"] || { count: 0 }).count;
        const statusCalls = after["GET /api/status"].count - before["GET /api/status"].count;
        assert.equal((after["GET /api/route/result"]?.count||0)-(before["GET /api/route/result"]?.count||0),1,`${name}: full result once`);
        assert.ok((after["GET /api/route/status"]?.count||0)>(before["GET /api/route/status"]?.count||0),name);
        assert.equal((after[`POST ${apiPath}`] || { count: 0 }).count - (before[`POST ${apiPath}`] || { count: 0 }).count, 1, name);
        if(!["checkVpnNode","addVpnNode"].includes(name))assert.ok(statusCalls >= 1, `${name}: route badges not refreshed`);
        const text = await page.textContent("#postApplyStatus");
        if (fails || ["xkeenAction","checkVpnNode","addVpnNode"].includes(name)) {
          assert.equal(checksCalls, 0, `${name}: post-checks after an error`);
          assert.equal(text, "—", name);
          if(fails)assert.match(await page.textContent("#log"),/engine failed/,name);
        } else {
          assert.equal(checksCalls, 1, `${name}: no post-checks`);
          assert.match(text, /^Проверка не пройдена:\n• nfqws2: порты профилей в очереди — профиль 2 \(youtube\.list\): UDP 443 нет в UDP_PORTS\nВнимание:\n• NFQUEUE: переходы/, name);
          assert.equal(await page.$eval("#postApplyStatus", (root) => root.className), "bad");
        }
      }
    }
    // A check sent with the result is shown without another request.
    await setMock({
      method: "POST", path: "/api/import/rollback", status: 202,
      body: { ok: true, job_id:jobId },
    });
    await setResponse("/api/route/status",{ok:true,job_id:jobId,status:"completed",active:false,output:"short"});
    await setResponse("/api/route/result",{ok:true,job_id:jobId,status:"completed",result_ok:true,active:false,output:"full",health:{ok:true,all_ok:true,checks:[{name:"Xray",ok:true,status:"ok",detail:"x"}]}});
    const before = await stats();
    await page.evaluate(() => rollbackImport());
    const after = await stats();
    assert.equal(after["GET /api/checks/config"].count, before["GET /api/checks/config"].count);
    assert.equal(await page.textContent("#postApplyStatus"), "Конфиги и службы: OK");

    // Restart survives lost status responses without submitting the POST again.
    const terminal={ok:true,job_id:jobId,operation:"xkeen",status:"completed",active:false,result_ok:true,output:"network mock completed"};
    await setMock({method:"POST",path:"/api/xkeen/restart",status:202,body:{ok:true,job_id:jobId}});
    await setMock({path:"/api/route/status",sequence:[{status:500,body:{ok:false,error:"offline"}},{status:500,body:{ok:false,error:"offline"}},terminal]});
    await setResponse("/api/route/result",terminal);
    let previous=await stats();
    await page.evaluate(()=>xkeenAction("restart"));
    let current=await stats();
    assert.equal(current["POST /api/xkeen/restart"].count-previous["POST /api/xkeen/restart"].count,1);
    assert.match(await page.textContent("#log"),/перезапуск сети прервал связь/);
    assert.match(await page.textContent("#log"),/network mock completed/);

    // Concurrent client-side attempts are refused before POST; background
    // idle renders cannot unlock buttons while another job is watched.
    await setMock({path:"/api/route/status",sequence:[{...terminal,status:"running",active:true},terminal]});
    await page.evaluate(()=>{window.uiPending=xkeenAction("restart")});
    await page.waitForFunction(()=>routeWatch!==null);
    assert.equal(await page.evaluate(()=>{busy(false);tunerControls(false);return Array.from(document.querySelectorAll("[data-action]")).every(b=>b.disabled)}),true);
    previous=await stats();
    const refused=await page.evaluate(()=>operation("/api/import/rollback","second").catch(e=>e.message));
    assert.match(refused,/другая операция/);
    current=await stats();
    assert.equal(current["POST /api/import/rollback"].count,previous["POST /api/import/rollback"].count);
    await page.evaluate(()=>window.uiPending);
    assert.equal(await page.$eval('[data-action="restart"]',b=>b.disabled),false);
    assert.match(await page.evaluate(()=>{renderTuner({status:"queued",active:true});return document.getElementById("tunerStatus").textContent}),/Запуск задания/);
    await page.evaluate(()=>renderTuner({status:"idle",active:false}));

    // The "check all" loop waits for each full result before the next POST.
    await setResponse("/api/vpn-nodes",{ok:true,active:"n1",drift:false,warning:"",canonical_tag:"vless-reality",recovery_needed:false,
      nodes:["n1","n2"].map(id=>({id,name:id,active:id==="n1",protocol:"vless",endpoint:"example:443",network:"tcp",security:"reality",health:null}))});
    const checked={...terminal,operation:"vpn-check",health:{ok:true,latency_ms:1,http_code:204}};
    await setResponse("/api/route/status",checked);
    await setMock({path:"/api/route/result",sequence:[checked,checked]});
    const trace=[];
    const record=request=>{const url=new URL(request.url());if(request.method()==="POST"&&url.pathname.startsWith("/api/vpn-nodes/check/"))trace.push(url.pathname);if(url.pathname==="/api/route/result")trace.push("result")};
    page.on("request",record);
    await page.evaluate(()=>checkAllVpnNodes());
    page.off("request",record);
    assert.deepEqual(trace,["/api/vpn-nodes/check/n1","result","/api/vpn-nodes/check/n2","result"]);
    // Editing never preloads credentials; blank source is omitted, active source is disabled.
    await page.locator('button[data-tab="vpn-nodes"]').click();
    await setResponse("/api/vpn-nodes/update/n2",{ok:true,node:{id:"n2",name:"Европа"}});
    await page.evaluate(()=>editVpnNode({id:"n2",name:"Резерв",active:false}));
    assert.equal(await page.locator("#vpnEditSource").inputValue(),"");
    await page.locator("#vpnEditName").fill("Европа");
    const editRequest=page.waitForRequest(request=>new URL(request.url()).pathname==="/api/vpn-nodes/update/n2");
    await page.locator("#vpnEditSave").click();
    assert.deepEqual((await editRequest).postDataJSON(),{name:"Европа"});
    await page.waitForFunction(()=>document.getElementById("vpnEditCard").hidden);
    await page.evaluate(()=>editVpnNode({id:"n1",name:"Основной",active:true}));
    assert.equal(await page.locator("#vpnEditSource").isDisabled(),true);
    await page.locator("#vpnEditCancel").click();
    assert.equal(await page.locator("#vpnEditSource").inputValue(),"");
    // Selection/recovery refresh the visible node list once, not once in the
    // shared watcher plus again in their own finally. Post-checks stay intact.
    for (const action of [() => selectVpnNode("n2"), () => recoverVpnNode()]) {
      await page.waitForFunction(() => pendingReads.size === 0);
      const start = await stats();
      await page.evaluate(action);
      const end = await stats();
      assert.equal(end["GET /api/vpn-nodes"].count - start["GET /api/vpn-nodes"].count, 1);
      assert.equal(end["GET /api/checks/config"].count - start["GET /api/checks/config"].count, 1);
    }
    await page.close();
    await setResponse("/api/tuner/status", { ok: true, status: "idle", active: false });

    const dnsPage=await openPanel(browser,errors);
    await dnsPage.waitForFunction(()=>document.querySelector('[data-dns-mode="doh"]').disabled===false);
    assert.equal(await dnsPage.locator('[data-dns-mode="vless"]').isDisabled(),true);
    const dnsState={ok:true,supported:true,mode:'doh',interface:'Home',detail:'',pending:false,recovery_mode:null,host_overrides:0};
    await setResponse('/api/dns',dnsState);
    const dnsDone={...terminal,operation:'dns-mode',service:'dns',mode:'doh'};
    await setResponse('/api/route/status',dnsDone);await setMock({path:'/api/route/result',sequence:[dnsDone]});
    await setMock({method:'POST',path:'/api/dns/doh',status:202,body:{ok:true,job_id:jobId}});
    const dnsRequest=dnsPage.waitForRequest(r=>new URL(r.url()).pathname==='/api/dns/doh');
    await dnsPage.locator('[data-dns-mode="doh"]').click();
    assert.deepEqual((await dnsRequest).postDataJSON(),{confirm:true});
    await dnsPage.waitForFunction(()=>document.getElementById('dnsModeStatus').textContent.includes('DoH на роутере'));
    assert.equal(await dnsPage.locator('[data-dns-mode="doh"]').isDisabled(),true);
    await dnsPage.evaluate(()=>renderDnsMode({ok:true,supported:true,mode:'doh',interface:'Home',pending:true,recovery_mode:'vless'}));
    assert.equal(await dnsPage.locator('[data-dns-mode="vless"]').isDisabled(),false);
    assert.equal(await dnsPage.locator('[data-dns-mode="doh"]').isDisabled(),true);
    await dnsPage.close();
    const notificationsPage=await openPanel(browser,errors);
    await notificationsPage.locator('.tab[data-tab="notifications"]').click();
    await notificationsPage.waitForFunction(()=>document.getElementById('notifyTopic').value.length>0);
    assert.equal(await notificationsPage.locator('#notifyToken').inputValue(),'');
    assert.deepEqual(await notificationsPage.locator('#notifyEvents legend').allTextContents(),['Zapret и расписание','VPN']);
    assert.equal(await notificationsPage.locator('[data-notify-event="night-failed"]').isChecked(),false);
    assert.match(await notificationsPage.locator('#notifyToken').getAttribute('placeholder'),/сохранён/);
    const notifyBody=await (await fetch(BASE+'/api/notifications')).json();
    await setMock({method:'POST',path:'/api/notifications/save',body:{...notifyBody,enabled:true}});
    await notificationsPage.locator('#notifyEnabled').check();
    await notificationsPage.locator('#notifyToken').fill('fake-secret-token');
    const notificationRequest=notificationsPage.waitForRequest(r=>new URL(r.url()).pathname==='/api/notifications/save');
    await notificationsPage.locator('#notifySave').click();
    const notifySaved=(await notificationRequest).postDataJSON();
    assert.equal(notifySaved.token,'fake-secret-token');assert.equal(notifySaved.enabled,true);
    await notificationsPage.waitForFunction(()=>document.getElementById('notifyMessage').textContent==='Сохранено.');
    assert.equal(await notificationsPage.locator('#notifyToken').inputValue(),'');
    await notificationsPage.locator('#notifyTest').click();
    await notificationsPage.waitForFunction(()=>document.getElementById('notifyMessage').textContent.includes('Тест поставлен'));
    await notificationsPage.locator('#notifyGenerate').click();
    await notificationsPage.waitForFunction(()=>document.getElementById('notifyTopic').value.startsWith('kdn-bbb'));
    await notificationsPage.close();
    assert.deepEqual(errors, []);
  } finally {
    await browser.close();
    server.kill();
  }
  console.log("panel-ui-tests-ok");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
