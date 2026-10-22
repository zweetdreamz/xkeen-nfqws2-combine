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

async function openPanel(browser, errors) {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  page.on("pageerror", (error) => errors.push(String(error)));
  page.on("dialog", (dialog) => dialog.accept());
  await page.goto(`${BASE}/`);
  await page.waitForFunction(() => document.querySelector('[data-service="youtube"] .current').textContent !== "—");
  return page;
}

async function finishXkeenAction(page) {
  await page.click('[data-action="restart"]');
  await page.waitForFunction(() => document.getElementById("log").textContent.includes("mock"));
  // busy(false) runs in the finally block after the status refresh.
  await page.waitForFunction(() => !document.querySelector('[data-action="restart"]').disabled);
}

async function main() {
  const server = await startServer();
  const launchOptions = {};
  if (process.env.PLAYWRIGHT_CHROMIUM_PATH) {
    launchOptions.executablePath = process.env.PLAYWRIGHT_CHROMIUM_PATH;
  }
  const browser = await playwright.chromium.launch(launchOptions);
  const errors = [];
  try {
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
    await page.waitForTimeout(7000);
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
    const versionId = "20261020T100000Z-aaaaaaaaaaaa-applied-1";
    const operations = [
      ["applyImport", "/api/import/apply", () => {
        selectedReport = { service: "youtube" };
        validatedDescriptor = { service: "youtube", candidate_id: "aaaaaaaaaaaa" };
        return applyImport();
      }],
      ["clearImport", "/api/import/clear/youtube", () => clearImport("youtube")],
      ["rollbackImport", "/api/import/rollback", () => rollbackImport()],
      ["applyVersion", `/api/profiles/apply/youtube/${versionId}`, (id) => applyVersion("youtube", id)],
      ["applyTunerResult", "/api/tuner/apply", () => applyTunerResult()],
    ];
    for (const [name, apiPath, operation] of operations) {
      for (const fails of [false, true]) {
        await setMock(fails
          ? { method: "POST", path: apiPath, status: 500, body: { ok: false, error: "engine failed" } }
          : { method: "POST", path: apiPath, status: 200, body: { ok: true, output: "mock" } });
        await page.evaluate(() => { const root = document.getElementById("postApplyStatus"); root.textContent = "—"; root.className = "hint"; });
        const before = await stats();
        await page.evaluate(operation, versionId);
        const after = await stats();
        const checksCalls = (after["GET /api/checks/config"] || { count: 0 }).count - (before["GET /api/checks/config"] || { count: 0 }).count;
        const statusCalls = after["GET /api/status"].count - before["GET /api/status"].count;
        assert.equal((after[`POST ${apiPath}`] || { count: 0 }).count - (before[`POST ${apiPath}`] || { count: 0 }).count, 1, name);
        assert.ok(statusCalls >= 1, `${name}: route badges not refreshed`);
        const text = await page.textContent("#postApplyStatus");
        if (fails) {
          assert.equal(checksCalls, 0, `${name}: post-checks after an error`);
          assert.equal(text, "—", name);
        } else {
          assert.equal(checksCalls, 1, `${name}: no post-checks`);
          assert.match(text, /^Проверка не пройдена:\n• nfqws2: порты профилей в очереди — профиль 2 \(youtube\.list\): UDP 443 нет в UDP_PORTS\nВнимание:\n• NFQUEUE: переходы/, name);
          assert.equal(await page.$eval("#postApplyStatus", (root) => root.className), "bad");
        }
      }
    }
    // A check sent with the result is shown without another request.
    await setMock({
      method: "POST", path: "/api/import/rollback", status: 200,
      body: { ok: true, output: "mock", health: { ok: true, all_ok: true, checks: [{ name: "Xray", ok: true, status: "ok", detail: "x" }] } },
    });
    const before = await stats();
    await page.evaluate(() => rollbackImport());
    const after = await stats();
    assert.equal(after["GET /api/checks/config"].count, before["GET /api/checks/config"].count);
    assert.equal(await page.textContent("#postApplyStatus"), "Конфиги и службы: OK");
    await page.close();
    await setResponse("/api/tuner/status", { ok: true, status: "idle", active: false });

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
