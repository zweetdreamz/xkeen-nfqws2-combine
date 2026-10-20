/* Browser-origin probes. No router-side proxy or fetch endpoint is used. */
let browserDiagnosticRun = null;

async function clientProbe(url, method, parentSignal) {
  const controller = new AbortController();
  let timedOut = false;
  const cancel = () => controller.abort();
  parentSignal.addEventListener('abort', cancel, {once: true});
  if (parentSignal.aborted) controller.abort();
  const timer = setTimeout(() => { timedOut = true; controller.abort(); }, 10000);
  const started = performance.now();
  try {
    const options = {method, mode: 'no-cors', cache: 'no-store', credentials: 'omit',
      // Fetch requires follow for no-cors requests; other modes fail before I/O.
      redirect: 'follow', referrerPolicy: 'no-referrer', signal: controller.signal};
    if (method === 'POST') {
      options.body = crypto.getRandomValues(new Uint8Array(65536));
      options.headers = {'Content-Type': 'text/plain'};
    }
    await fetch(url, options);
    return {status: 'ok', ms: Math.round(performance.now() - started)};
  } catch (error) {
    if (parentSignal.aborted) throw error;
    return {status: timedOut ? 'timeout' : 'unknown', ms: Math.round(performance.now() - started),
      detail: timedOut ? 'Нет ответа за 10 секунд' :
        String(error && error.message ? error.message : error).slice(0, 500)};
  } finally {
    clearTimeout(timer);
    parentSignal.removeEventListener('abort', cancel);
  }
}

function browserDiagnosticProgress(run, status) {
  const percentage = Math.round(100 * run.done / Math.max(1, run.total));
  document.getElementById('diagnosticProgress').classList.add('visible');
  document.getElementById('diagnosticStatus').textContent = status;
  document.getElementById('diagnosticPercent').textContent = percentage + '%';
  document.getElementById('diagnosticBar').style.width = percentage + '%';
  document.getElementById('diagnosticSummary').textContent =
    'Из браузера: ответов ' + run.ok + ' · неопределённых/таймаутов ' + run.warn +
    ' · выполнено ' + run.done + '/' + run.total;
}

function addClientResult(target, checks) {
  const box = document.createElement('article');
  box.className = 'diagnostic-item ' + (checks.every(c => c.status === 'ok') ? 'ok' : 'warn');
  const title = document.createElement('b');
  title.textContent = target.name;
  const detail = document.createElement('div');
  detail.className = 'diagnostic-detail';
  detail.textContent = target.url;
  const tokens = document.createElement('div');
  tokens.className = 'protocols';
  checks.forEach(check => {
    const span = document.createElement('span');
    span.className = 'protocol ' + (check.status === 'ok' ? 'ok' : 'warn');
    span.textContent = check.label + ': ' +
      (check.status === 'ok' ? 'ОТВЕТ ПОЛУЧЕН' : check.status === 'timeout' ? 'ТАЙМАУТ' : 'НЕОПРЕДЕЛЁННО') +
      ' · ' + check.ms + ' мс';
    tokens.append(span);
    if (check.detail) {
      const reason = document.createElement('div');
      reason.className = 'diagnostic-detail';
      reason.textContent = check.label + ': ' + check.detail;
      box.append(reason);
    }
  });
  box.append(title, detail, tokens);
  document.getElementById('diagnosticResults').append(box);
}

async function runBrowserDiagnostic(kind) {
  if (browserDiagnosticRun || diagnosticWatch) return;
  const run = {controller: new AbortController(), done: 0, total: 0, ok: 0, warn: 0};
  browserDiagnosticRun = run;
  busy(true);
  diagnosticControls(true);
  document.getElementById('diagnosticResults').textContent = '';
  browserDiagnosticProgress(run, 'Получаю список целей…');
  try {
    const state = await api('/api/diagnostics/status');
    if (state.active) throw new Error('Сначала завершите проверку роутера');
    const [route, tuner] = await Promise.all([api('/api/route/status'), api('/api/tuner/status')]);
    if (route.active || tuner.active) throw new Error('Сначала завершите переключение маршрута или подбор');
    const data = await api('/api/diagnostics/targets');
    const targets = data[kind];
    run.total = targets.length;
    let index = 0;
    const worker = async () => {
      while (index < targets.length && !run.controller.signal.aborted) {
        const target = targets[index++];
        const baseline = await clientProbe(target.url, 'GET', run.controller.signal);
        baseline.label = 'HTTPS';
        const checks = [baseline];
        if (kind === 'dpi') {
          const transfer = await clientProbe(target.url, 'POST', run.controller.signal);
          transfer.label = 'POST 64 КиБ';
          checks.push(transfer);
        }
        if (run.controller.signal.aborted) return;
        addClientResult(target, checks);
        checks.every(c => c.status === 'ok') ? run.ok++ : run.warn++;
        run.done++;
        browserDiagnosticProgress(run, 'Проверяю из браузера…');
      }
    };
    // Settle all workers before enabling a new run, including after cancellation.
    const outcomes = await Promise.allSettled(Array.from({length: 3}, worker));
    if (!run.controller.signal.aborted) {
      const failed = outcomes.find(item => item.status === 'rejected');
      if (failed) throw failed.reason;
    }
    browserDiagnosticProgress(run, run.controller.signal.aborted ? 'Остановлено' : 'Готово — проверено из браузера');
  } catch (error) {
    run.controller.abort();
    document.getElementById('diagnosticStatus').textContent = 'Проверка прервана';
    document.getElementById('diagnosticSummary').textContent = String(error);
  } finally {
    browserDiagnosticRun = null;
    busy(false);
    diagnosticControls(false);
  }
}
