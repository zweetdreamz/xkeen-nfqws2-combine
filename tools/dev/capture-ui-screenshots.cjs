/* Offline README captures: render only the public template and invented data.
 * Usage: node tools/dev/capture-ui-screenshots.cjs
 * Requires Playwright and its Chromium (or KDN_SCREENSHOT_BROWSER executable).
 * Never reads router files, credentials, cached responses, or browser profiles.
 */
const fs = require('node:fs/promises');
const path = require('node:path');
const {chromium} = require('playwright');

async function main() {
  const root = path.resolve(__dirname, '../..');
  const output = path.join(root, 'docs/images');
  const source = await fs.readFile(path.join(root, 'tools/router/kdn/web/assets/index.html'), 'utf8');
  const inline = [...source.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)]
    .map(match => match[1]).find(code => code.includes('function updateService'));
  if (!inline || !inline.includes('log("панель готова",true);')) throw new Error('Template bootstrap changed');
  const script = inline.slice(0, inline.indexOf('log("панель готова",true);'));
  const html = source.replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, '')
    .replace('__SERVICE_CONFIG_SECTION__', '');
  const browser = await chromium.launch({
    ...(process.env.KDN_SCREENSHOT_BROWSER ? {executablePath: process.env.KDN_SCREENSHOT_BROWSER} : {}),
    headless: true,
    args: ['--disable-background-networking', '--disable-component-update', '--no-proxy-server'],
  });
  try {
    const context = await browser.newContext({viewport: {width: 1440, height: 1400}, locale: 'ru-RU', timezoneId: 'Europe/Moscow', colorScheme:'dark', reducedMotion:'reduce', serviceWorkers: 'block'});
    // This is an offline UI render, not a connection to the router or ntfy.
    await context.route('**/*', route => route.abort());
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setContent(html);
    await page.addScriptTag({content: script});
    await page.evaluate(() => {
      window.fetch = async () => { throw new Error('Network disabled in screenshot renderer'); };
      document.getElementById('dot').className = 'dot ok';
      document.getElementById('statusText').textContent = 'XKeen работает';
      const note = document.createElement('div');
      note.textContent = 'Демонстрация интерфейса · приватные данные скрыты';
      note.style = 'color:var(--faint);font-size:12px;text-align:right;margin-bottom:12px';
      document.querySelector('.tabs').after(note);
      for (const [service, mode] of Object.entries({'discord-tcp':'zapret', 'discord-voice':'zapret', youtube:'zapret', telegram:'vpn'})) updateService(service, mode);
      renderDnsMode({supported:true, interface:'Home', mode:'vless'});
      renderAutomation({active:false, config:{enabled:true, times:['03:00', '15:00'], services:Object.fromEntries(['youtube','discord-tcp'].map(id => [id,{enabled:true,mix_level:'safe',max_candidates:32,source_file:''}]))}, state:{status:'idle'}, next_run:null}, true);
      document.getElementById('automationSummary').textContent = 'Включено · ожидание запуска';
      renderNotifications({enabled:true, topic:'', events:['youtube-updated','discord-updated','vpn-down','vpn-recovered'], pending:0, choices:[
        {id:'youtube-updated',title:'YouTube: профиль обновлён'}, {id:'discord-updated',title:'Discord: профиль обновлён'},
        {id:'night-error',title:'Ночная проверка: ошибка'}, {id:'restored',title:'Профиль восстановлен'},
        {id:'vpn-down',title:'VPN: проверка не проходит'}, {id:'vpn-ip',title:'VPN: изменился выходной IP'},
        {id:'vpn-recovered',title:'VPN снова работает'}, {id:'inspection-unavailable',title:'Контроль VPN недоступен'},
      ]}, true);
      document.getElementById('notifyTopic').value = '████████ · скрыто';
      document.getElementById('notifyToken').placeholder = 'Скрыто';
      document.getElementById('vpnSummary').textContent = 'Активна: Основная · 3 ноды. Все VPN-правила используют тег vless-reality.';
      const list = document.getElementById('vpnNodesList');
      for (const [name, protocol, network, security, active] of [
        ['Основная','VLESS','TCP','REALITY',true], ['Резервная','TROJAN','TCP','TLS',false], ['Мобильная','HYSTERIA2','UDP','TLS',false],
      ]) {
        const card = document.createElement('article'); card.className = 'vpn-node-card' + (active?' active':'');
        // Constants only: no real endpoint, SNI, UUID, password or key is read.
        card.innerHTML = `<div class="vpn-node-head"><div class="vpn-node-title"><b>${name}</b><code class="vpn-node-endpoint">████████:████</code></div><span class="${active?'good':'current'}">${active?'АКТИВНА':'РЕЗЕРВ'}</span></div><div class="vpn-node-meta vpn-node-tags"><span class="vpn-node-tag protocol">${protocol}</span><span class="vpn-node-tag transport">${network}</span><span class="vpn-node-tag security">${security}</span><span class="vpn-node-tag sni">SNI скрыт</span></div><div class="vpn-node-health good">Демонстрационный результат · соединение работает · 85 мс · HTTP 200</div><div class="vpn-node-actions"><button>Редактировать</button><button>Проверить</button>${active?'':'<button class="apply">Сделать активной</button>'}</div>`;
        list.append(card);
      }
    });
    await fs.mkdir(output, {recursive:true});
    for (const [tab, filename, endSelector] of [
      ['control','control.png','#control > section:nth-of-type(3)'],
      ['vpn-nodes','vpn-nodes.png','#vpn-nodes > section:first-child'],
      ['automation','schedule.png','#automation > section:last-child'],
      ['notifications','notifications.png','#notifications > section:first-child'],
    ]) {
      await page.evaluate(id => {
        document.querySelectorAll('.tab-page').forEach(el => el.classList.toggle('active',el.id===id));
        document.querySelectorAll('.tab').forEach(el => el.classList.toggle('active',el.dataset.tab===id));
      }, tab);
      const box = await page.locator(endSelector).boundingBox();
      if (!box) throw new Error('Missing screenshot boundary: '+endSelector);
      await page.screenshot({path:path.join(output,filename), animations:'disabled', clip:{x:0,y:0,width:1440,height:Math.ceil(box.y+box.height+22)}});
    }
    if (errors.length) throw new Error(errors.join('\n'));
    console.log('Saved 4 offline screenshots with demonstration data to docs/images');
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode=1; });
