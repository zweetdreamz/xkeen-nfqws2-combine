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
  const output = process.env.KDN_SCREENSHOT_OUTPUT || path.join(root, 'docs/images');
  const width = Number(process.env.KDN_SCREENSHOT_WIDTH || 1440);
  const theme = process.env.KDN_SCREENSHOT_THEME === 'dark' ? 'dark' : 'light';
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
    const context = await browser.newContext({viewport: {width, height: 2200}, locale: 'ru-RU', timezoneId: 'Europe/Moscow', colorScheme:theme, reducedMotion:'reduce', serviceWorkers: 'block'});
    // This is an offline UI render, not a connection to the router or ntfy.
    await context.route('**/*', route => route.abort());
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.setContent(html);
    await page.addScriptTag({content: script});
    await page.evaluate(async theme => {
      document.documentElement.dataset.theme = theme;
      syncThemeButton();
      window.fetch = async () => { throw new Error('Network disabled in screenshot renderer'); };
      document.getElementById('dot').className = 'dot ok';
      document.getElementById('statusText').textContent = 'XKeen работает';
      const note = document.createElement('div');
      note.textContent = 'Демонстрация интерфейса · приватные данные скрыты';
      note.style = 'color:var(--faint);font-size:11px;margin:-8px 0 18px';
      document.querySelector('.page-heading').after(note);
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
      const nodes = [
        {id:'primary',name:'Основная',protocol:'vless',network:'tcp',security:'reality',active:true},
        {id:'backup',name:'Резервная',protocol:'trojan',network:'tcp',security:'tls',active:false},
        {id:'mobile',name:'Мобильная',protocol:'hysteria2',network:'udp',security:'tls',active:false},
      ].map(node => ({...node,endpoint:'████████:████',sni:'Скрыт',
        ping:{ok:true,latency_ms:85,http_code:204},health:null}));
      window.fetch = async url => {
        if (url !== '/api/vpn-nodes') throw new Error('Network disabled in screenshot renderer');
        return {ok:true,json:async()=>({ok:true,nodes,active:'primary',canonical_tag:'vless-reality',recovery_needed:false})};
      };
      syncNavigation('vpn-nodes');
      await refreshVpnNodes();
      window.fetch = async () => { throw new Error('Network disabled in screenshot renderer'); };
      syncNavigation('control');
    }, theme);
    await fs.mkdir(output, {recursive:true});
    for (const [tab, filename, endSelector] of [
      ['control','control.png','#control > section:nth-of-type(3)'],
      ['vpn-nodes','vpn-nodes.png','#vpn-nodes > section:first-child'],
      ['automation','schedule.png','#automation > section:last-child'],
      ['notifications','notifications.png','#notifications > section:first-child'],
    ]) {
      await page.evaluate(id => syncNavigation(id), tab);
      const box = await page.locator(endSelector).boundingBox();
      if (!box) throw new Error('Missing screenshot boundary: '+endSelector);
      const height = Math.ceil(box.y+box.height+22);
      await page.evaluate(async height => {
        document.querySelector('.sidebar').style.height = `${height}px`;
        window.scrollTo(0, 0);
        await new Promise(requestAnimationFrame);
      }, height);
      await page.screenshot({path:path.join(output,filename), animations:'disabled', clip:{x:0,y:0,width,height}});
    }
    if (errors.length) throw new Error(errors.join('\n'));
    console.log(`Saved 4 offline screenshots (${theme}, ${width}px) to ${output}`);
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error.message); process.exitCode=1; });
