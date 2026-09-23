const { chromium } = require('playwright-core');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({ headless: true, executablePath: 'C:/Program Files/Google/Chrome/Application/chrome.exe' });
  const output = path.resolve('../.runtime');
  const errors = [];
  const desktop = await browser.newPage({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1 });
  desktop.on('pageerror', error => errors.push(error.message));
  await desktop.goto('http://127.0.0.1:3000', { waitUntil: 'networkidle' });
  await desktop.getByText('Poisoned invoice · defended', { exact: true }).first().waitFor();
  await desktop.locator('.react-flow__node[data-id="5"]').click();
  await desktop.getByText('Blocked before delivery').waitFor();
  const graphRows = await desktop.locator('.react-flow__node').evaluateAll(nodes => new Set(nodes.map(node => Math.round(node.getBoundingClientRect().top / 20))).size);
  if (graphRows < 2) throw new Error('Workflow collapsed into a single row');
  await desktop.screenshot({ path: path.join(output, 'next-desktop.png'), fullPage: true });
  const mobile = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 1 });
  mobile.on('pageerror', error => errors.push(error.message));
  await mobile.goto('http://127.0.0.1:3000', { waitUntil: 'networkidle' });
  await mobile.screenshot({ path: path.join(output, 'next-mobile.png'), fullPage: true });
  console.log(JSON.stringify({ title: await desktop.title(), graphNodes: await desktop.locator('.react-flow__node').count(), graphRows, mobileWidth: await mobile.locator('body').evaluate(el => el.scrollWidth), errors }));
  await browser.close();
  if (errors.length) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
