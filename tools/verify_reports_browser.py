from pathlib import Path
import json
from playwright.sync_api import sync_playwright
p=Path(__file__).resolve().parents[1]
out=[]
with sync_playwright() as playwright:
 browser=playwright.chromium.launch(headless=True, executable_path='/usr/bin/chromium',args=['--no-sandbox'])
 for name in ('Requirements','Closeout'):
  path=p / f'HMT_DevSecOps_{name}_v1.0.0.html'
  page=browser.new_page(viewport={'width':1280,'height':900},device_scale_factor=1)
  errors=[]
  page.on('pageerror',lambda exc: errors.append(str(exc)))
  page.set_content(path.read_text(),wait_until='load')
  page.wait_for_timeout(300)
  circles=page.locator('svg circle').count()
  assert circles==14,(name,circles)
  if name=='Requirements':
   assert page.locator('#req-rows tr').count()==16
   page.locator('#search').fill('REQ-006')
   assert page.locator('#req-rows tr:visible').count()==1
   page.locator('#impact-id').select_option('REQ-006')
   page.locator('#impact').click()
   assert 'HTTP' in page.locator('#impact-result').inner_text()
  else:
   assert page.locator('#gate-rows tr').count()==25
   page.locator('#filter').select_option('HOLD')
   assert page.locator('#gate-rows tr:visible').count()==10
  assert not errors,errors
  img=p/'evidence'/f'HMT_DevSecOps_{name}_v1.0.0.png'
  page.screenshot(path=str(img),full_page=True)
  out.append({'report':name,'graph_nodes':circles,'screenshot':str(img.relative_to(p)),'javascript_errors':errors,'status':'PASS'})
  page.close()
 browser.close()
(p/'evidence/browser_reconciliation.json').write_text(json.dumps(out,indent=2)+'\n')
print(json.dumps(out,indent=2))
