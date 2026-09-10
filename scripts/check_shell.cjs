// Usage: node scripts/check_shell.cjs evaluated-dashboard.html [screenshots-dir]
// Requires Playwright and Chrome; API fixtures never execute incident actions.
const fs = require('fs');
const path = require('path');
const assert = require('node:assert/strict');
const {chromium} = require('playwright');
(async () => {
  const browser = await chromium.launch({channel:process.env.BROWSER_CHANNEL || 'chrome', headless:true});
  try {
    const page = await browser.newPage();
    const errors=[];
    page.on('pageerror', e=>errors.push(e.message));
    const html=fs.readFileSync(process.argv[2],'utf8');
    const approval={approval_id:'approval-1',incident_id:'INC-006-CONFIG-REGRESSION',action:'cloud_run_rollback',status:'APPROVED',risk:'LOW',expiration_time:'2099-01-01T00:00:00Z',decided_by:'operator',decided_at:'2026-09-10T12:00:00Z',decided_message:'Reviewed',target_resource:'checkout-service'};
    await page.route('**/*', async route=>{
      const url=new URL(route.request().url());
      if(url.pathname==='/') return route.fulfill({contentType:'text/html',body:html});
      if(!url.pathname.startsWith('/api/') && url.pathname!='/health') return route.fulfill({body:''});
      assert.equal(route.request().method(),'GET','Layout checks must never execute actions');
      let data=[];
      if(url.pathname==='/api/projects') data=[{project_id:'checkout',name:'Checkout Platform',environment:'production',open_incidents:2},{project_id:'test',name:'test',environment:'demo',open_incidents:0}];
      else if(url.pathname==='/api/approvals/pending') data=[{...approval,status:'PENDING',approval_id:'pending-1'}];
      else if(url.pathname==='/api/approvals/recent') data=Array.from({length:30},(_,i)=>({...approval,approval_id:`history-${i}`}));
      else if(url.pathname.startsWith('/api/approvals/')) data=approval;
      else if(url.pathname==='/health') data={version:'local'};
      await route.fulfill({contentType:'application/json',body:JSON.stringify(data)});
    });
    await page.goto('http://shell.test/');
    for(const [width,height] of [[1920,1080],[1600,900],[1440,900],[1366,768],[1024,768]]){
      await page.setViewportSize({width,height});
      for(const view of ['home','projects','incidents','approvals']){
        await page.evaluate(view=>showView(view),view);
        if(view==='approvals') await page.evaluate(()=>loadApprovalCenter());
        if(view==='incidents') await page.evaluate(()=>openIncident('INC-006-CONFIG-REGRESSION'));
        const boxes=await page.evaluate(()=>{
          const side=document.querySelector('.sidebar'),main=document.querySelector('main');
          return {side:side.getBoundingClientRect().toJSON(),main:main.getBoundingClientRect().toJSON(),overflow:document.documentElement.scrollWidth-document.documentElement.clientWidth,
            routes:[...document.querySelectorAll('[id^="view-"]')].every(e=>e.parentElement===main),visible:[...document.querySelectorAll('.view')].filter(e=>getComputedStyle(e).display!=='none').length,
            brand:parseFloat(getComputedStyle(document.querySelector('.brand')).fontSize),history:side.querySelectorAll('details').length,bodyHeight:document.body.getBoundingClientRect().height,
            contentOverflow:main.scrollWidth-main.clientWidth,sidebarOverflow:side.scrollWidth-side.clientWidth,
            title:document.querySelector('#inc-title').getBoundingClientRect().toJSON()};
        });
        assert.equal(boxes.routes,true,'Every route belongs to main');
        assert.equal(boxes.visible,1,'Exactly one route visible');
        assert.equal(boxes.side.width,width>=1200?272:232);
        assert.equal(boxes.side.left,0);
        assert.equal(boxes.main.left,boxes.side.right);
        assert.equal(boxes.main.right,width);
        assert.equal(boxes.main.bottom,height);
        assert.equal(boxes.bodyHeight,height);
        assert.ok(boxes.overflow<=1);
        assert.ok(boxes.contentOverflow<=1,'Main content is not horizontally clipped');
        assert.ok(boxes.sidebarOverflow<=1,'Sidebar content wraps within its column');
        assert.ok(boxes.brand>=18 && boxes.brand<=22);
        assert.equal(boxes.history,0);
        if(width===1440) assert.ok(boxes.main.width>=1000);
        if(view==='incidents') assert.ok(boxes.title.top>=60 && boxes.title.bottom<height,'Incident visible initially');
        if(view==='approvals') assert.equal(await page.locator('#approval-history button').filter({hasText:'Execute'}).count(),0);
        if(process.argv[3] && view==='incidents'){
          fs.mkdirSync(process.argv[3],{recursive:true});
          await page.screenshot({path:path.join(process.argv[3],`shell-${width}.png`)});
        }
      }
      console.log(`${width}x${height}: 4 routes passed`);
    }
    await page.evaluate(a=>{LAST_INCIDENT=a.incident_id;renderRemediation({action:a.action},a,'ALLOWED_WITH_APPROVAL');},approval);
    assert.equal(await page.locator('#remediation-box button').filter({hasText:'Execute & Verify'}).count(),1);
    for(const extra of [{status:'REJECTED'},{expiration_time:'2000-01-01T00:00:00Z'},{incident_id:'old-incident'}]){
      await page.evaluate(a=>renderRemediation({action:a.action},a,'ALLOWED_WITH_APPROVAL'),{...approval,...extra});
      assert.equal(await page.locator('#remediation-box button').filter({hasText:'Execute & Verify'}).count(),0);
    }
    await page.setViewportSize({width:1440,height:900});
    await page.evaluate(()=>{
      document.querySelector('.proj-row .lbl').textContent='INC-006-CONFIG-REGRESSION'.repeat(12);
      renderApprovalSummary(Array.from({length:100},()=>({})));
    });
    assert.equal(await page.locator('.sidebar').evaluate(e=>e.scrollWidth<=e.clientWidth),true);
    assert.equal(await page.locator('.sidebar').evaluate(e=>e.getBoundingClientRect().width),272);
    await page.evaluate(()=>toggleSidebar());
    assert.equal(await page.locator('.sidebar').evaluate(e=>e.getBoundingClientRect().width),72);
    await page.setViewportSize({width:390,height:844});
    await page.evaluate(()=>{showView('home');toggleSidebar();});
    await page.locator('.sidebar').evaluate(e=>e.getAnimations().forEach(a=>a.finish()));
    assert.equal(await page.locator('.sidebar').evaluate(e=>Math.round(e.getBoundingClientRect().left)),0);
    assert.equal(await page.locator('.sidebar .lbl').first().isVisible(),true,'Mobile drawer retains labels after desktop collapse');
    await page.keyboard.press('Escape');
    assert.equal(await page.evaluate(()=>document.body.classList.contains('drawer-open')),false);
    assert.deepEqual(errors,[]);
    console.log('Mobile drawer, approval placement and JavaScript checks passed');
  } finally { await browser.close(); }
})().catch(e=>{console.error(e);process.exitCode=1;});
