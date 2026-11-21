import { test } from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import { gateway, controllerClass, boundedBody } from './controller.mjs';
if(!globalThis.crypto)Object.defineProperty(globalThis,"crypto",{value:webcrypto});
const boot='12345678-1234-1234-1234-123456789abc';
const id='a'.repeat(64), nonce='b'.repeat(32), cap='c'.repeat(64);
function fixture(){
 const data=new Map();let starts=0,destroys=0;
 const ctx={id:{toString:()=>id},blockConcurrencyWhile:fn=>fn(),storage:{async get(k){return Array.isArray(k)?new Map(k.map(x=>[x,data.get(x)])):data.get(k);},async put(k,v){if(typeof k==='object')for(const [a,b] of Object.entries(k))data.set(a,b);else data.set(k,v);},async setAlarm(t){data.set('alarm',t);}},container:{running:false,start(){starts++;this.running=true;},async setInactivityTimeout(){},async destroy(){destroys++;this.running=false;},async exec(){return {stdout:new Response(boot+'\n').body,exitCode:Promise.resolve(0)};}}};
 const Box=controllerClass(class{}),box=new Box(ctx,{RUN_NONCE:nonce});
 const req=(path,value={},headers={})=>box.fetch(new Request('https://controller.invalid'+path,{method:'POST',body:JSON.stringify(value),headers}));
 return {ctx,data,box,req,starts:()=>starts,destroys:()=>destroys};
}
test('authentication fails before DO selection',async()=>{
 const env={BOX:{idFromName(){throw Error('must not select');}}};
 assert.equal((await gateway(new Request('https://test.invalid/exec',{method:'POST'}),env)).status,401);
});
test('valid capability cannot change nonce or route',async()=>{
 const hash=Buffer.from(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(cap))).toString('hex');
 const env={AUTH_SHA256:hash,RUN_NONCE:nonce,BOX:{idFromName(){throw Error('must not select');}}};
 const req=new Request('https://test.invalid/create',{method:'POST',headers:{authorization:'Bearer '+cap,'x-sandprobe-run':'wrong'}});
 assert.equal((await gateway(req,env)).status,409);
});
test('create is once only; destroy permanently fences without restart',async()=>{
 const f=fixture();assert.equal((await f.req('/create',{nonce})).status,200);assert.equal(f.starts(),1);
 assert.equal((await f.req('/create',{nonce})).status,409);
 assert.equal((await f.req('/destroy',{id:'wrong'})).status,409);assert.equal(f.destroys(),0);
 assert.equal((await f.req('/destroy',{id})).status,200);assert.equal(f.ctx.container.running,false);
 assert.equal((await f.req('/create',{nonce})).status,409);assert.equal(f.starts(),1);
});
test('expiry alarm fences and stops box',async()=>{
 const f=fixture();await f.req('/create',{nonce});assert.ok(f.data.get('alarm')>Date.now());await f.box.alarm();assert.equal(f.data.get('closed'),true);assert.equal(f.ctx.container.running,false);
});
test('changed boot identity stops guest operations and destroys container',async()=>{
 const f=fixture();await f.req('/create',{nonce});
 const r=await f.req('/exec',{argv:['/bin/true']},{'x-sandprobe-id':id,'x-sandprobe-boot':'87654321-1234-1234-1234-123456789abc'});
 assert.equal(r.status,502);assert.equal(f.ctx.container.running,false);assert.equal(f.starts(),1);
});
test('body limit rejects streamed oversized input',async()=>{
 const body=new ReadableStream({start(c){c.enqueue(new Uint8Array(16*1024*1024+1));c.close();}});
 await assert.rejects(()=>boundedBody(new Request('https://test.invalid',{method:'POST',body,duplex:'half'})));
});
test('stalled exec acquisition has a deadline and fences container',async(t)=>{
 t.mock.timers.enable({apis:['setTimeout']});
 const f=fixture();f.ctx.container.exec=()=>new Promise(()=>{});
 const pending=f.box.raw(['/bin/true']);t.mock.timers.tick(95000);
 await assert.rejects(pending);assert.equal(f.ctx.container.running,false);assert.equal(f.data.get('closed'),true);
});
test('bootstrap execution failure fences instead of retaining a live box',async()=>{
 const f=fixture();f.ctx.container.exec=async()=>{throw Error('private-provider-error');};
 const response=await f.req('/create',{nonce});assert.equal(response.status,502);assert.equal(f.ctx.container.running,false);
 assert.ok(!(await response.text()).includes('private-provider-error'));
});
