// PRV-10: management credentials never enter the guest.
const LIMIT=16*1024*1024, OUTPUT=8*1024*1024;
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const PRIVATE=/^\/tmp\/\.sandprobe-[A-Za-z0-9]{12}$/;
const reply=(value,status=200)=>Response.json(value,{status});
export async function boundedBody(request) {return boundedStream(request.body,LIMIT);}
async function boundedStream(stream,limit=OUTPUT) {
  if(!stream)return new Uint8Array();
  const reader=stream.getReader(),chunks=[];let size=0;
  try{for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>limit)throw Error('limit');chunks.push(value);}}
  catch(e){await reader.cancel().catch(()=>{});throw e;}
  const data=new Uint8Array(size);let offset=0;for(const c of chunks){data.set(c,offset);offset+=c.length;}return data;
}
export async function gateway(request,env) {
  try{
    const bearer=request.headers.get('authorization')||'';
    if(!/^Bearer [a-f0-9]{64}$/.test(bearer))return reply({error:'unauthorized'},401);
    const hash=Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(bearer.slice(7))))).map(b=>b.toString(16).padStart(2,'0')).join('');
    if(hash!==env.AUTH_SHA256)return reply({error:'unauthorized'},401);
    const url=new URL(request.url);
    if(request.method!=='POST'||!['/create','/status','/exec','/upload','/destroy'].includes(url.pathname)||url.search)return reply({error:'route'},404);
    if(request.headers.get('x-sandprobe-run')!==env.RUN_NONCE)return reply({error:'identity'},409);
    return await env.BOX.get(env.BOX.idFromName(env.RUN_NONCE)).fetch(request);
  }catch{return reply({error:'controller_failure'},502);}
}
export function controllerClass(Base){return class SandprobeBox extends Base{
  constructor(ctx,env){super(ctx,env);this.ctx=ctx;this.env=env;this.busy=false;
    if(ctx.container?.running)ctx.blockConcurrencyWhile(()=>ctx.container.setInactivityTimeout(120000));}
  async fence(){await this.ctx.storage.put('closed',true);await this.ctx.container.destroy();}
  async alarm(){await this.fence();}
  async raw(argv,input=new Uint8Array()){
    let timer;
    const execute=(async()=>{
      const process=await this.ctx.container.exec(argv,{stdin:new Response(input).body,stderr:'ignore',env:{SANDPROBE_TWIN:'1'}});
      const [data,exit]=await Promise.all([boundedStream(process.stdout),process.exitCode]);
      if(!Number.isInteger(exit)||exit!==0)throw Error('command_failed');return data;
    })();
    const deadline=new Promise((_,reject)=>{timer=setTimeout(()=>{void this.fence().catch(()=>{});reject(Error('command_timeout'));},95000);});
    try{return await Promise.race([execute,deadline]);}
    catch(e){await this.fence().catch(()=>{});throw e;}finally{clearTimeout(timer);}
  }
  async boot(){const text=new TextDecoder().decode(await this.raw(['/bin/cat','/proc/sys/kernel/random/boot_id'])).trim();if(!UUID.test(text))throw Error('boot_identity');return text;}
  async alive(expected){const state=await this.ctx.storage.get(['created','closed','expires','boot']);
    if(!state.get('created')||state.get('closed')||Date.now()>=state.get('expires')||!this.ctx.container.running)throw Error('not_running');
    if(expected!==state.get('boot')||await this.boot()!==expected){await this.fence();throw Error('identity');}}
  async fetch(request){
    if(this.busy)return reply({error:'busy'},409);this.busy=true;
    try{const op=new URL(request.url).pathname,body=await boundedBody(request),value=op==='/upload'?null:JSON.parse(new TextDecoder().decode(body)||'{}'),id=this.ctx.id.toString();
      if(op==='/create'){
        if(await this.ctx.storage.get('created'))return reply({error:'create_used'},409);
        if(value.nonce!==this.env.RUN_NONCE)return reply({error:'identity'},409);
        const expires=Date.now()+900000;
        await this.ctx.storage.put({created:true,expires});await this.ctx.storage.setAlarm(expires);
        this.ctx.container.start({image:'cloudflare/debian-trixie',entrypoint:['sleep','infinity'],instance:'lite',enableInternet:true});
        await this.ctx.container.setInactivityTimeout(120000);
        // Native exec waits for its process; no retry, restart or second start.
        const boot=await this.boot();await this.ctx.storage.put('boot',boot);
        return reply({id,boot,expires,image:'cloudflare/debian-trixie'});
      }
      if(op==='/destroy'){if(value.id!==id)return reply({error:'identity'},409);await this.fence();return reply({id,created:!!await this.ctx.storage.get('created'),closed:true,running:this.ctx.container.running});}
      if(op==='/status')return reply({id,created:!!await this.ctx.storage.get('created'),closed:!!await this.ctx.storage.get('closed'),running:this.ctx.container.running});
      if(request.headers.get('x-sandprobe-id')!==id)return reply({error:'identity'},409);
      await this.alive(request.headers.get('x-sandprobe-boot'));
      if(op==='/exec'){
        if(!Array.isArray(value.argv)||value.argv.length<1||value.argv.length>16||value.argv.some(x=>typeof x!=='string'||x.length>16384||x.includes('\0')))return reply({error:'argv'},400);
        const data=await this.raw(value.argv,Uint8Array.from(atob(value.stdin||''),c=>c.charCodeAt(0)));
        return reply({id,stdout:new TextDecoder().decode(data),exit_code:0});
      }
      if(op==='/upload'){
        const dir=request.headers.get('x-sandprobe-dir');if(!PRIVATE.test(dir||''))return reply({error:'path'},400);
        await this.raw(['/bin/sh','-c',`test -d '${dir}' && test ! -L '${dir}' && umask 077 && set -C && cat > '${dir}/probe' && chmod 700 '${dir}/probe'`],body);
        return reply({id,uploaded:true});
      }
      return reply({error:'route'},404);
    }catch{if(await this.ctx.storage.get('created'))await this.fence().catch(()=>{});return reply({error:'operation_failed'},502);}finally{this.busy=false;}
  }
};}
