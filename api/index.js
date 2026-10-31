'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const E=process.env,BASE=(E.BASE_URL||'https://'+E.VERCEL_URL).replace(/\/$/,'');
const OWNER=E.ADMIN_ID||'1009385844920025148',CID=E.DISCORD_CLIENT_ID,CSEC=E.DISCORD_CLIENT_SECRET;
const API=E.DISCORD_API||'https://discord.com/api',AUTHZ=E.DISCORD_AUTHORIZE||'https://discord.com/oauth2/authorize';
const SECRET=E.SESSION_SECRET||crypto.randomBytes(32).toString('hex');
const SECURE=BASE.startsWith('https'),TP=true;
const DUR={'30m':18e5,'1h':36e5,'5h':18e6,'1d':864e5,'1w':6048e5,'1m':2592e6,life:0},PRODUCTS=['online','offline'];

const KV_URL = E.KVSKIBIDI_KV_REST_API_URL;
const KV_TOKEN = E.KVSKIBIDI_KV_REST_API_TOKEN;

let db={users:{},keys:{}}, dbLoaded = false;

const loadDb = async () => {
  if (dbLoaded || !KV_URL) return;
  try {
    const r = await fetch(KV_URL + '/get/htp_db', { headers: { Authorization: 'Bearer ' + KV_TOKEN } });
    const j = await r.json();
    if (j.result) db = JSON.parse(j.result);
    dbLoaded = true;
  } catch(e) { console.error('KV Load', e); }
};

const save = async () => {
  if (!KV_URL) return;
  try {
    await fetch(KV_URL + '/set/htp_db', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + KV_TOKEN },
      body: JSON.stringify(JSON.stringify(db))
    });
  } catch(e) { console.error('KV Save', e); }
};

const now=()=>Date.now(),live=x=>x===0||x>now(),add=(c,ms)=>c===0||ms===0?0:Math.max(now(),c||0)+ms;
const sig=d=>crypto.createHmac('sha256',SECRET).update(d).digest('base64url');
const seal=o=>{const d=Buffer.from(JSON.stringify(o)).toString('base64url');return d+'.'+sig(d)};
const unseal=c=>{try{const[d,s]=c.split('.'),x=sig(d);if(!s||s.length!==x.length||!crypto.timingSafeEqual(Buffer.from(s),Buffer.from(x)))return null;const o=JSON.parse(Buffer.from(d,'base64url'));return o.e>now()?o:null}catch{return null}};
const jar=h=>Object.fromEntries((h||'').split(';').map(x=>{const i=x.indexOf('=');return[x.slice(0,i).trim(),x.slice(i+1).trim()]}).filter(x=>x[0]));
const ck=(n,v,age)=>`${n}=${v}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${age}${SECURE?'; Secure':''}`;
const CSP="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' https://cdn.discordapp.com data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'";
const send=(r,c,b,t='text/plain',h={})=>{r.writeHead(c,{'Content-Type':t+'; charset=utf-8','Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'same-origin','Content-Security-Policy':CSP,...h});r.end(b)};
const json=(r,c,o)=>send(r,c,JSON.stringify(o),'application/json');
const go=(r,u,h={})=>{r.writeHead(302,{Location:u,'Cache-Control':'no-store',...h});r.end()};
const file=f=>fs.readFileSync(path.join(__dirname, '..', f));
const page=(r,f)=>send(r,200,file(f),'text/html');
const nf=r=>send(r,404,'Not found');

const rl=new Map(),hit=(k,max,win)=>{const t=now(),a=(rl.get(k)||[]).filter(x=>t-x<win);a.push(t);rl.set(k,a);return a.length<=max};
const body=q=>new Promise(ok=>{let s='';q.on('data',c=>{s+=c;if(s.length>1e4)q.destroy()});q.on('end',()=>{try{ok(JSON.parse(s||'{}'))}catch{ok({})}});q.on('error',()=>ok({}))});
const AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789',kh=k=>crypto.createHash('sha256').update(String(k).trim().toUpperCase()).digest('hex');
const mkKey=()=>'HTP-'+[0,1,2].map(()=>Array.from({length:5},()=>AL[crypto.randomInt(AL.length)]).join('')).join('-');

module.exports = async (q, r) => {
  try {
    await loadDb();
    const u=new URL(q.url,BASE),p=u.pathname,m=q.method,ip=((TP&&q.headers['x-forwarded-for'])||'').split(',')[0].trim()||q.socket.remoteAddress;
    const s=unseal(jar(q.headers.cookie).s||''),usr=s&&(db.users[s.u]||(db.users[s.u]={access:{}}));
    const admin=!!s&&(s.u===OWNER||live(usr.admin)),can=pr=>!!s&&live(usr.access[pr]);
    
    if(m==='GET'){
     if(p==='/')return page(r,'public/landing.html');
     if(p==='/brand.css')return send(r,200,file('public/brand.css'),'text/css');
     if(p==='/admin')return admin?page(r,'protected/admin.html'):nf(r);
     const a=p.match(/^\/app\/(online|offline)$/);
     if(a)return can(a[1])?page(r,'protected/'+a[1]+'.html'):go(r,'/');
     if(p==='/api/me')return json(r,200,{user:s?{id:s.u,name:s.n,avatar:s.a}:null,admin,owner:!!s&&s.u===OWNER,access:Object.fromEntries(PRODUCTS.map(x=>[x,s&&live(usr.access[x])?usr.access[x]:null]))});
     if(p==='/auth/login'){if(!CID)return send(r,500,'Discord app not configured');const st=crypto.randomBytes(16).toString('hex');
      return go(r,AUTHZ+'?'+new URLSearchParams({client_id:CID,response_type:'code',scope:'identify',redirect_uri:BASE+'/auth/callback',state:st,prompt:'none'}),{'Set-Cookie':ck('st',st,600)})}
     if(p==='/auth/callback'){
      const st=jar(q.headers.cookie).st,code=u.searchParams.get('code');
      if(!code||!st||u.searchParams.get('state')!==st)return send(r,400,'Login failed. Go back and try again.');
      const t=await(await fetch(API+'/oauth2/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams({client_id:CID,client_secret:CSEC,grant_type:'authorization_code',code,redirect_uri:BASE+'/auth/callback'})})).json();
      if(!t.access_token)return send(r,400,'Login failed');
      const d=await(await fetch(API+'/users/@me',{headers:{Authorization:'Bearer '+t.access_token}})).json();
      if(!/^\d{15,25}$/.test(d.id||''))return send(r,400,'Login failed');
      const x=db.users[d.id]||(db.users[d.id]={access:{}});x.name=d.global_name||d.username||'user';x.avatar=d.avatar?`https://cdn.discordapp.com/avatars/${d.id}/${d.avatar}.png?size=64`:null;
      await save();
      return go(r,'/',{'Set-Cookie':[ck('s',seal({u:d.id,n:x.name,a:x.avatar,e:now()+6048e5}),604800),ck('st','',0)]});
     }
     if(p==='/api/admin/keys'){if(!admin)return nf(r);
      return json(r,200,Object.entries(db.keys).sort((a,b)=>b[1].at-a[1].at).slice(0,200).map(([h,k])=>({id:h.slice(0,12),hint:k.hint,type:k.type,product:k.product,dur:k.dur,at:k.at,used:k.used?(db.users[k.used.by]?.name||k.used.by):null,revoked:!!k.revoked})))}
     return nf(r);
    }
    if(m==='POST'){
     if(q.headers.origin!==BASE||!/json/.test(q.headers['content-type']||''))return send(r,403,'Forbidden');
     if(p==='/auth/logout')return send(r,200,'{"ok":1}','application/json',{'Set-Cookie':ck('s','',0)});
     if(!s)return json(r,401,{error:'Log in first'});
     const b=await body(q);
     if(p==='/api/redeem'){
      if(!hit('rd:'+s.u,8,6e5)||!hit('ri:'+ip,20,6e5))return json(r,429,{error:'Too many attempts. Wait a few minutes.'});
      const k=db.keys[kh(b.key)];
      if(!k||k.used||k.revoked)return json(r,400,{error:'Invalid or already used key'});
      k.used={by:s.u,at:now()};
      if(k.type==='admin')usr.admin=add(usr.admin,k.ms);else usr.access[k.product]=add(usr.access[k.product],k.ms);
      await save();return json(r,200,{ok:1});
     }
     if(p==='/api/admin/gen'){
      if(!admin)return nf(r);if(!hit('ad:'+s.u,60,6e5))return json(r,429,{error:'Slow down'});
      const type=b.type==='admin'?'admin':'access';
      if(typeof b.dur!=='string'||!Object.hasOwn(DUR,b.dur)||(type==='access'&&!PRODUCTS.includes(b.product)))return json(r,400,{error:'Bad options'});
      if(type==='admin'&&s.u!==OWNER)return json(r,403,{error:'Only the owner can create admin keys'});
      const n=Math.min(Math.max(+b.count|0,1),25),out=[];
      for(let i=0;i<n;i++){const k=mkKey();db.keys[kh(k)]={hint:k.slice(-4),type,product:type==='admin'?null:b.product,dur:b.dur,ms:DUR[b.dur],by:s.u,at:now(),used:null};out.push(k)}
      await save();return json(r,200,{keys:out});
     }
     if(p==='/api/admin/revoke'){
      if(!admin)return nf(r);const id=String(b.id);if(id.length<8)return json(r,400,{error:'Bad id'});
      const h=Object.keys(db.keys).find(x=>x.startsWith(id));if(!h||db.keys[h].used)return json(r,400,{error:'Only unused keys can be revoked'});
      db.keys[h].revoked=true;await save();return json(r,200,{ok:1});
     }
    }
    nf(r);
  } catch(e) {
    console.error(e);
    try { send(r,500,'Server error') } catch{}
  }
};
