const FAMILY_ID="family-1";
// Secrets live in Wrangler secrets, never in source (see README): PARENT_PIN_HASH, FAMILY_PASSCODE_HASH, SESSION_SECRET.
// A family session unlocks the app on a device for 30 days; a parent session unlocks Parent HQ for an hour.
const ROLES={parent:{cookie:"bq_parent",ttl:3600,secret:"PARENT_PIN_HASH"},family:{cookie:"bq_family",ttl:30*86400,secret:"FAMILY_PASSCODE_HASH"}};
// Failed attempts allowed per fixed window, counted separately per role: per client IP, and across all clients (stops IP rotation).
const AUTH_LIMITS=[{key:(role,ip)=>`${role}:ip:${ip}`,max:5,window:900},{key:role=>`${role}:global`,max:30,window:3600}];
const PARENT_ACTIONS=new Set(["approve","reject","penalty","reset"]);
// Input and storage bounds. The whole state is one D1 row (2 MB max), so every list that grows is capped.
const LIMITS={body:256*1024,items:100,name:80,emoji:16,description:200,pending:50,history:5000,stateBytes:1500000,screenDays:7};
// Bumping CATALOG_VERSION overwrites the stored catalog with the defaults below on next read.
const CATALOG_VERSION=4;
const DEFAULT_CHORES=[
{id:1,name:"Put toys and books away",emoji:"🧸",points:3,difficulty:"Easy"},
{id:2,name:"Clear your plate without a reminder",emoji:"🍽️",points:3,difficulty:"Easy"},
{id:3,name:"Put dirty clothes in the laundry",emoji:"👕",points:3,difficulty:"Easy"},
{id:4,name:"Practise a sport or activity",emoji:"⚽",points:5,difficulty:"Medium"},
{id:5,name:"Do a creative project",emoji:"🎨",points:5,difficulty:"Medium"},
{id:6,name:"Read a book for 10 mins",emoji:"📖",points:5,difficulty:"Medium"},
{id:7,name:"Be in bed on time",emoji:"🛏️",points:5,difficulty:"Medium"},
{id:8,name:"Tidy your whole room",emoji:"🧹",points:10,difficulty:"Hard"},
{id:9,name:"Help with a big family job",emoji:"🌟",points:20,difficulty:"Epic"}
];
const DEFAULT_REWARDS=[
{id:101,name:"Ice cream",emoji:"🍦",cost:30,type:"other",minutes:0},
{id:102,name:"Sweet snack",emoji:"🍬",cost:30,type:"sweet",minutes:0},
{id:103,name:"Movie night (choose your own movie)",emoji:"🎬",cost:50,type:"other",minutes:0},
{id:104,name:"30 mins of video game",emoji:"🎮",cost:60,type:"screen",minutes:30},
{id:105,name:"5 arcade games",emoji:"🎯",cost:60,type:"other",minutes:0},
{id:106,name:"Special treat/outing",emoji:"✨",cost:150,type:"other",minutes:0},
{id:107,name:"Holiday",emoji:"🏖️",cost:1000,type:"other",minutes:0}
];
const DEFAULT_PENALTIES=[
{id:201,name:"Hitting other people",emoji:"👊",points:-5},
{id:202,name:"Saying bad things to others",emoji:"💬",points:-5},
{id:203,name:"Not listening to instructions three times in a row",emoji:"👂",points:-5}
];
const DEFAULT_BADGES=[
{id:301,name:"100 Points",emoji:"⭐",description:"Earn 100 total points",type:"points",target:100},
{id:302,name:"500 Points",emoji:"🌟",description:"Earn 500 total points",type:"points",target:500},
{id:303,name:"1,000 Points",emoji:"🏆",description:"Earn 1,000 total points",type:"points",target:1000},
{id:304,name:"Level 10",emoji:"🚀",description:"Reach Level 10",type:"level",target:10},
{id:305,name:"Level 20",emoji:"🦸",description:"Reach Level 20",type:"level",target:20}
];
const STARTER={catalogVersion:CATALOG_VERSION,points:0,totalEarned:0,streak:0,lastDone:null,chores:DEFAULT_CHORES,rewards:DEFAULT_REWARDS,penalties:DEFAULT_PENALTIES,badges:DEFAULT_BADGES,settings:{approval:false,cap:0,bonus:true},history:[],archivedQuests:0,pending:[],screenUsed:{}};
const enc=new TextEncoder();
function b64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf)))}
function unb64(s){return Uint8Array.from(atob(s),c=>c.charCodeAt(0))}
function b64url(buf){return b64(buf).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")}
function unb64url(s){s=s.replace(/-/g,"+").replace(/_/g,"/");return unb64(s+"=".repeat((4-s.length%4)%4))}
function sameBytes(a,b){if(a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a[i]^b[i];return d===0}
async function pbkdf2(pin,salt,iterations){const k=await crypto.subtle.importKey("raw",enc.encode(pin),"PBKDF2",false,["deriveBits"]);return new Uint8Array(await crypto.subtle.deriveBits({name:"PBKDF2",hash:"SHA-256",salt,iterations},k,256))}
function nowSec(){return Math.floor(Date.now()/1000)}
// Secret hash format: pbkdf2-sha256$<iterations>$<base64 salt>$<base64 hash> (generate with scripts/hash-pin.mjs)
async function verifySecret(env,role,value){const name=ROLES[role].secret,[alg,iter,salt,hash]=String(env[name]||"").split("$");if(alg!=="pbkdf2-sha256"||!Number(iter)||!salt||!hash)throw Error(`${name} secret is not configured`);return sameBytes(await pbkdf2(String(value),unb64(salt),Number(iter)),unb64(hash))}
async function hmacKey(env){if(!env.SESSION_SECRET)throw Error("SESSION_SECRET secret is not configured");return crypto.subtle.importKey("raw",enc.encode(env.SESSION_SECRET),{name:"HMAC",hash:"SHA-256"},false,["sign","verify"])}
// Token is "<exp>.<sig>" where sig = HMAC("<role>.<exp>"), so a token for one role never verifies as another.
async function makeSession(env,role){const exp=nowSec()+ROLES[role].ttl;return `${exp}.${b64url(await crypto.subtle.sign("HMAC",await hmacKey(env),enc.encode(`${role}.${exp}`)))}`}
async function hasSession(request,env,role){const m=(request.headers.get("Cookie")||"").match(new RegExp(`(?:^|;\\s*)${ROLES[role].cookie}=([^;]+)`));if(!m)return false;const [exp,sig]=m[1].split(".");if(!sig||!(Number(exp)>nowSec()))return false;try{return await crypto.subtle.verify("HMAC",await hmacKey(env),unb64url(sig),enc.encode(`${role}.${exp}`))}catch{return false}}
async function isFamily(request,env){return await hasSession(request,env,"family")||await hasSession(request,env,"parent")}
function sessionCookie(role,value,maxAge=ROLES[role].ttl){return `${ROLES[role].cookie}=${value}; Path=/api; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`}
function clone(x){return JSON.parse(JSON.stringify(x))}
// Static pages get their security headers from public/_headers; API responses get theirs here.
const API_HEADERS={"Content-Type":"application/json","Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Content-Security-Policy":"default-src 'none'; frame-ancestors 'none'","Referrer-Policy":"no-referrer"};
function json(data,status=200,headers={}){return new Response(JSON.stringify(data),{status,headers:{...API_HEADERS,...headers}})}
// CSRF guard for every state-changing /api call. Browsers send Origin (and usually Sec-Fetch-Site) on these requests,
// and another site can only send a JSON Content-Type after a CORS preflight, which this API never grants.
function crossSite(request,url){const origin=request.headers.get("Origin"),site=request.headers.get("Sec-Fetch-Site");return (origin!==null&&origin!==url.origin)||(site!==null&&site!=="same-origin"&&site!=="none")}
function isJson(request){return (request.headers.get("Content-Type")||"").split(";")[0].trim().toLowerCase()==="application/json"}
function unauthorized(role="parent"){return json({error:role==="family"?"This device is locked":"Parent login required"},401)}
async function authLockout(env,role,ip){const now=nowSec();let wait=0;for(const l of AUTH_LIMITS){const r=await env.DB.prepare("SELECT count,window_start FROM auth_attempts WHERE key=?").bind(l.key(role,ip)).first();if(r&&r.count>=l.max&&r.window_start+l.window>now)wait=Math.max(wait,r.window_start+l.window-now)}return wait}
async function recordAuthFailure(env,role,ip){const now=nowSec();for(const l of AUTH_LIMITS)await env.DB.prepare("INSERT INTO auth_attempts(key,count,window_start) VALUES(?1,1,?2) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN window_start+?3<=?2 THEN 1 ELSE count+1 END,window_start=CASE WHEN window_start+?3<=?2 THEN ?2 ELSE window_start END").bind(l.key(role,ip),now,l.window).run()}
async function clearAuthFailures(env,role,ip){await env.DB.prepare("DELETE FROM auth_attempts WHERE key=?").bind(AUTH_LIMITS[0].key(role,ip)).run()}
async function login(request,env,role){await ensureDb(env);const ip=request.headers.get("CF-Connecting-IP")||"unknown",wait=await authLockout(env,role,ip);if(wait)return json({ok:false,error:`Too many wrong attempts. Try again in ${Math.ceil(wait/60)} min.`},429,{"Retry-After":String(wait)});const b=await readBody(request),value=typeof b.pin==="string"?b.pin:"";if(value.length>64||!await verifySecret(env,role,value)){await recordAuthFailure(env,role,ip);return json({ok:false},401)}await clearAuthFailures(env,role,ip);return json({ok:true},200,{"Set-Cookie":sessionCookie(role,await makeSession(env,role))})}
class BadInput extends Error{}
class Conflict extends Error{}
function need(ok,msg){if(!ok)throw new BadInput(msg)}
async function readBody(request){need(Number(request.headers.get("Content-Length")||0)<=LIMITS.body,"Request is too large");const t=await request.text();need(enc.encode(t).length<=LIMITS.body,"Request is too large");let b;try{b=JSON.parse(t)}catch{throw new BadInput("Request body must be JSON")}need(b&&typeof b==="object"&&!Array.isArray(b),"Request body must be a JSON object");return b}
function onlyKeys(b,allowed){for(const k of Object.keys(b))need(allowed.includes(k),`Unknown field: ${k}`)}
function text(v,label,max,required=true){if(v==null&&!required)return "";need(typeof v==="string",`${label} must be text`);const t=v.trim();need(t||!required,`${label} is required`);need(t.length<=max,`${label} must be ${max} characters or fewer`);return t}
function int(v,label,min,max){need(Number.isInteger(v)&&v>=min&&v<=max,`${label} must be a whole number from ${min} to ${max}`);return v}
function oneOf(v,label,options){need(options.includes(v),`${label} must be one of: ${options.join(", ")}`);return v}
const emoji=(v,fallback)=>text(v,"Emoji",LIMITS.emoji,false)||fallback;
const itemId=v=>int(v,"Id",1,Number.MAX_SAFE_INTEGER);
const CATALOG={
chores:c=>({id:itemId(c.id),name:text(c.name,"Chore name",LIMITS.name),emoji:emoji(c.emoji,"⭐"),points:int(c.points,"Chore points",1,1000),difficulty:oneOf(c.difficulty??"Medium","Difficulty",["Easy","Medium","Hard","Epic"])}),
rewards:r=>({id:itemId(r.id),name:text(r.name,"Reward name",LIMITS.name),emoji:emoji(r.emoji,"🎁"),cost:int(r.cost,"Reward cost",1,100000),type:oneOf(r.type??"other","Reward type",["screen","sweet","other"]),minutes:int(r.minutes??0,"Reward minutes",0,1440)}),
penalties:p=>({id:itemId(p.id),name:text(p.name,"Penalty name",LIMITS.name),emoji:emoji(p.emoji,"⚠️"),points:int(p.points,"Penalty points",-1000,-1)}),
badges:b=>({id:itemId(b.id),name:text(b.name,"Badge name",LIMITS.name),emoji:emoji(b.emoji,"🏅"),description:text(b.description,"Badge description",LIMITS.description,false),type:oneOf(b.type??"points","Badge type",["points","level","quests","chore"]),target:int(b.target,"Badge target",1,1000000),...(b.choreName!=null&&{choreName:text(b.choreName,"Badge chore",LIMITS.name)})})
};
function validCatalogList(kind,v){need(Array.isArray(v),`${kind} must be a list`);need(v.length<=LIMITS.items,`Too many ${kind} (max ${LIMITS.items})`);const ids=new Set();return v.map(x=>{need(x&&typeof x==="object"&&!Array.isArray(x),`Invalid item in ${kind}`);const y=CATALOG[kind](x);need(!ids.has(y.id),`Duplicate id in ${kind}`);ids.add(y.id);return y})}
const SETTINGS={approval:v=>{need(typeof v==="boolean","Approval must be true or false");return v},cap:v=>int(v,"Screen-time cap",0,1440),bonus:v=>{need(typeof v==="boolean","Bonus must be true or false");return v}};
function validSettings(b){onlyKeys(b,Object.keys(SETTINGS));return Object.fromEntries(Object.entries(b).map(([k,v])=>[k,SETTINGS[k](v)]))}
// Oldest history entries are dropped past the cap; completed quests are tallied so quest-count badges stay earned.
function trimHistory(s,max){if(s.history.length<=max)return;const dropped=s.history.splice(max);s.archivedQuests+=dropped.filter(h=>h.kind==="chore").length}
function today(){return new Date().toLocaleDateString("en-CA")}
function cleanState(s){const x={...clone(STARTER),...s};x.catalogVersion=Number(s.catalogVersion||0);x.points=Number(s.points||0);x.totalEarned=Number(s.totalEarned||0);x.chores=(s.chores||DEFAULT_CHORES).map(c=>({id:Number(c.id),name:String(c.name),emoji:String(c.emoji||"⭐"),points:Number(c.points),difficulty:String(c.difficulty||"Medium")}));x.rewards=(s.rewards||DEFAULT_REWARDS).map(r=>({id:Number(r.id),name:String(r.name),emoji:String(r.emoji||"🎁"),cost:Number(r.cost),type:r.type||"other",minutes:Number(r.minutes||0)}));x.penalties=(s.penalties||DEFAULT_PENALTIES).map(p=>({id:Number(p.id),name:String(p.name),emoji:String(p.emoji||"⚠️"),points:Number(p.points||-5)}));x.badges=(s.badges||DEFAULT_BADGES).map(b=>({id:Number(b.id),name:String(b.name),emoji:String(b.emoji||"🏅"),description:String(b.description||""),type:b.type||"points",target:Number(b.target||0),...(b.choreName?{choreName:String(b.choreName)}:{})}));const st=s.settings||{};x.settings={approval:st.approval===true,cap:Number(st.cap)||0,bonus:st.bonus!==false};x.archivedQuests=Number(s.archivedQuests||0);x.history=Array.isArray(s.history)?s.history:[];trimHistory(x,LIMITS.history);x.pending=Array.isArray(s.pending)?s.pending:[];const since=new Date(Date.now()-LIMITS.screenDays*86400000).toLocaleDateString("en-CA");x.screenUsed=Object.fromEntries(Object.entries(s.screenUsed||{}).filter(([d])=>d>=since));delete x.minutes;return x}
async function ensureDb(env){await env.DB.exec(`CREATE TABLE IF NOT EXISTS family (id TEXT PRIMARY KEY,name TEXT NOT NULL,parent_pin_hash TEXT NOT NULL,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS family_state (family_id TEXT PRIMARY KEY,data TEXT NOT NULL,updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT,family_id TEXT NOT NULL,child_name TEXT NOT NULL,amount INTEGER NOT NULL,type TEXT NOT NULL,description TEXT NOT NULL,ref_id TEXT,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);CREATE INDEX IF NOT EXISTS idx_transactions_family_date ON transactions(family_id,created_at);CREATE TABLE IF NOT EXISTS auth_attempts (key TEXT PRIMARY KEY,count INTEGER NOT NULL,window_start INTEGER NOT NULL);`);await env.DB.prepare("INSERT OR IGNORE INTO family (id,name,parent_pin_hash) VALUES (?,?,?)").bind(FAMILY_ID,"Benji's Family","managed-by-secret").run()}
async function getRaw(env){await ensureDb(env);return await env.DB.prepare("SELECT data FROM family_state WHERE family_id=?").bind(FAMILY_ID).first()}
// Stored JSON each state object was read from. save() only writes if the row still holds exactly that JSON,
// so two overlapping requests (e.g. a double-tapped redeem) can't both spend the same points.
const loadedFrom=new WeakMap();
// If long names still push the row near D1's size limit, shed more history rather than fail every write.
async function save(env,s){const x=cleanState(s);let data=JSON.stringify(x);while(enc.encode(data).length>LIMITS.stateBytes&&x.history.length){trimHistory(x,Math.floor(x.history.length*0.8));data=JSON.stringify(x)}const prev=loadedFrom.get(s);
if(prev===undefined)await env.DB.prepare("INSERT INTO family_state(family_id,data,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(family_id) DO UPDATE SET data=excluded.data,updated_at=CURRENT_TIMESTAMP").bind(FAMILY_ID,data).run();
else if(!(await env.DB.prepare("UPDATE family_state SET data=?1,updated_at=CURRENT_TIMESTAMP WHERE family_id=?2 AND data=?3").bind(data,FAMILY_ID,prev).run()).meta.changes)throw new Conflict();
loadedFrom.set(s,data);return data}
async function state(env){const row=await getRaw(env);if(!row){const s=clone(STARTER);await save(env,s);return s}const s=cleanState(JSON.parse(row.data));loadedFrom.set(s,row.data);return s}
async function tx(env,amount,type,description,refId=null,at=new Date().toISOString()){await env.DB.prepare("INSERT INTO transactions(family_id,child_name,amount,type,description,ref_id,created_at) VALUES(?,?,?,?,?,?,?)").bind(FAMILY_ID,"Benji",amount,type,description,refId,at).run()}
function applyCatalog(s){if(s.catalogVersion>=CATALOG_VERSION)return s;return {...s,catalogVersion:CATALOG_VERSION,chores:clone(DEFAULT_CHORES),rewards:clone(DEFAULT_REWARDS),penalties:clone(DEFAULT_PENALTIES),badges:clone(DEFAULT_BADGES)}}
async function read(env){let s=await state(env);const updated=applyCatalog(s);if(updated!==s){loadedFrom.set(updated,loadedFrom.get(s));await save(env,updated);s=updated}return s}
function addHistory(s,text,amount,kind){s.history.unshift({id:crypto.randomUUID(),text,amount:Number(amount),kind,date:today(),at:new Date().toISOString()})}
function updateStreak(s,d){if(s.lastDone!==d){const y=new Date(Date.now()-86400000).toLocaleDateString("en-CA");s.streak=s.lastDone===y?s.streak+1:1;s.lastDone=d}}
export default {async fetch(request,env){const url=new URL(request.url);try{
if(url.pathname.startsWith("/api/")&&request.method!=="GET"&&request.method!=="HEAD"){if(crossSite(request,url))return json({error:"Cross-site request refused"},403);if(!isJson(request))return json({error:"Content-Type must be application/json"},415)}
if(url.pathname==="/api/health") {await ensureDb(env);return json({ok:true})}
if(url.pathname==="/api/state"&&request.method==="GET"){if(!await isFamily(request,env))return unauthorized("family");return json({state:await read(env)})}
if(url.pathname==="/api/parent-auth"&&request.method==="POST")return await login(request,env,"parent")
if(url.pathname==="/api/family-auth"&&request.method==="POST")return await login(request,env,"family")
if(url.pathname==="/api/parent-logout"&&request.method==="POST")return json({ok:true},200,{"Set-Cookie":sessionCookie("parent","",0)})
if(url.pathname==="/api/family-logout"&&request.method==="POST")return json({ok:true},200,{"Set-Cookie":sessionCookie("family","",0)})
if(url.pathname==="/api/settings"&&request.method==="PUT"){if(!await hasSession(request,env,"parent"))return unauthorized();const b=validSettings(await readBody(request)),s=await read(env);s.settings={...s.settings,...b};await save(env,s);return json({state:s})}
if(url.pathname==="/api/admin"&&request.method==="PUT"){if(!await hasSession(request,env,"parent"))return unauthorized();const b=await readBody(request),kinds=Object.keys(CATALOG);onlyKeys(b,kinds);const lists=Object.fromEntries(Object.entries(b).map(([k,v])=>[k,validCatalogList(k,v)])),s=await read(env);Object.assign(s,lists);await save(env,s);return json({state:s})}
if(url.pathname==="/api/action"&&request.method==="POST"){const b=await readBody(request),a=b.action;if(PARENT_ACTIONS.has(a)){if(!await hasSession(request,env,"parent"))return unauthorized()}else if(!await isFamily(request,env))return unauthorized("family");const s=await read(env);
if(a==="complete"){const c=s.chores.find(x=>x.id===Number(b.id));if(!c)return json({error:"Chore not found"},404);const d=today();if(s.settings.approval){need(s.pending.length<LIMITS.pending,"Too many quests are waiting for approval. Ask a parent to review them first.");const p={id:crypto.randomUUID(),choreId:c.id,name:c.name,emoji:c.emoji,points:c.points,date:d,createdAt:new Date().toISOString()};s.pending.push(p);await save(env,s);return json({ok:true,pending:true,pendingId:p.id,state:s})}s.points+=c.points;s.totalEarned+=c.points;updateStreak(s,d);addHistory(s,`Completed ${c.name}`,c.points,"chore");await save(env,s);await tx(env,c.points,"chore",`Completed ${c.name}`,String(c.id));return json({ok:true,state:s})}
if(a==="approve"||a==="reject"){const id=String(b.pendingId||"");const i=s.pending.findIndex(p=>String(p.id)===id);if(i<0)return json({error:"Pending request not found or already processed"},404);const p=s.pending[i];s.pending.splice(i,1);if(a==="approve"){s.points+=Number(p.points);s.totalEarned+=Number(p.points);updateStreak(s,p.date||today());addHistory(s,`Completed ${p.name}`,Number(p.points),"chore")}await save(env,s);if(a==="approve")await tx(env,Number(p.points||0),"chore",`Approved ${p.name}`,String(p.choreId||""));return json({ok:true,state:s})}
if(a==="penalty"){const p=s.penalties.find(x=>x.id===Number(b.id));if(!p)return json({error:"Penalty not found"},404);s.points=Math.max(0,s.points+Number(p.points));addHistory(s,p.name,p.points,"penalty");await save(env,s);await tx(env,p.points,"penalty",p.name,String(p.id));return json({state:s})}
if(a==="redeem"){const r=s.rewards.find(x=>x.id===Number(b.id));if(!r)return json({error:"Reward not found"},404);if(s.points<r.cost)return json({error:"Not enough points"},400);if(r.type==="screen"&&s.settings.cap){const used=s.screenUsed[today()]||0;if(used+r.minutes>s.settings.cap)return json({error:`Daily screen limit: ${s.settings.cap} min`},400);s.screenUsed[today()]=used+r.minutes}s.points-=r.cost;addHistory(s,`Unlocked ${r.name}`,-r.cost,"reward");await save(env,s);await tx(env,-r.cost,"reward",`Unlocked ${r.name}`,String(r.id));return json({state:s,reward:r})}
if(a==="reset"){await save(env,clone(STARTER));await env.DB.prepare("DELETE FROM transactions WHERE family_id=?").bind(FAMILY_ID).run();return json({state:clone(STARTER)})}
return json({error:"Unknown action"},400)}
return env.ASSETS.fetch(request)
}catch(e){if(e instanceof BadInput)return json({error:e.message},400);if(e instanceof Conflict)return json({error:"Something else changed at the same moment. Please try again."},409);
// Details go to the Worker logs (npx wrangler tail), never to the client.
console.error(e);return json({error:"Server error"},500)}}};