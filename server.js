const http=require('http'),fs=require('fs'),path=require('path'),crypto=require('crypto');
const PORT=process.env.PORT||3000, ROOT=__dirname, PUBLIC=ROOT, DB=path.join(ROOT,'data.json');
const sessions=new Map(), attempts=new Map(), otpChallenges=new Map(), farmerSessions=new Map(), otpRequests=new Map(), otpCooldowns=new Map(), otpVerifyLimits=new Map();
const OTP_PEPPER=process.env.OTP_PEPPER||'';
const COOKIE_SECURE=process.env.NODE_ENV==='production'?'; Secure':'';
// DEMO ONLY: any valid 10-digit number is verified without sending an SMS.
const DEMO_OTP_MODE=true;
const seed={farmers:[],bookings:[],prices:[],centres:["Mandapeta Procurement Centre","Rajahmundry Procurement Centre","Amalapuram Procurement Centre"],crops:["Rice","Wheat","Maize","Groundnut","Cotton","Other"],audit:[],admins:[],settings:{upiId:"",payeeName:"CropSync"},slotCapacity:{"Mandapeta Procurement Centre":{maxFarmers:5,maxQuintals:20},"Rajahmundry Procurement Centre":{maxFarmers:5,maxQuintals:20},"Amalapuram Procurement Centre":{maxFarmers:5,maxQuintals:20}},slots:["09:00 - 09:30 AM","09:30 - 10:00 AM","10:00 - 10:30 AM","10:30 - 11:00 AM","11:00 - 11:30 AM","11:30 AM - 12:00 PM","12:00 - 12:30 PM","12:30 - 01:00 PM","02:00 - 02:30 PM","02:30 - 03:00 PM","03:00 - 03:30 PM","03:30 - 04:00 PM","04:00 - 04:30 PM","04:30 - 05:00 PM"]};
function load(){
 try{
  const d=JSON.parse(fs.readFileSync(DB,'utf8'));
  if(!d.slotCapacity||typeof d.slotCapacity!=='object')d.slotCapacity={};
  if(!Array.isArray(d.slots))d.slots=[...seed.slots];
  if(!d.settings)d.settings={upiId:"",payeeName:"CropSync"};
  if(!Array.isArray(d.farmers))d.farmers=[];
  if(!Array.isArray(d.bookings))d.bookings=[];
  if(!Array.isArray(d.prices))d.prices=[];
  if(!Array.isArray(d.centres))d.centres=[...seed.centres];
  for(const c of d.centres){if(!d.slotCapacity[c]||typeof d.slotCapacity[c]!=='object')d.slotCapacity[c]={maxFarmers:5,maxQuintals:20};}
  if(!Array.isArray(d.crops))d.crops=[...seed.crops];
  if(!Array.isArray(d.audit))d.audit=[];
  // Migrate the original single administrator without exposing its password hash.
  if(!Array.isArray(d.admins))d.admins=d.admin? [{id:id('ADM'),email:d.admin.email,salt:d.admin.salt,hash:d.admin.hash,role:'super_admin',active:true,createdAt:new Date().toISOString()}] : [];
  d.admins=d.admins.filter(a=>a&&a.email&&a.salt&&a.hash).map(a=>({...a,id:a.id||id('ADM'),email:String(a.email).toLowerCase().trim(),role:a.role==='super_admin'?'super_admin':'admin',active:a.active!==false}));
  delete d.admin;
  return d;
 }catch{save(seed);return structuredClone(seed)}
}
function save(d){fs.writeFileSync(DB,JSON.stringify(d,null,2))}
let db=load();
function securityHeaders(res){res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','strict-origin-when-cross-origin');res.setHeader('Permissions-Policy','camera=(), microphone=(), geolocation=()');if(process.env.NODE_ENV==='production')res.setHeader('Strict-Transport-Security','max-age=31536000; includeSubDomains')}
function json(res,code,obj){securityHeaders(res);res.writeHead(code,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(obj))}
function body(req){return new Promise((resolve,reject)=>{let s='';req.on('data',c=>{s+=c;if(s.length>1e6)req.destroy()});req.on('end',()=>{try{resolve(s?JSON.parse(s):{})}catch(e){reject(e)}})})}
function cookie(req,n){const m=(req.headers.cookie||'').match(new RegExp('(?:^|; )'+n+'=([^;]*)'));return m&&decodeURIComponent(m[1])}
function session(req){const id=cookie(req,'cs_session');const s=id&&sessions.get(id);if(!s)return null;if(s.expires<Date.now()){sessions.delete(id);return null}s.expires=Date.now()+15*60e3;return s}
function admin(req,res){const s=session(req);if(!s?.admin){json(res,401,{error:'Admin authentication required'});return null}const a=db.admins.find(x=>x.id===s.adminId&&x.active);if(!a){json(res,401,{error:'Administrator account is inactive or unavailable'});return null}return {...s,account:a}}
function farmer(req,res){const sid=cookie(req,'cs_farmer_session'),s=sid&&farmerSessions.get(sid);if(!s||s.expires<Date.now()){if(sid)farmerSessions.delete(sid);json(res,401,{error:'Verify your mobile number with OTP to continue'});return null}s.expires=Date.now()+15*60e3;return s}
function verifiedPhone(req,res,phone){const s=farmer(req,res);if(!s)return null;if(String(phone||'')!==s.phone){json(res,403,{error:'You can access only your verified mobile number'});return null}return s}
function superAdmin(req,res){const s=admin(req,res);if(!s)return null;if(s.account.role!=='super_admin'){json(res,403,{error:'Super Admin access required'});return null}return s}
function safeAdmin(a){return {id:a.id,email:a.email,role:a.role,active:a.active,createdAt:a.createdAt}}
function activeSuperAdmins(){return db.admins.filter(a=>a.active&&a.role==='super_admin')}
function hash(p,salt){return crypto.scryptSync(p,salt,64).toString('hex')} function newSalt(){return crypto.randomBytes(16).toString('hex')}
function audit(action,details){db.audit.unshift({id:'AUD-'+Date.now(),time:new Date().toISOString(),action,details});db.audit=db.audit.slice(0,200);save(db)}
function id(p){return p+'-'+Date.now().toString(36).toUpperCase()+'-'+crypto.randomBytes(3).toString('hex').toUpperCase()}
function otpHash(challengeId,phone,code){return crypto.createHmac('sha256',OTP_PEPPER).update(`${challengeId}:${phone}:${code}`).digest()}
function sameHash(a,b){return Buffer.isBuffer(a)&&Buffer.isBuffer(b)&&a.length===b.length&&crypto.timingSafeEqual(a,b)}
function maskPhone(phone){return `******${String(phone).slice(-4)}`}
function clientIp(req){return String(req.headers['x-forwarded-for']||req.socket.remoteAddress||'unknown').split(',')[0].trim()}
function createFarmerSession(res,phone){const sid=crypto.randomBytes(32).toString('hex');farmerSessions.set(sid,{phone,registrationAuthorized:true,expires:Date.now()+15*60e3});res.setHeader('Set-Cookie',`cs_farmer_session=${sid}; HttpOnly${COOKIE_SECURE}; SameSite=Strict; Path=/; Max-Age=900`)}
function twilioConfigured(){return Boolean(OTP_PEPPER&&process.env.TWILIO_ACCOUNT_SID&&process.env.TWILIO_AUTH_TOKEN&&process.env.TWILIO_FROM)}
async function sendOtpSms(phone,code){
 if(!twilioConfigured())throw new Error('OTP SMS service is not configured');
 const sid=process.env.TWILIO_ACCOUNT_SID,token=process.env.TWILIO_AUTH_TOKEN;
 const form=new URLSearchParams({To:`+91${phone}`,From:process.env.TWILIO_FROM,Body:`Your CropSync verification code is ${code}. It expires in 5 minutes. Do not share this code.`});
 const response=await fetch(`https://api.twilio.com/2010-04-01/Accounts/${encodeURIComponent(sid)}/Messages.json`,{method:'POST',headers:{Authorization:`Basic ${Buffer.from(`${sid}:${token}`).toString('base64')}`,'Content-Type':'application/x-www-form-urlencoded'},body:form});
 if(!response.ok)throw new Error('OTP SMS could not be sent. Please try again later.');
}
function today(){const d=new Date();d.setMinutes(d.getMinutes()-d.getTimezoneOffset());return d.toISOString().slice(0,10)}
function queue(date,centre){return db.bookings.filter(b=>b.date===date&&b.centre===centre&&b.queueStatus==='waiting').sort((a,b)=>a.queueNumber-b.queueNumber)}
function nextQ(date,centre){const n=db.bookings.filter(b=>b.date===date&&b.centre===centre).map(b=>Number(b.queueNumber)||0);return (n.length?Math.max(...n):0)+1}
function safeFarmer(f){return {id:f.id,name:f.name,phone:f.phone,village:f.village,crop:f.crop,land:f.land,createdAt:f.createdAt,updatedAt:f.updatedAt}}
function getCapacity(centre){
 const c=db.slotCapacity&&db.slotCapacity[centre];
 return {
  maxFarmers:Number(c?.maxFarmers)||10,
  maxQuintals:Number(c?.maxQuintals)||200
 };
}
function slotUsage(date,centre,slot){
 const active=db.bookings.filter(b=>b.date===date&&b.centre===centre&&b.slot===slot&&b.status!=='Rejected');
 return {
  farmers:active.length,
  quintals:Number(active.reduce((sum,b)=>sum+(Number(b.quantity)||0),0).toFixed(3))
 };
}
function slotStatus(date,centre,slot){
 const cap=getCapacity(centre), used=slotUsage(date,centre,slot);
 const remainingFarmers=Math.max(0,cap.maxFarmers-used.farmers);
 const remainingQuintals=Math.max(0,Number((cap.maxQuintals-used.quintals).toFixed(3)));
 return {
  slot,
  full:remainingFarmers<=0||remainingQuintals<=0,
  farmersUsed:used.farmers,
  farmersCapacity:cap.maxFarmers,
  remainingFarmers,
  quintalsUsed:used.quintals,
  quintalsCapacity:cap.maxQuintals,
  remainingQuintals
 };
}
async function route(req,res){
 try{
  const u=new URL(req.url,'http://localhost'); const p=u.pathname;
  if(req.method==='GET'&&p==='/api/bootstrap')return json(res,200,{crops:db.crops,centres:db.centres,slots:db.slots||seed.slots,slotCapacity:db.slotCapacity||{},settings:{payeeName:db.settings.payeeName,upiConfigured:!!db.settings.upiId},today:today(),adminConfigured:db.admins.length>0});
  if(req.method==='POST'&&p==='/api/admin/setup'){if(db.admins.length)return json(res,409,{error:'Admin is already configured'});const b=await body(req),email=String(b.email||'').toLowerCase().trim();if(!email||!b.password||b.password.length<8)return json(res,400,{error:'Email and password (8+ characters) are required'});const salt=newSalt();db.admins.push({id:id('ADM'),email,salt,hash:hash(b.password,salt),role:'super_admin',active:true,createdAt:new Date().toISOString()});save(db);audit('SUPER_ADMIN_SETUP','Initial Super Admin account created');return json(res,200,{ok:true})}
  if(req.method==='POST'&&p==='/api/admin/login'){const ip=req.socket.remoteAddress||'unknown',a=attempts.get(ip)||{n:0,until:0};if(a.until>Date.now())return json(res,429,{error:'Too many failed attempts. Try again later.'});const b=await body(req),account=db.admins.find(x=>x.email===String(b.email||'').toLowerCase().trim());const ok=!!account&&account.active&&crypto.timingSafeEqual(Buffer.from(hash(b.password||'',account.salt)),Buffer.from(account.hash));if(!ok){a.n++;if(a.n>=5){a.until=Date.now()+5*60e3;a.n=0}attempts.set(ip,a);return json(res,401,{error:'Invalid administrator credentials'})}attempts.delete(ip);const sid=crypto.randomBytes(32).toString('hex');sessions.set(sid,{admin:true,adminId:account.id,expires:Date.now()+15*60e3});res.setHeader('Set-Cookie',`cs_session=${sid}; HttpOnly${COOKIE_SECURE}; SameSite=Strict; Path=/; Max-Age=900`);audit('ADMIN_LOGIN',account.email);return json(res,200,{ok:true,role:account.role})}
  if(req.method==='POST'&&p==='/api/admin/logout'){const s=session(req);if(s)audit('ADMIN_LOGOUT','Administrator logged out');const sid=cookie(req,'cs_session');if(sid)sessions.delete(sid);res.setHeader('Set-Cookie',`cs_session=; HttpOnly${COOKIE_SECURE}; SameSite=Strict; Path=/; Max-Age=0`);return json(res,200,{ok:true})}
  if(req.method==='GET'&&p==='/api/admin/me'){const s=session(req),a=s&&db.admins.find(x=>x.id===s.adminId&&x.active);return json(res,200,{authenticated:!!a,configured:db.admins.length>0,role:a?.role||null,email:a?.email||null})}
  if(req.method==='GET'&&p==='/api/admin/admins'){const s=superAdmin(req,res);if(!s)return;return json(res,200,{admins:db.admins.map(safeAdmin),currentAdminId:s.account.id})}
  if(req.method==='POST'&&p==='/api/admin/admins'){const s=superAdmin(req,res);if(!s)return;const b=await body(req),email=String(b.email||'').toLowerCase().trim(),role=b.role==='super_admin'?'super_admin':'admin';if(!email||!b.password||b.password.length<8)return json(res,400,{error:'Email and password (8+ characters) are required'});if(db.admins.some(a=>a.email===email))return json(res,409,{error:'An administrator with that email already exists'});const account={id:id('ADM'),email,salt:newSalt(),role,active:true,createdAt:new Date().toISOString()};account.hash=hash(b.password,account.salt);db.admins.push(account);save(db);audit('ADMIN_CREATE',`${s.account.email} created ${role}: ${email}`);return json(res,201,{admin:safeAdmin(account)})}
  if(req.method==='PATCH'&&p.startsWith('/api/admin/admins/')){const s=superAdmin(req,res);if(!s)return;const target=db.admins.find(a=>a.id===decodeURIComponent(p.split('/').pop()));if(!target)return json(res,404,{error:'Administrator not found'});if(target.id===s.account.id)return json(res,400,{error:'You cannot deactivate your own account'});const b=await body(req);if(typeof b.active!=='boolean')return json(res,400,{error:'Active status is required'});if(!b.active&&target.role==='super_admin'&&activeSuperAdmins().length<=1)return json(res,409,{error:'The last active Super Admin cannot be deactivated'});target.active=b.active;save(db);audit(b.active?'ADMIN_ACTIVATE':'ADMIN_DEACTIVATE',`${s.account.email} changed ${target.email}`);return json(res,200,{admin:safeAdmin(target)})}
  if(req.method==='DELETE'&&p.startsWith('/api/admin/admins/')){const s=superAdmin(req,res);if(!s)return;const target=db.admins.find(a=>a.id===decodeURIComponent(p.split('/').pop()));if(!target)return json(res,404,{error:'Administrator not found'});if(target.id===s.account.id)return json(res,400,{error:'You cannot delete your own account'});if(target.role==='super_admin'&&target.active&&activeSuperAdmins().length<=1)return json(res,409,{error:'The last active Super Admin cannot be deleted'});db.admins=db.admins.filter(a=>a.id!==target.id);save(db);audit('ADMIN_DELETE',`${s.account.email} deleted ${target.email}`);return json(res,200,{ok:true})}
  if(req.method==='POST'&&p==='/api/otp'){
    const b=await body(req),phone=String(b.phone||''),ip=clientIp(req),key=`${ip}:${phone}`,now=Date.now();
    if(!/^\d{10}$/.test(phone))return json(res,400,{error:'Enter a valid 10-digit mobile number'});
    if(DEMO_OTP_MODE){createFarmerSession(res,phone);audit('DEMO_PHONE_VERIFIED',`Demo verification for ${maskPhone(phone)}`);return json(res,200,{ok:true,verified:true,message:'Demo verification complete. No SMS was sent.'})}
    if(!twilioConfigured())return json(res,503,{error:'OTP SMS service is not configured. Contact the administrator.'});
    const cooldown=otpCooldowns.get(phone);if(cooldown&&cooldown>now)return json(res,429,{error:'Please wait 60 seconds before requesting another OTP.'});
    let r=otpRequests.get(key)||{count:0,reset:now+10*60e3};if(r.reset<now)r={count:0,reset:now+10*60e3};if(r.count>=3)return json(res,429,{error:'Too many OTP requests. Try again in a few minutes.'});
    const challengeId=crypto.randomBytes(32).toString('hex'),code=String(crypto.randomInt(100000,1000000));
    try{await sendOtpSms(phone,code)}catch(error){return json(res,502,{error:error.message})}
    for(const [existingId,challenge] of otpChallenges){if(challenge.phone===phone)otpChallenges.delete(existingId)}
    otpChallenges.set(challengeId,{phone,hash:otpHash(challengeId,phone,code),expires:now+5*60e3,attempts:0});
    r.count++;otpRequests.set(key,r);otpCooldowns.set(phone,now+60e3);audit('OTP_SENT',`OTP sent to ${maskPhone(phone)}`);
    return json(res,200,{ok:true,challengeId,message:'OTP sent. It expires in 5 minutes.'})
  }
  if(req.method==='POST'&&p==='/api/otp/verify'){
    const b=await body(req),challengeId=String(b.challengeId||''),code=String(b.code||''),ip=clientIp(req),now=Date.now(),limitKey=`${ip}:${challengeId}`;
    let limit=otpVerifyLimits.get(limitKey)||{count:0,reset:now+30*60e3};if(limit.reset<now)limit={count:0,reset:now+30*60e3};if(limit.count>=10)return json(res,429,{error:'Too many verification attempts. Please request a new OTP.'});
    const o=otpChallenges.get(challengeId);if(!o||o.expires<now){if(o)otpChallenges.delete(challengeId);return json(res,401,{error:'Invalid or expired OTP'})}
    if(!/^\d{6}$/.test(code)||!sameHash(o.hash,otpHash(challengeId,o.phone,code))){o.attempts++;limit.count++;otpVerifyLimits.set(limitKey,limit);if(o.attempts>=5)otpChallenges.delete(challengeId);return json(res,401,{error:'Invalid or expired OTP'})}
    otpChallenges.delete(challengeId);const sid=crypto.randomBytes(32).toString('hex');farmerSessions.set(sid,{phone:o.phone,registrationAuthorized:true,expires:now+15*60e3});res.setHeader('Set-Cookie',`cs_farmer_session=${sid}; HttpOnly${COOKIE_SECURE}; SameSite=Strict; Path=/; Max-Age=900`);audit('OTP_VERIFIED',`OTP verified for ${maskPhone(o.phone)}`);return json(res,200,{verified:true})
  }
  if(req.method==='GET'&&p==='/api/farmers'){const s=session(req);if(!s?.admin)return json(res,200,{farmers:[]});return json(res,200,{farmers:db.farmers.map(safeFarmer)})}
  if(req.method==='POST'&&p==='/api/farmers'){const b=await body(req),s=verifiedPhone(req,res,b.phone);if(!s)return;if(!s.registrationAuthorized)return json(res,401,{error:'Verify your mobile number with a new OTP to register'});const name=String(b.name||'').trim(),village=String(b.village||'').trim(),land=Number(b.land);if(name.length<2||name.length>100||!/^\d{10}$/.test(b.phone)||village.length<2||village.length>100||!b.crop||!Number.isFinite(land)||land<=0||land>10000)return json(res,400,{error:'Invalid registration details'});if(!db.crops.includes(b.crop))return json(res,400,{error:'Invalid crop'});if(db.farmers.some(f=>f.phone===b.phone))return json(res,409,{error:'Mobile number already registered'});const f={id:id('FARM'),name,phone:b.phone,village,crop:b.crop,land,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};db.farmers.push(f);s.registrationAuthorized=false;save(db);audit('FARMER_REGISTER',`${f.id} registered`);return json(res,201,{farmer:safeFarmer(f)})}
  if(req.method==='PUT'&&p.startsWith('/api/farmers/')){if(!admin(req,res))return;const f=db.farmers.find(x=>x.id===decodeURIComponent(p.split('/').pop()));if(!f)return json(res,404,{error:'Farmer not found'});const b=await body(req);if(!/^\d{10}$/.test(b.phone)||db.farmers.some(x=>x.id!==f.id&&x.phone===b.phone))return json(res,400,{error:'Invalid or duplicate mobile number'});Object.assign(f,{name:b.name.trim(),phone:b.phone,village:b.village.trim(),crop:b.crop,land:Number(b.land),updatedAt:new Date().toISOString()});save(db);audit('FARMER_UPDATE',f.id);return json(res,200,{farmer:safeFarmer(f)})}
  if(req.method==='DELETE'&&p.startsWith('/api/farmers/')){if(!admin(req,res))return;const fid=decodeURIComponent(p.split('/').pop());if(db.bookings.some(b=>b.farmerId===fid&&!['Rejected','Payment Completed'].includes(b.status)))return json(res,409,{error:'Cannot delete a farmer with an active booking'});db.farmers=db.farmers.filter(f=>f.id!==fid);save(db);audit('FARMER_DELETE',fid);return json(res,200,{ok:true})}
  if(req.method==='GET'&&p==='/api/slots'){
    const q=new URL(req.url,'http://localhost').searchParams;
    const date=q.get('date')||today();
    const centre=q.get('centre')||db.centres[0];
    if(!db.centres.includes(centre))return json(res,400,{error:'Invalid procurement centre'});
    const slots=db.slots||seed.slots;
    return json(res,200,{date,centre,capacity:getCapacity(centre),slots:slots.map(slot=>slotStatus(date,centre,slot))});
  }
  if(req.method==='POST'&&p==='/api/admin/capacity'){
    if(!admin(req,res))return;
    const b=await body(req),centre=String(b.centre||'').trim();
    const farmers=Number(b.farmers),quintals=Number(b.quintals);
    if(!db.centres.includes(centre)||!Number.isInteger(farmers)||farmers<1||!(quintals>0))
      return json(res,400,{error:'Centre, maximum farmers (1+) and maximum quintals (>0) are required'});
    db.slotCapacity[centre]={maxFarmers:farmers,maxQuintals:quintals};
    save(db);audit('SLOT_CAPACITY_UPDATE',`${centre}: ${farmers} farmers / ${quintals} quintals per slot`);
    return json(res,200,{ok:true,centre,capacity:db.slotCapacity[centre]});
  }
  if(req.method==='GET'&&p==='/api/admin/capacity'){
    if(!admin(req,res))return;
    return json(res,200,{slotCapacity:db.slotCapacity||{}});
  }

  if(req.method==='GET'&&p==='/api/bookings'){const bq=new URL(req.url,'http://localhost').searchParams.get('phone');if(!verifiedPhone(req,res,bq))return;const f=db.farmers.find(x=>x.phone===bq);if(!f)return json(res,404,{error:'Farmer not found'});return json(res,200,{bookings:db.bookings.filter(b=>b.farmerId===f.id).map(b=>({...b,farmerName:f.name}))})}
  if(req.method==='POST'&&p==='/api/bookings'){
    const b=await body(req);if(!verifiedPhone(req,res,b.phone))return;const f=db.farmers.find(x=>x.phone===b.phone);
    if(!f)return json(res,404,{error:'No farmer profile found'});
    const quantity=Number(b.quantity);
    if(!db.crops.includes(b.crop)||!db.centres.includes(b.centre)||!b.date||b.date<today()||!b.slot||!(quantity>0))
      return json(res,400,{error:'Invalid booking details'});
    if(!db.slots.includes(b.slot))
      return json(res,400,{error:'Invalid time slot'});
    if(db.bookings.some(x=>x.farmerId===f.id&&x.date===b.date&&x.centre===b.centre&&x.slot===b.slot&&!['Rejected','Payment Completed'].includes(x.status)))
      return json(res,409,{error:'Active booking already exists for this centre, date and slot'});
    const cap=getCapacity(b.centre),used=slotUsage(b.date,b.centre,b.slot);
    const remainingFarmers=cap.maxFarmers-used.farmers;
    const remainingQuintals=Number((cap.maxQuintals-used.quintals).toFixed(3));
    if(remainingFarmers<=0||remainingQuintals<=0)
      return json(res,409,{error:'This time slot is full. Please choose another slot.',code:'SLOT_FULL',slot:b.slot,remainingFarmers:Math.max(0,remainingFarmers),remainingQuintals:Math.max(0,remainingQuintals)});
    if(quantity>remainingQuintals)
      return json(res,409,{error:`Only ${remainingQuintals} quintals remain in this slot. Please reduce quantity or choose another slot.`,code:'QUINTAL_CAPACITY_EXCEEDED',slot:b.slot,remainingQuintals});
    const pr=db.prices.find(x=>x.date===b.date&&x.centre===b.centre&&x.crop===b.crop);
    const q=b.date===today()?nextQ(b.date,b.centre):null;
    const x={id:id('BK'),farmerId:f.id,centre:b.centre,crop:b.crop,date:b.date,slot:b.slot,quantity,queueNumber:q,queueStatus:q?'waiting':'scheduled',status:'Booked',paymentStatus:'Pending',paymentMode:null,transactionId:null,estimatedAmount:pr?Number((pr.price*quantity).toFixed(2)):null,amount:null,paymentReference:null,createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()};
    db.bookings.push(x);save(db);
    return json(res,201,{booking:x,slot:slotStatus(b.date,b.centre,b.slot)});
  }
  if(req.method==='GET'&&p==='/api/queue'){const q=queue(today(),new URL(req.url,'http://localhost').searchParams.get('centre')||db.centres[0]);return json(res,200,{queue:q.map((b,i)=>({id:b.id,queueNumber:b.queueNumber,centre:b.centre,slot:b.slot,position:i+1,estimatedWait:i*15}))})}
  if(req.method==='GET'&&p==='/api/admin/data'){if(!admin(req,res))return;return json(res,200,{farmers:db.farmers,bookings:db.bookings,prices:db.prices,centres:db.centres,crops:db.crops,slots:db.slots||seed.slots,slotCapacity:db.slotCapacity||{},audit:db.audit.slice(0,50),settings:{payeeName:db.settings.payeeName,upiId:db.settings.upiId}})}
  if(req.method==='POST'&&p==='/api/admin/price'){if(!admin(req,res))return;const b=await body(req);if(!b.date||!db.centres.includes(b.centre)||!db.crops.includes(b.crop)||!(Number(b.price)>0))return json(res,400,{error:'Invalid price'});let x=db.prices.find(x=>x.date===b.date&&x.centre===b.centre&&x.crop===b.crop);if(x)x.price=Number(b.price);else db.prices.push(x={id:id('PR'),date:b.date,centre:b.centre,crop:b.crop,price:Number(b.price)});save(db);audit(x.id?'PRICE_UPDATE':'PRICE_CREATE',`${b.date}/${b.crop}/${b.centre}`);return json(res,200,{price:x})}
  if(req.method==='DELETE'&&p.startsWith('/api/admin/price/')){if(!admin(req,res))return;const pid=decodeURIComponent(p.split('/').pop());db.prices=db.prices.filter(x=>x.id!==pid);save(db);audit('PRICE_DELETE',pid);return json(res,200,{ok:true})}
  if(req.method==='POST'&&p==='/api/admin/centre'){if(!admin(req,res))return;const b=await body(req);if(!b.name?.trim())return json(res,400,{error:'Centre name required'});if(!db.centres.includes(b.name.trim()))db.centres.push(b.name.trim());save(db);audit('CENTRE_CREATE',b.name.trim());return json(res,200,{centres:db.centres})}
  if(req.method==='DELETE'&&p.startsWith('/api/admin/centre/')){if(!admin(req,res))return;const name=decodeURIComponent(p.split('/').slice(4).join('/'));if(db.bookings.some(b=>b.centre===name))return json(res,409,{error:'Cannot remove a centre used by bookings'});db.centres=db.centres.filter(x=>x!==name);save(db);return json(res,200,{centres:db.centres})}
  if(req.method==='POST'&&p==='/api/admin/crop'){if(!admin(req,res))return;const b=await body(req);if(!b.name?.trim())return json(res,400,{error:'Crop name required'});if(!db.crops.includes(b.name.trim()))db.crops.push(b.name.trim());save(db);audit('CROP_CREATE',b.name.trim());return json(res,200,{crops:db.crops})}
  if(req.method==='POST'&&p==='/api/admin/booking/status'){if(!admin(req,res))return;const b=await body(req),x=db.bookings.find(x=>x.id===b.id);if(!x)return json(res,404,{error:'Booking not found'});const allowed=['Booked','Arrived','Quality Check','Awaiting Approval','Approved','Procurement Complete','Payment Processing','Payment Completed'];if(!allowed.includes(b.status))return json(res,400,{error:'Invalid status'});x.status=b.status;x.paymentMode=b.paymentMode||x.paymentMode;if(b.status==='Payment Completed'){x.paymentStatus='Completed';x.transactionId=x.transactionId||id('TXN')}x.updatedAt=new Date().toISOString();save(db);audit('BOOKING_STATUS',`${x.id} -> ${x.status}`);return json(res,200,{booking:x})}
  if(req.method==='POST'&&p==='/api/admin/booking/reject'){if(!admin(req,res))return;const b=await body(req),x=db.bookings.find(x=>x.id===b.id);if(!x)return json(res,404,{error:'Booking not found'});x.status='Rejected';x.rejectReason=b.reason||'Not specified';x.updatedAt=new Date().toISOString();save(db);audit('BOOKING_REJECT',x.id);return json(res,200,{booking:x})}
  if(req.method==='POST'&&p==='/api/admin/queue/serve'){if(!admin(req,res))return;const x=queue(today(),db.centres[0])[0]||db.bookings.find(b=>b.date===today()&&b.queueStatus==='waiting');if(!x)return json(res,404,{error:'No farmer waiting today'});x.queueStatus='served';x.status='Arrived';x.updatedAt=new Date().toISOString();save(db);audit('QUEUE_SERVE',x.id);return json(res,200,{booking:x})}
  if(req.method==='POST'&&p==='/api/payment/request'){const b=await body(req);if(!verifiedPhone(req,res,b.phone))return;const f=db.farmers.find(x=>x.phone===b.phone),x=db.bookings.find(x=>x.id===b.bookingId);if(!f||!x||x.farmerId!==f.id)return json(res,403,{error:'You can pay only for your own booking'});if(!['Procurement Complete','Payment Processing'].includes(x.status))return json(res,400,{error:'Payment is not yet available'});const amount=Number(x.amount||x.estimatedAmount||0);if(!(amount>0))return json(res,400,{error:'Payable amount is not available yet'});if(!db.settings.upiId)return json(res,400,{error:'Admin has not configured the UPI ID'});x.amount=amount;x.paymentStatus='Initiated';x.paymentMode='UPI';x.paymentReference=x.paymentReference||id('UPI');x.updatedAt=new Date().toISOString();save(db);const upi=`upi://pay?pa=${encodeURIComponent(db.settings.upiId)}&pn=${encodeURIComponent(db.settings.payeeName)}&am=${amount.toFixed(2)}&cu=INR&tn=${encodeURIComponent('CropSync '+x.id)}`;return json(res,200,{booking:x,upiUrl:upi})}
  if(req.method==='POST'&&p==='/api/admin/settings'){if(!admin(req,res))return;const b=await body(req);if(!b.upiId||!b.upiId.includes('@'))return json(res,400,{error:'Enter a valid UPI ID'});db.settings.upiId=b.upiId.trim();db.settings.payeeName=(b.payeeName||'CropSync').trim();save(db);audit('PAYMENT_SETTINGS','UPI payment settings updated');return json(res,200,{ok:true})}
  if(req.method==='POST'&&p==='/api/admin/booking/amount'){if(!admin(req,res))return;const b=await body(req),x=db.bookings.find(x=>x.id===b.id);if(!x||!(Number(b.amount)>0))return json(res,400,{error:'Invalid booking or amount'});x.amount=Number(b.amount);x.updatedAt=new Date().toISOString();save(db);audit('PAYABLE_AMOUNT',`${x.id} amount updated`);return json(res,200,{booking:x})}
  if(req.method==='GET'&&p==='/api/tracking'){const phone=new URL(req.url,'http://localhost').searchParams.get('phone');if(!verifiedPhone(req,res,phone))return;const f=db.farmers.find(x=>x.phone===phone);if(!f)return json(res,404,{error:'Farmer not found'});return json(res,200,{bookings:db.bookings.filter(b=>b.farmerId===f.id)})}
  if(req.method==='GET'&&p==='/api/health')return json(res,200,{ok:true});
  if(req.method==='GET'){let file=p==='/'?'/index.html':p;file=path.normalize(file).replace(/^\.\.(\/|\\)/,'');const fp=path.join(PUBLIC,file);if(!fp.startsWith(PUBLIC)||!fs.existsSync(fp)||fs.statSync(fp).isDirectory())return json(res,404,{error:'Not found'});const ext=path.extname(fp),types={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.json':'application/json'};securityHeaders(res);res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream'});return fs.createReadStream(fp).pipe(res)}
  json(res,404,{error:'Not found'});
 }catch(e){console.error(e);json(res,500,{error:'Server error'})}
}
http.createServer(route).listen(PORT,()=>console.log(`CropSync running at http://localhost:${PORT}`));
