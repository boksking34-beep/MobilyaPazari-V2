const webpush=require('web-push');
module.exports=function(db){
let ready;
async function init(){
 if(!ready)ready=(async()=>{
 await db.query("CREATE TABLE IF NOT EXISTS admin_push_config (id integer PRIMARY KEY CHECK(id=1), public_key text NOT NULL, private_key text NOT NULL)");
 await db.query("CREATE TABLE IF NOT EXISTS admin_push_device (id integer PRIMARY KEY CHECK(id=1), user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE, subscription jsonb NOT NULL)");
 const keys=webpush.generateVAPIDKeys();
 await db.query("INSERT INTO admin_push_config VALUES(1,$1,$2) ON CONFLICT DO NOTHING",[keys.publicKey,keys.privateKey]);
 const k=(await db.query("SELECT public_key,private_key FROM admin_push_config WHERE id=1")).rows[0];
 webpush.setVapidDetails('https://mobilya-pazari-v2.onrender.com/',k.public_key,k.private_key);
 return k.public_key;
 })().catch(e=>{ready=null;throw e});
 return ready;
}
async function allowed(u){return !!u&&u.role==='admin'&&!!(await db.query("SELECT 1 FROM users WHERE id=$1 AND public_id=1 AND role='admin' AND NOT blocked",[u.id])).rowCount}
async function route(req,url,reply,u,body){
 if(!await allowed(u))return reply(403,{error:'Yetki yok'});
 const key=await init();
 if(req.method==='GET'&&url==='/admin-push/key')return reply(200,{key});
 if(req.method!=='POST'||req.headers.origin!=='https://mobilya-pazari-v2.onrender.com')return reply(403,{error:'Yetki yok'});
 if(url==='/admin-push/subscribe'){
 const s=await body(req);let endpoint;try{endpoint=new URL(s.endpoint)}catch{return reply(400,{error:'Geçersiz cihaz'})}
 if(endpoint.protocol!=='https:'||endpoint.port||endpoint.username||endpoint.password||!['fcm.googleapis.com','updates.push.services.mozilla.com','web.push.apple.com'].includes(endpoint.hostname)||!/^[-_A-Za-z0-9]{87}$/.test(s.keys?.p256dh||'')||!/^[-_A-Za-z0-9]{22}$/.test(s.keys?.auth||''))return reply(400,{error:'Geçersiz cihaz'});
 await db.query("INSERT INTO admin_push_device VALUES(1,$1,$2) ON CONFLICT(id) DO UPDATE SET user_id=EXCLUDED.user_id,subscription=EXCLUDED.subscription",[u.id,JSON.stringify({endpoint:s.endpoint,keys:s.keys})]);
 return reply(200,{ok:true});
 }
 if(url==='/admin-push/disable'){await db.query('DELETE FROM admin_push_device WHERE user_id=$1',[u.id]);return reply(200,{ok:true})}
 if(url==='/admin-push/test'){return reply(200,{ok:await send('Test bildirimi','Yönetici bildirimleri çalışıyor.')})}
 return reply(404,{error:'Bulunamadı'});
}
async function send(title,body){
 try{await init();const r=(await db.query("SELECT d.subscription FROM admin_push_device d JOIN users u ON u.id=d.user_id WHERE d.id=1 AND u.public_id=1 AND u.role='admin' AND NOT u.blocked")).rows[0];if(!r)return false;
 try{await webpush.sendNotification(r.subscription,JSON.stringify({title,body}),{TTL:3600,timeout:5000});return true}catch(e){if([404,410].includes(e.statusCode))await db.query('DELETE FROM admin_push_device WHERE subscription=$1::jsonb',[JSON.stringify(r.subscription)]);return false}
 }catch(e){console.error('Admin push failed');return false}
}
return {route,send};
};
