
require('dotenv').config();
const express=require('express'), session=require('express-session'), helmet=require('helmet'), rateLimit=require('express-rate-limit'), multer=require('multer'), bcrypt=require('bcryptjs'), Database=require('better-sqlite3'), crypto=require('crypto'), fs=require('fs'),path=require('path');
if(!process.env.ADMIN_PASSWORD||!process.env.SESSION_SECRET||process.env.SESSION_SECRET.length<32){console.error('Configure ADMIN_PASSWORD e SESSION_SECRET (32+ caracteres) no .env');process.exit(1)}
fs.mkdirSync('data',{recursive:true});fs.mkdirSync('uploads',{recursive:true});
const db=new Database('data/xt.sqlite');db.pragma('journal_mode = WAL');
db.exec(`CREATE TABLE IF NOT EXISTS teams(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, logo TEXT, captain TEXT NOT NULL, phone TEXT NOT NULL, rush1 TEXT NOT NULL, rush2 TEXT NOT NULL, grenade TEXT NOT NULL, support TEXT NOT NULL, reserves TEXT, status TEXT NOT NULL DEFAULT 'pendente', created TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY,value TEXT NOT NULL);`);
db.exec(`CREATE TABLE IF NOT EXISTS scores(team_id INTEGER PRIMARY KEY, placement INTEGER NOT NULL DEFAULT 0, kills INTEGER NOT NULL DEFAULT 0, points INTEGER NOT NULL DEFAULT 0, FOREIGN KEY(team_id) REFERENCES teams(id));`);
const defaults={rules:'Sem cavalo. Carros apenas para locomoção. Proibido marcar na loja. 4 quedas: Bermuda, Purgatório, Kalahari e Nova Terra. Pontuação LBFF 2021. Sem trapaças. Apenas 1 emulador por equipe.',capacity:'12',event:'XTREINO DEMꓳN SLꓥYER'};
for(const [k,v] of Object.entries(defaults))db.prepare('INSERT OR IGNORE INTO config(key,value) VALUES (?,?)').run(k,v);
const app=express();app.disable('x-powered-by');app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:'30kb'}));app.use(express.urlencoded({extended:false}));
app.use(session({name:'xt.sid',secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:process.env.NODE_ENV==='production',maxAge:8*60*60*1000}}));
const limiter=rateLimit({windowMs:15*60*1000,limit:20,standardHeaders:'draft-7',legacyHeaders:false});
const upload=multer({storage:multer.diskStorage({destination:'uploads',filename:(req,file,cb)=>cb(null,crypto.randomUUID()+'.'+(file.mimetype==='image/png'?'png':file.mimetype==='image/webp'?'webp':'jpg'))}),limits:{fileSize:2*1024*1024},fileFilter:(req,file,cb)=>cb(null,['image/png','image/jpeg','image/webp'].includes(file.mimetype))});
const get=(k)=>db.prepare('SELECT value FROM config WHERE key=?').get(k)?.value;
const admin=(req,res,next)=>req.session.admin?next():res.status(401).json({error:'Acesso exclusivo do ADM'});
const clean=(v,n=80)=>String(v||'').trim().slice(0,n);
app.get('/api/public',(req,res)=>res.json({event:get('event'),rules:get('rules'),capacity:Number(get('capacity')),occupied:db.prepare("SELECT count(*) n FROM teams WHERE status IN ('pendente','aprovada')").get().n,teams:db.prepare("SELECT id,name,logo,status FROM teams WHERE status='aprovada' ORDER BY id ASC").all(),ranking:db.prepare("SELECT t.id,t.name,COALESCE(s.placement,0) placement,COALESCE(s.kills,0) kills,COALESCE(s.points,0) points FROM teams t LEFT JOIN scores s ON s.team_id=t.id WHERE t.status='aprovada' ORDER BY points DESC,kills DESC,t.id ASC").all()}));
app.use('/logos',express.static('uploads',{index:false,fallthrough:false}));
app.post('/api/register',limiter,upload.single('logo'),(req,res)=>{
const fields=['name','captain','phone','rush1','rush2','grenade','support'],t={};for(const k of fields)t[k]=clean(req.body[k],k==='phone'?25:60);
if(fields.some(k=>!t[k])){if(req.file)fs.unlinkSync(req.file.path);return res.status(400).json({error:'Preencha todos os campos obrigatórios'})}
if(!/^[+()\d\s-]{8,25}$/.test(t.phone)){if(req.file)fs.unlinkSync(req.file.path);return res.status(400).json({error:'WhatsApp inválido'})}
const transaction=db.transaction(()=>{
const n=db.prepare("SELECT count(*) n FROM teams WHERE status IN ('pendente','aprovada')").get().n;
if(n>=Number(get('capacity')))return false;
db.prepare('INSERT INTO teams(name,logo,captain,phone,rush1,rush2,grenade,support,reserves) VALUES(?,?,?,?,?,?,?,?,?)').run(t.name,req.file?req.file.filename:null,t.captain,t.phone,t.rush1,t.rush2,t.grenade,t.support,clean(req.body.reserves,200));return true;
});
if(!transaction()){if(req.file)fs.unlinkSync(req.file.path);return res.status(409).json({error:'As 12 vagas estão preenchidas'})}
res.json({ok:true,message:'Inscrição recebida! Aguarde aprovação.'});
});
app.post('/api/admin/login',limiter,(req,res)=>{
const u=clean(req.body.user),p=String(req.body.password||'');
const goodUser=u===(process.env.ADMIN_USER||'killerX');
const a=crypto.scryptSync(p,'xt-login-v2',32),b=crypto.scryptSync(process.env.ADMIN_PASSWORD,'xt-login-v2',32);const goodPass=crypto.timingSafeEqual(a,b);
if(!goodUser||!goodPass)return res.status(401).json({error:'Login ou senha incorretos'});
req.session.regenerate(e=>{if(e)return res.status(500).json({error:'Erro de sessão'});req.session.admin=true;res.json({ok:true})});
});
app.post('/api/admin/logout',admin,(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/admin/session',(req,res)=>res.json({admin:!!req.session.admin}));
app.get('/api/admin/data',admin,(req,res)=>res.json({teams:db.prepare('SELECT t.*,COALESCE(s.placement,0) placement,COALESCE(s.kills,0) kills,COALESCE(s.points,0) points FROM teams t LEFT JOIN scores s ON s.team_id=t.id ORDER BY t.id DESC').all(),rules:get('rules'),capacity:Number(get('capacity')),event:get('event')}));
app.patch('/api/admin/teams/:id',admin,(req,res)=>{if(!['pendente','aprovada','recusada'].includes(req.body.status))return res.status(400).json({error:'Status inválido'});const r=db.prepare('UPDATE teams SET status=? WHERE id=?').run(req.body.status,Number(req.params.id));res.json({ok:r.changes>0})});
app.put('/api/admin/scores/:id',admin,(req,res)=>{const id=Number(req.params.id),t=db.prepare('SELECT id FROM teams WHERE id=?').get(id),placement=Number(req.body.placement),kills=Number(req.body.kills),points=Number(req.body.points);if(!t||![placement,kills,points].every(v=>Number.isInteger(v)&&v>=0&&v<=10000))return res.status(400).json({error:'Pontuação inválida'});db.prepare('INSERT INTO scores(team_id,placement,kills,points) VALUES(?,?,?,?) ON CONFLICT(team_id) DO UPDATE SET placement=excluded.placement,kills=excluded.kills,points=excluded.points').run(id,placement,kills,points);res.json({ok:true})});
app.delete('/api/admin/teams/:id',admin,(req,res)=>{const t=db.prepare('SELECT logo FROM teams WHERE id=?').get(Number(req.params.id));if(t?.logo)try{fs.unlinkSync(path.join('uploads',t.logo))}catch{};db.prepare('DELETE FROM scores WHERE team_id=?').run(Number(req.params.id));db.prepare('DELETE FROM teams WHERE id=?').run(Number(req.params.id));res.json({ok:true})});
app.put('/api/admin/config',admin,(req,res)=>{const rules=clean(req.body.rules,3000),event=clean(req.body.event,100),capacity=Number(req.body.capacity);if(!rules||!event||!Number.isInteger(capacity)||capacity<1||capacity>100)return res.status(400).json({error:'Configuração inválida'});for(const [k,v] of Object.entries({rules,event,capacity:String(capacity)}))db.prepare('UPDATE config SET value=? WHERE key=?').run(v,k);res.json({ok:true})});
app.post('/api/admin/finish',admin,(req,res)=>{if(req.body.confirm!=='FINALIZAR XT')return res.status(400).json({error:'Digite FINALIZAR XT para confirmar'});const all=db.prepare('SELECT logo FROM teams').all();db.prepare('DELETE FROM scores').run();const r=db.prepare('DELETE FROM teams').run();for(const t of all)if(t.logo)try{fs.unlinkSync(path.join('uploads',t.logo))}catch{};res.json({ok:true,removed:r.changes})});
app.use(express.static('public'));
app.use((err,req,res,next)=>res.status(400).json({error:err.code==='LIMIT_FILE_SIZE'?'Logo deve ter no máximo 2 MB':'Erro ao enviar arquivo ou processar pedido'}));
app.listen(Number(process.env.PORT)||3000,()=>console.log('Site em http://localhost:'+(process.env.PORT||3000)));
