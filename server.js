const express=require('express'),Database=require('better-sqlite3'),bcrypt=require('bcryptjs'),crypto=require('crypto');
const db=new Database(process.env.DB||'helpdesk.db');db.pragma('journal_mode=WAL');
db.exec(`CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,name TEXT NOT NULL,email TEXT UNIQUE NOT NULL,pass TEXT NOT NULL,role TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tickets(id INTEGER PRIMARY KEY,title TEXT NOT NULL,descr TEXT,cat TEXT,pr TEXT,st TEXT DEFAULT 'Novo',req INT,tech INT DEFAULT 0,asset INT DEFAULT 0,at INT);
CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY,ticket INT,u INT,t INT,x TEXT);
CREATE TABLE IF NOT EXISTS assets(id INTEGER PRIMARY KEY,name TEXT NOT NULL,type TEXT,serial TEXT,user INT DEFAULT 0,status TEXT);
CREATE TABLE IF NOT EXISTS kb(id INTEGER PRIMARY KEY,title TEXT NOT NULL,body TEXT);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,user INT,exp INT);`);
const ST=["Novo","Em atendimento","Aguardando","Resolvido","Fechado"],PR=["Crítica","Alta","Média","Baixa"],ROLES=["Admin","Técnico","Solicitante"];
if(!db.prepare('SELECT 1 FROM users').get()){
  const u=db.prepare('INSERT INTO users(name,email,pass,role) VALUES(?,?,?,?)');
  u.run('Administrador','admin@empresa.com',bcrypt.hashSync('admin123',10),'Admin');
  u.run('Bruno Lima','bruno@empresa.com',bcrypt.hashSync('tecnico123',10),'Técnico');
  u.run('Carla Dias','carla@empresa.com',bcrypt.hashSync('user123',10),'Solicitante');
  db.prepare("INSERT INTO kb(title,body) VALUES('Como redefinir minha senha','Peça a redefinição abrindo um chamado em Acesso e senha.')").run();
}
const app=express();app.use(express.json({limit:'100kb'}));
const ck=r=>Object.fromEntries((r.headers.cookie||'').split(';').filter(Boolean).map(c=>{const i=c.indexOf('=');return[c.slice(0,i).trim(),c.slice(i+1)]}));
const auth=(q,s,n)=>{const t=ck(q).sid,r=t&&db.prepare('SELECT u.id,u.name,u.role FROM sessions s JOIN users u ON u.id=s.user WHERE s.token=? AND s.exp>?').get(t,Date.now());
  if(!r)return s.status(401).json({error:'Faça login'});q.me=r;q.staff=r.role!=='Solicitante';n()};
const need=f=>(q,s,n)=>f(q)?n():s.status(403).json({error:'Sem permissão'});
const staff=need(q=>q.staff),admin=need(q=>q.me.role==='Admin');
app.post('/api/login',(q,s)=>{const{email,pass}=q.body||{},u=db.prepare('SELECT * FROM users WHERE email=?').get(String(email||'').toLowerCase());
  if(!u||!bcrypt.compareSync(String(pass||''),u.pass))return s.status(400).json({error:'E-mail ou senha incorretos'});
  const t=crypto.randomBytes(32).toString('hex');db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(t,u.id,Date.now()+864e5*7);
  s.setHeader('Set-Cookie',`sid=${t}; HttpOnly; SameSite=Strict; Path=/; Max-Age=604800`);s.json({ok:1})});
app.post('/api/logout',(q,s)=>{db.prepare('DELETE FROM sessions WHERE token=?').run(ck(q).sid||'');s.setHeader('Set-Cookie','sid=; Max-Age=0; Path=/');s.json({ok:1})});
app.use('/api',auth);
app.get('/api/data',(q,s)=>{const m=q.me,st=q.staff;
  const T=db.prepare(`SELECT id,title,descr AS "desc",cat,pr,st,req,tech,asset,at FROM tickets ${st?'':'WHERE req='+m.id}`).all();
  const C=db.prepare('SELECT ticket,u,t,x FROM comments ORDER BY t').all();T.forEach(t=>t.cm=C.filter(c=>c.ticket===t.id));
  s.json({me:m.id,tickets:T,assets:db.prepare(`SELECT id,name,type,serial,user,status FROM assets ${st?'':'WHERE user='+m.id}`).all(),
    kb:db.prepare('SELECT * FROM kb').all(),users:db.prepare(`SELECT id,name,role${m.role==='Admin'?',email':''} FROM users`).all()})});
app.post('/api/tickets',(q,s)=>{const b=q.body;if(!b.title||!PR.includes(b.pr))return s.status(400).json({error:'Dados inválidos'});
  s.json({id:db.prepare('INSERT INTO tickets(title,descr,cat,pr,req,asset,at) VALUES(?,?,?,?,?,?,?)').run(b.title,b.desc||'',b.cat||'Outro',b.pr,q.me.id,+b.asset||0,Date.now()).lastInsertRowid})});
app.put('/api/tickets/:id',(q,s)=>{const t=db.prepare('SELECT * FROM tickets WHERE id=?').get(q.params.id),b=q.body;
  if(!t||(!q.staff&&t.req!==q.me.id))return s.status(404).json({error:'Chamado não encontrado'});
  if(q.staff){if(!ST.includes(b.st)||!PR.includes(b.pr))return s.status(400).json({error:'Dados inválidos'});
    const tech=+b.tech||0,st=tech&&b.st==='Novo'?'Em atendimento':b.st;db.prepare('UPDATE tickets SET st=?,pr=?,tech=? WHERE id=?').run(st,b.pr,tech,t.id)}
  if(b.comment)db.prepare('INSERT INTO comments(ticket,u,t,x) VALUES(?,?,?,?)').run(t.id,q.me.id,Date.now(),String(b.comment).slice(0,5000));s.json({ok:1})});
app.post('/api/assets',staff,(q,s)=>{const b=q.body;if(!b.name)return s.status(400).json({error:'Informe o nome'});
  db.prepare('INSERT INTO assets(name,type,serial,user,status) VALUES(?,?,?,?,?)').run(b.name,b.type,b.serial||'',+b.user||0,b.status);s.json({ok:1})});
app.delete('/api/assets/:id',staff,(q,s)=>{db.prepare('DELETE FROM assets WHERE id=?').run(q.params.id);s.json({ok:1})});
app.post('/api/kb',staff,(q,s)=>{if(!q.body.title)return s.status(400).json({error:'Informe o título'});db.prepare('INSERT INTO kb(title,body) VALUES(?,?)').run(q.body.title,q.body.body||'');s.json({ok:1})});
app.delete('/api/kb/:id',staff,(q,s)=>{db.prepare('DELETE FROM kb WHERE id=?').run(q.params.id);s.json({ok:1})});
app.post('/api/users',admin,(q,s)=>{const b=q.body;if(!b.name||!b.email||!b.pass||b.pass.length<6||!ROLES.includes(b.role))return s.status(400).json({error:'Preencha tudo (senha com 6+ caracteres)'});
  try{db.prepare('INSERT INTO users(name,email,pass,role) VALUES(?,?,?,?)').run(b.name,b.email.toLowerCase(),bcrypt.hashSync(b.pass,10),b.role);s.json({ok:1})}catch(e){s.status(400).json({error:'E-mail já cadastrado'})}});
app.use(express.static(__dirname+'/public'));
app.listen(process.env.PORT||3000,()=>console.log('Central de TI em http://localhost:'+(process.env.PORT||3000)));
