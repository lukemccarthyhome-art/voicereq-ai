(async ()=>{
  const fetch = global.fetch;
  const db = require('../database-adapter');
  const auth = require('../auth');
  const projectId = process.argv[2] || '1';
  const user = await db.getUser('luke@voicereq.ai');
  const token = auth.generateToken(user);
  const res = await fetch('http://localhost:3001/admin/projects/'+projectId+'/extract-design', { method: 'POST', headers: { cookie: 'authToken='+token }, redirect: 'manual' });
  console.log('status', res.status, 'location', res.headers.get('location'));
  const text = await res.text();
  console.log(text.substring(0,2000));
})();
