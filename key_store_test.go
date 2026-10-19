package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fakeKeyStoreHelper(t *testing.T, source string) *CommandKeyStore {
	t.Helper()
	path := filepath.Join(t.TempDir(), "helper.py")
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	return NewCommandKeyStore(path)
}

func TestCommandKeyStoreUsesOnlyStdinAndValidatesCreateReceipt(t *testing.T) {
	t.Setenv("KEY_MANAGEMENT_MASTER_KEY", "master-key-must-not-reach-helper")
	s := fakeKeyStoreHelper(t, `import json,sys,os
d=json.load(sys.stdin)
assert len(sys.argv)==1
assert 'KEY_MANAGEMENT_MASTER_KEY' not in os.environ
assert d['operation']=='create'
assert d['credential'].startswith('sk-')
assert d['record']['user_id']==42
assert d['record']['nonce']=='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
json.dump({'ok':True,'key':{'id':8,'user_id':42,'key':d['credential'],'name':'test'}},sys.stdout)
`)
	record := ManagedRecord{Nonce: strings.Repeat("a", 32), UserID: 42, AdminID: 1, GroupID: 3, Name: "test"}
	credential := "sk-" + strings.Repeat("b", 64)
	key, err := s.Create(context.Background(), record, credential)
	if err != nil || key.ID != 8 || key.Key != credential {
		t.Fatalf("create receipt not accepted: %v", err)
	}
	record.UserID = 43
	if _, err = s.Create(context.Background(), record, credential); err == nil || strings.Contains(err.Error(), credential) {
		t.Fatal("mismatched or failed receipt accepted, or raw credentials exposed")
	}
}

func TestCommandKeyStoreSuppressesHelperOutputAndSupportsPreflight(t *testing.T) {
	secret := "postgres-password-and-full-api-key-must-stay-private"
	s := fakeKeyStoreHelper(t, `import json,sys
d=json.load(sys.stdin)
if d['operation']=='check':
 json.dump({'ok':True},sys.stdout)
else:
 print('postgres-password-and-full-api-key-must-stay-private',file=sys.stderr)
 print('{"ok":false,"kind":"conflict","error":"postgres-password-and-full-api-key-must-stay-private"}')
 sys.exit(1)
`)
	if err := s.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := s.Update(context.Background(), ManagedRecord{UserID: 42}, secret, map[string]any{"status": "inactive"})
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("helper exception details were exposed")
	}
	if failure, ok := err.(*ManagerError); !ok || failure.Status != 409 {
		t.Fatal("identity conflict must remain distinguishable")
	}
}

func TestCommandKeyStoreCancelsAndBoundsOutput(t *testing.T) {
	s := fakeKeyStoreHelper(t, "import time\ntime.sleep(20)\n")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := s.Check(ctx); err == nil || time.Since(start) > 2*time.Second {
		t.Fatal("helper ignored request cancellation")
	}
	s = fakeKeyStoreHelper(t, "print('secret' * 20000)\n")
	if err := s.Check(context.Background()); err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatal("unbounded helper output or leaked details")
	}
}

func TestPythonKeyStoreScopesWritesChecksOwnershipAndInvalidatesNativeCache(t *testing.T) {
	path, err := filepath.Abs("key_store.py")
	if err != nil {
		t.Fatal(err)
	}
	// The fake DB checks the actual SQL and arguments emitted by the helper. It
	// deliberately fails if any wallet/user/counter/group update is attempted.
	script := `import importlib.util,json,sys,hashlib,datetime
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('key_store',sys.argv[1]);h=importlib.util.module_from_spec(spec);spec.loader.exec_module(h)
record={'nonce':'a'*32,'admin_id':1,'user_id':42,'key_id':0,'name':'name<&','group_id':3,'expires_at':''}
credential='sk-'+'b'*64
class Cursor:
 def __init__(self): self.rows=[];self.calls=[];self.rowcount=0
 def execute(self,sql,args=None):
  self.calls.append((sql,args));self.rowcount=0
  if sql.startswith('SELECT pg_advisory'): return
  if sql==h.IDENTITY_SQL:
   self.answer={'id':42,'email':'km-'+'a'*32+'@keymgr.invalid','notes':'sub2api-key-management owner=1 nonce='+'a'*32,'role':'user','status':'active'};return
  if sql==h.KEYS_SQL:self.answer=list(self.rows);return
  if sql.startswith('INSERT INTO public.api_keys'):
   assert args==(42,credential,'name&lt;&amp;',3,None),args
   self.rows=[{'id':8,'user_id':42,'key':credential,'name':args[2],'group_id':3,'status':'active','quota':0,'quota_used':0,'expires_at':None,'last_used_at':None,'created_at':datetime.datetime.now(datetime.timezone.utc)}];self.answer=self.rows[0];return
  if sql.startswith('UPDATE public.api_keys'):
   assert 'status=%s' in sql and 'name=%s' in sql and 'updated_at=NOW()' in sql
   assignments=sql.split(' SET ',1)[1].split(' WHERE ',1)[0]
   assert not any(column+'=' in assignments for column in ('group_id','quota','quota_used','user_id'))
   assert args==('new&lt;&#34;','inactive',8,42,credential),args
   self.rowcount=1;return
  raise AssertionError(sql)
 def fetchone(self):return self.answer
 def fetchall(self):return self.answer
c=Cursor()
h.validate_request({'operation':'create','record':record,'credential':credential})
first=h.write(c,'create',record,credential,{})
assert first['id']==8
c.rows[0]['quota_used']=12.5;c.rows[0]['status']='inactive'
second=h.write(c,'create',dict(record,key_id=8),credential,{})
assert second['quota_used']==12.5 and second['status']=='inactive'
assert len([sql for sql,args in c.calls if sql.startswith('INSERT')])==1
h.write(c,'update',dict(record,key_id=8),credential,{'name':'new<"','status':'inactive'})
try:h.validate_request({'operation':'update','record':dict(record,key_id=8),'credential':credential,'fields':{'quota_used':0}});raise AssertionError('counter write accepted')
except ValueError:pass
try:h.write(c,'update',dict(record,key_id=99),credential,{'status':'active'});raise AssertionError('foreign key accepted')
except h.Conflict:pass
class BadIdentity(Cursor):
 def fetchone(self):
  result=super().fetchone();result=dict(result);result['notes']='foreign';return result
try:h.write(BadIdentity(),'create',record,credential,{});raise AssertionError('foreign identity accepted')
except h.Conflict:pass
class Redis:
 def __init__(self):self.calls=[]
 def delete(self,key):self.calls.append(('DEL',key))
 def publish(self,channel,payload):self.calls.append(('PUBLISH',channel,payload));return 1
r=Redis();h.invalidate(r,credential);digest=hashlib.sha256(credential.encode()).hexdigest()
assert r.calls==[('DEL','apikey:auth:'+digest),('PUBLISH','auth:cache:invalidate',digest)]
class CheckCursor:
 def __init__(self,deny_outbox=False,deny_sequence=False):self.calls=[];self.deny_outbox=deny_outbox;self.deny_sequence=deny_sequence
 def __enter__(self):return self
 def __exit__(self,*args):pass
 def execute(self,sql,args=None):
  assert sql.lstrip().startswith('SELECT '),'preflight performed a database write'
  self.calls.append(sql)
  self.answer=[{'attname':column} for column in ('user_id','key','name')] if sql==h.REQUIRED_SQL else {'allowed':True}
  if 'auth_cache_invalidation_outbox' in sql:
   if self.deny_outbox and 'has_column_privilege' in sql:self.answer={'allowed':False}
   if self.deny_sequence and 'has_sequence_privilege' in sql:self.answer={'allowed':False}
 def fetchone(self):return self.answer
 def fetchall(self):return self.answer
for kwargs in ({'deny_outbox':True},{'deny_sequence':True}):
 try:h.check(CheckCursor(**kwargs));raise AssertionError('missing native trigger privilege was accepted')
 except ValueError:pass
class CheckConnection:
 def __init__(self):self.cur=CheckCursor();self.readonly=None;self.closed=False
 def set_session(self,**kwargs):self.readonly=kwargs['readonly']
 def cursor(self,**kwargs):return self.cur
 def close(self):self.closed=True
 def rollback(self):pass
 def commit(self):raise AssertionError('preflight committed a write')
class ProbeRedis(Redis):
 def ping(self):self.calls.append(('PING',));return True
connection=CheckConnection();probe=ProbeRedis()
h.connect_db=lambda:(connection,object);h.connect_redis=lambda:probe
assert h.handle_request({'operation':'check'})=={'ok':True}
assert connection.readonly is True and connection.closed
assert [call[0] for call in probe.calls]==['PING','DEL','PUBLISH']
assert probe.calls[1][1].startswith('apikey:auth:')
assert probe.calls[2][1]=='auth:cache:invalidate'
assert probe.calls[2][2]!=digest,'preflight targeted the actual credential'
print('scoped key writes and native cache invalidation passed')
`
	command := exec.Command("/usr/bin/python3", "-I", "-c", script, path)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Python scope verification failed: %s", output)
	}
}
