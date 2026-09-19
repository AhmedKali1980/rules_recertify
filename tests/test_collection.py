import csv, json, os, sqlite3, stat, tempfile, unittest
from datetime import date
from pathlib import Path
from unittest.mock import patch
from rules_recertify.collection import _validated_usage_rows, collect, collect_policy
from rules_recertify.config import Settings

FAKE = r'''#!/usr/bin/env python3
import csv,os,sys
args=sys.argv
cmd=next(x for x in ('ruleset-export','label-export','rule-export','rule-usage') if x in args)
if os.getenv('FAKE_COMMAND_LOG'):
 with open(os.environ['FAKE_COMMAND_LOG'],'a') as log: log.write(' '.join(args[1:])+'\n')
if os.getenv('FAKE_POLICY_FAIL') and cmd=='rule-export' and '--traffic-count' not in args:
 raise SystemExit('forced policy failure')
out=args[args.index('--output-file')+1]
def write(headers, rows):
 with open(out,'w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=headers); w.writeheader(); w.writerows(rows)
if cmd=='ruleset-export': write(['ruleset_name','enabled','href'],[{'ruleset_name':'APP','enabled':'true','href':'/rs/1'},{'ruleset_name':'INFRA','enabled':'true','href':'/rs/infra'}])
elif cmd=='label-export': write(['key','value'],[{'key':'app','value':'APP'}])
elif cmd=='rule-export' and '--traffic-count' not in args:
 rows=[{'ruleset_name':'APP','ruleset_scope':'app:APP;env:PRD','ruleset_enabled':'true','rule_type':'allow','rule_enabled':'true','ruleset_href':'/rs/1','rule_href':'/r/1','services':'443 TCP'},{'ruleset_name':'INFRA','ruleset_scope':'','ruleset_enabled':'true','rule_type':'allow','rule_enabled':'true','ruleset_href':'/rs/infra','rule_href':'/r/infra','services':'All Services'}]
 write(['ruleset_name','ruleset_scope','ruleset_enabled','rule_type','rule_enabled','ruleset_href','rule_href','services'],rows[:1] if os.getenv('FAKE_DROP_INFRA') else rows)
elif cmd=='rule-export':
 q='{"start_date":"2026-08-20T00:00:00Z","end_date":"2026-08-21T00:00:00Z"}'
 write(['ruleset_href','rule_href','async_query_status','flows','flows_by_port','query_body'],[{'ruleset_href':'/rs/1','rule_href':'/r/1','async_query_status':'','flows':'','flows_by_port':'','query_body':q}])
else:
 q='{"start_date":"2026-08-20T00:00:00Z","end_date":"2026-08-21T00:00:00Z"}'
 rows=[{'ruleset_href':'/rs/1','rule_href':'/r/1','async_query_status':'completed','flows':'3','flows_by_port':'443 TCP (3)','query_body':q}]
 if os.getenv('FAKE_INVALID_QUERY_BODY'):
  rows.append({'ruleset_href':'/rs/1','rule_href':'/r/invalid','async_query_status':'unknown','flows':'','flows_by_port':'','query_body':''})
 write(['ruleset_href','rule_href','async_query_status','flows','flows_by_port','query_body'],rows)
'''
FAKE_OVERSIZED = r'''#!/usr/bin/env python3
import csv,sys
args=sys.argv
cmd=next(x for x in ('ruleset-export','label-export','rule-export','rule-usage') if x in args)
out=args[args.index('--output-file')+1]
def write(headers, rows):
 with open(out,'w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=headers); w.writeheader(); w.writerows(rows)
if cmd=='ruleset-export':
 write(['ruleset_name','enabled','href'],[{'ruleset_name':'BIG','enabled':'true','href':'/rs/big'}])
elif cmd=='label-export':
 write(['key','value'],[{'key':'app','value':'BIG'}])
elif cmd=='rule-export' and '--traffic-count' not in args:
 headers=['ruleset_name','ruleset_scope','ruleset_enabled','rule_type','rule_enabled','ruleset_href','rule_href','services']
 write(headers,[{'ruleset_name':'BIG','ruleset_scope':'app:BIG;env:PRD','ruleset_enabled':'true','rule_type':'allow','rule_enabled':'true','ruleset_href':'/rs/big','rule_href':f'/r/{i}','services':'443 TCP'} for i in range(101)])
else:
 raise SystemExit('oversized ruleset must not be submitted')
'''
FAKE_RUNTIME_OVERSIZED = r'''#!/usr/bin/env python3
import csv,sys
args=sys.argv
cmd=next(x for x in ('ruleset-export','label-export','rule-export','rule-usage') if x in args)
out=args[args.index('--output-file')+1]
def write(headers, rows):
 with open(out,'w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=headers); w.writeheader(); w.writerows(rows)
if cmd=='ruleset-export':
 write(['ruleset_name','enabled','href'],[{'ruleset_name':'BIG','enabled':'true','href':'/rs/big'}])
elif cmd=='label-export':
 write(['key','value'],[{'key':'app','value':'BIG'}])
elif cmd=='rule-export' and '--traffic-count' not in args:
 headers=['ruleset_name','ruleset_scope','ruleset_enabled','rule_type','rule_enabled','ruleset_href','rule_href','services']
 write(headers,[{'ruleset_name':'BIG','ruleset_scope':'app:BIG;env:PRD','ruleset_enabled':'true','rule_type':'allow','rule_enabled':'true','ruleset_href':'/rs/big','rule_href':f'/r/{i}','services':'443 TCP'} for i in range(100)])
elif cmd=='rule-export':
 print('traffic-rule-limit set to 100 and total rules is 101')
 raise SystemExit(1)
else:
 raise SystemExit('excluded ruleset must not be polled')
'''


def _policy_reference_stub(root):
 stub=root/'policy-stub'; stub.mkdir()
 workload_headers=['href','hostname','name','external_data_set','created_at','interfaces',
                   'public_ip','ip_with_default_gw','app','env','loc','role','managed',
                   'enforcement','external_data_reference','OS','os_id']
 with (stub/'export_wkld.csv').open('w',newline='',encoding='utf-8') as handle:
  writer=csv.DictWriter(handle,fieldnames=workload_headers); writer.writeheader()
  writer.writerow({'href':'/w/1','hostname':'host.example','name':'host','interfaces':'eth0:10.0.0.1',
                   'ip_with_default_gw':'10.0.0.1','app':'APP','env':'PRD','managed':'TRUE'})
 with (stub/'export_iplists.csv').open('w',newline='',encoding='utf-8') as handle:
  writer=csv.DictWriter(handle,fieldnames=['name','include']); writer.writeheader()
  writer.writerow({'name':'NZ3_TEST','include':'10.0.0.0/24'})
 with (stub/'export_services.csv').open('w',newline='',encoding='utf-8') as handle:
  writer=csv.DictWriter(handle,fieldnames=['name','service_ports']); writer.writeheader()
  writer.writerow({'name':'WEB-SVC','service_ports':'443 TCP'})
 return stub


class CollectionTest(unittest.TestCase):
 def test_collect_policy_publishes_complete_inventory_without_traffic(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'
   binary.write_text(FAKE); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   command_log=root/'commands.log'
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),
                     raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'))
   with patch.dict(os.environ, {'FAKE_COMMAND_LOG':str(command_log)}):
    result=collect_policy(settings,_policy_reference_stub(root))
   self.assertEqual(result['status'],'SUCCESS')
   self.assertEqual(result['rule_count'],2)
   commands=command_log.read_text()
   self.assertNotIn('--traffic-count',commands)
   self.assertNotIn('rule-usage',commands)
   self.assertTrue((root/'raw'/'snapshot'/'manifest.json').is_file())
   self.assertTrue((root/'raw'/'snapshot'/'export_wkld.derived.csv').is_file())
   with sqlite3.connect(root/'db.sqlite') as connection:
    run_type,status=connection.execute('SELECT run_type,status FROM runs').fetchone()
    rules=connection.execute('SELECT rule_href,is_present FROM rules ORDER BY rule_href').fetchall()
    snapshot=connection.execute('SELECT status,rule_count,snapshot_path FROM policy_snapshots').fetchone()
   self.assertEqual((run_type,status),('POLICY_COLLECTION','SUCCESS'))
   self.assertEqual(rules,[('/r/1',1),('/r/infra',1)])
   self.assertEqual(snapshot[:2],('COMPLETE',2))
   self.assertEqual(snapshot[2],str(root/'raw'/'snapshot'))

 def test_failed_collect_policy_preserves_previous_current_rules_and_snapshot(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'
   binary.write_text(FAKE); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),
                     raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'))
   stub=_policy_reference_stub(root)
   collect_policy(settings,stub)
   original_manifest=(root/'raw'/'snapshot'/'manifest.json').read_text()
   with patch.dict(os.environ, {'FAKE_POLICY_FAIL':'1'}):
    with self.assertRaises(Exception):
     collect_policy(settings,stub)
   with sqlite3.connect(root/'db.sqlite') as connection:
    current=connection.execute('SELECT rule_href,is_present FROM rules ORDER BY rule_href').fetchall()
    snapshots=connection.execute('SELECT COUNT(*) FROM policy_snapshots').fetchone()[0]
   self.assertEqual(current,[('/r/1',1),('/r/infra',1)])
   self.assertEqual(snapshots,1)
   self.assertEqual((root/'raw'/'snapshot'/'manifest.json').read_text(),original_manifest)

 def test_successful_collect_policy_marks_disappeared_rule_absent(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'
   binary.write_text(FAKE); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),
                     raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'))
   stub=_policy_reference_stub(root)
   collect_policy(settings,stub)
   with patch.dict(os.environ, {'FAKE_DROP_INFRA':'1'}):
    collect_policy(settings,stub)
   with sqlite3.connect(root/'db.sqlite') as connection:
    states=dict(connection.execute('SELECT rule_href,is_present FROM rules'))
   self.assertEqual(states,{'/r/1':1,'/r/infra':0})

 def test_malformed_port_detail_is_isolated_with_rule_identity(self):
  query='{"start_date":"2026-08-20T00:00:00Z","end_date":"2026-08-21T00:00:00Z"}'
  valid, invalid_query, invalid_ports=_validated_usage_rows(
   [{'rule_href':'/r/bad','query_body':query,'flows_by_port':'not a protocol'}],
   date(2026,8,20),date(2026,8,21)
  )
  self.assertEqual(valid,[])
  self.assertEqual(invalid_query,[])
  self.assertEqual(invalid_ports[0]['rule_href'],'/r/bad')

 def test_end_to_end_with_fake_workloader(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'; binary.write_text(FAKE); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'),query_initial_delay_minutes=0)
   result=collect(settings,date(2026,8,20),date(2026,8,21),no_wait=True)
   self.assertEqual(result['status'],'SUCCESS'); self.assertEqual(result['completed'],1)
   self.assertEqual(result['excluded_scope_ruleset_count'],1)
   self.assertEqual(result['excluded_scope_rulesets'][0]['reason'],'EMPTY_SCOPE')
   self.assertTrue(list((root/'raw').glob('*/manifest.json')))

 def test_oversized_ruleset_is_skipped_and_audited(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'; binary.write_text(FAKE_OVERSIZED); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'),traffic_batch_size=100,query_initial_delay_minutes=0)
   result=collect(settings,date(2026,8,20),date(2026,8,21),no_wait=True)
   self.assertEqual(result['status'],'WARNING')
   self.assertEqual(result['skipped_oversized_ruleset_count'],1)
   self.assertEqual(result['skipped_oversized_rule_count'],101)
   self.assertEqual(result['batches'],[])
   with sqlite3.connect(root/'db.sqlite') as connection:
    category=connection.execute('SELECT category FROM data_quality').fetchone()[0]
   self.assertEqual(category,'RULESET_SKIPPED_OVERSIZED')

 def test_invalid_query_body_is_audited_without_aborting_collection(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'; binary.write_text(FAKE); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'),query_initial_delay_minutes=0)
   with patch.dict(os.environ, {'FAKE_INVALID_QUERY_BODY':'1'}):
    result=collect(settings,date(2026,8,20),date(2026,8,21),no_wait=True)
   self.assertEqual(result['status'],'WARNING')
   self.assertEqual(result['invalid_query_body_count'],1)
   with sqlite3.connect(root/'db.sqlite') as connection:
    categories={row[0] for row in connection.execute('SELECT category FROM data_quality')}
    usage_count=connection.execute('SELECT COUNT(*) FROM usage_windows').fetchone()[0]
   self.assertIn('USAGE_SKIPPED_INVALID_QUERY_BODY',categories)
   self.assertEqual(usage_count,1)

 def test_workloader_rule_limit_error_excludes_ruleset_without_aborting(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'; binary.write_text(FAKE_RUNTIME_OVERSIZED); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'),traffic_batch_size=100,query_initial_delay_minutes=0)
   result=collect(settings,date(2026,8,20),date(2026,8,21),no_wait=True)
   self.assertEqual(result['status'],'WARNING')
   self.assertEqual(result['runtime_oversized_ruleset_count'],1)
   self.assertEqual(result['runtime_oversized_rulesets'],[{'ruleset_href':'/rs/big','inventory_rule_count':100,'reported_rule_count':101,'reason':'TRAFFIC_RULE_LIMIT_EXCEEDED'}])
   with sqlite3.connect(root/'db.sqlite') as connection:
    category=connection.execute('SELECT category FROM data_quality').fetchone()[0]
   self.assertEqual(category,'RULESET_SKIPPED_TRAFFIC_RULE_LIMIT_EXCEEDED')
