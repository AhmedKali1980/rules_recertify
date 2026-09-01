import json, os, sqlite3, stat, tempfile, unittest
from datetime import date
from pathlib import Path
from rules_recertify.collection import collect
from rules_recertify.config import Settings

FAKE = r'''#!/usr/bin/env python3
import csv,sys
args=sys.argv
cmd=next(x for x in ('ruleset-export','rule-export','rule-usage') if x in args)
out=args[args.index('--output-file')+1]
def write(headers, rows):
 with open(out,'w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=headers); w.writeheader(); w.writerows(rows)
if cmd=='ruleset-export': write(['ruleset_name','enabled','href'],[{'ruleset_name':'APP','enabled':'true','href':'/rs/1'}])
elif cmd=='rule-export' and '--traffic-count' not in args:
 write(['ruleset_name','ruleset_scope','ruleset_enabled','rule_type','rule_enabled','ruleset_href','rule_href','services'],[{'ruleset_name':'APP','ruleset_scope':'app:APP;env:PRD','ruleset_enabled':'true','rule_type':'allow','rule_enabled':'true','ruleset_href':'/rs/1','rule_href':'/r/1','services':'443 TCP'}])
elif cmd=='rule-export':
 q='{"start_date":"2026-08-20T00:00:00Z","end_date":"2026-08-21T00:00:00Z"}'
 write(['ruleset_href','rule_href','async_query_status','flows','flows_by_port','query_body'],[{'ruleset_href':'/rs/1','rule_href':'/r/1','async_query_status':'','flows':'','flows_by_port':'','query_body':q}])
else:
 q='{"start_date":"2026-08-20T00:00:00Z","end_date":"2026-08-21T00:00:00Z"}'
 write(['ruleset_href','rule_href','async_query_status','flows','flows_by_port','query_body'],[{'ruleset_href':'/rs/1','rule_href':'/r/1','async_query_status':'completed','flows':'3','flows_by_port':'443 TCP (3)','query_body':q}])
'''
FAKE_OVERSIZED = r'''#!/usr/bin/env python3
import csv,sys
args=sys.argv
cmd=next(x for x in ('ruleset-export','rule-export','rule-usage') if x in args)
out=args[args.index('--output-file')+1]
def write(headers, rows):
 with open(out,'w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=headers); w.writeheader(); w.writerows(rows)
if cmd=='ruleset-export':
 write(['ruleset_name','enabled','href'],[{'ruleset_name':'BIG','enabled':'true','href':'/rs/big'}])
elif cmd=='rule-export' and '--traffic-count' not in args:
 headers=['ruleset_name','ruleset_scope','ruleset_enabled','rule_type','rule_enabled','ruleset_href','rule_href','services']
 write(headers,[{'ruleset_name':'BIG','ruleset_scope':'','ruleset_enabled':'true','rule_type':'allow','rule_enabled':'true','ruleset_href':'/rs/big','rule_href':f'/r/{i}','services':'443 TCP'} for i in range(101)])
else:
 raise SystemExit('oversized ruleset must not be submitted')
'''
class CollectionTest(unittest.TestCase):
 def test_end_to_end_with_fake_workloader(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); bindir=root/'bin'; bindir.mkdir(); binary=bindir/'workloader'; binary.write_text(FAKE); binary.chmod(binary.stat().st_mode|stat.S_IEXEC)
   settings=Settings(pce='p',workloader_dir=str(bindir),state_db=str(root/'db.sqlite'),raw_dir=str(root/'raw'),output_dir=str(root/'out'),log_dir=str(root/'logs'),query_initial_delay_minutes=0)
   result=collect(settings,date(2026,8,20),date(2026,8,21),no_wait=True)
   self.assertEqual(result['status'],'SUCCESS'); self.assertEqual(result['completed'],1)
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
