import tempfile, unittest
from pathlib import Path
from rules_recertify.history.database import Database
from rules_recertify.reference import ingest_reference

class ReferenceTest(unittest.TestCase):
 def test_ingest_excludes_no_ip_and_enriches_nz3(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); wk=root/'wk.csv'; ip=root/'ip.csv'
   wk.write_text('href;hostname;name;interfaces;ip_with_default_gw;app;env;managed\n/w/1;host.example;h;aut0:10.20.30.40;;APP;PRD;FALSE\n/w/2;;h2;;;APP;PRD;FALSE\n')
   ip.write_text('name;include\nNZ3_TEST;10.20.30.0/24# production network\n')
   db=Database(root/'db'); db.initialize(); db.begin_run('r','REFERENCE',{})
   result=ingest_reference(db,wk,ip,'r')
   self.assertEqual(result['workloads'],1)
   with db.connect() as c:
    row=c.execute('select short_hostname,addresses_json from workloads').fetchone()
    quality=c.execute('select count(*) from data_quality').fetchone()[0]
    member=c.execute('select member from ip_lists').fetchone()[0]
   self.assertEqual(row[0],'host'); self.assertIn('10.20.30.40',row[1]); self.assertEqual(quality,1)
   self.assertEqual(member,'10.20.30.0/24')
