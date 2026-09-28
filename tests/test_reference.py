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

 def test_derived_short_hostname_is_preserved_including_empty_fallback_marker(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); wk=root/'wk.csv'; ip=root/'ip.csv'
   wk.write_text(
    'href;hostname;short_hostname;name;interfaces;ip_with_default_gw;app;env;managed\n'
    '/w/1;host.example;HOST;host-name;aut0:10.0.0.1;;APP;PRD;FALSE\n'
    '/w/2;;;fallback-name;aut0:10.0.0.2;;APP;PRD;FALSE\n'
   )
   ip.write_text('name;include\nNZ3_TEST;10.0.0.0/24\n')
   db=Database(root/'db'); db.initialize(); db.begin_run('r','REFERENCE',{})
   ingest_reference(db,wk,ip,'r')
   with db.connect() as connection:
    rows=list(connection.execute('select short_hostname,name from workloads order by href'))
   self.assertEqual([tuple(row) for row in rows], [('HOST','host-name'), ('','fallback-name')])

 def test_complete_raw_ip_list_export_keeps_non_nz3_members_for_reporting(self):
  with tempfile.TemporaryDirectory() as d:
   root=Path(d); wk=root/'wk.csv'; ip=root/'ip.csv'
   wk.write_text('href;hostname;name;interfaces;ip_with_default_gw;app;env;managed\n/w/1;host;h;aut0:10.0.0.1;;APP;PRD;FALSE\n')
   ip.write_text('name;include\nBUSINESS_IPL;"192.168.19.0/24#GEN1;192.168.20.1#GEN2"\n')
   db=Database(root/'db'); db.initialize(); db.begin_run('r','REFERENCE',{})
   ingest_reference(db,wk,ip,'r')
   with db.connect() as connection:
    members=list(connection.execute('select name,member from ip_lists order by member'))
   self.assertEqual([tuple(row) for row in members], [('BUSINESS_IPL','192.168.19.0/24'),('BUSINESS_IPL','192.168.20.1')])
