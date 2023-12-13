import sys
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree
from gvm.errors import GvmError
from clickhouse_driver import Client
from dateutil import parser

path = '/run/gvmd/gvmd.sock'
connection = UnixSocketConnection(path=path)
transform = EtreeCheckCommandTransform()
output_file = "your_xml_file.xml"

username_gvm = 'edit_me'
password_gvm = 'edit_me'
server_db = 'edit_me'
port_db = 9000
username_db = 'default'
password_db = 'edit_me'
database_name = 'edit_me'
db_table = 'edit_me'

# ClickHouse connection configuration
client = Client(host=server_db, port=port_db, user=username_db, password=password_db, database=database_name)

# Create table if not exists
created_db = '''
    CREATE TABLE IF NOT EXISTS {db_table} (
        Timestamp VARCHAR(255),
        Timezone VARCHAR(255),
        Task_Name VARCHAR(255),
        IP VARCHAR(255),
        Hostname VARCHAR(255),
        Port_Protocol VARCHAR(255),
        CVSS FLOAT,
        Summary TEXT,
        Solution TEXT,
        Full_detail TEXT
    ) ENGINE = MergeTree()
      ORDER BY Timestamp
'''
client.execute(created_db)

def insert_into_clickhouse(client, data):
    sql_query = """
        INSERT INTO {db_table} 
        (Timestamp, Timezone, Task_Name, IP, Port_Protocol, Hostname, CVSS, Summary, Solution, Full_detail) 
        VALUES 
        (%(timestamp)s, %(timezone)s, %(task_name)s, %(ip)s, %(port_protocol)s, %(hostname)s, %(cvss)s, %(summary)s, %(solution)s, %(full_detail)s)
    """
    client.execute(sql_query, data)

def run_gvm_command(gmp, report_ids):
    try:
        report_data = gmp.get_report(report_id=report_ids, details=True)
        return report_data
    except GvmError as e:
        print(f"Error running GVM command: {e}")
        return None

try:
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(username_gvm, password_gvm)
        reports = gmp.get_reports()
        report_ids = reports.xpath('//report/@id')[-1]
        print(f"Report Latest ID: {report_ids}")

        report_data = run_gvm_command(gmp, report_ids)
        if report_data is not None:
            detail_reports = gmp.get_report(str(report_ids), filter_string="apply_overrides=0 levels=hml rows=1000 min_qod=70 first=1 sort-reverse=severity notes=1 overrides=1", details=True)

            xml_string = etree.tostring(detail_reports, pretty_print=True, encoding="utf-8").decode("utf-8")
            root = etree.fromstring(xml_string)
            task_name = root.find('.//report/task/name').text
            timezone = root.find('.//report/timezone').text
            for x in root.findall('.//report/report/results/'):
                ip = x.find('./host').text
                hostname = x.find('./host/hostname').text if x.find('./host/hostname') is not None and x.find('./host/hostname').text is not None else '[Không xác định]'
                port_protocol = x.find('./port').text
                cvss = x.find('./nvt/cvss_base').text
                full_detail = x.find('./nvt/tags').text
                solution = x.find('./nvt/solution').text
                summary = x.find('./nvt/name').text
                timestamp = x.find('./modification_time').text if x.find('./modification_time') is not None else ''
                
                # insert to database with score of cvss > 6
                if float(cvss) > 6:
                    data = {
                        'timestamp': timestamp,
                        'timezone': timezone,
                        'task_name': task_name,
                        'ip': ip,
                        'port_protocol': port_protocol,
                        'hostname': hostname,
                        'cvss': cvss,
                        'summary': summary,
                        'solution': solution,
                        'full_detail': full_detail
                    }
                    insert_into_clickhouse(client, data)


        else:
            print("Failed to download or export to ClickHouse this report, please double-check and try again.")

except GvmError as e:
    print('An error occurred', e, file=sys.stderr)

finally:
    # Disconnect from ClickHouse
    client.disconnect()
