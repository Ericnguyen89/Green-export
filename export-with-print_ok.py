import sys
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree
from gvm.errors import GvmError

path = '/run/gvmd/gvmd.sock'
connection = UnixSocketConnection(path=path)
transform = EtreeCheckCommandTransform()
output_file = "your_xml_file.xml"
username = 'admin'
password = 'CTN@1305'

def run_gvm_command(gmp, report_ids):
    try:
        report_data = gmp.get_report(report_id=report_ids, details=True)
        return report_data
    except GvmError as e:
        print(f"Error running GVM command: {e}")
        return None
try:
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate(username, password)
        reports = gmp.get_reports()
        report_ids = reports.xpath('//report/@id')[-1]
        print(f"Report Latest ID: {report_ids}")

        report_data = run_gvm_command(gmp, report_ids)
        if report_data is not None:
            detail_reports = gmp.get_report(str(report_ids), filter_string="apply_overrides=0 levels=hml rows=1000 min_qod=70 first=1 sort-reverse=severity notes=1 overrides=1", details=True)

            # Convert the XML element to a string
            xml_string = etree.tostring(detail_reports, pretty_print=True, encoding="utf-8").decode("utf-8")

            ## Write the string to the file
            # with open(output_file, "w") as file:
            #     file.write(xml_string)

            # print(f"Report downloaded and saved to {output_file}")
            # trích xuất dữ liệu từ dữ liệu đã được xác định từ ReportID mới nhất
            root = etree.fromstring(xml_string)
            task_name = root.find('.//report/task/name').text
            for x in root.findall('.//report/report/results/'):
                print("-----------------------")         
                ip = x.find('./host').text
                hostname=x.find('./host/hostname').text if x.find('./host/hostname') is not None and x.find('./host/hostname').text is not None else '[Không xác định]'
                port_protocol =x.find('./port').text
                cvss =x.find('./nvt/cvss_base').text
                summary =x.find('./nvt/tags').text
                solution =x.find('./nvt/solution').text
                title_error = x.find('./nvt/name').text
                # Thực thi lệnh in với điều kiện    
                if float(cvss) > 6:
                    print(f"Task Name: {task_name}")
                    print(f"IP target: {ip}")
                    print(f"Port in host: {port_protocol}")
                    print(f"Hostname: {hostname}")
                    print(f"Severity Score: {cvss}")
                    print(f"Error Name: {title_error}")
                    print(f"Full Detail: \n {summary}")
                    

        else:
            print("Failed to download the report.")

except GvmError as e:
    print('An error occurred', e, file=sys.stderr)
