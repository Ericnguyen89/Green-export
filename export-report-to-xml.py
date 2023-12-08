import sys
import os
from flask import cli
import gvm
from gvm.connections import UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeCheckCommandTransform
from lxml import etree  # Import the etree module

path = '/run/gvmd/gvmd.sock'
connection = UnixSocketConnection(path=path)
transform = EtreeCheckCommandTransform()
output_file = "output.xml"  # Use .xml extension for XML files
username = 'admin'
password = 'admin'

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
        print(str(report_ids))

        report_data = run_gvm_command(gmp, report_ids)
        if report_data:
            # Convert the XML element to a string
            xml_string = etree.tostring(report_data, pretty_print=True, encoding="utf-8").decode("utf-8")

            # Write the string to the file
            with open(output_file, "w") as file:
                file.write(xml_string)
            print(f"Report downloaded and saved to {output_file}")
        else:
            print("Failed to download the report.")

except GvmError as e:
    print('An error occurred', e, file=sys.stderr)
