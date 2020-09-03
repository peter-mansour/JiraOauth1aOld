package com.jira.server.oauth1a;

import com.google.api.client.http.GenericUrl;
import java.io.IOException;

public class App {
    public static void main( String[] args ) throws IOException, Exception
    {
        JiraOauth1a tst = new JiraOauth1a();
        String rsp = JiraOauth1a.requests.get(new GenericUrl("https://jira-dev.us.ngridtools.com/rest/api/2/serverInfo"));
        System.err.println(rsp);
    }
}