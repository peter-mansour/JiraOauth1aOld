package com.jira.server.oauth1a;

import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import com.google.api.client.auth.oauth.*;
import com.google.api.client.http.GenericUrl;
import com.google.api.client.http.apache.v2.ApacheHttpTransport;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.chrome.ChromeOptions;
import org.openqa.selenium.chrome.ChromeDriverService;
import org.openqa.selenium.remote.DesiredCapabilities;
import org.openqa.selenium.remote.RemoteWebDriver;
import org.openqa.selenium.NoSuchElementException;

public class JiraOauth1a
{
    private requestTokenJiraOauth1a req;
    private authTokenJiraOauth1a req_pkt;
    private accessTokenJiraOauth1a access_req;
    private OAuthCredentialsResponse rsp, access_rsp;

    public static final class requests{
        public static String get(GenericUrl url) throws IOException{
            return new BufferedReader(
                new InputStreamReader(
                    new ApacheHttpTransport()
                        .createRequestFactory(getAccessPkt())
                        .buildGetRequest(url)
                        .execute()
                        .getContent(), StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));
        }
    }

    public static class accessTokenJiraOauth1a extends OAuthGetAccessToken{
        public accessTokenJiraOauth1a(OauthPkt pkt){
            super(pkt.url);
            this.consumerKey    = pkt.conskey;
            this.signer         = pkt.sign;
            this.transport      = pkt.httpTransport;
            this.verifier       = pkt.oauthScrt;
            this.temporaryToken = pkt.tkn;
            this.usePost        = pkt.usePost;
        }
    }

    public class authTokenJiraOauth1a {

        public ChromeDriverService srvc;
        public ChromeDriverService.Builder build;
        public WebDriver driver;
        public String fullink;
        public static final int TRIALS = 3;
        public static final String success_code = "Your verification code is \'(.*)\'";
        public static final String auth_query = "?oauth_token=";

        public authTokenJiraOauth1a(String url, String tkn) {
            this.fullink = url+auth_query+tkn;
        }

        public void spawnSel(File f_exe) throws IOException {
            this.build = new ChromeDriverService.Builder();
            this.build.usingAnyFreePort();
            this.build.usingDriverExecutable(f_exe);
            this.srvc = this.build.build();
            this.srvc.start();
            DesiredCapabilities mod = DesiredCapabilities.chrome();
            ChromeOptions opt = new ChromeOptions();
            opt.addArguments("--headless",
                    "--disable-gpu",
                    "--silent",
                    "--log-level=3",
                    "--disable-logging",
                    "--window-size=1920,1200",
                    "--ignore-certificate-errors");
            mod.setCapability(ChromeOptions.CAPABILITY, opt);
            //System.setProperty("webdriver.chrome.silentOutput", "true");
            this.driver = new RemoteWebDriver(this.srvc.getUrl(), mod);
            this.driver.manage().timeouts().implicitlyWait(8, TimeUnit.SECONDS);
        }

        public void despawnSel() {
            this.driver.quit();
            this.srvc.stop();
        }

        public String authorize() throws IOException {
            spawnSel(Config.getChromeDriver());
            int trial = 0;
            String rsp = "";
            while(trial++ < TRIALS) {
                try {
                    try2authorize();
                } catch (NoSuchElementException | InterruptedException e) {
                    //TODO
                }
                rsp = this.driver.findElement(By.id("content")).getText();
                if(!rsp.contains("Xsrf token validation failed")){
                    break;
                }
            }
            despawnSel();
            Matcher tkn = Pattern.compile(success_code).matcher(rsp);
            if(tkn.find()) {
                return tkn.group(1);
            }
            return null;
        }

        public void try2authorize() throws NoSuchElementException, InterruptedException{
            this.driver.get(this.fullink.toString());
            if (this.driver.getCurrentUrl().contains("login.jsp")) {
                this.driver.findElement(By.id("login-form-username")).sendKeys(Config.getUsername());
                this.driver.findElement(By.id("login-form-password")).sendKeys(Config.getPassword());
                this.driver.findElement(By.id("login-form-submit")).click();
            }
            Thread.sleep(1000);
            this.driver.findElement(By.id("approve")).click();
        }
    }
    public class requestTokenJiraOauth1a extends OAuthGetTemporaryToken{
        public requestTokenJiraOauth1a(OauthPkt pkt){
            super(pkt.url);
            this.consumerKey    = pkt.conskey;
            this.signer         = pkt.sign;
            this.transport      = new ApacheHttpTransport();
            this.callback       = "oob";
            this.usePost        = true;
        }
    }
    public static class OauthPkt{
        String url          = null;
        String oauthScrt    = null;
        String tkn          = null;
        boolean usePost     = false;
        String conskey      = Config.getConsumerKey();
        OAuthRsaSigner sign = Config.getSignature();
        ApacheHttpTransport httpTransport = new ApacheHttpTransport();
        public OauthPkt(String url, String tkn, String scrt, boolean post){
            this.url        = url;
            this.oauthScrt  = scrt;
            this.tkn        = tkn;
            this.usePost    = post;
        }
    }

    public JiraOauth1a(){
        try{
            Config.load();
            //Config.print(); /* use to print configuration hashmap */
            //Tverify access using rest api ?
            String access = Config.getAccessToken();
            if(access == null || access.isEmpty()){
                perfOauthDance();
            }
            else{
                //TODO: depends on app / requestor needs
            }
        }
        catch (Exception e){
            //TODO: handle critical errors
            e.printStackTrace();
        }
    }

    public static OAuthParameters getAccessPkt(){
        return new accessTokenJiraOauth1a(
                new OauthPkt(Config.getAccessUrl(),
                    Config.getAccessToken(),
                    Config.getAuthSecret(), true))
                .createParameters();
    }

    private void perfOauthDance() throws IOException, Exception {
        req = new requestTokenJiraOauth1a(new OauthPkt(
                Config.getRequestUrl(), null, null, true));
        rsp = req.execute();
        Config.setRequestToken(rsp.token);
        Config.setRequestTokenSecret(rsp.tokenSecret);
        req_pkt = new authTokenJiraOauth1a(Config.getAuthUrl(), rsp.token);
        String auth_scrt = req_pkt.authorize();
        if (auth_scrt == null) {
            //TODO: implement transaction 2 recovery
            throw new Exception("");
        } else {
            Config.setAuthSecret(auth_scrt);
            access_req = new accessTokenJiraOauth1a(
                    new OauthPkt(Config.getAccessUrl(), rsp.token, auth_scrt, true));
            access_rsp = access_req.execute();
            if (access_rsp.token != null) {
                Config.setAccessToken(access_rsp.token);
                Config.store();
                //verify access using rest api ?
            }
        }
    }
}