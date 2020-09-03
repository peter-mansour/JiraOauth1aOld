package com.jira.server.oauth1a;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Arrays;
import java.util.HashMap;
import java.util.ArrayList;
import com.google.api.client.auth.oauth.OAuthRsaSigner;
import org.apache.commons.codec.binary.Base64;

public final class Config {
    private enum Session{
        SERVICE("service-id"),
        URI_BASE("uri-base"),
        URI_REQ("uri-request"),
        URI_ACCESS("uri-access"),
        URI_AUTH("uri-authorize"),
        KEY_CONS("consumer-key"),
        KEY_PVT("private-key-path"),
        TKN_REQ("request-token"),
        TKN_ACCESS("access-token"),
        SCRT_TKN_REQ("request-token-secret"),
        SCRT_OAUTH("oauth-secret"),
        CHROME_DRIVER("chrome-driver-path"),
        UNM("username"),
        PWD("password");

        private final String field;
        Session(final String field){
            this.field = field;
        }

        public String getField(){
            return this.field;
        }
    }

    private static String field;
    private static String oauth_val = "";
    private static File f_config;
    private final static String ERR_CONFIG = "Failed to find config file";
    private final static String DIRLCL = System.getProperty("user.dir");
    private static HashMap<String, String> confx;
    private static Properties etprop = new Properties();

    public static void store() throws IOException {
        Arrays.stream(Session.values())
                .forEach(oauth_key->{
                    String field = oauth_key.getField();
                    etprop.setProperty(field, (String)confx.get(field));
                });
        etprop.store(new FileOutputStream(f_config), null);
    }

    private static File recoverConfig(){
        for(String path: findFileOrDir(".config", DIRLCL)) {
            File f = new File(path);
            if (isValid(f)) {
                return f;
            }
        }
        return null;
    }

    private static boolean isValid(File f){
        try {
            if (f.exists() && f.isFile() && f.canRead()) {
                etprop.load(new FileInputStream(f));
                String srvc = etprop.getProperty(Session.SERVICE.getField());
                return (srvc.trim().toLowerCase().equals("jiraoauth1a"));
            }
        }
        catch(IOException e){
            //TODO: log exception & recover
        }
        return false;
    }

    public static void load() throws FileNotFoundException, IOException {
        f_config = recoverConfig();
        if(f_config == null){
            throw new FileNotFoundException(ERR_CONFIG);
        }
        Properties p = new Properties();
        confx = new HashMap<String, String>();
        etprop.load(new FileInputStream(f_config));
        Arrays.stream(Session.values())
                .forEach(oauth_key->{
                    field = etprop.getProperty(oauth_key.getField());
                    if(field == null){
                        field = "";
                    }
                    confx.put(oauth_key.getField(), field);
                });
    }

    public static void print(){
        Iterator m_iter = confx.entrySet().iterator();
        while(m_iter.hasNext()){
            Map.Entry ele = (Map.Entry)m_iter.next();
            System.err.println(ele.getKey()+" : "+ele.getValue());
        }
    }

    private static ArrayList<String> findFileOrDir(String nm, String root){
        ArrayList<String> f_match = new ArrayList<String>();
        try {
            Files.walk(Paths.get(root))
                    .forEach(f -> {
                        if (nm.equalsIgnoreCase(f.getFileName().toString())) {
                            f_match.add(f.toString());
                        }
                    });
        }
        catch(IOException e){
            // TODO: log exception & recover
        }
        return f_match;
    }

    private static PrivateKey loadPKCS8(String f_path) throws
            IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final String[] unwanted = {
                "-----BEGIN PRIVATE KEY-----",
                "-----END PRIVATE KEY-----",
                "\\r\\n", "\\n", "\\t", "\\f", "\\b", "\\\\"
        };
        String k_pem = new String(Files.readAllBytes(Paths.get(f_path)));
        for (String prob : unwanted){
            k_pem = k_pem.replaceAll(prob, "");
        }
        PKCS8EncodedKeySpec k_spec = new PKCS8EncodedKeySpec(Base64.decodeBase64(k_pem));
        return KeyFactory.getInstance("RSA").generatePrivate(k_spec);
    }

    private static ArrayList<File> findFileByExt(String ext, String dir) {
        File fx = new File(dir);
        File[] match = fx.listFiles((path, nm)->nm.toLowerCase().endsWith(ext));
        return new ArrayList<File>(Arrays.asList(match));
    }

    public static Map<String, String> getOauthHeader() throws
            FileNotFoundException, IOException{
        File f = new File(etprop.getProperty(Session.KEY_PVT.getField()));
        FileInputStream fs = new FileInputStream(f);
        byte[] dt = new byte[(int) f.length()];
        fs.read(dt);
        fs.close();
        final String pvt_str = new String(dt, "UTF-8");
        final Map<String, String> m = new HashMap<String, String>(Map.ofEntries(
                Map.entry("accessToken", getAccessToken()),
                Map.entry("accessTokenSecret", getAuthSecret()),
                Map.entry("consumerKey", getConsumerKey()),
                Map.entry("privateKey", pvt_str)
        ));
        return m;
    }

    public static String getBaseUrl(){
        return confx.get(Session.URI_BASE.getField());
    }

    public static String getRequestUrl(){
        return confx.get(Session.URI_BASE.getField())+confx.get(Session.URI_REQ.getField());
    }

    public static String getAccessUrl(){
        return confx.get(Session.URI_BASE.getField())+confx.get(Session.URI_ACCESS.getField());
    }

    public static String getAuthUrl(){
        return confx.get(Session.URI_BASE.getField())+confx.get(Session.URI_AUTH.getField());
    }

    public static String getConsumerKey(){
        return confx.get(Session.KEY_CONS.getField());
    }

    public static OAuthRsaSigner getSignature(){
        OAuthRsaSigner sign = new OAuthRsaSigner();
        try {
            sign.privateKey = loadPKCS8(confx.get(Session.KEY_PVT.getField()));
        }
        catch(IOException|NoSuchAlgorithmException|InvalidKeySpecException e){
            //handle exception
        }
        return sign;
    }

    public static String getUsername(){
        return confx.get(Session.UNM.getField());
    }

    public static String getPassword(){
        return confx.get(Session.PWD.getField());
    }

    public static String getRequestToken(){
        return confx.get(Session.TKN_REQ.getField());
    }

    public static String getRequestTokenSecret(){
        return confx.get(Session.SCRT_TKN_REQ.getField());
    }

    public static String getAuthSecret(){
        return confx.get(Session.SCRT_OAUTH.getField());
    }

    public static String getAccessToken(){
        return confx.get(Session.TKN_ACCESS.getField());
    }

    public static File getChromeDriver(){
        return new File(confx.get(Session.CHROME_DRIVER.getField()));
    }

    public static void setRequestToken(String tkn){
        confx.put(Session.TKN_REQ.getField(), tkn);
    }

    public static void setRequestTokenSecret(String scrtkn){
        confx.put(Session.SCRT_TKN_REQ.getField(), scrtkn);
    }

    public static void setAuthSecret(String scrt){
        confx.put(Session.SCRT_OAUTH.getField(), scrt);
    }

    public static void setAccessToken(String tkn){
        confx.put(Session.TKN_ACCESS.getField(), tkn);
    }
}
