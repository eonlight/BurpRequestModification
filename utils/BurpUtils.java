package utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ConnectException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Base64;

import burp.IBurpExtenderCallbacks;

public class BurpUtils {
	public static final String NAME = "BurpUtils", VERSION = "1.0.0", DEFAULT_HEADER = "RequestModification";

	public static final boolean DEBUG = false;
	
	private static BurpUtils instance = null;
	private IBurpExtenderCallbacks callbacks = null;
	
	public String header, path;
	
	public PrintWriter stdout, stderr;
	private BurpUtils(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true);		
		this.loadConfigs();
		
		this.header = this.header == null ? DEFAULT_HEADER : this.header;
		this.path = this.path == null ? "" : this.path;
		
		this.finishedLoading();
	}
	
	private void finishedLoading(){
		this.write("[*] Loaded " + NAME + " v" + VERSION);
	}
	
	public static void createInstance(IBurpExtenderCallbacks callbacks){
		BurpUtils.instance = new BurpUtils(callbacks);
	}
	
	public static BurpUtils getInstance(){
		return BurpUtils.instance;
	}
	
	public void write(String output){
		this.stdout.write(output + "\n");
		this.stdout.flush();
	}
	
	public void error(String output){
		this.stderr.write(output + "\n");
		this.stderr.flush();
	}
	
	public void saveConfigs(){
		callbacks.saveExtensionSetting("header", this.header);
		callbacks.saveExtensionSetting("path", this.path);
	}
	
	private void loadConfigs(){
		this.header = callbacks.loadExtensionSetting("header");
		this.path = callbacks.loadExtensionSetting("path");
	}
	
	public static String makeGetRequest(String url){
		StringBuffer response = new StringBuffer();
		try {
			URLConnection connection = new URL(url).openConnection();				
			BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
			while ((url = in.readLine()) != null)
				response.append(url);
			in.close();
			return response.toString();
		} catch(ConnectException e){
			// Connection timeout - do nothing
			if(BurpUtils.DEBUG)
				e.printStackTrace(BurpUtils.getInstance().stderr);
		} catch (MalformedURLException e) {
			if(BurpUtils.DEBUG)
				e.printStackTrace(BurpUtils.getInstance().stderr);
		} catch (IOException e) {
			if(BurpUtils.DEBUG)
				e.printStackTrace(BurpUtils.getInstance().stderr);
		} catch(Exception e){
			if(BurpUtils.DEBUG)
				e.printStackTrace(BurpUtils.getInstance().stderr);
		}
		
		return null;
	}
	
	public static String b64encode(String plain){
		return Base64.getEncoder().encodeToString(plain.getBytes());
	}
	
	public static String b64encode(byte[] plain){
		return Base64.getEncoder().encodeToString(plain);
	}
	
	public static byte[] b64decode(String plain){
		return Base64.getDecoder().decode(plain);
	}
	
	public static byte[] b64decode(byte[] plain){
		return Base64.getDecoder().decode(plain);
	}

}
