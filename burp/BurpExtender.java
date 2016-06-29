package burp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

import configtab.RequestModificationConfigTab;
import utils.BurpUtils;

public class BurpExtender implements IBurpExtender, IHttpListener {
	
	private static final String NAME = "Request Modification", VERSION = "1.0.0";
	private IBurpExtenderCallbacks callbacks;
	
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName(NAME);
		BurpUtils.createInstance(callbacks);
		this.callbacks = callbacks;
		callbacks.registerHttpListener(this);
		callbacks.addSuiteTab(new RequestModificationConfigTab());
		this.finishedLoading();
	}
	
	private void finishedLoading(){
		BurpUtils.getInstance().write("[*] Loaded Extension " + NAME + " v" + VERSION + " (C) Ruben de Campos");
	}
	
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if(messageIsRequest && (IBurpExtenderCallbacks.TOOL_SCANNER == toolFlag || IBurpExtenderCallbacks.TOOL_REPEATER == toolFlag || IBurpExtenderCallbacks.TOOL_INTRUDER == toolFlag )) {
			List<String> headers = this.callbacks.getHelpers().analyzeRequest(messageInfo.getRequest()).getHeaders();			
			for(String h : headers)
				if(BurpUtils.getInstance().header == null || BurpUtils.getInstance().header.isEmpty() || h.toLowerCase().contains(BurpUtils.getInstance().header.toLowerCase())){
					messageInfo.setRequest(this.performModification(messageInfo.getRequest()));
					break;
				}
		}
	}
	
	private byte[] performModification(byte[] request){		
		if(BurpUtils.getInstance().path == null || BurpUtils.getInstance().path.isEmpty())
			return request;
		
		try {
			Process p = Runtime.getRuntime().exec(new String[]{BurpUtils.getInstance().path, BurpUtils.b64encode(request)});
			p.waitFor();
			BufferedReader input = new BufferedReader(new InputStreamReader(p.getInputStream()));
			String line, result = "";
			while ((line = input.readLine()) != null)
			  result += line;
			request = BurpUtils.b64decode(result);
		} catch (Exception e) {
			if(BurpUtils.DEBUG)
				e.printStackTrace(BurpUtils.getInstance().stderr);
		}
		return request;
	}

}
