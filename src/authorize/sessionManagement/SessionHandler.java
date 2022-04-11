package authorize.sessionManagement;

import burp.IHttpRequestResponse;

public interface SessionHandler
{
	public boolean isSession(IHttpRequestResponse messageInfo);
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext);
	
	public void insertSession(IHttpRequestResponse messageInfo);
	public void forceInsertSession(IHttpRequestResponse messageInfo);
	
	public void updateSession(IHttpRequestResponse messageInfo, byte invocationContext);
	public void updateSession(IHttpRequestResponse messageInfo);
	
	public String getSession();
	public void setSession(String newSession);
	
	public boolean isEnabled();
	public void setEnabled(boolean newValue);
	public void toggleEnable();
	
	public String getDescription();
	public void setDescription(String newDescription);
	
	public String toString();
}
