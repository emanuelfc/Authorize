package authorize.sessionManagement;

import burp.IHttpRequestResponse;

public interface SessionHandler
{
	public boolean isSession(byte[] request);
	public byte[] insertSession(byte[] request);
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext);
	public void updateSession(IHttpRequestResponse messageInfo, byte invocationContext);
	public void updateSession(IHttpRequestResponse messageInfo);
	public String getSession();
	public void setSession(String newSession);
	public boolean isEnabled();
	public void setEnabled(boolean newValue);
	public void toggleEnable();
	public String getDescription();
}
