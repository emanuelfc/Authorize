package authorize.sessionManagement;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import burp.IHttpRequestResponse;

public class SessionManager
{
	@JsonProperty
	@JsonDeserialize(contentAs=MatchReplaceSessionHandler.class)
	private List<SessionHandler> sessionHandlers;
	@JsonProperty
	private CookiesSessionHandler cookieSessionHandler;
	
	public SessionManager()
	{
		this.sessionHandlers = new LinkedList<SessionHandler>();
		this.cookieSessionHandler = new CookiesSessionHandler("", false);
	}
	
	@JsonIgnore
	public CookiesSessionHandler getCookieSessionHandler()
	{
		return this.cookieSessionHandler;
	}
	
	@JsonIgnore
	public synchronized List<SessionHandler> getSessionHandlers()
	{
		List<SessionHandler> fullList = new LinkedList<SessionHandler>(sessionHandlers);
		fullList.add(this.cookieSessionHandler);
		return fullList;
	}
	
	public synchronized boolean addSessionHandler(SessionHandler sessionHandler)
	{
		return this.sessionHandlers.add(sessionHandler);
	}
	
	public synchronized boolean removeSessionHandler(SessionHandler sessionHandler)
	{
		return this.sessionHandlers.remove(sessionHandler);
	}
	
	public synchronized byte[] insertSession(byte[] request)
	{
		for(SessionHandler sessionHandler: this.getSessionHandlers())
		{
			if(sessionHandler.isEnabled())
			{
				request = sessionHandler.insertSession(request);
			}
		}
		
		return request;
	}
	
	@JsonIgnore
	public synchronized Stream<SessionHandler> getEnabledSessionHandlers()
	{
		return this.getSessionHandlers().stream().filter((sessionHandler) -> (sessionHandler.isEnabled()));
	}
	
	public synchronized boolean isSession(byte[] request)
	{
		return this.getEnabledSessionHandlers().anyMatch((sessionHandler) -> (sessionHandler.isSession(request)));
	}
	
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		this.getEnabledSessionHandlers().forEach((sessionHandler) ->{sessionHandler.setSession(messageInfo, invocationContext);});
	}
	
	public synchronized void updateSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		this.getEnabledSessionHandlers().forEach((sessionHandler) ->{sessionHandler.updateSession(messageInfo, invocationContext);});
	}
	
	public synchronized void updateSession(IHttpRequestResponse messageInfo)
	{
		this.getEnabledSessionHandlers().forEach((sessionHandler) ->{sessionHandler.updateSession(messageInfo);});
	}
}
