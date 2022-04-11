package authorize.sessionManagement;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import burp.IHttpRequestResponse;

public class SessionManager
{
	@JsonProperty
	@JsonDeserialize(contentAs=HeaderSessionHandler.class)
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
	
	public synchronized void insertSession(IHttpRequestResponse message)
	{
		for(SessionHandler sessionHandler: this.getSessionHandlers())
		{
			if(sessionHandler.isEnabled())
			{
				sessionHandler.insertSession(message);
			}
		}
	}
	
	@JsonIgnore
	public synchronized Stream<SessionHandler> getEnabledSessionHandlers()
	{
		Stream<SessionHandler> sessionHandlerStream = this.getSessionHandlers().stream().filter((sessionHandler) -> (sessionHandler.isEnabled()));
		
		List<SessionHandler> sessionHandlerList = sessionHandlerStream.collect(Collectors.toList());
		
		if(!sessionHandlerList.isEmpty()) return sessionHandlerList.stream();
		
		return null;
	}
	
	public synchronized boolean isSession(IHttpRequestResponse messageInfo)
	{
		Stream<SessionHandler> enabledSessionHandlers = this.getEnabledSessionHandlers();
		
		if(enabledSessionHandlers != null)
		{			
			return enabledSessionHandlers.anyMatch((sessionHandler) -> (sessionHandler.isSession(messageInfo)));
		}
				
		return false;
	}
	
	private void forEachEnabledSessionHandler(Consumer<? super SessionHandler> action)
	{
		Stream<SessionHandler> enabledSessionHandlers = this.getEnabledSessionHandlers();
		
		if(enabledSessionHandlers != null)
		{
			enabledSessionHandlers.forEach(action);
		}
	}
	
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		this.forEachEnabledSessionHandler((sessionHandler) -> {sessionHandler.setSession(messageInfo, invocationContext);});
	}
	
	public synchronized void updateSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		this.forEachEnabledSessionHandler((sessionHandler) -> {sessionHandler.updateSession(messageInfo, invocationContext);});
	}
	
	public synchronized void updateSession(IHttpRequestResponse messageInfo)
	{
		this.forEachEnabledSessionHandler((sessionHandler) -> {sessionHandler.updateSession(messageInfo);});
	}
}
