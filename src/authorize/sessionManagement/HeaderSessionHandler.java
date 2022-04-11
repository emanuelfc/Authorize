package authorize.sessionManagement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import burp.IHttpRequestResponse;
import utils.httpMessage.HttpHeader;
import utils.httpMessage.HttpRequest;

public class HeaderSessionHandler implements SessionHandler
{
	private String headerMatch;
	private String session;
	private String description;
	private boolean enabled;
	
	@JsonCreator
	public HeaderSessionHandler(@JsonProperty("headerMatch") String headerMatch, 
								@JsonProperty("session") String session,
								@JsonProperty("description") String description,
								@JsonProperty("enabled") boolean enabled)
	{
		this.headerMatch = headerMatch;
		this.session = session;
		this.description = description;
		this.enabled = enabled;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof HeaderSessionHandler)
		{
			return this.equals((HeaderSessionHandler) other);
		}
		
		return false;
	}
	
	public boolean equals(HeaderSessionHandler other)
	{
		return this.headerMatch.equals(other.headerMatch) && this.session.equals(other.session);
	}
	
	public String getLocation()
	{
		return this.headerMatch;
	}

	public void setLocation(String newMatch)
	{
		this.headerMatch = newMatch;
	}
	
	@Override
	public String getSession()
	{
		return this.session;
	}

	@Override
	public void setSession(String newSession)
	{
		this.session = newSession.strip();
	}
	
	private String getSession(IHttpRequestResponse messageInfo)
	{
		HttpRequest request = new HttpRequest(messageInfo);
		
		HttpHeader header = request.getHeader(headerMatch);
		
		if(header != null)
		{
			return header.getValue();
		}
		
		return null;
	}
	
	@Override
	public boolean isSession(IHttpRequestResponse messageInfo)
	{
		String session = this.getSession(messageInfo);
		
		if(session != null)
		{
			return session.equals(this.session);
		}
		
		return false;
	}
	
	@Override
	public void forceInsertSession(IHttpRequestResponse messageInfo)
	{
		HttpRequest request = new HttpRequest(messageInfo);
		
		request.putHeader(this.headerMatch, this.session);
	}

	// Only add the respective session if the request contains the places to insert
	@Override
	public void insertSession(IHttpRequestResponse messageInfo)
	{
		HttpRequest request = new HttpRequest(messageInfo);
		
		HttpHeader header = request.getHeader(headerMatch);
		
		if(header != null)
		{
			this.forceInsertSession(messageInfo);
		}
	}
	
	@Override
	public String getDescription()
	{
		return this.description;
	}
	
	@Override
	public void setDescription(String description)
	{
		this.description = description;
	}
	
	@Override
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		HttpRequest request = new HttpRequest(messageInfo);
		
		HttpHeader header = request.getHeader(headerMatch);
		
		if(header != null)
		{
			this.setSession(header.getValue());;
		}
	}
	
	@Override
	public void updateSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		this.setSession(messageInfo, invocationContext);
	}
	
	@Override
	public void updateSession(IHttpRequestResponse messageInfo)
	{
		this.setSession(messageInfo, (byte)0);
	}
	
	@Override
	public boolean isEnabled()
	{
		return this.enabled;
	}
	
	@Override
	public void setEnabled(boolean value)
	{
		this.enabled = value;
	}

	@Override
	public void toggleEnable()
	{
		this.enabled = !this.enabled;
	}
	
	@Override
	public String toString()
	{
		return "HTTP Header | Match: " + this.headerMatch + " | " + "Replace: " + this.session;
	}

}
