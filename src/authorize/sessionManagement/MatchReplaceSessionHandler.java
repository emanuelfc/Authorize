package authorize.sessionManagement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import authorize.extractor.Extractor;
import authorize.extractor.ExtractorFactory;
import authorize.modifier.replace.ReplaceModifier;
import authorize.types.ModifierType;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class MatchReplaceSessionHandler implements SessionHandler
{
	private ModifierType sessionModifierType;
	private ReplaceModifier sessionModifier;
	private Extractor requestSessionExtractor;
	private ResponseSessionExtractor responseSessionExtractor;
	
	private String description;
	private boolean enabled;
	
	@JsonCreator
	public MatchReplaceSessionHandler(@JsonProperty("sessionModifierType") ModifierType sessionModifierType,
									  @JsonProperty("sessionModifier") ReplaceModifier sessionModifier,
									  @JsonProperty("responseSessionExtractor") ResponseSessionExtractor responseSessionExtractor,
									  @JsonProperty("description") String description,
									  @JsonProperty("enabled") boolean enabled)
	{
		this.setSessionModifier(sessionModifier, sessionModifierType);
		this.responseSessionExtractor = responseSessionExtractor;
		
		this.description = description;
		this.enabled = enabled;
	}
	
	@Override
	public String getSession()
	{
		return this.sessionModifier.getReplace();
	}

	@Override
	public void setSession(String newSession)
	{
		this.sessionModifier.setReplace(newSession.strip());
	}
	
	@Override
	public boolean isSession(byte[] request)
	{
		String requestSession = this.requestSessionExtractor.extract(request, this.sessionModifier.getMatch(), this.sessionModifier.isRegex());
		return requestSession != null ? requestSession.strip().equals(this.sessionModifier.getReplace()) : false;
	}

	@Override
	public byte[] insertSession(byte[] request)
	{
		return this.sessionModifier.modify(request);
	}
	
	public ModifierType getSessionModifierType()
	{
		return this.sessionModifierType;
	}
	
	public ReplaceModifier getSessionModifier()
	{
		return this.sessionModifier;
	}
	
	public void setSessionModifier(ReplaceModifier newSessionModifier, ModifierType newSessionModifierType)
	{
		this.sessionModifier = newSessionModifier;
		this.sessionModifierType = newSessionModifierType;
		
		this.requestSessionExtractor = ExtractorFactory.createExtractor(ExtractorTypeFromReplaceModifier.createExtractorType(newSessionModifierType));
	}
	
	public ResponseSessionExtractor getResponseSessionExtractor()
	{
		return this.responseSessionExtractor;
	}
	
	public void setResponseSessionExtractor(ResponseSessionExtractor newRrsponseSessionExtractor)
	{
		this.responseSessionExtractor = newRrsponseSessionExtractor;
	}
	
	@Override
	public String getDescription()
	{
		return this.description;
	}
	
	public void setDescription(String description)
	{
		this.description = description;
	}
	
	@Override
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		if(invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
		{
			this.setSessionFromRequest(messageInfo.getRequest());
		}
		else if(invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE || invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE)
		{
			this.setSessionFromResponse(messageInfo);
		}
	}
	
	private void setSessionFromRequest(byte[] request)
	{
		String session = this.requestSessionExtractor.extract(request, this.sessionModifier.getMatch(), this.sessionModifier.isRegex());
		if(session != null) this.setSession(session);
	}
	
	private void setSessionFromResponse(IHttpRequestResponse messageInfo)
	{
		if(this.responseSessionExtractor != null)
		{
			String sessionToken = this.responseSessionExtractor.extractSession(messageInfo.getResponse());
			if(sessionToken != null) this.setSession(sessionToken);
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
		// First, request
		this.setSessionFromRequest(messageInfo.getRequest());
		
		// Then, response
		this.setSessionFromResponse(messageInfo);
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
		return this.sessionModifierType.toString() + " | " + this.sessionModifier.toString();
	}

}
