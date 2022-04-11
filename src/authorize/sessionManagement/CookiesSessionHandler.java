package authorize.sessionManagement;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Joiner;
import com.google.common.base.Splitter;
import com.google.common.collect.ImmutableSet;
import authorize.AuthorizeUtils;
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import utils.Parameter;

public class CookiesSessionHandler implements SessionHandler
{	
	@JsonIgnore
	private List<Parameter> cookies;

	private boolean enabled;
	
	@JsonCreator
	public CookiesSessionHandler(@JsonProperty("session") String cookies, @JsonProperty("enabled") boolean enabled)
	{
		this.enabled = enabled;
		this.cookies = new LinkedList<Parameter>();
		this.setSession(cookies);
	}
	
	private void setCookies(List<IParameter> cookies)
	{
		this.cookies = AuthorizeUtils.convertBurpParametersToParameters(cookies);
	}
	
	@Override
	public boolean isSession(IHttpRequestResponse messageInfo)
	{
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(messageInfo.getRequest());
		List<IParameter> requestCookiesParams = AuthorizeUtils.getRequestCookies(requestInfo);
		List<Parameter> requestCookies = AuthorizeUtils.convertBurpParametersToParameters(requestCookiesParams);
		
		return requestCookies.containsAll(this.cookies);
	}
	
	private static boolean equalNameParameter(IParameter cookie1, IParameter cookie2)
	{
		return cookie1.getName().equals(cookie2.getName());
	}
	
	private static Set<IParameter> mergeCookies(Set<? extends IParameter> cookies1, Set<? extends IParameter> cookies2)
	{
		// Supplied cookie from cookies1 list should not exist in the cookies2 list
		Predicate<IParameter> nonExistingCookiePredicate = (cookie1) -> (cookies1.stream().noneMatch((cookie2) -> (equalNameParameter(cookie1, cookie2))));
		
		// Get only the cookies on cookies1 list that do not belong in cookies2 list
		Set<IParameter> allCookies = cookies1.stream().filter(nonExistingCookiePredicate).collect(Collectors.toSet());
		
		/*
			Add the cookies2 list to the current set
			
			Since cookies1 list did not have any cookies from the cookies2 list,
			we only have unique cookies.
		 */
		allCookies.addAll(cookies2);
		return allCookies;
	}
	
	/*
	 * Intersection by name
	 * cookies1 will be the set which we will use as the values for the set intersection values
	 */
	private Set<IParameter> getCookiesIntersection(Set<? extends IParameter> cookies1, Set<? extends IParameter> cookies2)
	{
		// Supplied cookie from cookies1 list should not exist in the cookies2 list
		Predicate<IParameter> sameCookiePredicate = (cookie1) -> (cookies1.stream().anyMatch((cookie2) -> (equalNameParameter(cookie1, cookie2))));
		
		// Get only the cookies on cookies1 list that do not belong in cookies2 list
		Set<IParameter> cookiesIntersection = cookies1.stream().filter(sameCookiePredicate).collect(Collectors.toSet());
		
		return cookiesIntersection;
	}
	
	private byte[] removeCookies(byte[] request, Set<IParameter> cookies)
	{
		for(IParameter cookie: cookies)
		{
			request = BurpExtender.helpers.removeParameter(request, cookie);
		}
		
		return request;
	}
	
	private byte[] addCookies(byte[] request, Set<IParameter> cookies)
	{
		for(IParameter cookie: cookies)
		{
			request = BurpExtender.helpers.addParameter(request, cookie);
		}
		
		return request;
	}
	
	private byte[] updateCookies(byte[] request, Set<Parameter> requestCookies, Set<IParameter> cookies)
	{
		Set<IParameter> requestCookiesIntersection = this.getCookiesIntersection(requestCookies, ImmutableSet.copyOf(this.cookies));
		request = this.removeCookies(request, requestCookiesIntersection);
		
		Set<IParameter> cookiesIntersection = this.getCookiesIntersection(ImmutableSet.copyOf(this.cookies), requestCookies);
		request = this.addCookies(request, cookiesIntersection);
		
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(request);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = AuthorizeUtils.copyRequestBody(request);
		
		return BurpExtender.helpers.buildHttpMessage(headers, body);
	}
	
	@Override
	public void insertSession(IHttpRequestResponse message)
	{
		byte[] newRequest = Arrays.copyOf(message.getRequest(), message.getRequest().length);
		
		Set<Parameter> requestCookies = ImmutableSet.copyOf(AuthorizeUtils.convertBurpParametersToParameters(AuthorizeUtils.getRequestCookies(newRequest)));
		Set<IParameter> sessionCookies = ImmutableSet.copyOf(this.cookies);
		
		message.setRequest(this.updateCookies(newRequest, requestCookies, sessionCookies));
	}
	
	@Override
	public void forceInsertSession(IHttpRequestResponse message)
	{
		byte[] newRequest = Arrays.copyOf(message.getRequest(), message.getRequest().length);
		
		Set<Parameter> requestCookies = ImmutableSet.copyOf(AuthorizeUtils.convertBurpParametersToParameters(AuthorizeUtils.getRequestCookies(newRequest)));
		for(Parameter cookieParam: requestCookies)
		{
			newRequest = BurpExtender.helpers.removeParameter(newRequest, cookieParam);
		}
		
		Set<IParameter> mergedCookies = mergeCookies(requestCookies, ImmutableSet.copyOf(this.cookies));
		
		for(IParameter cookieParam: mergedCookies)
		{
			newRequest = BurpExtender.helpers.addParameter(newRequest, cookieParam);
		}
		
		IRequestInfo analyzedRequest = BurpExtender.helpers.analyzeRequest(newRequest);
		List<String> headers = analyzedRequest.getHeaders();
		byte[] body = AuthorizeUtils.copyRequestBody(newRequest);
		
		message.setRequest(BurpExtender.helpers.buildHttpMessage(headers, body));
	}
	
	@Override
	public void setSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		if(invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
		{
			this.setCookies(AuthorizeUtils.getRequestCookies(messageInfo.getRequest()));
		}
		else if(invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE || invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE)
		{
			this.setCookies(AuthorizeUtils.getResponseCookies(messageInfo.getResponse()));
		}
	}
	
	public void updateSession(IHttpRequestResponse messageInfo, byte invocationContext)
	{
		if(invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST)
		{
			this.updateCookies(AuthorizeUtils.getRequestCookies(messageInfo.getRequest()));
		}
		else if(invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE || invocationContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE)
		{
			this.updateCookies(AuthorizeUtils.getResponseCookies(messageInfo.getResponse()));
		}
	}
	
	@Override
	public void updateSession(IHttpRequestResponse messageInfo)
	{
		// First, request
		this.updateCookies(AuthorizeUtils.getRequestCookies(messageInfo.getRequest()));
		
		// Then, response
		this.updateCookies(AuthorizeUtils.getResponseCookies(messageInfo.getResponse()));
	}
	
	@Override
	public String getSession()
	{
		return Joiner.on(";").join(this.cookies);
	}
	
	@Override
	public void setSession(@JsonProperty("session") String cookies)
	{
		if(cookies != null)
		{
			if(cookies.isBlank())
			{
				this.setCookies(new LinkedList<IParameter>());
			}
			else
			{
				this.setCookies(AuthorizeUtils.cookiesToParameters(this.sanitizeCookies(cookies)));
			}
		}
	}
	
	private String sanitizeCookies(String cookies)
	{
		return Joiner.on(";").join(Splitter.on(";").trimResults().omitEmptyStrings().split(cookies));
	}
	
	private void updateCookies(List<IParameter> newCookies)
	{
		for(IParameter newCookie: newCookies)
		{
			Parameter cookie = this.getCookie(newCookie.getName());
			if(cookie != null)
			{
				cookie.setValue(newCookie.getValue());
			}
		}
	}
	
	private Parameter getCookie(String cookieName)
	{
		for(Parameter cookie: this.cookies)
		{
			if(cookie.getName().equals(cookieName)) return cookie;
		}
		
		return null;
	}
	
	@Override
	public boolean isEnabled()
	{
		return this.enabled;
	}

	@Override
	public void setEnabled(boolean enabled)
	{
		this.enabled = enabled;
	}

	@Override
	public void toggleEnable()
	{
		this.enabled = !this.enabled;
	}
	
	@JsonIgnore
	public String getDescription()
	{
		return "Cookies";
	}

	@Override
	public void setDescription(String newDescription)
	{
		return;
	}

}
