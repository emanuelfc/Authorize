package authorize.matcher;

import java.util.AbstractMap;
import java.util.Map;
import java.util.regex.Pattern;

import authorize.AuthorizeUtils;
import authorize.types.MatchType;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import utils.httpMessage.HttpRequest;

public class MatchFunctions
{
	public static MatchFunction ScopeMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			HttpRequest httpRequest = new HttpRequest(messageInfo);
			
			return BurpExtender.callbacks.isInScope(httpRequest.getRequestInfo().getUrl());
		}
	};
	
	public static MatchFunction RequestMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(messageInfo.getRequest()), condition, isRegex);
		}
	};
	
	public static MatchFunction ResponseMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(messageInfo.getResponse()), condition, isRegex);
		}
	};

	public static MatchFunction RequestHeaderMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.getRequestFullHeader(messageInfo.getRequest(), condition, isRegex) != null;
		}
	};
	
	public static MatchFunction RequestBodyMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			HttpRequest httpRequest = new HttpRequest(messageInfo);
			
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(httpRequest.copyBody()), condition, isRegex);
		}
	};
	
	public static MatchFunction ResponseHeaderMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.getResponseFullHeader(messageInfo.getResponse(), condition, isRegex) != null;
		}
	};
	
	public static MatchFunction ResponseBodyMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(AuthorizeUtils.copyResponseBody(messageInfo.getResponse())), condition, isRegex);
		}
	};
	
	public static MatchFunction DomainNameMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.checkStringEquals(messageInfo.getHttpService().getHost(), condition, isRegex);
		}
	};
	
	public static MatchFunction URLMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			HttpRequest httpRequest = new HttpRequest(messageInfo);			
			
			return AuthorizeUtils.checkStringEquals(httpRequest.getRequestInfo().getUrl().toString(), condition, isRegex);
		}
	};
	
	public static MatchFunction PathMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			HttpRequest httpRequest = new HttpRequest(messageInfo);
			
			String path = httpRequest.getRequestInfo().getUrl().getPath();
			
			if(isRegex)
			{
				return Pattern.matches(condition, path);
			}
			else
			{
				return path.startsWith(condition);
			}
		}
	};
	
	public static MatchFunction MethodMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			HttpRequest httpRequest = new HttpRequest(messageInfo);
			
			return AuthorizeUtils.checkStringEquals(httpRequest.getRequestInfo().getMethod(), condition, isRegex);
		}
	};
	
	public static MatchFunction ProtocolMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.checkStringEquals(messageInfo.getHttpService().getProtocol(), condition, isRegex);
		}
	};
	
	public static MatchFunction StatusCodeMatchFunction = new MatchFunction()
	{
		@Override
		public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex)
		{
			return AuthorizeUtils.checkStringEquals(String.valueOf(BurpExtender.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode()), condition, isRegex);
		}
	};

	public static final Map<String, MatchFunction> matchFunctions = Map.ofEntries(
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.SCOPE.toString(), ScopeMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.REQUEST.toString(), RequestMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.RESPONSE.toString(), ResponseMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.REQUEST_HEADER.toString(), RequestHeaderMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.REQUEST_BODY.toString(), RequestBodyMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.RESPONSE_HEADER.toString(), ResponseHeaderMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.RESPONSE_BODY.toString(), ResponseBodyMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.DOMAIN_NAME.toString(), DomainNameMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.URL.toString(), URLMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.PATH.toString(), PathMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.HTTP_METHOD.toString(), MethodMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.PROTOCOL.toString(), ProtocolMatchFunction),
			new AbstractMap.SimpleEntry<String, MatchFunction>(MatchType.STATUS_CODE.toString(), StatusCodeMatchFunction)
	);
	
}
