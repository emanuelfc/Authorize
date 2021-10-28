package authorize.matcher;

import java.lang.invoke.WrongMethodTypeException;
import java.util.regex.Pattern;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class Matchers
{
	private static abstract class AbstractRequestMatcher extends AbstractMatcher
	{
		public AbstractRequestMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}
		
		public abstract boolean matches(byte[] request);
		
		public boolean matches(IHttpRequestResponse messageInfo)
		{
			return this.matches(messageInfo.getRequest());
		}
	}
	
	private static abstract class AbstractResponseMatcher extends AbstractMatcher
	{
		public AbstractResponseMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}
		
		public abstract boolean matches(byte[] request);
		
		public boolean matches(IHttpRequestResponse messageInfo)
		{
			return this.matches(messageInfo.getResponse());
		}
	}
	
	public static class RequestMatcher extends AbstractRequestMatcher
	{
		@JsonCreator
		public RequestMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] request)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(request), super.match, super.isRegex);
		}
	}
	
	public static class ResponseMatcher extends AbstractResponseMatcher
	{	
		@JsonCreator
		public ResponseMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] response)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(response), super.match, super.isRegex);
		}
	}

	public static class RequestHeaderMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public RequestHeaderMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] request)
		{
			return AuthorizeUtils.getRequestFullHeader(request, super.match, super.isRegex) != null;
		}
	}
	
	public static class RequestBodyMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public RequestBodyMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] request)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(AuthorizeUtils.copyRequestBody(request)), super.match, super.isRegex);
		}
	}
	
	public static class ResponseHeaderMatcher extends AbstractResponseMatcher
	{		
		@JsonCreator
		public ResponseHeaderMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] response)
		{
			return AuthorizeUtils.getResponseFullHeader(response, super.match, super.isRegex) != null;
		}
	}
	
	public static class ResponseBodyMatcher extends AbstractResponseMatcher
	{		
		@JsonCreator
		public ResponseBodyMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] response)
		{
			return AuthorizeUtils.checkStringContains(BurpExtender.helpers.bytesToString(AuthorizeUtils.copyResponseBody(response)), super.match, super.isRegex);
		}
	}
	
	public static class DomainNameMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public DomainNameMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] request)
		{
			throw new WrongMethodTypeException("Cannot obtain " + this.getClass().toString() + "with request bytes.");
		}
		
		@Override
		public boolean matches(IHttpRequestResponse messageInfo)
		{
			return AuthorizeUtils.checkStringEquals(messageInfo.getHttpService().getHost(), super.match, super.isRegex);
		}
	}
	
	public static class URLMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public URLMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}
		
		@Override
		public boolean matches(byte[] request)
		{
			throw new WrongMethodTypeException("Cannot obtain " + this.getClass().toString() + "with request bytes.");
		}
		
		@Override
		public boolean matches(IHttpRequestResponse messageInfo)
		{
			return AuthorizeUtils.checkStringEquals(BurpExtender.helpers.analyzeRequest(messageInfo).getUrl().toString(), super.match, super.isRegex);
		}
	}
	
	public static class PathMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public PathMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}
		
		@Override
		public boolean matches(byte[] request)
		{
			throw new WrongMethodTypeException("Cannot obtain " + this.getClass().toString() + "with request bytes.");
		}
		
		@Override
		public boolean matches(IHttpRequestResponse messageInfo)
		{
			String path = BurpExtender.helpers.analyzeRequest(messageInfo).getUrl().getPath();
			
			if(super.isRegex)
			{
				return Pattern.matches(super.match, path);
			}
			else
			{
				return path.startsWith(super.match);
			}
		}
	}
	
	public static class MethodMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public MethodMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] request)
		{
			return AuthorizeUtils.checkStringEquals(BurpExtender.helpers.analyzeRequest(request).getMethod(), super.match, super.isRegex);
		}
	}
	
	public static class ProtocolMatcher extends AbstractRequestMatcher
	{		
		@JsonCreator
		public ProtocolMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] request)
		{
			throw new WrongMethodTypeException("Cannot obtain " + this.getClass().toString() + "with request bytes.");
		}
		
		@Override
		public boolean matches(IHttpRequestResponse messageInfo)
		{
			return AuthorizeUtils.checkStringEquals(messageInfo.getHttpService().getProtocol(), super.match, super.isRegex);
		}
	}
	
	public static class StatusCodeMatcher extends AbstractResponseMatcher
	{		
		@JsonCreator
		public StatusCodeMatcher(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex)
		{
			super(match, isRegex);
		}

		@Override
		public boolean matches(byte[] response)
		{
			return AuthorizeUtils.checkStringEquals(String.valueOf(BurpExtender.helpers.analyzeResponse(response).getStatusCode()), super.match, super.isRegex);
		}
	}
	
}
