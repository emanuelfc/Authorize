package authorize.matcher;

import authorize.matcher.Matchers.DomainNameMatcher;
import authorize.matcher.Matchers.MethodMatcher;
import authorize.matcher.Matchers.PathMatcher;
import authorize.matcher.Matchers.ProtocolMatcher;
import authorize.matcher.Matchers.RequestBodyMatcher;
import authorize.matcher.Matchers.RequestHeaderMatcher;
import authorize.matcher.Matchers.RequestMatcher;
import authorize.matcher.Matchers.ResponseBodyMatcher;
import authorize.matcher.Matchers.ResponseHeaderMatcher;
import authorize.matcher.Matchers.ResponseMatcher;
import authorize.matcher.Matchers.StatusCodeMatcher;
import authorize.matcher.Matchers.URLMatcher;
import authorize.types.MatchType;

public class MatcherFactory
{	
	public static final Matcher createMatcher(MatchType type, String match, boolean isRegex)
	{
		switch(type)
		{				
			case REQUEST:
				return new RequestMatcher(match, isRegex);	
			
			case RESPONSE:
				return new ResponseMatcher(match, isRegex);
				
			case REQUEST_HEADER:
				return new RequestHeaderMatcher(match, isRegex);
				
			case RESPONSE_HEADER:
				return new ResponseHeaderMatcher(match, isRegex);
				
			case REQUEST_BODY:
				return new RequestBodyMatcher(match, isRegex);
				
			case RESPONSE_BODY:
				return new ResponseBodyMatcher(match, isRegex);
				
			case DOMAIN_NAME:
				return new DomainNameMatcher(match, isRegex);
				
			case URL:
				return new URLMatcher(match, isRegex);
				
			case PATH:
				return new PathMatcher(match, isRegex);
				
			case HTTP_METHOD:
				return new MethodMatcher(match, isRegex);
				
			case PROTOCOL:
				return new ProtocolMatcher(match, isRegex);
				
			case STATUS_CODE:
				return new StatusCodeMatcher(match, isRegex);
				
			default:
				throw new IllegalArgumentException("Invalid Match type: " + type.toString());
		}
	}
}
