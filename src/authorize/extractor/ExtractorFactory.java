package authorize.extractor;

import authorize.AuthorizeUtils;
import authorize.types.ExtractorType;
import authorize.types.ParameterType;

public class ExtractorFactory
{
	
	public static Extractor createExtractor(ExtractorType type)
	{
		switch(type)
		{
			case REQUEST:
			case RESPONSE:
				return (content, match, isRegex) -> (AuthorizeUtils.extractFromMessage(content, match, isRegex));
				
			case REQUEST_BODY:
				return (request, match, isRegex) -> (AuthorizeUtils.extractFromMessage(AuthorizeUtils.copyRequestBody(request), match, isRegex));
				
			case REQUEST_HEADER:
				return (request, match, isRegex) -> (AuthorizeUtils.getRequestHeaderValue(request, match, isRegex));
				
			case REQUEST_COOKIE:
				return new ParameterValueExtractor(ParameterType.COOKIE.getType());
				
			case REQUEST_URL_PARAM:
				return new ParameterValueExtractor(ParameterType.URL.getType());
				
			case REQUEST_URL_PARAM_BODY:
				return new ParameterValueExtractor(ParameterType.URL_BODY.getType());
				
			case REQUEST_JSON_PARAM:
				return new ParameterValueExtractor(ParameterType.JSON.getType());
				
			case RESPONSE_BODY:
				return (request, match, isRegex) -> (AuthorizeUtils.extractFromMessage(AuthorizeUtils.copyResponseBody(request), match, isRegex));
				
			case RESPONSE_HEADER:
				return (response, match, isRegex) -> (AuthorizeUtils.getResponseHeaderValue(response, match, isRegex));
				
			case RESPONSE_COOKIE:
				throw new UnsupportedOperationException();
				
			case RESPONSE_JSON_PARAM:
				throw new UnsupportedOperationException();
			
			default:
				throw new IllegalArgumentException("Invalid Extractor type = " + type.toString());
		}
	}
	
}
