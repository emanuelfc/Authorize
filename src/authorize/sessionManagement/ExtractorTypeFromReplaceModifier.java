package authorize.sessionManagement;

import authorize.types.ExtractorType;
import authorize.types.ModifierType;

public class ExtractorTypeFromReplaceModifier
{
	
	public static ExtractorType createExtractorType(ModifierType type)
	{
		switch(type)
		{
			case MATCH_REPLACE_REQUEST:
				return ExtractorType.REQUEST;
				
			case MATCH_REPLACE_BODY:
				return ExtractorType.REQUEST_BODY;
				
			case MATCH_REPLACE_HEADER_VALUE:
				return ExtractorType.REQUEST_HEADER;
				
			case MATCH_REPLACE_URL_PARAM:
				return ExtractorType.REQUEST_URL_PARAM;
				
			case MATCH_REPLACE_URL_PARAM_BODY:
				return ExtractorType.REQUEST_URL_PARAM_BODY;
				
			case MATCH_REPLACE_JSON_PARAM:
				return ExtractorType.REQUEST_JSON_PARAM;
			
			default:
				throw new IllegalArgumentException("Invalid ReplaceModifer type = " + type.toString());
		}
	}
	
}
