package authorize.modifier.replace;

import authorize.types.ModifierType;
import authorize.types.ParameterType;

public class ReplaceModifierFactory
{	
	public static ReplaceModifier createReplaceModifier(ModifierType type, String match, boolean isRegex, String replace)
	{
		switch(type)
		{
			case MATCH_REPLACE_REQUEST:
				return new ReplaceRequestModifier(match, isRegex, replace);
				
			case MATCH_REPLACE_HEADER:
				return new ReplaceHeaderModifier(match, isRegex, replace);
				
			case MATCH_REPLACE_HEADER_VALUE:
				return new ReplaceHeaderValueModifier(match, isRegex, replace);
				
			case MATCH_REPLACE_BODY:
				return new ReplaceRequestBodyModifier(match, isRegex, replace);
				
			case MATCH_REPLACE_COOKIE:
				return new ReplaceParameterValueModifier(match, isRegex, replace, ParameterType.COOKIE.getType());
				
			case MATCH_REPLACE_URL_PARAM:
				return new ReplaceParameterValueModifier(match, isRegex, replace, ParameterType.URL.getType());
				
			case MATCH_REPLACE_URL_PARAM_BODY:
				return new ReplaceParameterValueModifier(match, isRegex, replace, ParameterType.URL_BODY.getType());
				
			case MATCH_REPLACE_JSON_PARAM:
				return new ReplaceParameterValueModifier(match, isRegex, replace, ParameterType.JSON.getType());
				
			default:
				throw new IllegalArgumentException();
			
		}
	}
}
