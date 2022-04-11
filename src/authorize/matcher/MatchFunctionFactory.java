package authorize.matcher;

import authorize.types.MatchType;

public class MatchFunctionFactory
{	
	public static final MatchFunction getMatchFunction(MatchType type)
	{
		MatchFunction matchFunction = MatchFunctions.matchFunctions.get(type.toString());
		
		if(matchFunction != null)
		{
			return matchFunction;
		}

		throw new IllegalArgumentException("Invalid MatchFunction type: " + type.toString());
	}
}
