package authorize.interception;

import authorize.matcher.MatchFunctionFactory;
import authorize.matcher.Matcher;
import authorize.types.MatchType;

public class InterceptionRuleFactory
{	
	public static final MatchRule createMatchRule(MatchType matchType, String match, boolean relationship, boolean isRegex, String description, boolean enabled)
	{
		Matcher matcher = new Matcher(match, isRegex, MatchFunctionFactory.getMatchFunction(matchType));
		return new MatchRule(matchType, matcher, relationship, description, enabled);
	}
}
