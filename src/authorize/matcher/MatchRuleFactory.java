package authorize.matcher;

import authorize.types.MatchType;

public class MatchRuleFactory
{	
	public static final MatchRule createMatchRule(MatchType type, String match, boolean isRegex, String description, boolean enabled)
	{
		Matcher matcher = MatcherFactory.createMatcher(type, match, isRegex);
		return new MatchRule(type, matcher, isRegex, description, enabled);
	}
}
