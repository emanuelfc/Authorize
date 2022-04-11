package authorize.interception;

import java.util.LinkedList;
import java.util.List;
import java.util.function.Predicate;
import java.util.stream.Stream;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.types.MatchType;
import burp.IHttpRequestResponse;

public class InterceptionManager
{
	private List<MatchRule> interceptionRules;
	private ToolInterceptionRule toolInterceptionRule;
	
	public InterceptionManager()
	{
		this.interceptionRules = new LinkedList<MatchRule>();
		this.toolInterceptionRule = new ToolInterceptionRule();
	}
	
	@JsonCreator
	public InterceptionManager(@JsonProperty("interceptionRules") List<MatchRule> interceptionRules, @JsonProperty("toolInterceptionRule") ToolInterceptionRule toolInterceptionRule)
	{
		this.interceptionRules = interceptionRules;
		this.toolInterceptionRule = toolInterceptionRule;
	}
	
	public static Predicate<MatchRule> isRequestRuleFilter = (matchRule) -> {
		return matchRule.getMatchType().equals(MatchType.REQUEST) || 
				matchRule.getMatchType().equals(MatchType.REQUEST_HEADER) ||
				matchRule.getMatchType().equals(MatchType.REQUEST_BODY) ||
				matchRule.getMatchType().equals(MatchType.DOMAIN_NAME) ||
				matchRule.getMatchType().equals(MatchType.URL) ||
				matchRule.getMatchType().equals(MatchType.PATH) ||
				matchRule.getMatchType().equals(MatchType.HTTP_METHOD) ||
				matchRule.getMatchType().equals(MatchType.PROTOCOL);
	};
	
	public boolean testInterception(int toolFlag, IHttpRequestResponse messageInfo)
	{
		if(!this.toolInterceptionRule.isAllowedTool(toolFlag)) return false;
		
		synchronized(this.interceptionRules)
		{
			// All Rules - Request and Response Rules
			if(messageInfo.getResponse() != null)
			{	
				return this.interceptionRules.stream().allMatch((rule) -> (rule.apply(messageInfo)));
			}
			// Only Request Interception Rules
			else
			{
				Stream<MatchRule> requestRules = this.interceptionRules.stream().filter(isRequestRuleFilter);
				return requestRules.allMatch((rule) -> (rule.apply(messageInfo)));
			}
		}
	}
	
	public List<MatchRule> getInterceptionRules()
	{
		return this.interceptionRules;
	}
	
	public ToolInterceptionRule getToolInterceptionRule()
	{
		return this.toolInterceptionRule;
	}
}
