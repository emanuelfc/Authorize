package authorize.interception;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.matcher.MatchFunctionFactory;
import authorize.matcher.Matcher;
import authorize.types.MatchType;
import burp.IHttpRequestResponse;
import utils.AbstractRule;

public class MatchRule extends AbstractRule
{	
	private boolean relationship;	// Match / Does not Match
	private MatchType matchType;
	private Matcher matcher;
	
	public MatchRule(MatchType matchType, Matcher matcher, boolean relationship, String description, boolean enabled)
	{
		super(enabled, description);
		
		this.matchType = matchType;
		this.matcher = matcher;
		this.relationship = relationship;
	}
	
	@JsonCreator
	public MatchRule(@JsonProperty("matchType") MatchType matchType, @JsonProperty("condition") String condition, @JsonProperty("isRegex") boolean isRegex, @JsonProperty("relationship") boolean relationship, @JsonProperty("description") String description, @JsonProperty("enabled") boolean enabled)
	{
		this(matchType, new Matcher(condition, isRegex, matchType), relationship, description, enabled);
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof MatchRule)
		{
			return this.equals((MatchRule) other);
		}
		
		return false;
	}
	
	public boolean equals(MatchRule other)
	{
		return super.equals(other) && this.relationship == other.relationship && this.matcher.equals(other.matcher);
	}
	
	public MatchType getMatchType()
	{
		return this.matchType;
	}
	
	public boolean getRelationship()
	{
		return this.relationship;
	}
	
	public void setRelationship(boolean relationship)
	{
		this.relationship = relationship;
	}
	
	public boolean apply(IHttpRequestResponse messageInfo)
	{
		boolean res = this.matcher.isMatch(messageInfo);
		
		return this.relationship ? res : !res;
	}
	
	public String getCondition()
	{
		return this.matcher.getCondition();
	}
	
	public void setCondition(String newCondition)
	{
		this.matcher.setCondition(newCondition);
	}
	
	public boolean isRegex()
	{
		return this.matcher.isRegex();
	}
	
	public void setRegex(boolean isRegex)
	{
		this.matcher.setRegex(isRegex);
	}
	
	public void setMatchFunction(MatchType newMatchType)
	{		
		this.matcher.setMatchFunction(MatchFunctionFactory.getMatchFunction(newMatchType));
		this.matchType = newMatchType;
	}

}
