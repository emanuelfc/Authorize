package authorize.matcher;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.types.MatchType;
import burp.IHttpRequestResponse;
import utils.AbstractRule;

public class MatchRule extends AbstractRule
{	
	private boolean relationship;	// Match / Does not Match
	private MatchType matchType;
	private Matcher matcher;
	
	@JsonCreator
	public MatchRule(@JsonProperty("matchType") MatchType matchType, @JsonProperty("matcher") Matcher matcher, @JsonProperty("relationship") boolean relationship, @JsonProperty("description") String description, @JsonProperty("enabled") boolean enabled)
	{
		super(enabled, description);
		
		this.matchType = matchType;
		this.matcher = matcher;
		this.relationship = relationship;
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
		boolean res = this.matcher.matches(messageInfo);
		
		return this.relationship ? res : !res;
	}
	
	public Matcher getMatcher()
	{
		return this.matcher;
	}
	
	public void setMatcher(Matcher newMatch, MatchType newMatchType)
	{
		this.matcher = newMatch;
		this.matchType = newMatchType;
	}

}
