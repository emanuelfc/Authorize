package authorize.matcher;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.types.MatchType;
import burp.IHttpRequestResponse;

public class Matcher
{
	protected String condition;
	protected boolean isRegex;
	protected MatchFunction matchFunction;
	
	public Matcher()
	{
		this.condition = "";
		this.isRegex = false;
		this.matchFunction = null;
	}
	
	public Matcher(String condition, boolean isRegex, MatchFunction matchFunction)
	{
		this.condition = condition;
		this.isRegex = isRegex;
		this.matchFunction = matchFunction;
	}
	
	@JsonCreator
	public Matcher(@JsonProperty("condition") String condition, @JsonProperty("isRegex") boolean isRegex, @JsonProperty("matchType") MatchType matchType)
	{
		this(condition, isRegex, MatchFunctionFactory.getMatchFunction(matchType));
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof Matcher)
		{
			return this.equals((Matcher) other);
		}
		
		return false;
	}
	
	public boolean equals(Matcher other)
	{
		return this.condition.equals(other.getCondition()) && this.isRegex == other.isRegex() && this.matchFunction.equals(other.matchFunction);
	}
	
	public String getCondition()
	{
		return this.condition;
	}
	
	public void setCondition(String newCondition)
	{
		this.condition = newCondition;
	}
	
	public boolean isRegex()
	{
		return this.isRegex;
	}
	
	public void setRegex(boolean isRegex)
	{
		this.isRegex = isRegex;
	}
	
	public boolean isMatch(IHttpRequestResponse messageInfo)
	{
		return this.matchFunction.isMatch(messageInfo, condition, isRegex);
	}

	public void setMatchFunction(MatchFunction newMatchFunction)
	{
		this.matchFunction = newMatchFunction;
	}
}
