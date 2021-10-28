package authorize.matcher;

import burp.IHttpRequestResponse;

abstract class AbstractMatcher implements Matcher
{
	protected String match;
	protected boolean isRegex;
	
	public AbstractMatcher(String match, boolean isRegex)
	{
		this.match = match;
		this.isRegex = isRegex;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof AbstractMatcher)
		{
			return this.equals((AbstractMatcher) other);
		}
		
		return false;
	}
	
	public boolean equals(Matcher other)
	{
		return this.match.equals(other.getMatch()) && this.isRegex == other.isRegex();
	}
	
	public String getMatch()
	{
		return this.match;
	}
	
	public void setMatch(String match)
	{
		this.match = match;
	}
	
	public boolean isRegex()
	{
		return this.isRegex;
	}
	
	public void setRegex(boolean isRegex)
	{
		this.isRegex = isRegex;
	}
	
	public abstract boolean matches(byte[] content);
	public abstract boolean matches(IHttpRequestResponse messageInfo);
}
