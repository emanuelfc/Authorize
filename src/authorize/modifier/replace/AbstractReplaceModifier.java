package authorize.modifier.replace;

abstract class AbstractReplaceModifier implements ReplaceModifier
{
	protected String match;
	protected boolean isRegex;
	protected String replace;
	
	public AbstractReplaceModifier(String match, boolean isRegex, String replace)
	{
		this.match = match;
		this.isRegex = isRegex;
		this.replace = replace;
	}
	
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof AbstractReplaceModifier)
		{
			return this.equals((AbstractReplaceModifier) other);
		}
		
		return false;
	}
	
	public boolean equals(AbstractReplaceModifier other)
	{
		return this.match.equals(other.match) && this.isRegex == other.isRegex && this.replace.equals(other.replace);
	}
	
	public abstract byte[] modify(byte[] content);
	
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
	
	public String getReplace()
	{
		return this.replace;
	}
	
	public synchronized void setReplace(String replace)
	{
		this.replace = replace;
	}
	
	@Override
	public String toString()
	{
		return "Match: " + this.match + " | " + (this.isRegex == true ? "Regex" : "Literal") + " | " + "Replace: " + this.replace;
	}
}
