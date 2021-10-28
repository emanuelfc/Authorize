package utils;

public abstract class AbstractRule
{
	protected boolean enabled;
	protected String description;
	
	public AbstractRule(boolean enabled, String description)
	{
		this.enabled = enabled;
		this.description = description;
	}
	
	public String getDescription()
	{
		return this.description;
	}
	
	public void setDescription(String description)
	{
		this.description = description;
	}
	
	public boolean isEnabled()
	{
		return this.enabled;
	}
	
	public void setEnable(boolean enabled)
	{
		this.enabled = enabled;
	}
	
	public void toggleEnable()
	{
		this.enabled = !this.enabled;
	}
}
