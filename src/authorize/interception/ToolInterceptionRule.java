package authorize.interception;

import com.fasterxml.jackson.annotation.JsonProperty;

public class ToolInterceptionRule
{
	private int toolsFlag;
	
	public ToolInterceptionRule(@JsonProperty("toolsFlag") int toolsFlag)
	{
		this.toolsFlag = toolsFlag;
	}
	
	public ToolInterceptionRule()
	{
		this(0);
	}
	
	@Override
	public synchronized boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof ToolInterceptionRule)
		{
			return this.equals((ToolInterceptionRule) other);
		}
		
		return false;
	}
	
	public synchronized boolean equals(ToolInterceptionRule other)
	{
		return this.toolsFlag == other.toolsFlag;
	}
	
	public synchronized boolean isAllowedTool(int toolFlag)
	{
		return ((toolsFlag & toolFlag) > 0);
	}
	
	public synchronized int getToolsFlag()
	{
		return this.toolsFlag;
	}
	
	public synchronized void setToolsFlag(int toolsFlag)
	{
		this.toolsFlag = toolsFlag;
	}
	
	public synchronized void addTool(int newToolFlag)
	{
		this.toolsFlag |= newToolFlag;
	}
	
	public synchronized void removeTool(int oldToolFlag)
	{
		this.toolsFlag ^= oldToolFlag;
	}
}
