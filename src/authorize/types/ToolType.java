package authorize.types;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;

public enum ToolType
{
	BURP_SUITE(IBurpExtenderCallbacks.TOOL_SUITE),
	TARGET(IBurpExtenderCallbacks.TOOL_TARGET),
	PROXY(IBurpExtenderCallbacks.TOOL_PROXY),
	SPIDER(IBurpExtenderCallbacks.TOOL_SPIDER),
	SCANNER(IBurpExtenderCallbacks.TOOL_SCANNER),
	INTRUDER(IBurpExtenderCallbacks.TOOL_INTRUDER),
	REPEATER(IBurpExtenderCallbacks.TOOL_REPEATER),
	SEQUENCER(IBurpExtenderCallbacks.TOOL_SEQUENCER),
	//DECODER(IBurpExtenderCallbacks.TOOL_DECODER),
	//COMPARER(IBurpExtenderCallbacks.TOOL_COMPARER),
	EXTENDER(IBurpExtenderCallbacks.TOOL_EXTENDER);
	
	private int toolFlag;
	
	private ToolType(int toolFlag)
	{
		this.toolFlag = toolFlag;
	}
	
	public int getToolFlag()
	{
		return this.toolFlag;
	}
	
	public String toString()
	{
		return BurpExtender.callbacks.getToolName(toolFlag);
	}
	
	public boolean equals(ToolType other)
	{
		if(this == other) return true;
		
		return this.toolFlag == other.toolFlag;
	}
}
