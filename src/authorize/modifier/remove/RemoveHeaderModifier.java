package authorize.modifier.remove;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import authorize.modifier.Modifier;

public class RemoveHeaderModifier implements Modifier
{
	private String header;
	private boolean isRegex;
	
	@JsonCreator
	public RemoveHeaderModifier(@JsonProperty("header") String header, @JsonProperty("isRegex") boolean isRegex)
	{
		this.header = header;
		this.isRegex = isRegex;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof RemoveHeaderModifier)
		{
			return this.equals((RemoveHeaderModifier) other);
		}
		
		return false;
	}
	
	public boolean equals(RemoveHeaderModifier other)
	{
		return this.header.equals(header);
	}
	
	@Override
	public byte[] modify(byte[] content)
	{
		return AuthorizeUtils.removeHeader(content, header, this.isRegex);
	}
	
	public String getHeader()
	{
		return this.header;
	}

	public void setHeader(String newHeader)
	{
		this.header = newHeader;
	}
	
	public boolean isRegex()
	{
		return this.isRegex;
	}

	public void setRegex(boolean isRegex)
	{
		this.isRegex = isRegex;
	}
	
	@Override
	public String toString()
	{
		return this.header + " | " + (this.isRegex == true ? "Regex" : "Literal");
	}
}
