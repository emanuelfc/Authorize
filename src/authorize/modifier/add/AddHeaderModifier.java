package authorize.modifier.add;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import authorize.modifier.Modifier;

public class AddHeaderModifier implements Modifier
{
	private String header;
	
	@JsonCreator
	public AddHeaderModifier(@JsonProperty("header") String header)
	{
		this.header = header;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof AddHeaderModifier)
		{
			return this.equals((AddHeaderModifier) other);
		}
		
		return false;
	}
	
	public boolean equals(AddHeaderModifier other)
	{
		return this.header.equals(header);
	}
	
	@Override
	public byte[] modify(byte[] content)
	{
		return AuthorizeUtils.addHeader(content, this.header);
	}
	
	public String getHeader()
	{
		return this.header;
	}

	public void setHeader(String newHeader)
	{
		this.header = newHeader;
	}
	
	@Override
	public String toString()
	{
		return this.header;
	}
}
