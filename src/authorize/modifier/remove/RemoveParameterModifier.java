package authorize.modifier.remove;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import authorize.modifier.Modifier;
import authorize.types.ParameterType;

public class RemoveParameterModifier implements Modifier
{
	private String match;
	private boolean isRegex;
	private byte paramType;
	
	@JsonCreator
	public RemoveParameterModifier(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex, @JsonProperty("paramType") byte paramType)
	{
		this.match = match;
		this.isRegex = isRegex;
		this.paramType = paramType;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof RemoveParameterModifier)
		{
			return this.equals((RemoveParameterModifier) other);
		}
		
		return false;
	}
	
	public boolean equals(RemoveParameterModifier other)
	{
		return this.match.equals(this.match) && this.isRegex == other.isRegex && this.paramType == other.paramType;
	}
	
	@Override
	public byte[] modify(byte[] request)
	{
		return AuthorizeUtils.removeParamByName(request, this.match, this.isRegex, this.paramType);
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
	
	public byte getParamType()
	{
		return this.paramType;
	}

	public void setParamType(byte paramType)
	{
		this.paramType = paramType;
	}
	
	@Override
	public String toString()
	{
		return this.match + " | " + (this.isRegex == true ? "Regex" : "Literal") + " | " + "Parameter: " + ParameterType.typeToEnum(this.paramType);
	}
}
