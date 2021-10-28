package authorize.modifier.add;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import authorize.modifier.Modifier;
import authorize.types.ParameterType;

public class AddParameterModifier implements Modifier
{
	private String key, value;
	private byte paramType;
	
	@JsonCreator
	public AddParameterModifier(@JsonProperty("key") String key, @JsonProperty("value") String value, @JsonProperty("paramType") byte paramType)
	{
		this.key = key;
		this.value = value;
		this.paramType = paramType;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof AddParameterModifier)
		{
			return this.equals((AddParameterModifier) other);
		}
		
		return false;
	}
	
	public boolean equals(AddParameterModifier other)
	{
		return this.key.equals(this.key) && this.value.equals(other.value) && this.paramType == other.paramType;
	}
	
	@Override
	public byte[] modify(byte[] content)
	{
		return AuthorizeUtils.addParam(content, this.key, this.value, this.paramType);
	}
	
	public String getKey()
	{
		return this.key;
	}

	public void setKey(String newKey)
	{
		this.key = newKey;
	}
	
	public String getValue()
	{
		return this.value;
	}

	public void setValue(String newValue)
	{
		this.value = newValue;
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
		return "Key: " + this.key + " | " + "Value: " + this.value + " | " + "Parameter: " + ParameterType.typeToEnum(this.paramType);
	}
}
