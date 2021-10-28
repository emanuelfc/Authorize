package authorize.modifier.replace;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import authorize.types.ParameterType;

public class ReplaceParameterValueModifier extends AbstractReplaceModifier
{
	private byte paramType;
	
	@JsonCreator
	public ReplaceParameterValueModifier(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex, @JsonProperty("replace") String replace, @JsonProperty("paramType") byte paramType)
	{
		super(match, isRegex, replace);
		this.paramType = paramType;
	}

	@Override
	public byte[] modify(byte[] content)
	{
		return AuthorizeUtils.updateParamValue(content, match, replace, isRegex, this.paramType);
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
		return super.toString() + " | " + "Parameter: " + ParameterType.typeToEnum(this.paramType);
	}
}
