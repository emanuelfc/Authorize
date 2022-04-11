package authorize.modifier.replace;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;

public class ReplaceHeaderModifier extends AbstractReplaceModifier
{
	@JsonCreator
	public ReplaceHeaderModifier(@JsonProperty("match") String match, @JsonProperty("isRegex") boolean isRegex, @JsonProperty("replace") String replace)
	{
		super(match, isRegex, replace);
	}

	@Override
	public byte[] modify(byte[] request)
	{
		return AuthorizeUtils.updateHeaderValue(request, this.match, this.isRegex, this.replace);
	}
}