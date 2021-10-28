package authorize.modifier;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import authorize.types.ModifierType;
import utils.AbstractRule;

public class ModifierRule extends AbstractRule
{
	private ModifierType type;
	private Modifier modifier;
	
	@JsonCreator
	public ModifierRule(@JsonProperty("modifier") Modifier modifier, @JsonProperty("type") ModifierType type, @JsonProperty("enabled") boolean enabled, @JsonProperty("description") String description)
	{
		super(enabled, description);
		this.modifier = modifier;
		this.type = type;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof ModifierRule)
		{
			return this.equals((ModifierRule) other);
		}
		
		return false;
	}
	
	public boolean equals(ModifierRule other)
	{
		return this.modifier.equals(other.modifier) && this.type.equals(other.type);
	}
	
	public byte[] modify(byte[] content)
	{
		return this.modifier.modify(content);
	}
	
	public ModifierType getType()
	{
		return this.type;
	}
	
	public void setType(ModifierType newType)
	{
		this.type = newType;
	}
	
	public Modifier getModifier()
	{
		return this.modifier;
	}
	
	public void setModifier(Modifier newModifier)
	{
		this.modifier = newModifier;
	}
	
	@Override
	public String toString()
	{
		return this.type.toString() + " | " + this.modifier.toString();
	}
}
