package authorize.types;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum EnforcementStatus
{
	AUTHORIZED("Authorized"),
	UNAUTHORIZED("Unauthorized"),
	UNKNOWN("Unknown"),
	ACTING_USER("Same User"),
	DISABLED("Disabled"),
	NO_MESSAGE("No Message"),
	ERROR("Error");
	
	private String name;
	
	@JsonCreator
	private EnforcementStatus(String name)
	{
		this.name = name;
	}
	
	public String toString()
	{
		return this.name;
	}
	
	
	public boolean equals(EnforcementStatus other)
	{
		if(this == other) return true;
		
		return this.name.equals(other.name);
	}
	
	public static EnforcementStatus getByName(String name)
	{
		for(EnforcementStatus status: EnforcementStatus.values())
		{
			if(status.toString().equals(name)) return status;
		}
		
		return null;
	}
}
