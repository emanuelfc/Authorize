package authorize.types;

import com.fasterxml.jackson.annotation.JsonCreator;

public enum EnforcementStatus
{
	AUTHORIZED("Authorized"),
	AUTHORIZED_CONTAINS_PRIVATE_INFO("Authorized - Contains Private Info"),
	AUTHORIZED_SIMILAR_CONTENT("Authorized - Similar Content"),
	AUTHORIZED_EQUAL_CONTENT("Authorized - Equal Content"),
	
	UNAUTHORIZED("Unauthorized"),
	UNAUTHORIZED_BY_ENFORCEMENT_RULE("Unauthorized - by Enforcement Rule"),
	UNAUTHORIZED_NOT_ACCEPTABLE_SIMILAR_CONTENT("Unauthorized - No Acceptable Similar Content"),
	
	ACTING_USER("Current User"),
	DISABLED("Disabled"),
	NO_MESSAGE("No Message"),
	ERROR("Error"),
	UNKNOWN("Unknown");
	
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
