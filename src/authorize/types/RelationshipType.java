package authorize.types;

public enum RelationshipType
{
	MATCH("Matches", true),
	DONT_MATCH("Does not match", false);
	
	private boolean relationship;
	private String name;
	
	private RelationshipType(String name, boolean relationship)
	{
		this.name = name;
		this.relationship = relationship;
	}
	
	public boolean getRelationship()
	{
		return this.relationship;
	}
	
	public String toString()
	{
		return this.name;
	}
	
	public boolean equals(RelationshipType other)
	{
		if(this == other) return true;
		
		return this.name.equals(other.name) && this.relationship == other.relationship;
	}
}
