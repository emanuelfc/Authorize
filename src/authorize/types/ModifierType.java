package authorize.types;

public enum ModifierType
{
	// Add
	ADD_HEADER("Add - Header"),
	ADD_COOKIE("Add - Cookie"),
	ADD_URL_PARAM("Add - URL Parameter"),
	ADD_URL_PARAM_BODY("Add - URL Parameter in Body"),
	ADD_JSON_PARAM("Add - JSON Parameter"),
	
	// Remove
	REMOVE_HEADER("Remove - Header"),
	REMOVE_COOKIE("Remove - Cookie"),
	REMOVE_URL_PARAM("Remove - URL Parameter"),
	REMOVE_URL_PARAM_BODY("Remove - URL Parameter in Body"),
	REMOVE_JSON_PARAM("Remove - JSON Parameter"),
	
	// Match Replace
	MATCH_REPLACE_REQUEST("Match & Replace - Request"),
	MATCH_REPLACE_HEADER("Match & Replace - Header"),
	MATCH_REPLACE_HEADER_VALUE("Match & Replace - Header Value"),
	MATCH_REPLACE_BODY("Match & Replace - Body"),
	MATCH_REPLACE_COOKIE("Match & Replace - Cookie"),
	MATCH_REPLACE_URL_PARAM("Match & Replace - URL Parameter"),
	MATCH_REPLACE_URL_PARAM_BODY("Match & Replace - URL Parameter in Body"),
	MATCH_REPLACE_JSON_PARAM("Match & Replace - JSON Parameter");
	
	private String name;
	
	private ModifierType()
	{
		this.name = this.name();
	}
	
	private ModifierType(String name)
	{
		this.name = name;
	}
	
	public String toString()
	{
		return this.name;
	}
	
	public boolean equals(ModifierType other)
	{
		if(this == other) return true;
		
		return this.name.equals(other.name);
	}
}
