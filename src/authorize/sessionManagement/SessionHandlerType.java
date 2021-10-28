package authorize.sessionManagement;

public enum SessionHandlerType
{
	COOKIES("Cookies"),
	MATCH_REPLACE("Match & Replace");
	
	private String name;
	
	private SessionHandlerType()
	{
		this.name = this.name();
	}
	
	private SessionHandlerType(String name)
	{
		this.name = name;
	}
	
	public String toString()
	{
		return this.name;
	}
}
