package authorize.types;

public enum SessionHandlerType
{
	COOKIES("Cookies"),
	HEADER("Header");
	
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
