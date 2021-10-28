package authorize.types;

public enum MatchType
{
	REQUEST("Request"),
	RESPONSE("Response"),
	REQUEST_HEADER("Request Header"),
	REQUEST_BODY("Request Body"),
	RESPONSE_HEADER("Response Header"),
	RESPONSE_BODY("Response Body"),
	DOMAIN_NAME("Domain Name"),
	URL("URL"),
	PATH("Path"),
	HTTP_METHOD("HTTP Method"),
	PROTOCOL("Protocol"),
	STATUS_CODE("Status Code");
	
	private String name;
	
	private MatchType()
	{
		this.name = this.name();
	}
	
	private MatchType(String name)
	{
		this.name = name;
	}
	
	public String toString()
	{
		return this.name;
	}
	
	public boolean equals(MatchType other)
	{
		if(this == other) return true;
		
		return this.name.equals(other.name);
	}
}
