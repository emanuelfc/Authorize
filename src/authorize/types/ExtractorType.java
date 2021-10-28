package authorize.types;

public enum ExtractorType
{
	REQUEST("Request"),
	REQUEST_BODY("Request Body"),
	REQUEST_HEADER("Request Header (Value)"),
	REQUEST_COOKIE("Request Cookie"),
	REQUEST_URL_PARAM("Request URL Parameter"),
	REQUEST_URL_PARAM_BODY("Request URL Parameter in Body"),
	REQUEST_JSON_PARAM("Request JSON Parameter"),
	
	RESPONSE("Response"),
	RESPONSE_BODY("Response Body"),
	RESPONSE_HEADER("Response Header (Value)"),
	RESPONSE_COOKIE("Response Cookie"),
	RESPONSE_JSON_PARAM("Response JSON Parameter");
	
	private String name;
	
	private ExtractorType(String name)
	{
		this.name = name;
	}
	
	public String toString()
	{
		return this.name;
	}
	
	public boolean equals(ExtractorType other)
	{
		if(this == other) return true;
		
		return this.name.equals(other.name);
	}
}
