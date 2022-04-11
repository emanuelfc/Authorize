package utils.httpMessage;

public class HttpHeader
{
	private String headerName, headerValue;
	
	public HttpHeader(String headerName, String headerValue)
	{
		this.headerName = headerName;
		this.headerValue = headerValue;
	}
	
	public String getName()
	{
		return this.headerName;
	}
	
	public String getValue()
	{
		return this.headerValue;
	}
	
	public void setName(String newName)
	{
		this.headerName = newName;
	}
	
	public void setValue(String newValue)
	{
		this.headerValue = newValue;
	}
	
	public static HttpHeader parseHeaderFromString(String header)
	{
		String[] headerParts = header.split(header, 1);
		
		if(headerParts.length == 2)
		{
			return new HttpHeader(headerParts[0].trim(), headerParts[1].trim());
		}
		
		return null;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof HttpHeader)
		{
			return this.equals((HttpHeader) other);
		}
		
		return false;
	}
	
	public boolean equals(HttpHeader other)
	{
		return this.headerName.equals(other.headerName) && this.headerValue.equals(other.headerValue);
	}
	
	public String toString()
	{
		return this.headerName + ": " + this.headerValue;
	}
}
