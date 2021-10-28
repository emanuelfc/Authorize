package authorize.types;

import burp.IParameter;

public enum ParameterType
{
	URL("URL Parameter", IParameter.PARAM_URL),
	URL_BODY("URL Parameter in Body", IParameter.PARAM_BODY),
	COOKIE("Cookie", IParameter.PARAM_COOKIE),
	XML("XML Item", IParameter.PARAM_XML),
	XML_ATTR("XML Value Tag Attribute", IParameter.PARAM_XML_ATTR),
	MULTIPART_ATTR("Multipart Attribute", IParameter.PARAM_MULTIPART_ATTR),
	JSON("JSON", IParameter.PARAM_JSON);
	
	private String name;
	private byte paramType;
	
	private ParameterType(String name, byte paramType)
	{
		this.name = name;
		this.paramType = paramType;
	}
	
	public String toString()
	{
		return this.name;
	}
	
	public byte getType()
	{
		return this.paramType;
	}
	
	public boolean equals(ParameterType other)
	{
		if(this == other) return true;
		
		return this.name.equals(other.name) && this.paramType == other.paramType;
	}
	
	public static ParameterType typeToEnum(byte paramType)
	{
		switch(paramType)
		{
			case IParameter.PARAM_URL:
				return ParameterType.URL;
				
			case IParameter.PARAM_BODY:
				return ParameterType.URL_BODY;
				
			case IParameter.PARAM_COOKIE:
				return ParameterType.COOKIE;
				
			case IParameter.PARAM_XML:
				return ParameterType.XML;
				
			case IParameter.PARAM_XML_ATTR:
				return ParameterType.XML_ATTR;
				
			case IParameter.PARAM_MULTIPART_ATTR:
				return ParameterType.MULTIPART_ATTR;
				
			case IParameter.PARAM_JSON:
				return ParameterType.JSON;
				
			default:
				throw new IllegalArgumentException("Invalid paramType for typeToEnum = " + paramType);
			
		}
	}
}
