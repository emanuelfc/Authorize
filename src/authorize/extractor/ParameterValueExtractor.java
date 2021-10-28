package authorize.extractor;

import authorize.AuthorizeUtils;
import burp.IParameter;

public class ParameterValueExtractor implements Extractor
{
	private byte paramType;
	
	public ParameterValueExtractor(byte paramType)
	{
		this.paramType = paramType;
	}
	
	@Override
	public String extract(byte[] content, String match, boolean isRegex)
	{
		IParameter param = null;
		
		if(isRegex)
		{
			param = AuthorizeUtils.getParameterByNameRegex(content, match, this.paramType);
		}
		else
		{
			param = AuthorizeUtils.getParameter(content, match, this.paramType);
		}
		
		if(param != null) return param.getValue();
		else return null;
	}
	
}
