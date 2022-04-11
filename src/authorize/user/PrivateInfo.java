package authorize.user;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import authorize.AuthorizeUtils;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class PrivateInfo
{
	private String info;
	private boolean isRegex;
	private String description;
	private boolean enabled;
	
	@JsonCreator
	public PrivateInfo(@JsonProperty("info") String info, @JsonProperty("isRegex") boolean isRegex, @JsonProperty("description") String description, @JsonProperty("enabled") boolean enabled)
	{
		this.info = info;
		this.isRegex = isRegex;
		this.description = description;
		this.enabled = enabled;
	}
	
	public PrivateInfo(String info, boolean isRegex, String description)
	{
		this(info, isRegex, description, false);
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof PrivateInfo)
		{
			return this.equals((PrivateInfo) other);
		}
		
		return false;
	}
	
	public boolean equals(PrivateInfo other)
	{
		return this.info.equals(other.info) && this.isRegex == other.isRegex;
	}
	
	public String getInfo()
	{
		return this.info;
	}
	
	public void setInfo(String info)
	{
		this.info = info;
	}
	
	public boolean isRegex()
	{
		return this.isRegex;
	}
	
	public void setRegex(boolean isRegex)
	{
		this.isRegex = isRegex;
	}
	
	public String getDescription()
	{
		return this.description;
	}
	
	public void setDescription(String description)
	{
		this.description = description;
	}
	
	public boolean hasPrivateInfo(IHttpRequestResponse messageInfo)
	{
		String responseString = BurpExtender.helpers.bytesToString(messageInfo.getResponse());
		return AuthorizeUtils.checkStringContains(responseString, this.info, this.isRegex);
	}
	
	public boolean isEnabled()
	{
		return this.enabled;
	}
	
	public void setEnabled(boolean value)
	{
		this.enabled = value;
	}
	
	public void toggleEnable()
	{
		this.enabled = !this.enabled;
	}
}
