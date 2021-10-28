package authorize.messages;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import burp.IHttpRequestResponse;
import utils.HttpRequestResponse;

@JsonIgnoreType
public class ProxyMessage extends Message
{
	private int id;
	
	@JsonCreator
	public ProxyMessage(@JsonProperty("id") int id, @JsonProperty("message") @JsonDeserialize(as = HttpRequestResponse.class) IHttpRequestResponse messageInfo, @JsonProperty("timestamp") Date timestamp)
	{
		super(messageInfo, timestamp);
		
		this.id = id;
	}
	
	public ProxyMessage(int id, IHttpRequestResponse messageInfo)
	{
		super(messageInfo);
		
		this.id = id;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof ProxyMessage)
		{
			return this.equals((ProxyMessage) other);
		}
		
		return false;
	}
	
	public boolean equals(ProxyMessage other)
	{
		return this.id == other.id && super.equals(other);
	}
	
	public int getId()
	{
		return this.id;
	}
}
