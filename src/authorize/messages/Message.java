package authorize.messages;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import serialization.HttpRequestResponseSerializer;
import utils.HttpRequestResponse;

@JsonIgnoreType
public class Message
{
	protected IHttpRequestResponse message;
	protected Date timestamp;
	
	@JsonCreator
	public Message(@JsonProperty("message") @JsonDeserialize(as = HttpRequestResponse.class) IHttpRequestResponse messageInfo, @JsonProperty("timestamp") Date timestamp)
	{
		this.message = messageInfo != null ? BurpExtender.callbacks.saveBuffersToTempFiles(messageInfo) : null;
		this.timestamp = timestamp;
	}
	
	public Message(IHttpRequestResponse messageInfo)
	{
		this(messageInfo, new Date());
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof Message)
		{
			return this.equals((Message) other);
		}
		
		return false;
	}
	
	public boolean equals(Message other)
	{
		return this.message.equals(other.message) && this.timestamp.equals(other.timestamp);
	}
	
	@JsonSerialize(using = HttpRequestResponseSerializer.class)
	public IHttpRequestResponse getMessage()
	{	
		return this.message;
	}
	
	public Date getTimestamp()
	{
		return this.timestamp;
	}
}
