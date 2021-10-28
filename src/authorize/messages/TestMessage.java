package authorize.messages;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import burp.IHttpRequestResponse;
import utils.HttpRequestResponse;

@JsonIgnoreType
public class TestMessage extends Message
{
	private String testName;
	private Map<String, PrincipalMessage> principalMessages;
	
	@JsonCreator
	public TestMessage(@JsonProperty("testName") String testName, @JsonProperty("message") @JsonDeserialize(as = HttpRequestResponse.class) IHttpRequestResponse messageInfo, @JsonProperty("timestamp") Date timestamp)
	{
		super(messageInfo, timestamp);
		
		this.testName = testName;
		this.principalMessages = new HashMap<String, PrincipalMessage>();
	}
	
	public TestMessage(String testName, IHttpRequestResponse messageInfo)
	{
		this(testName, messageInfo, new Date());
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof TestMessage)
		{
			return this.equals((TestMessage) other);
		}
		
		return false;
	}
	
	public boolean equals(TestMessage other)
	{
		return this.testName.equals(other.testName) && super.equals(other);
	}
	
	public String getTestName()
	{
		return this.testName;
	}
	
	public void setTestName(String newTestName)
	{
		this.testName = newTestName;
	}
	
	public void setMessageInfo(IHttpRequestResponse newMessageInfo)
	{
		super.message = newMessageInfo;
	}
	
	public void setTimestamp(Date newTimestamp)
	{
		this.timestamp = newTimestamp;
	}
	
	public PrincipalMessage getPrincipalMessage(String principalName)
	{
		return this.principalMessages.get(principalName);
	}
	
	public void insertPrincipalTest(String principalName, PrincipalMessage principalMessage)
	{
		this.principalMessages.put(principalName, principalMessage);
	}
	
	public void removePrincipalTest(String principalName)
	{
		this.principalMessages.remove(principalName);
	}
	
	public Map<String, PrincipalMessage> getPrincipalMessages()
	{
		return this.principalMessages;
	}
}
