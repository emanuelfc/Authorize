package authorize.messages;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreType;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

import authorize.types.EnforcementStatus;
import burp.IHttpRequestResponse;
import utils.HttpRequestResponse;

@JsonIgnoreType
public class PrincipalMessage extends Message
{
	private EnforcementStatus status;
	
	@JsonCreator
	public PrincipalMessage(@JsonProperty("message") @JsonDeserialize(as = HttpRequestResponse.class) IHttpRequestResponse messageInfo, @JsonProperty("status") EnforcementStatus status)
	{
		super(messageInfo);
		this.status = status;
	}
	
	@Override
	public boolean equals(Object other)
	{
		if(this == other) return true;
		
		if(other instanceof PrincipalMessage)
		{
			return this.equals((PrincipalMessage) other);
		}
		
		return false;
	}
	
	public boolean equals(PrincipalMessage other)
	{
		return super.equals(other) && this.status.equals(other.status);
	}

	public EnforcementStatus getStatus()
	{
		return this.status;
	}
	
	public void setStatus(EnforcementStatus status)
	{
		this.status = status;
	}
}
