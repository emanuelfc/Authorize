package authorize.matcher;

import com.fasterxml.jackson.annotation.JsonTypeInfo;

import burp.IHttpRequestResponse;

@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "className")
public interface Matcher
{	
	public boolean equals(Matcher other);
	public String getMatch();
	public void setMatch(String match);
	public boolean isRegex();
	public void setRegex(boolean isRegex);
	public boolean matches(byte[] content);
	public boolean matches(IHttpRequestResponse messageInfo);
}
