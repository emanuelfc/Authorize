package authorize.matcher;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;

import burp.IHttpRequestResponse;
import serialization.MatchFunctionSerializer;

@JsonSerialize(using = MatchFunctionSerializer.class)
@FunctionalInterface
public interface MatchFunction
{
	public boolean isMatch(IHttpRequestResponse messageInfo, String condition, boolean isRegex);
}
