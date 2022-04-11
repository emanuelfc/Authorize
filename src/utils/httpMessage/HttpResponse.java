package utils.httpMessage;

import java.util.Arrays;
import java.util.function.Predicate;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IResponseInfo;

public class HttpResponse
{
	Predicate<IParameter> cookiePredicate = (param) -> (param.getType() == IParameter.PARAM_COOKIE);
	
	private IHttpRequestResponse messageInfo;
	private IResponseInfo responseInfo;
	
	public HttpResponse(IHttpRequestResponse messageInfo)
	{
		this.messageInfo = messageInfo;
		this.responseInfo = BurpExtender.helpers.analyzeResponse(messageInfo.getResponse());
	}
	
	public IHttpRequestResponse getMessageinfo()
	{
		return this.messageInfo;
	}
	
	public IResponseInfo getResponseInfo()
	{
		return this.responseInfo;
	}
	
	public byte[] copyResponse()
	{
		byte[] responseMessage = this.messageInfo.getResponse();
		return Arrays.copyOf(responseMessage, responseMessage.length);
	}
	
	public String getStatusline()
	{
		return null;
	}
	
	public int getStatusCode()
	{
		return 0;
	}
	
	public String getStatusText()
	{
		return null;
	}
	
	public byte[] toBytes()
	{
		return this.messageInfo.getResponse();
	}
}
