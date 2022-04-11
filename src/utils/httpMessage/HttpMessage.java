package utils.httpMessage;

import burp.IHttpRequestResponse;

public class HttpMessage
{
	private IHttpRequestResponse messageInfo;
	private HttpRequest httpRequest;
	private HttpResponse httpResponse;
	
	public HttpMessage(IHttpRequestResponse messageInfo)
	{
		this.messageInfo = messageInfo;
		this.httpRequest = new HttpRequest(messageInfo);
		
		if(messageInfo.getResponse() != null)
		{
			this.httpResponse = new HttpResponse(messageInfo);
		}
	}
	
	public IHttpRequestResponse getMessageInfo()
	{
		return this.messageInfo;
	}
	
	public HttpRequest getRequest()
	{
		return this.httpRequest;
	}
	
	public HttpResponse getResponse()
	{
		return this.httpResponse;
	}
}
