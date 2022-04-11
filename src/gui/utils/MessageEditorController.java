package gui.utils;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditorController;

public class MessageEditorController implements IMessageEditorController
{
	protected IHttpRequestResponse messageInfo;
	
	public MessageEditorController(IHttpRequestResponse messageInfo)
	{
		this.messageInfo = messageInfo;
	}
	
	public MessageEditorController()
	{
		this(null);
	}

	@Override
	public IHttpService getHttpService()
	{
		if(this.messageInfo != null)
		{
			return this.messageInfo.getHttpService();
		}
		
		return null;
	}

	@Override
	public byte[] getRequest()
	{
		if(this.messageInfo != null)
		{
			return this.messageInfo.getRequest();
		}
		
		return null;
	}

	@Override
	public byte[] getResponse()
	{
		if(this.messageInfo != null)
		{
			return this.messageInfo.getResponse();
		}
		
		return null;
	}
}
