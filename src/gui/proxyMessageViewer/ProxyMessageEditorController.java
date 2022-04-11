package gui.proxyMessageViewer;

import burp.IHttpRequestResponse;
import gui.utils.MessageEditorController;
import gui.utils.SelectionListener;

public class ProxyMessageEditorController extends MessageEditorController implements SelectionListener<IHttpRequestResponse>
{
	public ProxyMessageEditorController(IHttpRequestResponse messageInfo)
	{
		super(messageInfo);
	}
	
	public ProxyMessageEditorController()
	{
		this(null);
	}

	@Override
	public void onSelection(IHttpRequestResponse selection)
	{
		this.messageInfo = selection;
	}
}
