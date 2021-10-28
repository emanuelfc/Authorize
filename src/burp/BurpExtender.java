package burp;

import java.io.PrintStream;

import authorize.Authorize;
import gui.tabs.AuthorizeView;
import serialization.AuthorizeSerializer;

public class BurpExtender implements IBurpExtender, IHttpListener
{
	public static final String EXTENSION_NAME = "Authorize";
	
	public static IBurpExtenderCallbacks callbacks = null;
	public static IExtensionHelpers helpers = null;
	public static BurpExtender instance = null;
	
	private Authorize authorize;
	private AuthorizeView authorizeView;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		BurpExtender.instance = this;
		BurpExtender.callbacks = callbacks;
		BurpExtender.helpers = callbacks.getHelpers();
		
		callbacks.setExtensionName(EXTENSION_NAME);
		System.setOut(new PrintStream(BurpExtender.callbacks.getStdout()));
		System.setErr(new PrintStream(BurpExtender.callbacks.getStderr()));
		
		this.authorize = AuthorizeSerializer.load();
		if(this.authorize == null)
		{
			this.authorize = new Authorize();
		}
		
		this.authorizeView = new AuthorizeView();
		BurpExtender.callbacks.customizeUiComponent(this.authorizeView);
		callbacks.addSuiteTab(this.authorizeView);
		
		callbacks.registerHttpListener(this);
		callbacks.registerExtensionStateListener(new IExtensionStateListener()
		{

			@Override
			public void extensionUnloaded()
			{
				AuthorizeSerializer.save();
			}
	
		});
	}
	
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if(this.authorize.processMessage(toolFlag, messageIsRequest, messageInfo))
		{
			this.authorizeView.getProxyTab().getTable().getModel().fireTableDataChanged();
		}
	}
	
	public Authorize getAuthorize()
	{
		return this.authorize;
	}
	
	public void setAuthorize(Authorize authorize)
	{
		this.authorize = authorize;
		if(this.authorizeView != null) this.authorizeView.stateChanged(null);
	}
	
	public AuthorizeView getView()
	{
		return this.authorizeView;
	}
}
