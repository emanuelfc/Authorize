package gui.windows;

import java.awt.BorderLayout;
import java.awt.Dimension;

import javax.swing.JFrame;
import javax.swing.JSplitPane;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IRequestInfo;
import gui.controllerPanels.MessageEditorController;

@SuppressWarnings("serial")
public class AuthorizationMessageWindow extends JFrame
{
	private static final String WINDOW_NAME = "Message Window";
	private static final Dimension WINDOW_DIMENSION = new Dimension(1300, 800);
	
	private JSplitPane requestResponsePane;
	
	public AuthorizationMessageWindow(IHttpRequestResponse messageInfo)
	{
		super(WINDOW_NAME);
		
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(messageInfo);
		
		super.setTitle(requestInfo.getMethod() + " " + requestInfo.getUrl().getFile());
		
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		
		this.requestResponsePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		this.requestResponsePane.setResizeWeight(0.5);
		
		MessageEditorController messageEditor = new MessageEditorController(messageInfo);
		
		IMessageEditor requestViewer = BurpExtender.callbacks.createMessageEditor(messageEditor, false);
		requestViewer.getComponent().setPreferredSize(new Dimension(650, 800));
		this.requestResponsePane.setLeftComponent(requestViewer.getComponent());
		
		IMessageEditor responseViewer = BurpExtender.callbacks.createMessageEditor(messageEditor, false);
		responseViewer.getComponent().setPreferredSize(new Dimension(650, 800));
		this.requestResponsePane.setRightComponent(responseViewer.getComponent());
		
		if(messageInfo != null)
		{
			requestViewer.setMessage(messageInfo.getRequest(), true);
			responseViewer.setMessage(messageInfo.getResponse(), false);
		}
		else
		{
			byte[] messageDoesntExist = "Message Does Not Exist".getBytes();
			requestViewer.setMessage(messageDoesntExist, true);
			responseViewer.setMessage(messageDoesntExist, false);
		}
		
		this.add(BorderLayout.CENTER, requestResponsePane);
		this.setLocationByPlatform(true);
		this.setResizable(true);
		this.setPreferredSize(WINDOW_DIMENSION);
		this.pack();
		
		BurpExtender.callbacks.customizeUiComponent(this);
	}
}
