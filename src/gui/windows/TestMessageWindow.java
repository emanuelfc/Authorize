package gui.windows;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JSplitPane;

import authorize.messages.TestMessage;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import burp.IRequestInfo;
import gui.controllerPanels.MessageEditorController;
import utils.HttpRequestResponse;

@SuppressWarnings("serial")
public class TestMessageWindow extends JFrame
{
	private static final String WINDOW_NAME = "Test Message";
	private static final Dimension WINDOW_DIMENSION = new Dimension(1100, 700);
	
	private JSplitPane requestResponsePane;
	
	private IMessageEditor requestViewer;
	
	private TestMessage testMessage;
	
	public TestMessageWindow(TestMessage testMessage)
	{
		super(WINDOW_NAME + " - " + testMessage.getTestName());
		
		this.testMessage = testMessage;
		
		IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(this.testMessage.getMessage());
		
		super.setTitle(requestInfo.getMethod() + " " + requestInfo.getUrl().getFile());
		
		this.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		
		this.requestResponsePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		this.requestResponsePane.setResizeWeight(0.5);
		
		MessageEditorController messageEditor = new MessageEditorController(this.testMessage.getMessage());
		
		this.requestViewer  = BurpExtender.callbacks.createMessageEditor(messageEditor, true);
		this.requestViewer.getComponent().setPreferredSize(new Dimension(650, 800));
		this.requestResponsePane.setLeftComponent(this.requestViewer.getComponent());
		
		this.requestViewer.setMessage(this.testMessage.getMessage().getRequest(), true);
		
		this.add(BorderLayout.CENTER, requestResponsePane);
		this.setLocationByPlatform(true);
		this.setResizable(true);
		this.setPreferredSize(WINDOW_DIMENSION);
		this.pack();
		
		this.addWindowListener(new WindowListener()
		{

			@Override
			public void windowOpened(WindowEvent e){}

			@Override
			public void windowClosing(WindowEvent e)
			{
				if(TestMessageWindow.this.requestViewer.isMessageModified())
				{
					int result = JOptionPane.showConfirmDialog(null, "Request was modified. Save?", "Confirm Exit", JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
					if(result == JOptionPane.OK_OPTION)
					{
						IHttpRequestResponse newMessageInfo = new HttpRequestResponse(TestMessageWindow.this.requestViewer.getMessage(), 
																					TestMessageWindow.this.testMessage.getMessage().getResponse(), 
																					TestMessageWindow.this.testMessage.getMessage().getHttpService(),
																					TestMessageWindow.this.testMessage.getMessage().getComment(),
																					TestMessageWindow.this.testMessage.getMessage().getHighlight());
						
						TestMessageWindow.this.testMessage.setMessageInfo(newMessageInfo);
						BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
					}
				}
			}

			@Override
			public void windowClosed(WindowEvent e){}

			@Override
			public void windowIconified(WindowEvent e){}

			@Override
			public void windowDeiconified(WindowEvent e){}

			@Override
			public void windowActivated(WindowEvent e){}

			@Override
			public void windowDeactivated(WindowEvent e){}
	
		});
		
		BurpExtender.callbacks.customizeUiComponent(this);
	}
}
