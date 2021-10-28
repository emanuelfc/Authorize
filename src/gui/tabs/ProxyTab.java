package gui.tabs;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import burp.BurpExtender;
import burp.IMessageEditor;
import gui.controllerPanels.MessageEditorController;
import gui.tables.ProxyTable;

@SuppressWarnings("serial")
public class ProxyTab extends JSplitPane implements ChangeListener
{
	public static final String PROXY_TAB_NAME = "Proxy";
	
	private ProxyTable proxyTable;
	
	public ProxyTab()
	{
		super(JSplitPane.VERTICAL_SPLIT);
		this.setName(PROXY_TAB_NAME);
		
		// Request / Response Pane
		
		JSplitPane requestResponsePane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
		requestResponsePane.setResizeWeight(0.5);
		//JTabbedPane requestResponsePane = new JTabbedPane();
		
		MessageEditorController messageEditor = new MessageEditorController();
		
		IMessageEditor requestViewer = BurpExtender.callbacks.createMessageEditor(messageEditor, false);
		//requestResponsePane.addTab("Request", requestViewer.getComponent());
		requestResponsePane.setLeftComponent(requestViewer.getComponent());
		
		IMessageEditor responseViewer = BurpExtender.callbacks.createMessageEditor(messageEditor, false);
		//requestResponsePane.addTab("Response", responseViewer.getComponent());
		requestResponsePane.setRightComponent(responseViewer.getComponent());
		
		this.setBottomComponent(requestResponsePane);
		
		// Table Pane
		this.proxyTable = new ProxyTable(messageEditor, requestViewer, responseViewer);
		JScrollPane scrollPane = new JScrollPane(this.proxyTable);
		
		this.setTopComponent(scrollPane);
	}
	
	public ProxyTable getTable()
	{
		return this.proxyTable;
	}

	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.proxyTable.stateChanged(e);
	}
}
