package gui.tabs.proxyTab;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import burp.BurpExtender;
import burp.IMessageEditor;
import gui.proxyMessageViewer.MessagesViewerPanel;
import gui.proxyMessageViewer.ProxyMessageEditorController;

@SuppressWarnings("serial")
public class ProxyTab extends JSplitPane implements ChangeListener
{
	private ProxyTable proxyTable;
	
	public ProxyTab()
	{
		super(JSplitPane.VERTICAL_SPLIT);
		this.setName("Proxy");
		
		// Message (Request / Response) Panel
		ProxyMessageEditorController proxyMessageEditorController = new ProxyMessageEditorController();
		
		IMessageEditor requestEditor = BurpExtender.callbacks.createMessageEditor(proxyMessageEditorController, false);
		IMessageEditor responseEditor = BurpExtender.callbacks.createMessageEditor(proxyMessageEditorController, false);
		
		MessagesViewerPanel messagesViewerPanel = new MessagesViewerPanel(requestEditor, responseEditor);
		
		this.setBottomComponent(messagesViewerPanel);
		
		// Table Pane
		this.proxyTable = new ProxyTable(proxyMessageEditorController, requestEditor, responseEditor);
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
