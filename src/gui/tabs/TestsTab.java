package gui.tabs;

import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import burp.BurpExtender;
import burp.IMessageEditor;
import gui.controllerPanels.MessageEditorController;
import gui.tables.TestsTable;

@SuppressWarnings("serial")
public class TestsTab extends JSplitPane
{
	public static final String TESTS_TAB_NAME = "Tests";
	
	private TestsTable testsTable;
	
	public TestsTab()
	{
		super(JSplitPane.VERTICAL_SPLIT);
		this.setName(TESTS_TAB_NAME);
		
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
		this.testsTable = new TestsTable(messageEditor, requestViewer, responseViewer);
		JScrollPane scrollPane = new JScrollPane(this.testsTable);
		
		this.setTopComponent(scrollPane);
	}
	
	public TestsTable getTable()
	{
		return this.testsTable;
	}
}
