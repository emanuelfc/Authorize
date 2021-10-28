package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import authorize.messages.TestMessage;
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class CreateTestFromRequestMenu extends JMenuItem
{
	public static final String CREATE_TEST_FROM_REQUEST_MENU = "Create Test From Request";
	
	public CreateTestFromRequestMenu(IContextMenuInvocation invocation)
	{
		this.setText(CREATE_TEST_FROM_REQUEST_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				for(IHttpRequestResponse messageInfo: invocation.getSelectedMessages())
				{
					TestMessage testMessage = new TestMessage("New Test", messageInfo);
					BurpExtender.instance.getAuthorize().getTests().add(testMessage);
				}
				
				BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
			}
			
		});
	}
}
