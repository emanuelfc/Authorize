package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import authorize.messages.TestMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class ExecuteEnforcementTestMenu extends JMenuItem
{
	public static final String TEST_ENFORCEMENT_MENU = "Test Enforcement";
	
	public ExecuteEnforcementTestMenu(TestMessage testMessage)
	{
		this.setText(TEST_ENFORCEMENT_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				BurpExtender.instance.getAuthorize().executeEnforcementTest(testMessage);
				BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
			}
			
		});
	}
}
