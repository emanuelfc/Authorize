package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;

import authorize.messages.TestMessage;
import authorize.principal.Principal;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class ExecutePrincipalEnforcementTestMenu extends JMenuItem
{
	public static final String TEST_PRINCIPAL_ENFORCEMENT_MENU = "Test Enforcement (Principal)";
	
	public ExecutePrincipalEnforcementTestMenu(TestMessage testMessage, Principal principal)
	{
		this.setText(TEST_PRINCIPAL_ENFORCEMENT_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				BurpExtender.instance.getAuthorize().executeEnforcementTestForPrincipal(testMessage, principal);
				BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
			}
			
		});
	}
}
