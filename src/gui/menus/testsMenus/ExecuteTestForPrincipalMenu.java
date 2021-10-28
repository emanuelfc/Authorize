package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;

import authorize.messages.TestMessage;
import authorize.principal.Principal;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class ExecuteTestForPrincipalMenu extends JMenuItem
{
	public static final String TEST_PRINCIPAL_AUTHORIZATION_MENU = "Test Authorization (Principal)";
	
	public ExecuteTestForPrincipalMenu(TestMessage testMessage, Principal principal)
	{
		this.setText(TEST_PRINCIPAL_AUTHORIZATION_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				new Thread(new Runnable()
				{

					@Override
					public void run()
					{
						BurpExtender.instance.getAuthorize().executeTestForPrincipal(testMessage, principal);
						BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
					}
			
				}).start();;
					
			}
			
		});
	}
}
