package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.TestMessage;
import authorize.principal.Principal;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class DeletePrincipalTestMenu extends JMenuItem
{
	public static final String DELETE_PRINCIPAL_TEST_MENU = "Delete Principal Test";
	
	public DeletePrincipalTestMenu(TestMessage testMessage, Principal principal)
	{
		this.setText(DELETE_PRINCIPAL_TEST_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete Principal Test?") == JOptionPane.YES_OPTION)
				{
					testMessage.removePrincipalTest(principal.getName());
					BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
				}
			}
		});
	}
}
