package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.TestMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class DeleteTestMenu extends JMenuItem
{
	public static final String DELETE_TEST_MENU = "Delete Test";
	
	public DeleteTestMenu(TestMessage testMessage)
	{
		this.setText(DELETE_TEST_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete Test?") == JOptionPane.YES_OPTION)
				{
					BurpExtender.instance.getAuthorize().getTests().remove(testMessage);
					BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
				}
			}
			
		});
	}
}
