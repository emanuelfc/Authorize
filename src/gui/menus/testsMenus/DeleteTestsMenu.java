package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.TestMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class DeleteTestsMenu extends JMenuItem
{
	public static final String DELETE_TEST_MENU = "Delete Tests";
	
	public DeleteTestsMenu(List<TestMessage> testMessages)
	{
		this.setText(DELETE_TEST_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete Tests?") == JOptionPane.YES_OPTION)
				{
					for(TestMessage testMessage: testMessages)
					{
						BurpExtender.instance.getAuthorize().getTests().remove(testMessage);
						BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
					}
				}
			}
			
		});
	}
}
