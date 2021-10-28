package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import authorize.messages.TestMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class ExecuteTestMenu extends JMenuItem
{
	public static final String EXECUTE_TEST_MENU = "Execute Test";
	
	public ExecuteTestMenu(TestMessage testMessage)
	{
		this.setText(EXECUTE_TEST_MENU);
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
						BurpExtender.instance.getAuthorize().executeTest(testMessage);
						BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
					}
			
				}).start();
			}
			
		});
	}
}
