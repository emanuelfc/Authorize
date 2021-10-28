package gui.menus.testsMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.List;

import javax.swing.JMenuItem;

import authorize.messages.TestMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class ExecuteTestsMenu extends JMenuItem
{
	public static final String EXECUTE_TESTS_MENU = "Execute Tests";
	
	public ExecuteTestsMenu(List<TestMessage> testMessages)
	{
		this.setText(EXECUTE_TESTS_MENU);
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
						for(TestMessage testMessage: testMessages)
						{
							BurpExtender.instance.getAuthorize().executeTest(testMessage);
						}
						
						BurpExtender.instance.getView().getTestsTab().getTable().getModel().fireTableDataChanged();
					}
			
				}).start();
			}
			
		});
	}
}
