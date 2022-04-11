package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import authorize.messages.ProxyMessage;
import authorize.user.User;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class RetestUserAuthorizationMenu extends JMenuItem
{
	public static final String RETEST_AUTHORIZATION_MENU = "Retest Authorization (User)";
	
	public RetestUserAuthorizationMenu(ProxyMessage proxyMessage, User user)
	{
		this.setText(RETEST_AUTHORIZATION_MENU);
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
						BurpExtender.instance.getAuthorize().retestAuthorizationForUser(proxyMessage.getId(), user);
						BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
					}
			
				}).start();
			}
			
		});
	}
}
