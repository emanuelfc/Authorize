package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import authorize.messages.ProxyMessage;
import authorize.principal.Principal;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class RetestPrincipalAuthorizationMenu extends JMenuItem
{
	public static final String RETEST_AUTHORIZATION_MENU = "Retest Authorization (Principal)";
	
	public RetestPrincipalAuthorizationMenu(ProxyMessage proxyMessage, Principal principal)
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
						BurpExtender.instance.getAuthorize().retestAuthorizationForPrincipal(proxyMessage.getId(), principal);
						BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
					}
			
				}).start();
			}
			
		});
	}
}
