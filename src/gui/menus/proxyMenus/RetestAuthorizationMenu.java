package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import authorize.messages.ProxyMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class RetestAuthorizationMenu extends JMenuItem
{
	public static final String RETEST_AUTHORIZATION_MENU = "Retest Authorization";
	
	public RetestAuthorizationMenu(ProxyMessage proxyMessage)
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
						BurpExtender.instance.getAuthorize().retestAuthorization(proxyMessage.getId());
						BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
					}
			
				}).start();
			}
			
		});
	}
}
