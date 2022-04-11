package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenuItem;
import authorize.messages.ProxyMessage;
import authorize.user.User;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class RetestUserEnforcementMenu extends JMenuItem
{
	public static final String RETEST_ENFORCEMENT_MENU = "Retest Enforcement";
	
	public RetestUserEnforcementMenu(ProxyMessage proxyMessage, User user)
	{
		this.setText(RETEST_ENFORCEMENT_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				BurpExtender.instance.getAuthorize().retestEnforcement(proxyMessage.getId(), user);
				BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
			}
			
		});
	}
}
