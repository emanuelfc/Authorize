package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenuItem;

import authorize.messages.ProxyMessage;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class RetestEnforcementMenu extends JMenuItem
{
	public static final String RETEST_ENFORCEMENT_MENU = "Retest Enforcement";
	
	public RetestEnforcementMenu(ProxyMessage proxyMessage)
	{
		this.setText(RETEST_ENFORCEMENT_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				BurpExtender.instance.getAuthorize().retestEnforcementAll(proxyMessage.getId());
				BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
			}
			
		});
	}
}
