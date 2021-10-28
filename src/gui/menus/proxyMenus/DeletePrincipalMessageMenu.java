package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.ProxyMessage;
import authorize.principal.Principal;
import burp.BurpExtender;
import serialization.AuthorizeSerializer;

@SuppressWarnings("serial")
public class DeletePrincipalMessageMenu extends JMenuItem
{
	public static final String DELETE_MENU = "Delete (Principal Message)";
	
	public DeletePrincipalMessageMenu(ProxyMessage proxyMessage, Principal principal)
	{
		this.setText(DELETE_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete selected Principal Message?") == JOptionPane.YES_OPTION)
				{
					principal.getMessages().remove(proxyMessage.getId());
					
					BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
					
					try
					{
						AuthorizeSerializer.removePrincipalMessage(proxyMessage.getId(), principal);
					}
					catch(MalformedURLException e1)
					{
						// TODO Auto-generated catch block
						e1.printStackTrace();
					}
				}
			}
		});
	}
}
