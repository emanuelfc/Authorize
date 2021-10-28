package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.util.List;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.ProxyMessage;
import burp.BurpExtender;
import serialization.AuthorizeSerializer;

@SuppressWarnings("serial")
public class DeleteMessagesMenu extends JMenuItem
{
	public static final String DELETE_MESSAGES_MENU = "Delete Messages";
	
	public DeleteMessagesMenu(List<ProxyMessage> proxyMessages)
	{
		this.setText(DELETE_MESSAGES_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete Messages (Includes all Principal Messages)?") == JOptionPane.YES_OPTION)
				{
					for(ProxyMessage proxyMessage: proxyMessages)
					{
						BurpExtender.instance.getAuthorize().deleteMessage(proxyMessage.getId());
						
						try
						{
							AuthorizeSerializer.removeHistoryMessage(proxyMessage.getId());
						}
						catch(MalformedURLException e1)
						{
							// TODO Auto-generated catch block
							e1.printStackTrace();
						}
					}
					
					BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
				}
			}
			
		});
	}
}
