package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.ProxyMessage;
import burp.BurpExtender;
import serialization.AuthorizeSerializer;

@SuppressWarnings("serial")
public class DeleteMessageMenu extends JMenuItem
{
	public static final String DELETE_MESSAGE_MENU = "Delete Message";
	
	public DeleteMessageMenu(ProxyMessage proxyMessage)
	{
		this.setText(DELETE_MESSAGE_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete Message (Includes all User Messages)?") == JOptionPane.YES_OPTION)
				{
					BurpExtender.instance.getAuthorize().deleteMessage(proxyMessage.getId());
					BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
					
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
			}
			
		});
	}
}
