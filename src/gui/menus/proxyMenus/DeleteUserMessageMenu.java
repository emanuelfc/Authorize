package gui.menus.proxyMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import authorize.messages.ProxyMessage;
import authorize.user.User;
import burp.BurpExtender;
import serialization.AuthorizeSerializer;

@SuppressWarnings("serial")
public class DeleteUserMessageMenu extends JMenuItem
{
	public static final String DELETE_MENU = "Delete (User Message)";
	
	public DeleteUserMessageMenu(ProxyMessage proxyMessage, User user)
	{
		this.setText(DELETE_MENU);
		this.addActionListener(new ActionListener()
		{
			@Override
			public void actionPerformed(ActionEvent e)
			{
				if(JOptionPane.showConfirmDialog(null, "Delete selected User Message?") == JOptionPane.YES_OPTION)
				{
					user.getMessages().remove(proxyMessage.getId());
					
					BurpExtender.instance.getView().getProxyTab().getTable().getModel().fireTableDataChanged();
					
					try
					{
						AuthorizeSerializer.removeUserMessage(proxyMessage.getId(), user);
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
