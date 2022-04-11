package gui.menus.burpMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.user.User;
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class SendAsUserMenu extends JMenu
{
	public static final String SEND_AS_USER_MENU = "Send As User";
	
	public SendAsUserMenu(IContextMenuInvocation invocation)
	{
		this.setText(SEND_AS_USER_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				SendAsUserMenu.this.removeAll();
				
				for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
				{
					JMenuItem item = new JMenuItem(p.getName());
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							for(IHttpRequestResponse messageInfo: invocation.getSelectedMessages())
							{
								Runnable sendAsUserRunnable = new Runnable()
								{

									@Override
									public void run()
									{
										BurpExtender.instance.getAuthorize().sendAsUser(p, messageInfo);
									}
							
								};
								
								(new Thread(sendAsUserRunnable)).start();
							}
							
						}
					});
					
					SendAsUserMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
