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
public class MakeRequestAsUserMenu extends JMenu
{
	public static final String MAKE_INTERCEPTED_REQUEST_AS_USER_MENU = "Make Request As User";
	
	public MakeRequestAsUserMenu(IContextMenuInvocation invocation)
	{
		this.setText(MAKE_INTERCEPTED_REQUEST_AS_USER_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				MakeRequestAsUserMenu.this.removeAll();
				
				for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
				{
					JMenuItem item = new JMenuItem(p.getName());
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							if(invocation.getInvocationContext() == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
							{
								for(IHttpRequestResponse interceptedMessageInfo: invocation.getSelectedMessages())
								{
									if(interceptedMessageInfo.getResponse() == null)
									{
										p.buildRequest(interceptedMessageInfo);
									}
								}
							}
						}
					});
					
					MakeRequestAsUserMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
