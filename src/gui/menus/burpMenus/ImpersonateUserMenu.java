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

@SuppressWarnings("serial")
public class ImpersonateUserMenu extends JMenu
{
	public static final String IMPERSONATE_USER_MENU = "Impersonate User";
	
	public ImpersonateUserMenu(IContextMenuInvocation invocation)
	{
		this.setText(IMPERSONATE_USER_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				ImpersonateUserMenu.this.removeAll();
				
				User impersonatingUser = BurpExtender.instance.getAuthorize().getUserManager().getImpersonatingUser();
				
				JMenuItem item = new JMenuItem("None");
				
				item.addActionListener(new ActionListener()
				{
					@Override
					public void actionPerformed(ActionEvent arg0)
					{
						BurpExtender.instance.getAuthorize().getUserManager().setImpersonatingUser(null);
					}
				});
				
				ImpersonateUserMenu.this.add(item);
				
				for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
				{
					String name = p.getName();
					if(impersonatingUser != null && impersonatingUser.equals(p))
					{
						name = name + " " + "(Impersonating)";
					}
					item = new JMenuItem(name);
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							BurpExtender.instance.getAuthorize().getUserManager().setImpersonatingUser(p);
						}
					});
					
					ImpersonateUserMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
