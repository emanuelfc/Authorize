package gui.menus;

import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import gui.menus.burpMenus.AddPrivateInformationMenu;
import gui.menus.burpMenus.ImpersonateUserMenu;
import gui.menus.burpMenus.MakeRequestAsUserMenu;
import gui.menus.burpMenus.SessionMenu;
import gui.menus.burpMenus.SendAsUserMenu;

public class AuthorizeMenu implements IContextMenuFactory
{
	public static final String AUTHORIZE_MENU = "Authorize";
	
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{
		JMenu authorizeMenu = new JMenu(AUTHORIZE_MENU);
		
		authorizeMenu.add(new SessionMenu(invocation));
		authorizeMenu.add(new MakeRequestAsUserMenu(invocation));
		authorizeMenu.add(new SendAsUserMenu(invocation));
		authorizeMenu.add(new ImpersonateUserMenu(invocation));
		authorizeMenu.add(new AddPrivateInformationMenu(invocation));
		
		List<JMenuItem> menuItems = new LinkedList<JMenuItem>();
		menuItems.add(authorizeMenu);
		
		return menuItems;
	}
	
}
