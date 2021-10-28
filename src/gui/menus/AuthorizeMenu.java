package gui.menus;

import java.util.LinkedList;
import java.util.List;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import gui.menus.burpMenus.AddPrivateInformationMenu;
import gui.menus.burpMenus.ImpersonatePrincipalMenu;
import gui.menus.burpMenus.MakeRequestAsPrincipalMenu;
import gui.menus.burpMenus.SessionMenu;
import gui.menus.burpMenus.SendAsPrincipalMenu;
import gui.menus.testsMenus.CreateTestFromRequestMenu;

public class AuthorizeMenu implements IContextMenuFactory
{
	public static final String AUTHORIZE_MENU = "Authorize";
	
	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{
		JMenu authorizeMenu = new JMenu(AUTHORIZE_MENU);
		
		authorizeMenu.add(new SessionMenu(invocation));
		authorizeMenu.add(new MakeRequestAsPrincipalMenu(invocation));
		authorizeMenu.add(new SendAsPrincipalMenu(invocation));
		authorizeMenu.add(new ImpersonatePrincipalMenu(invocation));
		authorizeMenu.add(new AddPrivateInformationMenu(invocation));
		
		authorizeMenu.add(new CreateTestFromRequestMenu(invocation));
		
		List<JMenuItem> menuItems = new LinkedList<JMenuItem>();
		menuItems.add(authorizeMenu);
		
		return menuItems;
	}
	
}
