package gui.menus.burpMenus;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.user.User;
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import gui.menus.burpMenus.UserSessionHandlersMenu.SessionHandlerAction;
import gui.menus.burpMenus.UserSessionHandlersMenu.SessionManagerAction;

@SuppressWarnings("serial")
public class SetUserSessionMenu extends JMenu
{
	public static final String SET_USER_SESSION_MENU = "Set Session";
	
	public SetUserSessionMenu(IContextMenuInvocation invocation)
	{
		this.setText(SET_USER_SESSION_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				SetUserSessionMenu.this.removeAll();
				
				for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
				{
					SessionManagerAction managerAction = (sessionManager, message, invocation) -> {sessionManager.setSession(message, invocation);};
					SessionHandlerAction handlerAction = (sessionHandler, message, invocation) -> {sessionHandler.setSession(message, invocation);};
					JMenuItem item = new UserSessionHandlersMenu(p.getSessionManager(), p.getName(), invocation, handlerAction, managerAction);
					
					SetUserSessionMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}