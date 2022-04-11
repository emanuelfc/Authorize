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
public class UpdateUserSessionMenu extends JMenu
{
	public static final String UPDATE_USER_SESSION_MENU = "Update Session";
	
	public UpdateUserSessionMenu(IContextMenuInvocation invocation)
	{
		this.setText(UPDATE_USER_SESSION_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				UpdateUserSessionMenu.this.removeAll();
				
				for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
				{
					SessionManagerAction managerAction = (sessionManager, message, invocation) -> {sessionManager.updateSession(message, invocation);};
					SessionHandlerAction handlerAction = (sessionHandler, message, invocation) -> {sessionHandler.updateSession(message, invocation);};
					JMenuItem item = new UserSessionHandlersMenu(p.getSessionManager(), p.getName(), invocation, handlerAction, managerAction);
					
					UpdateUserSessionMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}