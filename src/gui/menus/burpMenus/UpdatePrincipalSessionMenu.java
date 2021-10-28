package gui.menus.burpMenus;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.principal.Principal;
import burp.BurpExtender;
import burp.IContextMenuInvocation;
import gui.menus.burpMenus.PrincipalSessionHandlersMenu.SessionHandlerAction;
import gui.menus.burpMenus.PrincipalSessionHandlersMenu.SessionManagerAction;

@SuppressWarnings("serial")
public class UpdatePrincipalSessionMenu extends JMenu
{
	public static final String UPDATE_PRINCIPAL_SESSION_MENU = "Update Session";
	
	public UpdatePrincipalSessionMenu(IContextMenuInvocation invocation)
	{
		this.setText(UPDATE_PRINCIPAL_SESSION_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				UpdatePrincipalSessionMenu.this.removeAll();
				
				for(Principal p: BurpExtender.instance.getAuthorize().getPrincipals().values())
				{
					SessionManagerAction managerAction = (sessionManager, message, invocation) -> {sessionManager.updateSession(message, invocation);};
					SessionHandlerAction handlerAction = (sessionHandler, message, invocation) -> {sessionHandler.updateSession(message, invocation);};
					JMenuItem item = new PrincipalSessionHandlersMenu(p.getSessionManager(), p.getName(), invocation, handlerAction, managerAction);
					
					UpdatePrincipalSessionMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}