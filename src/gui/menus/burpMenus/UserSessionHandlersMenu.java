package gui.menus.burpMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.sessionManagement.SessionHandler;
import authorize.sessionManagement.SessionManager;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class UserSessionHandlersMenu extends JMenu
{
	public UserSessionHandlersMenu(SessionManager userSessionManager, String userName, IContextMenuInvocation invocation, SessionHandlerAction handlerAction, SessionManagerAction managerAction)
	{
		this.setText(userName);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				UserSessionHandlersMenu.this.removeAll();

				JMenuItem item = new JMenuItem("All Session Handlers (Enabled)");
				item.addActionListener(new ActionListener()
				{
					@Override
					public void actionPerformed(ActionEvent arg0)
					{
						for(IHttpRequestResponse messageInfo: invocation.getSelectedMessages())
						{
							managerAction.sessionAction(userSessionManager, messageInfo, invocation.getInvocationContext());
						}
					}
				});
				UserSessionHandlersMenu.this.add(item);
				
				for(SessionHandler sessionHandler: userSessionManager.getSessionHandlers())
				{
					item = new JMenuItem(sessionHandler.getDescription());
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							for(IHttpRequestResponse messageInfo: invocation.getSelectedMessages())
							{
								handlerAction.sessionAction(sessionHandler, messageInfo, invocation.getInvocationContext());
							}
						}
					});
					
					UserSessionHandlersMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
	
	public interface SessionManagerAction
	{
		public void sessionAction(SessionManager usersessionManager, IHttpRequestResponse messageInfo, byte invocationContext);
	}
	
	public interface SessionHandlerAction
	{
		public void sessionAction(SessionHandler sessionHandler, IHttpRequestResponse messageInfo, byte invocationContext);
	}
}
