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
public class PrincipalSessionHandlersMenu extends JMenu
{
	public PrincipalSessionHandlersMenu(SessionManager principalSessionManager, String principalName, IContextMenuInvocation invocation, SessionHandlerAction handlerAction, SessionManagerAction managerAction)
	{
		this.setText(principalName);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				PrincipalSessionHandlersMenu.this.removeAll();

				JMenuItem item = new JMenuItem("All Session Handlers (Enabled)");
				item.addActionListener(new ActionListener()
				{
					@Override
					public void actionPerformed(ActionEvent arg0)
					{
						for(IHttpRequestResponse messageInfo: invocation.getSelectedMessages())
						{
							managerAction.sessionAction(principalSessionManager, messageInfo, invocation.getInvocationContext());
						}
					}
				});
				PrincipalSessionHandlersMenu.this.add(item);
				
				for(SessionHandler sessionHandler: principalSessionManager.getSessionHandlers())
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
					
					PrincipalSessionHandlersMenu.this.add(item);
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
		public void sessionAction(SessionManager principalsessionManager, IHttpRequestResponse messageInfo, byte invocationContext);
	}
	
	public interface SessionHandlerAction
	{
		public void sessionAction(SessionHandler sessionHandler, IHttpRequestResponse messageInfo, byte invocationContext);
	}
}
