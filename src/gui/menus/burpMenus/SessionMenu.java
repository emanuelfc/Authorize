package gui.menus.burpMenus;

import javax.swing.JMenu;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import burp.IContextMenuInvocation;

@SuppressWarnings("serial")
public class SessionMenu extends JMenu
{
	public static final String USER_SESSION_MENU = "Session";
	
	public SessionMenu(IContextMenuInvocation invocation)
	{
		this.setText(USER_SESSION_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				SessionMenu.this.removeAll();
				
				SessionMenu.this.add(new SetUserSessionMenu(invocation));
				SessionMenu.this.add(new SetUserSessionFromSelectionMenu(invocation));
				SessionMenu.this.add(new UpdateUserSessionMenu(invocation));
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}