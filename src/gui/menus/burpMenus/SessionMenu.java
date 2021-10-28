package gui.menus.burpMenus;

import javax.swing.JMenu;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import burp.IContextMenuInvocation;

@SuppressWarnings("serial")
public class SessionMenu extends JMenu
{
	public static final String PRINCIPAL_SESSION_MENU = "Session";
	
	public SessionMenu(IContextMenuInvocation invocation)
	{
		this.setText(PRINCIPAL_SESSION_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				SessionMenu.this.removeAll();
				
				SessionMenu.this.add(new SetPrincipalSessionMenu(invocation));
				SessionMenu.this.add(new SetPrincipalSessionFromSelectionMenu(invocation));
				SessionMenu.this.add(new UpdatePrincipalSessionMenu(invocation));
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}