package gui.menus.burpMenus;

import javax.swing.JMenu;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.AuthorizeUtils;
import authorize.user.User;
import burp.BurpExtender;
import burp.IContextMenuInvocation;

@SuppressWarnings("serial")
public class SetUserSessionFromSelectionMenu extends JMenu
{
	public static final String SET_USER_SESSION_MENU = "Set Session (Selection)";
	
	public SetUserSessionFromSelectionMenu(IContextMenuInvocation invocation)
	{
		this.setText(SET_USER_SESSION_MENU);
		String selection = AuthorizeUtils.extractStringSelection(invocation);
		if(selection != null)
		{
			this.addMenuListener(new MenuListener()
			{
				@Override
				public void menuSelected(MenuEvent e)
				{
					SetUserSessionFromSelectionMenu.this.removeAll();
					
					for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
					{
						SetUserSessionFromSelectionMenu.this.add(new UserSessionFromSelectionMenu(p, selection));
					}
				}
				
				@Override
				public void menuCanceled(MenuEvent e){}

				@Override
				public void menuDeselected(MenuEvent e){}
				
			});
		}
	}
}