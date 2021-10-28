package gui.menus.burpMenus;

import javax.swing.JMenu;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.AuthorizeUtils;
import authorize.principal.Principal;
import burp.BurpExtender;
import burp.IContextMenuInvocation;

@SuppressWarnings("serial")
public class SetPrincipalSessionFromSelectionMenu extends JMenu
{
	public static final String SET_PRINCIPAL_SESSION_MENU = "Set Session (Selection)";
	
	public SetPrincipalSessionFromSelectionMenu(IContextMenuInvocation invocation)
	{
		this.setText(SET_PRINCIPAL_SESSION_MENU);
		String selection = AuthorizeUtils.extractStringSelection(invocation);
		if(selection != null)
		{
			this.addMenuListener(new MenuListener()
			{
				@Override
				public void menuSelected(MenuEvent e)
				{
					SetPrincipalSessionFromSelectionMenu.this.removeAll();
					
					for(Principal p: BurpExtender.instance.getAuthorize().getPrincipals().values())
					{
						SetPrincipalSessionFromSelectionMenu.this.add(new PrincipalSessionFromSelectionMenu(p, selection));
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