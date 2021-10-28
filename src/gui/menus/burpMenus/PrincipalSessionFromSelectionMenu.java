package gui.menus.burpMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.principal.Principal;
import authorize.sessionManagement.SessionHandler;

@SuppressWarnings("serial")
public class PrincipalSessionFromSelectionMenu extends JMenu
{
	public PrincipalSessionFromSelectionMenu(Principal principal, String info)
	{
		this.setText(principal.getName());
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				PrincipalSessionFromSelectionMenu.this.removeAll();
				
				for(SessionHandler sessionHandler: principal.getSessionManager().getSessionHandlers())
				{
					JMenuItem item = new JMenuItem(sessionHandler.getDescription());
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							sessionHandler.setSession(info);
						}
					});
					
					PrincipalSessionFromSelectionMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
