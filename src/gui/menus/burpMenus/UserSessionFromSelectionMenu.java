package gui.menus.burpMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.sessionManagement.SessionHandler;
import authorize.user.User;

@SuppressWarnings("serial")
public class UserSessionFromSelectionMenu extends JMenu
{
	public UserSessionFromSelectionMenu(User user, String info)
	{
		this.setText(user.getName());
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				UserSessionFromSelectionMenu.this.removeAll();
				
				for(SessionHandler sessionHandler: user.getSessionManager().getSessionHandlers())
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
					
					UserSessionFromSelectionMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
