package gui.menus.burpMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.AuthorizeUtils;
import authorize.user.PrivateInfo;
import authorize.user.User;
import burp.BurpExtender;
import burp.IContextMenuInvocation;

@SuppressWarnings("serial")
public class AddPrivateInformationMenu extends JMenu
{
	public static final String ADD_PRIVATE_INFO_MENU = "Add Private Info (Selection)";
	
	public AddPrivateInformationMenu(IContextMenuInvocation invocation)
	{
		this.setText(ADD_PRIVATE_INFO_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				AddPrivateInformationMenu.this.removeAll();
				
				for(User p: BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers())
				{
					JMenuItem item = new JMenuItem(p.getName());
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							String selectionString = AuthorizeUtils.extractStringSelection(invocation);
							if(selectionString != null)
							{
								PrivateInfo privateInfo = new PrivateInfo(selectionString, false, "Set From \"Set Session (Selection)\" Menu", true);
								p.addPrivateInfo(privateInfo);
							}
						}
					});
					
					AddPrivateInformationMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
