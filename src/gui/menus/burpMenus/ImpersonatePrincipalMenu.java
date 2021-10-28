package gui.menus.burpMenus;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.event.MenuEvent;
import javax.swing.event.MenuListener;

import authorize.principal.Principal;
import burp.BurpExtender;
import burp.IContextMenuInvocation;

@SuppressWarnings("serial")
public class ImpersonatePrincipalMenu extends JMenu
{
	public static final String IMPERSONATE_PRINCIPAL_MENU = "Impersonate Principal";
	
	public ImpersonatePrincipalMenu(IContextMenuInvocation invocation)
	{
		this.setText(IMPERSONATE_PRINCIPAL_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				ImpersonatePrincipalMenu.this.removeAll();
				
				Principal impersonatingPrincipal = BurpExtender.instance.getAuthorize().getImpersonatingPrincipal();
				
				JMenuItem item = new JMenuItem("None");
				
				item.addActionListener(new ActionListener()
				{
					@Override
					public void actionPerformed(ActionEvent arg0)
					{
						BurpExtender.instance.getAuthorize().setImpersonatingPrincipal(null);
					}
				});
				
				ImpersonatePrincipalMenu.this.add(item);
				
				for(Principal p: BurpExtender.instance.getAuthorize().getPrincipals().values())
				{
					String name = p.getName();
					if(impersonatingPrincipal != null && impersonatingPrincipal.equals(p))
					{
						name = name + " " + "(Impersonating)";
					}
					item = new JMenuItem(name);
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							BurpExtender.instance.getAuthorize().setImpersonatingPrincipal(p);
						}
					});
					
					ImpersonatePrincipalMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
