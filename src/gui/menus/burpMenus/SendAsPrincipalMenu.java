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
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class SendAsPrincipalMenu extends JMenu
{
	public static final String SEND_AS_PRINCIPAL_MENU = "Send As Principal";
	
	public SendAsPrincipalMenu(IContextMenuInvocation invocation)
	{
		this.setText(SEND_AS_PRINCIPAL_MENU);
		this.addMenuListener(new MenuListener()
		{
			@Override
			public void menuSelected(MenuEvent e)
			{
				SendAsPrincipalMenu.this.removeAll();
				
				for(Principal p: BurpExtender.instance.getAuthorize().getPrincipals().values())
				{
					JMenuItem item = new JMenuItem(p.getName());
					
					item.addActionListener(new ActionListener()
					{
						@Override
						public void actionPerformed(ActionEvent arg0)
						{
							for(IHttpRequestResponse messageInfo: invocation.getSelectedMessages())
							{
								Runnable sendAsPrincipalRunnable = new Runnable()
								{

									@Override
									public void run()
									{
										BurpExtender.instance.getAuthorize().sendAsPrincipal(p, messageInfo.getRequest(), messageInfo.getHttpService());
									}
							
								};
								
								(new Thread(sendAsPrincipalRunnable)).start();
							}
							
						}
					});
					
					SendAsPrincipalMenu.this.add(item);
				}
			}
			
			@Override
			public void menuCanceled(MenuEvent e){}

			@Override
			public void menuDeselected(MenuEvent e){}
			
		});
	}
}
