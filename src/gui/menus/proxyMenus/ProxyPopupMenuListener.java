package gui.menus.proxyMenus;

import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.event.PopupMenuEvent;

import authorize.messages.PrincipalMessage;
import authorize.messages.ProxyMessage;
import authorize.principal.Principal;
import burp.BurpExtender;
import gui.menus.commonMenus.MessageContextMenuInvocation;
import gui.menus.commonMenus.MessagePopupMenuListener;
import gui.menus.commonMenus.SendToComparerRequestMenu;
import gui.menus.commonMenus.SendToComparerResponseMenu;
import gui.menus.commonMenus.SendToIntruderMenu;
import gui.menus.commonMenus.SendToRepeaterMenu;
import gui.tableModels.ProxyTableModel;
import gui.tables.ProxyTable;

public class ProxyPopupMenuListener extends MessagePopupMenuListener<ProxyMessage>
{
	public ProxyPopupMenuListener(ProxyTable proxyTable)
	{
		super(proxyTable);
	}
	
	public List<JMenuItem> createMenuItems(MessageContextMenuInvocation<ProxyMessage> invocation)
	{
		List<JMenuItem> menuItems = new LinkedList<JMenuItem>();
		
		if(invocation.getSelectedMessages().size() == 1)
		{
			menuItems.add(new RetestAuthorizationMenu(invocation.getSelectedMessage()));
			
			if(invocation.getSelectedPrincipal() != null)
			{
				menuItems.add(new RetestPrincipalAuthorizationMenu(invocation.getSelectedMessage(), invocation.getSelectedPrincipal()));
			}
			
			menuItems.add(new RetestEnforcementMenu(invocation.getSelectedMessage()));
			
			if(invocation.getSelectedPrincipal() != null)
			{
				menuItems.add(new RetestPrincipalEnforcementMenu(invocation.getSelectedMessage(), invocation.getSelectedPrincipal()));
			}
			
			menuItems.add(new DeleteMessageMenu(invocation.getSelectedMessage()));
		}

		if(invocation.getSelectedMessages().size() > 1)
		{
			menuItems.add(new DeleteMessagesMenu(invocation.getSelectedMessages()));
		}
		
		if(invocation.getSelectedMessages().size() == 1)
		{
			if(invocation.getSelectedPrincipal() != null)
			{
				menuItems.add(new DeletePrincipalMessageMenu(invocation.getSelectedMessage(), invocation.getSelectedPrincipal()));
			}
			
			if(invocation.getSelectedMessages().size() == 1)
			{
				menuItems.add(new SendToIntruderMenu(invocation.getSelectedMessage().getMessage()));
				menuItems.add(new SendToRepeaterMenu(invocation.getSelectedMessage().getMessage()));
				menuItems.add(new SendToComparerRequestMenu(invocation.getSelectedMessage().getMessage()));
				menuItems.add(new SendToComparerResponseMenu(invocation.getSelectedMessage().getMessage()));
			}
		}
	
		return menuItems;
	}

	@Override
	public void popupMenuWillBecomeInvisible(PopupMenuEvent e){}

	@Override
	public void popupMenuCanceled(PopupMenuEvent e){}

	@Override
	protected ProxyMessage getMessage(int row)
	{
		int messageId = BurpExtender.instance.getView().getProxyTab().getTable().tableRowToMessageId(row);
		ProxyMessage selectedMessage = BurpExtender.instance.getAuthorize().getMessages().get(messageId);
		return selectedMessage;
	}
	
	@Override
	protected boolean isPrincipalColumn(int col)
	{
		return ProxyTableModel.isPrincipalColumn(col);
	}

	@Override
	protected Principal getPrincipalByColIndex(int col)
	{
		return ProxyTableModel.getPrincipalByColIndex(col);
	}

	@Override
	protected boolean hasPrincipalMessage(Principal principal, int row)
	{
		int messageId = BurpExtender.instance.getView().getProxyTab().getTable().tableRowToMessageId(row);
		PrincipalMessage principalMessage = principal.getMessage(messageId);
		if(principalMessage != null)
		{
			return principalMessage.getMessage() != null;
		}
		
		return false;
	}
	
}
