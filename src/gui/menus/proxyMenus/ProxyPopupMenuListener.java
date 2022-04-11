package gui.menus.proxyMenus;

import java.util.LinkedList;
import java.util.List;
import javax.swing.JMenuItem;
import javax.swing.event.PopupMenuEvent;

import authorize.messages.UserMessage;
import authorize.messages.ProxyMessage;
import authorize.user.User;
import burp.BurpExtender;
import gui.menus.commonMenus.MessageContextMenuInvocation;
import gui.menus.commonMenus.MessagePopupMenuListener;
import gui.menus.commonMenus.SendToComparerRequestMenu;
import gui.menus.commonMenus.SendToComparerResponseMenu;
import gui.menus.commonMenus.SendToIntruderMenu;
import gui.menus.commonMenus.SendToRepeaterMenu;
import gui.tabs.proxyTab.ProxyTable;
import gui.tabs.proxyTab.ProxyTableModel;

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
			
			if(invocation.getSelectedUser() != null)
			{
				menuItems.add(new RetestUserAuthorizationMenu(invocation.getSelectedMessage(), invocation.getSelectedUser()));
			}
			
			menuItems.add(new RetestEnforcementMenu(invocation.getSelectedMessage()));
			
			if(invocation.getSelectedUser() != null)
			{
				menuItems.add(new RetestUserEnforcementMenu(invocation.getSelectedMessage(), invocation.getSelectedUser()));
			}
			
			menuItems.add(new DeleteMessageMenu(invocation.getSelectedMessage()));
		}

		if(invocation.getSelectedMessages().size() > 1)
		{
			menuItems.add(new DeleteMessagesMenu(invocation.getSelectedMessages()));
		}
		
		if(invocation.getSelectedMessages().size() == 1)
		{
			if(invocation.getSelectedUser() != null)
			{
				menuItems.add(new DeleteUserMessageMenu(invocation.getSelectedMessage(), invocation.getSelectedUser()));
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
	protected boolean isUserColumn(int col)
	{
		return ProxyTableModel.isUserColumn(col);
	}

	@Override
	protected User getUserByColIndex(int col)
	{
		return ProxyTableModel.getUserByColIndex(col);
	}

	@Override
	protected boolean hasUserMessage(User user, int row)
	{
		int messageId = BurpExtender.instance.getView().getProxyTab().getTable().tableRowToMessageId(row);
		UserMessage userMessage = user.getMessage(messageId);
		if(userMessage != null)
		{
			return userMessage.getMessage() != null;
		}
		
		return false;
	}
	
}
