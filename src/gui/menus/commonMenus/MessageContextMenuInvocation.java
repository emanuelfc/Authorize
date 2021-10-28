package gui.menus.commonMenus;

import java.util.List;
import authorize.messages.Message;
import authorize.principal.Principal;

public class MessageContextMenuInvocation<T extends Message>
{
	private T selectedMessage;
	private List<T> selectedMessages;
	private Principal selectedPrincipal;
	
	public MessageContextMenuInvocation(T selectedMessage, List<T> selectedMessages, Principal selectedPrincipal)
	{
		this.selectedMessage = selectedMessage;
		this.selectedMessages = selectedMessages;
		this.selectedPrincipal = selectedPrincipal;
	}
	
	public T getSelectedMessage()
	{
		return this.selectedMessage;
	}

	public List<T> getSelectedMessages()
	{
		return this.selectedMessages;
	}
	
	public Principal getSelectedPrincipal()
	{
		return this.selectedPrincipal;
	}
}
