package gui.menus.commonMenus;

import java.util.List;
import authorize.messages.Message;
import authorize.user.User;

public class MessageContextMenuInvocation<T extends Message>
{
	private T selectedMessage;
	private List<T> selectedMessages;
	private User selectedUser;
	
	public MessageContextMenuInvocation(T selectedMessage, List<T> selectedMessages, User selectedUser)
	{
		this.selectedMessage = selectedMessage;
		this.selectedMessages = selectedMessages;
		this.selectedUser = selectedUser;
	}
	
	public T getSelectedMessage()
	{
		return this.selectedMessage;
	}

	public List<T> getSelectedMessages()
	{
		return this.selectedMessages;
	}
	
	public User getSelectedUser()
	{
		return this.selectedUser;
	}
}
