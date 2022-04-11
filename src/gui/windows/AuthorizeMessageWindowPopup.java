package gui.windows;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import gui.tabs.proxyTab.ProxyTable;
import gui.tabs.proxyTab.ProxyTableModel;

public class AuthorizeMessageWindowPopup implements MouseListener
{
	private ProxyTable authTable;
	
	public AuthorizeMessageWindowPopup(ProxyTable authTable)
	{
		this.authTable = authTable;
	}

	@Override
	public void mouseClicked(MouseEvent e)
	{
		if(e.getClickCount() == 2)
		{
			IHttpRequestResponse messageInfo = null;
			
			int messageId = this.authTable.tableRowToMessageId(this.authTable.getSelectedRow());
			
			if(ProxyTableModel.isUserColumn(this.authTable.getSelectedColumn()))
			{
				messageInfo = ProxyTableModel.getUserByColIndex(this.authTable.getSelectedColumn()).getMessage(messageId).getMessage();
			}
			else
			{
				messageInfo = BurpExtender.instance.getAuthorize().getMessages().get(messageId).getMessage();
			}
			
			AuthorizationMessageWindow messageWindow = new AuthorizationMessageWindow(messageInfo);
			messageWindow.setVisible(true);
		}
	}

	@Override
	public void mousePressed(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseReleased(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseEntered(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}

	@Override
	public void mouseExited(MouseEvent e)
	{
		// TODO Auto-generated method stub
	}
}
