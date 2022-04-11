package gui.tabs.proxyTab;

import java.util.Date;
import javax.swing.table.AbstractTableModel;

import authorize.messages.UserMessage;
import authorize.types.EnforcementStatus;
import authorize.messages.ProxyMessage;
import authorize.user.User;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class ProxyTableModel extends AbstractTableModel
{
	private static String[] normalColumns = {"#", "Host", "Method", "URL", "Status", "Time"};
	private static Class<?>[] normalColumnTypes = {Integer.class, String.class, String.class, String.class, Short.class, Date.class};
	
	public static String STATUS_SEPARATOR = " - ";
	
	public ProxyTableModel()
	{
		
	}
	
	public Class<?> getColumnClass(int col)
	{
		if(!isUserColumn(col)) return normalColumnTypes[col];
		else return String.class;
	}
	
	public static boolean isUserColumn(int col)
	{
		return col >= normalColumns.length;
	}
	
	public static int columnToUserIndex(int col)
	{
		return col - normalColumns.length;
	}
	
	public static User getUserByColIndex(int col)
	{	
		return BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers().get(ProxyTableModel.columnToUserIndex(col));
	}
	
	public String getColumnName(int col)
	{
		if(!isUserColumn(col)) return normalColumns[col];
		else
		{
			return ProxyTableModel.getUserByColIndex(col).getName();
		}
	}

	@Override
	public int getColumnCount()
	{
		return normalColumns.length + BurpExtender.instance.getAuthorize().getUserManager().getOrderedUsers().size();
	}

	@Override
	public int getRowCount()
	{
		return BurpExtender.instance.getAuthorize().getMessages().size();
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(!isUserColumn(col))
		{
			return this.getValueAtNormalColumn(row, col);
		}
		else
		{
			return this.getValueAtUserColumn(row, col);
		}
	}
	
	public int modelRowToMessageId(int row)
	{
		return BurpExtender.instance.getAuthorize().getMessages().values().stream().skip(row).iterator().next().getId();
	}
	
	private Object getValueAtNormalColumn(int row, int col)
	{
		int messageId = this.modelRowToMessageId(row);
		
		ProxyMessage m = BurpExtender.instance.getAuthorize().getMessages().get(messageId);
		
		switch(col)
		{
			case 0:
				return m.getId();
				
			case 1:
				return m.getMessage().getHttpService().toString();
				
			case 2:
				return BurpExtender.helpers.analyzeRequest(m.getMessage()).getMethod();
				
			case 3:
				return BurpExtender.helpers.analyzeRequest(m.getMessage()).getUrl().getFile();
				
			case 4:
				return BurpExtender.helpers.analyzeResponse(m.getMessage().getResponse()).getStatusCode();
				
			case 5:
				return m.getTimestamp();
			
			default:
				throw new IllegalArgumentException("Invalid column for Message column = " + col);
		}
	}
	
	private String getValueAtUserColumn(int row, int col)
	{
		int messageId = this.modelRowToMessageId(row);
		UserMessage userMessage = getUserByColIndex(col).getMessage(messageId);
		
		if(userMessage != null)
		{
			IHttpRequestResponse messageInfo = userMessage.getMessage();
			
			if(messageInfo != null)
			{
				short statusCode = BurpExtender.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode();
				return String.valueOf(statusCode) + " - " + userMessage.getStatus().toString();
			}
			else return userMessage.getStatus().toString();
		}
		else
		{
			return EnforcementStatus.NO_MESSAGE.toString();
		}
	}
}
