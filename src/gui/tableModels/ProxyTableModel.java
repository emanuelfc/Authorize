package gui.tableModels;

import java.util.Date;
import java.util.Iterator;
import javax.swing.table.AbstractTableModel;

import authorize.messages.PrincipalMessage;
import authorize.messages.ProxyMessage;
import authorize.principal.Principal;
import authorize.types.EnforcementStatus;
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
		if(!isPrincipalColumn(col)) return normalColumnTypes[col];
		else return String.class;
	}
	
	public static boolean isPrincipalColumn(int col)
	{
		return col >= normalColumns.length;
	}
	
	public static int columnToPrincipalIndex(int col)
	{
		return col - normalColumns.length;
	}
	
	public static Principal getPrincipalByColIndex(int col)
	{
		Iterator<Principal> iterPrincipals = BurpExtender.instance.getAuthorize().getPrincipals().values().iterator();
		int i = columnToPrincipalIndex(col);
		while(i-- > 0)
		{
			iterPrincipals.next();
		}
		
		return iterPrincipals.next();
	}
	
	public String getColumnName(int col)
	{
		if(!isPrincipalColumn(col)) return normalColumns[col];
		else
		{
			return ProxyTableModel.getPrincipalByColIndex(col).getName();
		}
	}

	@Override
	public int getColumnCount()
	{
		return normalColumns.length + BurpExtender.instance.getAuthorize().getPrincipals().size();
	}

	@Override
	public int getRowCount()
	{
		return BurpExtender.instance.getAuthorize().getMessages().size();
	}

	@Override
	public Object getValueAt(int row, int col)
	{
		if(!isPrincipalColumn(col))
		{
			return this.getValueAtNormalColumn(row, col);
		}
		else
		{
			return this.getValueAtPrincipalColumn(row, col);
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
	
	private String getValueAtPrincipalColumn(int row, int col)
	{
		int messageId = this.modelRowToMessageId(row);
		PrincipalMessage principalMessage = getPrincipalByColIndex(col).getMessage(messageId);
		
		if(principalMessage != null)
		{
			IHttpRequestResponse messageInfo = principalMessage.getMessage();
			
			if(messageInfo != null)
			{
				short statusCode = BurpExtender.helpers.analyzeResponse(messageInfo.getResponse()).getStatusCode();
				return statusCode + STATUS_SEPARATOR + principalMessage.getStatus().toString();
			}
			else return principalMessage.getStatus().toString();
		}
		else return EnforcementStatus.NO_MESSAGE.toString();
	}
}
