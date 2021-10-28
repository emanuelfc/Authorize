package gui.tableModels;

import java.util.Date;
import java.util.Iterator;
import javax.swing.table.AbstractTableModel;

import authorize.messages.PrincipalMessage;
import authorize.messages.TestMessage;
import authorize.principal.Principal;
import authorize.types.EnforcementStatus;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

@SuppressWarnings("serial")
public class TestsTableModel extends AbstractTableModel
{
	private static String[] normalColumns = {"Test Name", "Host", "Method", "URL", "Status", "Last Test Date"};
	private static Class<?>[] normalColumnTypes = {String.class, String.class, String.class, String.class, Short.class, Date.class};
	
	public static String STATUS_SEPARATOR = " - ";
	
	public TestsTableModel()
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
			return TestsTableModel.getPrincipalByColIndex(col).getName();
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
		return BurpExtender.instance.getAuthorize().getTests().size();
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
	
	private Object getValueAtNormalColumn(int row, int col)
	{
		TestMessage m = this.getTestMessage(row);
		
		switch(col)
		{
			case 0:
				return m.getTestName();
				
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
	
	private TestMessage getTestMessage(int row)
	{
		return BurpExtender.instance.getAuthorize().getTests().get(row);
	}
	
	private String getValueAtPrincipalColumn(int row, int col)
	{
		TestMessage testMessage = this.getTestMessage(row);
		
		PrincipalMessage principalMessage = testMessage.getPrincipalMessage(getPrincipalByColIndex(col).getName());
		
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
	
	@Override
	public boolean isCellEditable(int row, int col)
	{
		return col == 0;
	}
	
	@Override
	public void setValueAt(Object val, int row, int col)
	{
		int index = row;
		
		TestMessage m = BurpExtender.instance.getAuthorize().getTests().get(index);
		
		if(m != null) m.setTestName((String) val);
	}
}
