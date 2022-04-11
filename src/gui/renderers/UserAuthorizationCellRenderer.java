package gui.renderers;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import authorize.messages.UserMessage;
import authorize.user.User;
import gui.tabs.proxyTab.ProxyTable;
import gui.tabs.proxyTab.ProxyTableModel;

@SuppressWarnings("serial")
public class UserAuthorizationCellRenderer extends DefaultTableCellRenderer
{
	private ProxyTable proxyTable;
	
	public UserAuthorizationCellRenderer(ProxyTable proxyTable)
	{
		super();
		
		this.setOpaque(true);
		this.setHorizontalAlignment(LEFT);
		this.setVerticalAlignment(CENTER);
		
		this.proxyTable = proxyTable;
	}
	
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col)
	{
		Component renderer = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
		
		renderer.setForeground(Color.WHITE);
		renderer.setBackground(new Color(60, 63, 65));
		
		if(ProxyTableModel.isUserColumn(col))
		{
			User user = ProxyTableModel.getUserByColIndex(col);
			UserMessage userMessage = user.getMessage(this.proxyTable.tableRowToMessageId(row));
			
			if(userMessage != null)
			{
				renderer.setForeground(Color.BLACK);
				
				switch(userMessage.getStatus())
				{
					case AUTHORIZED:
					case AUTHORIZED_CONTAINS_PRIVATE_INFO:
					case AUTHORIZED_SIMILAR_CONTENT:
					case AUTHORIZED_EQUAL_CONTENT:
						renderer.setBackground(new Color(100, 255, 100));
						//renderer.setBackground(Color.GREEN);
						break;
					
					case UNAUTHORIZED:
					case UNAUTHORIZED_BY_ENFORCEMENT_RULE:
					case UNAUTHORIZED_NOT_ACCEPTABLE_SIMILAR_CONTENT:
						renderer.setBackground(new Color(255, 100, 100));
						//renderer.setBackground(Color.RED);
						break;

					case UNKNOWN:
						renderer.setBackground(new Color(255, 255, 100));
						//renderer.setBackground(Color.YELLOW);
						break;
						
					case ACTING_USER:
						renderer.setBackground(new Color(51, 204, 255));
						//renderer.setBackground(Color.BLUE);
						break;
						
					case DISABLED:
						renderer.setBackground(new Color(180, 180, 180));
						//renderer.setBackground(Color.LIGHT_GRAY);
						break;
						
					case ERROR:
						renderer.setBackground(new Color(180, 180, 180));
						//renderer.setBackground(Color.LIGHT_GRAY);
						break;
					
					default:
						renderer.setForeground(Color.WHITE);
						renderer.setBackground(new Color(60, 63, 65));
						//renderer.setBackground(Color.LIGHT_GRAY);
						break;
				}
			}
		}
		
		if(isSelected)
		{
			renderer.setBackground(renderer.getBackground().darker());
		}
		
		return renderer;
	}
}
