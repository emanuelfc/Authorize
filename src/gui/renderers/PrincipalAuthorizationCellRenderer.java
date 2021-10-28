package gui.renderers;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import authorize.types.EnforcementStatus;
import gui.tableModels.ProxyTableModel;

@SuppressWarnings("serial")
public class PrincipalAuthorizationCellRenderer extends DefaultTableCellRenderer
{
	public PrincipalAuthorizationCellRenderer()
	{
		this.setOpaque(true);
	}
	
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col)
	{
		Component renderer = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
		
		String[] statusParts = ((String)value).split(ProxyTableModel.STATUS_SEPARATOR);
		if(statusParts.length == 2)
		{
			String enforcementStatus = statusParts[1];
			
			switch(EnforcementStatus.getByName(enforcementStatus))
			{
				case AUTHORIZED:
					renderer.setBackground(Color.GREEN);
					break;
				
				case UNAUTHORIZED:
					renderer.setBackground(Color.RED);
					break;

				case UNKNOWN:
					renderer.setBackground(Color.YELLOW);
					break;
					
				case ACTING_USER:
					renderer.setBackground(new Color(51, 204, 255));
					break;
					
				case DISABLED:
					renderer.setBackground(Color.LIGHT_GRAY);
					break;
					
				case ERROR:
					renderer.setBackground(Color.LIGHT_GRAY);
					break;
				
				default:
					renderer.setBackground(Color.LIGHT_GRAY);
					break;
			}
		}
		else
		{
			renderer.setBackground(Color.LIGHT_GRAY);
		}
		
		return renderer;
	}
}
