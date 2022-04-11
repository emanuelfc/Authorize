package gui.renderers;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

@SuppressWarnings("serial")
public class ProxyDefaultTableCellRenderer extends DefaultTableCellRenderer
{
	public ProxyDefaultTableCellRenderer()
	{
		this.setOpaque(true);
		this.setHorizontalAlignment(LEFT);
		this.setVerticalAlignment(CENTER);
	}
	
	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int col)
	{
		Component renderer = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, col);
		
		renderer.setForeground(Color.WHITE);
		renderer.setBackground(new Color(60, 63, 65));
		
		if(isSelected)
		{
			renderer.setBackground(renderer.getBackground().darker());
		}
		
		return renderer;
	}
}
