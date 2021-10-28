package gui.renderers;

import java.awt.Component;
import java.util.Map.Entry;

import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.ListCellRenderer;

import authorize.enforcement.SimilarityStrategy;

@SuppressWarnings("serial")
public class SimilarityStrategyListRenderer extends JLabel implements ListCellRenderer<Entry<String, SimilarityStrategy>>
{
	public SimilarityStrategyListRenderer()
	{
		super();
		super.setOpaque(true);
	}

	@Override
	public Component getListCellRendererComponent(JList<? extends Entry<String, SimilarityStrategy>> list, Entry<String, SimilarityStrategy> value, int index, boolean isSelected, boolean cellHasFocus)
	{
		if(isSelected)
		{
			setBackground(list.getSelectionBackground());
			setForeground(list.getSelectionForeground());
		}
		else
		{
			setBackground(list.getBackground());
			setForeground(list.getForeground());
		}
		
		setFont(list.getFont());
		
		setText((value == null) ? "" : value.getKey());
		
		return this;
	}

}
