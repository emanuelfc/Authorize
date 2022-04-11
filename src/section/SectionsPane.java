package section;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JPanel;

@SuppressWarnings("serial")
public class SectionsPane extends JPanel
{
	public SectionsPane()
	{
		super();
		
		this.setLayout(new GridBagLayout());
	}
	
	protected void addSection(Section section)
	{
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = new Insets(0, 0, 5, 0);
		gbc.gridx = 0;
		gbc.weightx = 1;
		gbc.weighty = 1;
		gbc.gridy = this.getComponentCount();
		
		this.add(section, gbc);
	}
}
