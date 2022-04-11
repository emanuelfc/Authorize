package section;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.border.EmptyBorder;

@SuppressWarnings("serial")
public class SectionSettings extends JPanel
{
	private JButton helpButton;
	private JButton configButton;
	
	public SectionSettings()
	{
		super();
		
		this.setLayout(new GridBagLayout());
		this.setBorder(new EmptyBorder(0, 10, 0, 10));
		
		Dimension buttonsDimensions = new Dimension(20,20);
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = new Insets(0, 0, 5, 0);
		gbc.gridx = 0;
		gbc.gridy = this.getComponentCount();
		
		// Help Button
		helpButton = new JButton();
		helpButton.setMaximumSize(buttonsDimensions);
		helpButton.setPreferredSize(buttonsDimensions);
		helpButton.setIcon(null);

		gbc.gridy = this.getComponentCount();
		this.add(helpButton, gbc);
		
		// Config Button
		configButton = new JButton();
		configButton.setMaximumSize(buttonsDimensions);
		configButton.setPreferredSize(buttonsDimensions);
		configButton.setIcon(null);

		gbc.gridy = this.getComponentCount();
		gbc.insets.bottom = 0;
		this.add(configButton, gbc);
	}

}
