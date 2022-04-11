package section;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import gui.utils.BurpLabel;

@SuppressWarnings("serial")
public class SectionLabel extends JPanel
{
	private final Insets DEFAULT_INSETS = new Insets(0, 0, 16, 0);
	private final Insets FIX_INSETS_BETWEEN_TITLE_DESCRIPTION = new Insets(0, 0, 9, 0);
	private final Insets DESCRIPTION_INSETS = new Insets(0, 0, 14, 0);
	
	public SectionLabel(String title, String description)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.insets = this.DEFAULT_INSETS;
		
		gbc.weightx = 1;
		gbc.weighty = 0;
		
		// Title
		gbc.gridx = 0;
		gbc.gridy = 0;
		BurpLabel tableLabel = new BurpLabel(title);
		
		if(description != null && !description.isBlank())
		{
			gbc.insets = this.FIX_INSETS_BETWEEN_TITLE_DESCRIPTION;
		}
		
		this.add(tableLabel, gbc);	
		
		// Description
		if(description != null && !description.isBlank())
		{
			JTextArea descriptionLabel = new JTextArea(description);
			descriptionLabel.setWrapStyleWord(true);
			descriptionLabel.setLineWrap(true);
			descriptionLabel.setOpaque(false);
			descriptionLabel.setEditable(false);
			descriptionLabel.setFocusable(false);
			descriptionLabel.setColumns(80);
			gbc.gridx = 0;
			gbc.gridy = 1;
			gbc.insets = this.DESCRIPTION_INSETS;
			this.add(descriptionLabel, gbc);
		}
	}
}
