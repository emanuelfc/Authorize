package section;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;

import javax.swing.BoxLayout;
import javax.swing.JPanel;

@SuppressWarnings("serial")
public class Section extends JPanel
{
	private JPanel settingsPanel;
	private JPanel componentsPanel;
	
	public Section(String title, String description)
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.fill = GridBagConstraints.NONE;
		
		// Settings Buttons
		gbc.gridx = 0;
		gbc.gridy = 0;
		this.settingsPanel = new SectionSettings();
		//this.add(this.settingsPanel, gbc);
		
		gbc.weightx = 1;
		gbc.weighty = 1;
		
		// Section Components
		gbc.gridx = 1;
		gbc.gridy = 0;
		this.componentsPanel = new JPanel();
		this.componentsPanel.setLayout(new BoxLayout(this.componentsPanel, BoxLayout.Y_AXIS));
		this.add(this.componentsPanel, gbc);
		
		SectionLabel sectionLabel = new SectionLabel(title, description);
		this.addSectionComponent(sectionLabel);
	}
	
	public Section(String title)
	{
		this(title, null);
	}
	
	public void addSectionComponent(Component component)
	{
		this.componentsPanel.add(component);
	}
}
