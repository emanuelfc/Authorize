package gui.tabs.configTab;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.List;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JToggleButton;
import javax.swing.border.EmptyBorder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.filechooser.FileFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import authorize.Authorize;
import authorize.interception.MatchRule;
import authorize.types.MatchType;
import burp.BurpExtender;
import gui.ContentSimilarityPanel;
import gui.tabs.MatchRuleControllerPanel;
import gui.tabs.MatchTableModel;
import section.Section;
import serialization.AuthorizeSerializer;

@SuppressWarnings("serial")
public class ConfigurationTab extends JScrollPane implements ChangeListener
{
	public static final String AUTHORIZE_ON_BUTTON_TEXT = "Authorize is On";
	public static final String AUTHORIZE_OFF_BUTTON_TEXT = "Authorize is Off";
	
	private InterceptionControllerPanel interceptionControllerPanel;
	private ContentSimilarityPanel contentSimilarityPanel;
	
	public ConfigurationTab()
	{
		super();
		
		this.setName("Configuration");
		
		JPanel configPanel = new JPanel();
		this.setViewportView(configPanel);
		configPanel.setBorder(new EmptyBorder(20, 45, 10, 30));
		configPanel.setLayout(new GridBagLayout());
		configPanel.setAlignmentX(LEFT_ALIGNMENT);
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(0, 0, 15, 0);
		gbc.anchor = GridBagConstraints.WEST;
		
		gbc.gridx = 0;
		configPanel.add(this.createToggleButton(), gbc);
		
		gbc.gridx = 1;
		configPanel.add(this.createImportConfigButton(), gbc);
		
		gbc.gridx = 2;
		configPanel.add(this.createExportConfigButton(), gbc);
		
		gbc.insets = new Insets(0, 0, 10, 0);
		
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.weightx = 1;
		gbc.weighty = 1;
		
		Section globalModifiersSection = new Section("Global Modifier Rules", "Global Modifiers applies to ALL HTTP messages.");
		globalModifiersSection.addSectionComponent(new GlobalModifierRulesControllerPanel());
		configPanel.add(globalModifiersSection, gbc);
		
		gbc.gridy = 2;
		MatchType[] enforcementMatchTypes = {MatchType.RESPONSE, MatchType.RESPONSE_BODY, MatchType.RESPONSE_HEADER, MatchType.STATUS_CODE};
		
		
		MatchRuleControllerPanel enforcementControllerPanel = new MatchRuleControllerPanel(new MatchTableModel()
				{

					@Override
					protected MatchRule getEntry(int row, int col)
					{
						return BurpExtender.instance.getAuthorize().getEnforcementManager().getEnforcementRules().get(row);
					}

					@Override
					public int getRowCount()
					{
						return BurpExtender.instance.getAuthorize().getEnforcementManager().getEnforcementRules().size();
					}
			
				},
				enforcementMatchTypes)
				{
		
					@Override
					protected List<MatchRule> getEntries()
					{
						return BurpExtender.instance.getAuthorize().getEnforcementManager().getEnforcementRules();
					}
					
					@Override
					protected boolean addMatchRule(MatchRule matchRule)
					{
						return BurpExtender.instance.getAuthorize().getEnforcementManager().addRule(matchRule);
					}
		
					@Override
					protected boolean removeAction(ActionEvent e)
					{
						if(BurpExtender.instance.getAuthorize().getEnforcementManager().removeRule(this.selection))
						{
							this.tableModel.fireTableDataChanged();
							return true;
						}
						
						return false;
					}
		
				};
		
		gbc.gridheight = 1;
		gbc.gridwidth = 2;
		Section enforcementControllerSection = new Section("Enforcement Rules");
		enforcementControllerSection.addSectionComponent(enforcementControllerPanel);
		configPanel.add(enforcementControllerSection, gbc);
		
		gbc.gridy = 3;
		Section interceptionControllerSection = new Section("Interception Rules", "Interception Rules specify which requests, and Burp Suite Tool, will be intercepted by Authorize.");
		this.interceptionControllerPanel = new InterceptionControllerPanel();
		interceptionControllerSection.addSectionComponent(this.interceptionControllerPanel);
		configPanel.add(interceptionControllerSection, gbc);
		
		gbc.gridy = 4;
		String CONTENT_SIMILARITY_PANEL_DESCRIPTION = ""
				+ "This rule specifies how to compare the response bodies (the content) of the Base Request and User Request.\n"
				+ "While their responses might not be equal, they might share a lot of similarities between them, including "
				+ "restricted information within the unauthorized User Response and the authorized one.\n"
				+ "A naive approach would be to simply compare both responses, and assume that if they are not entirely equal then there wasn't "
				+ "any breach of the Authorization and Access Control Policies.\n"
				+ "This rule aims at allowing the user to evaluate the Enforcement Status of the request based of a Similarity Score - "
				+ "A Score ranging from 0% to 100% describing how similar the responses are.\n"
				+ "\n"
				+ "Authorized Score - If the Similarity Score is greater than or equal to this value, classify the Enforcement Status as Authorized.\n"
				+ "Unauthorized Score - If the Similarity Score is less than or equal to this value, classify the Enforcement Status as Unauthorized.\n"
				+ "If the Similarity Score falls between the two ranges, no decision can be made within our confidence values, therefore classify the Enforcement Status as Unknown.\n"
				+ "\n"
				+ "The default algorithm is Equals.";
		Section contentSimilaritySection = new Section("Content Similarity", CONTENT_SIMILARITY_PANEL_DESCRIPTION);
		this.contentSimilarityPanel = new ContentSimilarityPanel();
		contentSimilaritySection.addSectionComponent(this.contentSimilarityPanel);
		gbc.weightx = 0;
		gbc.weighty = 0;
		configPanel.add(contentSimilaritySection, gbc);
	}
	
	private JButton createImportConfigButton()
	{
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		
		JButton importConfigButton = new JButton("Import Config.");
		importConfigButton.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				int res = fileChooser.showOpenDialog(ConfigurationTab.this);
				
				if(res == JFileChooser.APPROVE_OPTION)
				{
					try
					{
						ObjectMapper objectMapper = new ObjectMapper();
						Authorize authorize = objectMapper.readValue(fileChooser.getSelectedFile(), Authorize.class);
						BurpExtender.instance.setAuthorize(authorize);
						JOptionPane.showMessageDialog(null, "Import successful!");
					}
					catch(IOException e1)
					{
						// Auto-generated catch block
						e1.printStackTrace();
						JOptionPane.showMessageDialog(null, "Import failed!");
					}
					
				}
				
			}
			
		});
		
		return importConfigButton;
	}
	
	private JButton createExportConfigButton()
	{
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
		
		fileChooser.addChoosableFileFilter(new FileFilter()
		{
			@Override
			public String getDescription()
			{
				return "JSON or Text Files";
			}
			
			@Override
			public boolean accept(File f)
			{
				if(f.isDirectory()) return false;
				else
				{
					String filename = f.getName().toLowerCase();
					return filename.endsWith(".json") || filename.endsWith(".txt");
				}
			}
		});
		
		JButton exportConfigButton = new JButton("Export Config.");
		exportConfigButton.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				int res = fileChooser.showSaveDialog(ConfigurationTab.this);
				
				if(res == JFileChooser.APPROVE_OPTION)
				{					
					try(FileWriter fileWriter = new FileWriter(fileChooser.getSelectedFile()))
					{
						fileWriter.write(AuthorizeSerializer.serializeAuthorize(AuthorizeSerializer.createSerializer()));
						JOptionPane.showMessageDialog(null, "Export successfully completed!");
					}
					catch(IOException e1)
					{
						e1.printStackTrace();
						JOptionPane.showMessageDialog(null, "Export failed!");
					}
				}
				
			}
			
		});
		
		return exportConfigButton;
	}
	
	private JToggleButton createToggleButton()
	{
		String buttonText = BurpExtender.instance.getAuthorize().isEnabled() ? AUTHORIZE_ON_BUTTON_TEXT : AUTHORIZE_OFF_BUTTON_TEXT;
		
		JToggleButton authorizeEnabledButton = new JToggleButton(buttonText, BurpExtender.instance.getAuthorize().isEnabled());
		authorizeEnabledButton.addActionListener(new ActionListener()
		{

			@Override
			public void actionPerformed(ActionEvent e)
			{
				BurpExtender.instance.getAuthorize().toggleEnable();
			}
			
		});
		authorizeEnabledButton.addChangeListener(new ChangeListener()
		{

			@Override
			public void stateChanged(ChangeEvent e)
			{
				if(authorizeEnabledButton.isSelected())
				{
					authorizeEnabledButton.setText(AUTHORIZE_ON_BUTTON_TEXT);
				}
				else
				{
					authorizeEnabledButton.setText(AUTHORIZE_OFF_BUTTON_TEXT);
				}
				
			}
			
		});
		
		return authorizeEnabledButton;
	}

	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.interceptionControllerPanel.stateChanged(e);
		this.contentSimilarityPanel.stateChanged(e);
	}
}
