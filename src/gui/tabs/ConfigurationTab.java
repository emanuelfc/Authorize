package gui.tabs;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
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
import authorize.types.MatchType;
import burp.BurpExtender;
import gui.ContentSimilarityPanel;
import gui.controllerPanels.GlobalModifierRulesControllerPanel;
import gui.controllerPanels.InterceptionControllerPanel;
import gui.controllerPanels.MatchRuleControllerPanel;
import serialization.AuthorizeSerializer;

@SuppressWarnings("serial")
public class ConfigurationTab extends JScrollPane implements ChangeListener
{
	public static final String CONFIGURATION_TAB_NAME = "Configuration";
	
	public static final String AUTHORIZE_ON_BUTTON_TEXT = "Authorize is On";
	public static final String AUTHORIZE_OFF_BUTTON_TEXT = "Authorize is Off";
	
	private GlobalModifierRulesControllerPanel modifiersControllerPanel;
	private MatchRuleControllerPanel enforcementControllerPanel;
	private InterceptionControllerPanel interceptionControllerPanel;
	private ContentSimilarityPanel contentSimilarityPanel;
	
	public ConfigurationTab()
	{
		super();
		
		this.setName(CONFIGURATION_TAB_NAME);
		
		JPanel configPanel = new JPanel();
		this.setViewportView(configPanel);
		configPanel.setBorder(new EmptyBorder(20, 45, 10, 30));
		configPanel.setLayout(new GridBagLayout());
		configPanel.setAlignmentX(LEFT_ALIGNMENT);
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.insets = new Insets(0, 0, 15, 0);
		//gbc.anchor = GridBagConstraints.FIRST_LINE_START;
		gbc.anchor = GridBagConstraints.WEST;
		
		gbc.gridx = 0;
		configPanel.add(this.createToggleButton(), gbc);
		
		gbc.gridx = 1;
		configPanel.add(this.createImportConfigButton(), gbc);
		
		gbc.gridx = 2;
		configPanel.add(this.createExportConfigButton(), gbc);
		
		gbc.insets = new Insets(0, 0, 10, 0);
		//gbc.fill = GridBagConstraints.HORIZONTAL;
		
		gbc.gridx = 0;
		gbc.gridy = 1;
		gbc.weightx = 1;
		gbc.weighty = 1;
		this.modifiersControllerPanel = new GlobalModifierRulesControllerPanel(BurpExtender.instance.getAuthorize().getGlobalModifiers());
		configPanel.add(this.modifiersControllerPanel, gbc);
		
		gbc.gridy = 2;
		MatchType[] enforcementMatchTypes = {MatchType.RESPONSE, MatchType.RESPONSE_BODY, MatchType.RESPONSE_HEADER, MatchType.STATUS_CODE};
		this.enforcementControllerPanel = new MatchRuleControllerPanel(enforcementMatchTypes, "Enforcement Rules", BurpExtender.instance.getAuthorize().getEnforcementManager().getEnforcementRules(), BurpExtender.instance.getAuthorize().getEnforcementManager()::getEnforcementRules);
		configPanel.add(this.enforcementControllerPanel, gbc);
		
		gbc.gridy = 3;
		this.interceptionControllerPanel = new InterceptionControllerPanel();
		configPanel.add(this.interceptionControllerPanel, gbc);
		
		gbc.gridy = 4;
		this.contentSimilarityPanel = new ContentSimilarityPanel();
		configPanel.add(this.contentSimilarityPanel, gbc);
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
						// TODO Auto-generated catch block
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
		this.modifiersControllerPanel.stateChanged(e);
		this.enforcementControllerPanel.stateChanged(e);
		this.interceptionControllerPanel.stateChanged(e);
		this.contentSimilarityPanel.stateChanged(e);
	}
}
