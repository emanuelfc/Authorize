package gui.controllerPanels;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JPanel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import authorize.types.MatchType;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class InterceptionControllerPanel extends JPanel implements ChangeListener
{
	public static final String INTERCEPTION_RULES_TABLE_NAME = "Interception Rules";
	
	private ToolInterceptionControllerPanel toolInterceptionRuleControllerPanel;
	private MatchRuleControllerPanel httpInterceptionControllerPanel;
	
	public InterceptionControllerPanel()
	{
		super();
		this.httpInterceptionControllerPanel = new MatchRuleControllerPanel(MatchType.values(), INTERCEPTION_RULES_TABLE_NAME, BurpExtender.instance.getAuthorize().getInterceptionManager().getInterceptionRules(), BurpExtender.instance.getAuthorize().getInterceptionManager()::getInterceptionRules);
		this.toolInterceptionRuleControllerPanel = new ToolInterceptionControllerPanel();
		
		this.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.FIRST_LINE_START;
		
		gbc.gridx = 0;
		gbc.gridy = 0;
		this.add(this.httpInterceptionControllerPanel, gbc);
		
		gbc.insets = new Insets(35, 15, 0, 0);
		gbc.gridx = 1;
		gbc.gridy = 0;
		gbc.weightx = 1;
		gbc.weighty = 1;
		this.add(this.toolInterceptionRuleControllerPanel, gbc);
	}
	
	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.toolInterceptionRuleControllerPanel.stateChanged(e);
		this.httpInterceptionControllerPanel.stateChanged(e);
	}
}
