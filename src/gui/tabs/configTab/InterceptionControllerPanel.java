package gui.tabs.configTab;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import authorize.interception.MatchRule;
import authorize.types.MatchType;
import burp.BurpExtender;
import gui.tabs.MatchRuleControllerPanel;
import gui.tabs.MatchTableModel;

@SuppressWarnings("serial")
public class InterceptionControllerPanel extends JPanel implements ChangeListener
{
	private MatchRuleControllerPanel httpInterceptionControllerPanel;
	private ToolInterceptionControllerPanel toolInterceptionRuleControllerPanel;
	
	public InterceptionControllerPanel()
	{
		super();
		
		this.httpInterceptionControllerPanel = new MatchRuleControllerPanel(new MatchTableModel()
				{

					@Override
					protected MatchRule getEntry(int row, int col)
					{
						return BurpExtender.instance.getAuthorize().getInterceptionManager().getInterceptionRules().get(row);
					}

					@Override
					public int getRowCount()
					{
						return BurpExtender.instance.getAuthorize().getInterceptionManager().getInterceptionRules().size();
					}
			
				}, MatchType.values())
		{

			@Override
			protected boolean addMatchRule(MatchRule matchRule)
			{
				if(this.getEntries().add(matchRule))
				{
					this.tableModel.fireTableDataChanged();
					return true;
				}
				
				return false;
			}

			@Override
			protected List<MatchRule> getEntries()
			{
				return BurpExtender.instance.getAuthorize().getInterceptionManager().getInterceptionRules();
			}

			@Override
			protected boolean removeAction(ActionEvent e)
			{
				if(this.getEntries().remove(this.selection))
				{
					this.tableModel.fireTableDataChanged();
					return true;
				}
				
				return false;
			}
	
		};
		this.toolInterceptionRuleControllerPanel = new ToolInterceptionControllerPanel();
		
		this.setLayout(new GridBagLayout());
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		
		gbc.gridx = 0;
		gbc.gridy = 0;
		this.add(this.httpInterceptionControllerPanel, gbc);
		
		gbc.insets = new Insets(0, 15, 0, 0);
		gbc.gridx = 1;
		gbc.gridy = 0;
		this.add(this.toolInterceptionRuleControllerPanel, gbc);
	}
	
	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.toolInterceptionRuleControllerPanel.stateChanged(e);
	}
}
