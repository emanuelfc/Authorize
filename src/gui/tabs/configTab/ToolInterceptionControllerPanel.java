package gui.tabs.configTab;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JCheckBox;
import javax.swing.JPanel;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;

import authorize.interception.ToolInterceptionRule;
import authorize.types.ToolType;
import burp.BurpExtender;

@SuppressWarnings("serial")
public class ToolInterceptionControllerPanel extends JPanel implements ChangeListener
{
	private List<ToolCheckBox> toolsButtons;
	
	public ToolInterceptionControllerPanel()
	{
		super();
		this.setLayout(new GridBagLayout());
		
		this.setAlignmentX(LEFT_ALIGNMENT);
		
		this.toolsButtons = new LinkedList<ToolCheckBox>();
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.FIRST_LINE_START;
		gbc.insets = new Insets(0, 0, 2, 0);
		gbc.gridx = 0;
		gbc.gridy = 0;
		
		for(ToolType type: ToolType.values())
		{
			ToolCheckBox toolCheckBox = new ToolCheckBox(type);
			this.add(toolCheckBox, gbc);
			this.toolsButtons.add(toolCheckBox);
			
			gbc.gridy++;
		}
	}
	
	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.toolsButtons.forEach((toolCheckbox) -> {toolCheckbox.stateChanged(e);});
	}
	
	private class ToolCheckBox extends JCheckBox implements ChangeListener, ItemListener
	{
		private ToolType toolType;
		
		public ToolCheckBox(ToolType toolType)
		{
			super(toolType.toString());
			this.toolType = toolType;
			this.setSelected(BurpExtender.instance.getAuthorize().getInterceptionManager().getToolInterceptionRule().isAllowedTool(toolType.getToolFlag()));
			this.addItemListener(this::itemStateChanged);
		}
		
		@Override
		public void itemStateChanged(ItemEvent e)
		{
			ToolInterceptionRule toolInterceptionRule = BurpExtender.instance.getAuthorize().getInterceptionManager().getToolInterceptionRule();
			if(e.getStateChange() == ItemEvent.SELECTED) toolInterceptionRule.addTool(this.toolType.getToolFlag());
			else toolInterceptionRule.removeTool(this.toolType.getToolFlag());
		}

		@Override
		public void stateChanged(ChangeEvent e)
		{
			this.setSelected(BurpExtender.instance.getAuthorize().getInterceptionManager().getToolInterceptionRule().isAllowedTool(toolType.getToolFlag()));
		}
	}

}
