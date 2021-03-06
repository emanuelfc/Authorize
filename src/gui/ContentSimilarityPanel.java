package gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.Map.Entry;

import javax.swing.JComboBox;
import javax.swing.JFormattedTextField;
import javax.swing.ListCellRenderer;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.text.NumberFormatter;

import authorize.enforcement.SimilarityStrategies;
import authorize.enforcement.SimilarityStrategy;
import burp.BurpExtender;
import gui.renderers.SimilarityStrategyListRenderer;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class ContentSimilarityPanel extends AbstractEntityPanel implements ChangeListener
{
	private JComboBox<Entry<String, SimilarityStrategy>> strategyComboBox;
	private JFormattedTextField authScore;
	private JFormattedTextField unauthScore;
	
	public ContentSimilarityPanel()
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		gbc.insets = new Insets(5, 0, 10, 0);
		gbc = super.createBaseConstraints();
		
		this.strategyComboBox = this.createComboBox();
		
		super.addLabeledComponent("Similarity Algorithm:", this.strategyComboBox);
		
		this.authScore = this.createScoreField(new PropertyChangeListener()
		{

			@Override
			public void propertyChange(PropertyChangeEvent evt)
			{
				double newAuthScore = (double) evt.getNewValue();
				BurpExtender.instance.getAuthorize().getEnforcementManager().setAuthorizedScore(newAuthScore);
			}
			
		});
		super.addLabeledComponent("Authorized Score:", this.authScore);
		
		this.unauthScore = this.createScoreField(new PropertyChangeListener()
		{

			@Override
			public void propertyChange(PropertyChangeEvent evt)
			{
				double newAuthScore = (double) evt.getNewValue();
				BurpExtender.instance.getAuthorize().getEnforcementManager().setUnauthorizedScore(newAuthScore);
			}
			
		});
		super.addLabeledComponent("Unauthorized Score:", this.unauthScore);
	}
	
	private JComboBox<Entry<String, SimilarityStrategy>> createComboBox()
	{
		@SuppressWarnings("unchecked")
		Entry<String, SimilarityStrategy>[] options = new Entry[SimilarityStrategies.strategies.entrySet().size()];
		options = SimilarityStrategies.strategies.entrySet().toArray(options);
		
		SimilarityStrategyListRenderer stratRendeer = new SimilarityStrategyListRenderer();
		
		// For some reason setRenderer doesnt work, force the renderer to be used.
		JComboBox<Entry<String, SimilarityStrategy>> comboBox = new JComboBox<Entry<String, SimilarityStrategy>>(options)
		{
			@Override
			public ListCellRenderer<? super Entry<String, SimilarityStrategy>> getRenderer()
			{
		        return stratRendeer;
		    }
		};
		
		comboBox.setSelectedItem(this.getStrategyEntryByFunction(SimilarityStrategies.Equals));
		
		comboBox.setRenderer(stratRendeer);
		
		comboBox.addActionListener(new ActionListener()
		{

			@SuppressWarnings("unchecked")
			@Override
			public void actionPerformed(ActionEvent e)
			{
				Entry<String, SimilarityStrategy> selectedEntry = (Entry<String, SimilarityStrategy>) comboBox.getSelectedItem();
				
				BurpExtender.instance.getAuthorize().getEnforcementManager().setStrategy(selectedEntry.getValue());
			}
			
		});
		
		return comboBox;
	}
	
	private Entry<String, SimilarityStrategy> getStrategyEntryByFunction(SimilarityStrategy strat)
	{
		for(Entry<String, SimilarityStrategy> entry: SimilarityStrategies.strategies.entrySet())
		{
			if(entry.getValue().equals(strat))
			{
				return entry;
			}
		}
		
		return null;
	}
	
	private JFormattedTextField createScoreField(PropertyChangeListener action)
	{
		NumberFormat format = DecimalFormat.getInstance();
		format.setMaximumIntegerDigits(1);
		format.setMinimumFractionDigits(2);
		format.setMaximumFractionDigits(2);
		
		NumberFormatter formatter = new NumberFormatter(format);
		formatter.setMaximum(1.00);
		formatter.setMinimum(0.00);
		
		JFormattedTextField scoreField = new JFormattedTextField(formatter);
		scoreField.setValue(0.00);
		
		scoreField.addPropertyChangeListener("value", action);
		
		return scoreField;
	}
	
	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.strategyComboBox.setSelectedItem(this.getStrategyEntryByFunction(BurpExtender.instance.getAuthorize().getEnforcementManager().getSimilarityStrategy()));
		this.authScore.setValue(BurpExtender.instance.getAuthorize().getEnforcementManager().getAuthorizedScore());
		this.unauthScore.setValue(BurpExtender.instance.getAuthorize().getEnforcementManager().getUnauthorizedScore());
	}
}
