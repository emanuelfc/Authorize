package gui;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
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
import javax.swing.JLabel;
import javax.swing.JTextArea;
import javax.swing.ListCellRenderer;
import javax.swing.UIManager;
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
	public static final String CONTENT_SIMILARITY_PANEL_NAME = "Content Similarity Rule";
	
	public static final String CONTENT_SIMILARITY_PANEL_DESCRIPTION = ""
			+ "This rule specifies how to compare the response bodies (the content) of the Base Request and Principal Request.\n"
			+ "While their responses might not be equal, they might share a lot of similarities between them, including "
			+ "restricted information within the unauthorized Principal Response and the authorized one.\n"
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
	
	private JComboBox<Entry<String, SimilarityStrategy>> strategyComboBox;
	private JFormattedTextField authScore;
	private JFormattedTextField unauthScore;
	
	public ContentSimilarityPanel()
	{
		super();
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		
		gbc.gridy = 0;
		gbc.gridwidth = 2;
		gbc.insets = new Insets(5, 0, 10, 0);
		
		JLabel tableLabel = new JLabel(CONTENT_SIMILARITY_PANEL_NAME);
		tableLabel.setFont(new Font(tableLabel.getFont().getName(), Font.BOLD, 15));
		tableLabel.setForeground(new Color(255, 102, 51));
		this.add(tableLabel, gbc);
		
		gbc = super.createBaseConstraints();
		
		gbc.gridy = this.getComponentCount();
		
		gbc.gridx = 0;
		gbc.gridwidth = 2;
		this.add(this.createDescription(), gbc);
		
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
	
	private JTextArea createDescription()
	{
		JTextArea descriptionLabel = new JTextArea(CONTENT_SIMILARITY_PANEL_DESCRIPTION);
		
		descriptionLabel.setPreferredSize(new Dimension(1000,250));
		descriptionLabel.setWrapStyleWord(true);
		descriptionLabel.setLineWrap(true);
		descriptionLabel.setOpaque(false);
		descriptionLabel.setEditable(false);
		descriptionLabel.setFocusable(false);
		descriptionLabel.setBackground(UIManager.getColor("Label.background"));
		descriptionLabel.setFont(UIManager.getFont("Label.font"));
		descriptionLabel.setBorder(UIManager.getBorder("Label.border"));
		
		return descriptionLabel;
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
