package gui.sessionManagement;

import java.awt.Color;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JTextField;

import authorize.extractor.ExtractorFactory;
import authorize.sessionManagement.ResponseSessionExtractor;
import authorize.types.ExtractorType;
import gui.utils.AbstractEntityPanel;

@SuppressWarnings("serial")
public class ResponseSessionExtractorPanel extends AbstractEntityPanel
{
	public static ExtractorType[] extractorTypes = {ExtractorType.RESPONSE, ExtractorType.RESPONSE_BODY, ExtractorType.RESPONSE_COOKIE, ExtractorType.RESPONSE_HEADER, ExtractorType.RESPONSE_JSON_PARAM};
	
	private JComboBox<ExtractorType> extractorTypeField;
	private JTextField matchField;
	private JCheckBox isRegexField;
	
	public ResponseSessionExtractorPanel(ExtractorType extractorType, String match, boolean isRegex)
	{
		super();
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = super.createBaseConstraints();
		gbc.gridwidth = 2;
		
		JLabel panelTitle = new JLabel("Response Session Extractor");
		panelTitle.setFont(new Font(panelTitle.getFont().getName(), Font.BOLD, 15));
		panelTitle.setForeground(new Color(255, 102, 51));
		this.addComponent(panelTitle, gbc);

		this.extractorTypeField = new JComboBox<ExtractorType>(extractorTypes);
		if(extractorType != null) this.extractorTypeField.setSelectedItem(extractorType);
		super.addLabeledComponent("Type:", this.extractorTypeField);
		
		this.matchField = super.addLabeledTextField("Match:", match);
		
		this.isRegexField = new JCheckBox("Regex Match");
		this.isRegexField.setSelected(isRegex);
		super.addComponent(this.isRegexField, 1, this.getComponentCount());
	}
	
	public ResponseSessionExtractorPanel(ResponseSessionExtractor responseSessionExtractor)
	{
		this(responseSessionExtractor.getExtractorType(), responseSessionExtractor.getMatch(), responseSessionExtractor.isRegex());
	}
	
	public ResponseSessionExtractorPanel()
	{
		this(null, "", false);
	}
	
	public ResponseSessionExtractor create()
	{
		return new ResponseSessionExtractor(this.matchField.getText(), this.isRegexField.isSelected(), ExtractorFactory.createExtractor((ExtractorType) this.extractorTypeField.getSelectedItem()), (ExtractorType) this.extractorTypeField.getSelectedItem());
	}
	
	public void edit(ResponseSessionExtractor responseSessionExtractor)
	{
		responseSessionExtractor.setMatch(this.matchField.getText());
		responseSessionExtractor.setRegex(this.isRegexField.isSelected());
		responseSessionExtractor.setExtractor(ExtractorFactory.createExtractor((ExtractorType) this.extractorTypeField.getSelectedItem()), (ExtractorType) this.extractorTypeField.getSelectedItem());
	}
}
