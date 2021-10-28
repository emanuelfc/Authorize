package gui.utils;

import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public abstract class EntryControllerPanel<E> extends JPanel
{	
	private static final Dimension TABLE_DIMENSIONS = new Dimension(1000,200);
	
	protected ButtonsPanel buttonsPanel;
	protected JTable table;
	protected AbstractTableModel tableModel;
	
	protected List<E> elements;
	
	protected E selection;
	protected List<SelectionListener<E>> selectionListeners;
	
	protected EntryControllerPanel(List<E> elements, AbstractTableModel tableModel, String title)
	{
		super();
		
		this.elements = elements;
		
		this.selection = null;
		this.selectionListeners = new LinkedList<SelectionListener<E>>();
		this.tableModel = tableModel;
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.WEST;
		
		gbc.gridy = 0;
		gbc.gridwidth = 2;
		gbc.insets = new Insets(5, 0, 10, 0);
		
		JLabel tableLabel = new JLabel(title);
		tableLabel.setFont(new Font(tableLabel.getFont().getName(), Font.BOLD, 15));
		tableLabel.setForeground(new Color(255, 102, 51));
		this.add(tableLabel, gbc);
		
		gbc.insets.top = 0;
		gbc.gridy = 1;
		gbc.gridwidth = 1;
		gbc.insets = new Insets(0, 0, 0, 5);
		
		this.buttonsPanel = new ButtonsPanel(this::addAction, this::editAction, this::removeAction);
		
		this.add(this.buttonsPanel, gbc);
		
		gbc.gridx = 1;
		gbc.gridheight = 2;
		gbc.weightx = 1;
		gbc.weighty = 1;
		gbc.insets = new Insets(0, 0, 0, 0);
		
		this.add(this.createTable(), gbc);
		
		this.customizeTable();
	}
	
	public abstract class EntrySelectionListener implements ListSelectionListener
	{
		public abstract List<E> getEntriesList();

		@Override
		public void valueChanged(ListSelectionEvent e)
		{
			ListSelectionModel model = ((ListSelectionModel)e.getSource());
			if(!model.isSelectionEmpty())
			{
				int index = EntryControllerPanel.this.table.convertRowIndexToModel(EntryControllerPanel.this.table.getSelectedRow());
				E selectedEntry = this.getEntriesList().get(index);
				EntryControllerPanel.this.setSelectedEntry(selectedEntry);
			}
		}
		
	}
	
	protected abstract void customizeTable();
	
	private JScrollPane createTable()
	{
		this.table = new JTable(this.tableModel);
		this.table.setAutoCreateRowSorter(true);
		this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		this.table.setRowSelectionAllowed(true);
		this.table.setColumnSelectionAllowed(false);

		JScrollPane scrollPane = new JScrollPane(this.table);
		scrollPane.setPreferredSize(TABLE_DIMENSIONS);
		scrollPane.setMaximumSize(TABLE_DIMENSIONS);
		scrollPane.setSize(TABLE_DIMENSIONS);
		
		return scrollPane;
	}
	
	private void triggerListeners(E entry)
	{
		// Tell all observers about the change
		for(SelectionListener<E> listener: selectionListeners)
		{
			listener.onSelection(entry);
		}
	}
	
	protected void setSelectedEntry(E selectedEntry)
	{
		this.selection = selectedEntry;
		this.triggerListeners(selectedEntry);
	}
	
	public void addSelectEntryListener(SelectionListener<E> listener)
	{
		this.selectionListeners.add(listener);
	}
	
	public void removeSelectEntryListener(SelectionListener<E> listener)
	{
		this.selectionListeners.remove(listener);
	}
	
	protected abstract void addAction(ActionEvent e);
	protected abstract void editAction(ActionEvent e);
	
	protected void removeAction(ActionEvent e)
	{
		if(this.selection != null && this.elements != null)
		{
			if(this.elements.remove(this.selection))
			{
				this.setSelectedEntry(null);
				this.tableModel.fireTableDataChanged();
			}
		}
		else JOptionPane.showMessageDialog(null, "Please select an Entry to remove!");
	}
}
