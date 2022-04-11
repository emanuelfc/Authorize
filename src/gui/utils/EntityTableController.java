package gui.utils;

import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.util.LinkedList;
import java.util.List;

import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;

@SuppressWarnings("serial")
public abstract class EntityTableController<E> extends JPanel implements ListSelectionListener
{	
	private static final Dimension TABLE_DIMENSIONS = new Dimension(1000,200);
	
	protected ButtonsPanel buttonsPanel;
	protected JTable table;
	protected AbstractTableModel tableModel;
	
	protected E selection;
	protected List<SelectionListener<E>> selectionListeners;
	
	protected EntityTableController(AbstractTableModel tableModel)
	{
		super();
		
		this.selection = null;
		this.selectionListeners = new LinkedList<SelectionListener<E>>();
		this.tableModel = tableModel;
		
		this.setLayout(new GridBagLayout());
		
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.FIRST_LINE_START;
		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = 1;
		gbc.weighty = 1;
		
		gbc.gridy = 0;
		gbc.gridwidth = 1;
		gbc.insets = new Insets(0, 0, 0, 5);
		
		this.buttonsPanel = new ButtonsPanel(this::addAction, this::editAction, this::removeAction);
		
		this.add(this.buttonsPanel, gbc);
		
		gbc.gridx = 1;
		gbc.gridheight = 2;
		gbc.insets = new Insets(0, 0, 0, 0);
		
		this.add(this.createTable(), gbc);
		
		this.customizeTable();
	}
	
	protected abstract void customizeTable();
	
	private JScrollPane createTable()
	{
		this.table = new JTable(this.tableModel);
		this.table.setAutoCreateRowSorter(true);
		this.table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		this.table.setRowSelectionAllowed(true);
		this.table.setColumnSelectionAllowed(false);
		
		this.table.getSelectionModel().addListSelectionListener(this);

		JScrollPane scrollPane = new JScrollPane(this.table);
		scrollPane.setPreferredSize(TABLE_DIMENSIONS);
		scrollPane.setMaximumSize(TABLE_DIMENSIONS);
		scrollPane.setSize(TABLE_DIMENSIONS);		
		
		return scrollPane;
	}
	
	private void triggerSelectionListener(E selection)
	{
		// Tell all observers about the change
		for(SelectionListener<E> listener: this.selectionListeners)
		{
			listener.onSelection(selection);
		}
	}
	
	protected void setSelectedEntry(E selection)
	{
		this.selection = selection;
		this.triggerSelectionListener(selection);
	}
	
	protected abstract List<E> getEntries();
	
	@Override
	public void valueChanged(ListSelectionEvent e)
	{
		ListSelectionModel model = ((ListSelectionModel)e.getSource());
		
		if(!model.isSelectionEmpty() && !e.getValueIsAdjusting())
		{
			int index = this.table.convertRowIndexToModel(this.table.getSelectedRow());
			E selectedEntry = this.getEntries().get(index);
			this.setSelectedEntry(selectedEntry);
		}
	}
	
	public boolean addSelectionListener(SelectionListener<E> listener)
	{
		return this.selectionListeners.add(listener);
	}
	
	public boolean removeSelectionListener(SelectionListener<E> listener)
	{
		return this.selectionListeners.remove(listener);
	}
	
	protected abstract boolean addAction(ActionEvent e);
	protected abstract boolean editAction(ActionEvent e);
	protected abstract boolean removeAction(ActionEvent e);
}
