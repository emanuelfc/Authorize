package gui.tabs.proxyTab;

import java.awt.Component;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.swing.JPopupMenu;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.TableModelEvent;
import javax.swing.event.TableModelListener;
import javax.swing.table.TableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableModel;
import javax.swing.table.TableRowSorter;

import authorize.messages.UserMessage;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IMessageEditor;
import gui.menus.proxyMenus.ProxyPopupMenuListener;
import gui.proxyMessageViewer.ProxyMessageEditorController;
import gui.renderers.ProxyDefaultTableCellRenderer;
import gui.renderers.UserAuthorizationCellRenderer;
import gui.windows.AuthorizeMessageWindowPopup;

@SuppressWarnings("serial")
public class ProxyTable extends JTable implements ChangeListener
{
	private ProxyMessageEditorController messageEditor;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private ProxyTableModel proxyTableModel;
	
	public ProxyTable(ProxyMessageEditorController messageEditor, IMessageEditor requestViewer, IMessageEditor responseViewer)
	{
		super();
		
		this.autoCreateColumnsFromModel = true;
		
		this.proxyTableModel = new ProxyTableModel();
		this.setModel(this.proxyTableModel);
		
		this.proxyTableModel.addTableModelListener(new TableModelListener()
		{

			@Override
			public void tableChanged(TableModelEvent e)
			{
				if(e.getFirstRow() == TableModelEvent.HEADER_ROW)
				{
					ProxyTable.this.customizeTable();
				}
			}
			
		});
		
		this.customizeTable();

		this.messageEditor = messageEditor;
		
		this.requestViewer = requestViewer;
		this.responseViewer = responseViewer;
		
		this.addMouseListener(new AuthorizeMessageWindowPopup(this));
		
		JPopupMenu popupMenu = new JPopupMenu();
		popupMenu.addPopupMenuListener(new ProxyPopupMenuListener(this));
		this.setComponentPopupMenu(popupMenu);
	}
	
	private void customizeTable()
	{	
		this.setAutoCreateRowSorter(true);
		
		// Sort by proxy message id - descending
		this.getRowSorter().toggleSortOrder(0); 
		TableRowSorter<TableModel> sorter = new TableRowSorter<>(this.getModel());
		this.setRowSorter(sorter);
		List<RowSorter.SortKey> sortKeys = new ArrayList<>();
		int columnIndexToSort = 0;
		sortKeys.add(new RowSorter.SortKey(columnIndexToSort, SortOrder.DESCENDING));
		sorter.setSortKeys(sortKeys);
		sorter.sort();
		
		TableColumnModel columnModel = this.getColumnModel();
		
		ProxyDefaultTableCellRenderer proxyDefaultTableCellRenderer = new ProxyDefaultTableCellRenderer();
		
		// ID Column
		TableColumn idColumn = columnModel.getColumn(0);
		idColumn.setPreferredWidth(50);
		idColumn.setMinWidth(50);
		idColumn.setCellRenderer(proxyDefaultTableCellRenderer);
		
		// Host Column
		TableColumn hostColumn = columnModel.getColumn(1);
		hostColumn.setPreferredWidth(220);
		hostColumn.setCellRenderer(proxyDefaultTableCellRenderer);
		
		// Method Column
		TableColumn methodColumn = columnModel.getColumn(2);
		methodColumn.setPreferredWidth(60);
		methodColumn.setMinWidth(50);
		methodColumn.setCellRenderer(proxyDefaultTableCellRenderer);
		
		// URL - Path Column
		TableColumn pathColumn = columnModel.getColumn(3);
		pathColumn.setPreferredWidth(380);
		pathColumn.setCellRenderer(proxyDefaultTableCellRenderer);
		
		// Status Column
		TableColumn statusColumn = columnModel.getColumn(4);
		statusColumn.setPreferredWidth(55);
		statusColumn.setMinWidth(55);
		statusColumn.setCellRenderer(proxyDefaultTableCellRenderer);
		
		// Time Column
		TableColumn timeColumn = columnModel.getColumn(5);
		timeColumn.setPreferredWidth(140);
		timeColumn.setMinWidth(140);
		
		TableCellRenderer dateCellRenderer = new ProxyDefaultTableCellRenderer()
		{
			private SimpleDateFormat dateFormat = new SimpleDateFormat("HH:mm:ss dd/MM/YYYY");
			
			public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column)
			{
				if(value instanceof Date)
				{
					value = dateFormat.format(value);
				}
				
				return super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
			}
		};
		
		timeColumn.setCellRenderer(dateCellRenderer);
		this.setDefaultRenderer(Date.class, dateCellRenderer);
		
		UserAuthorizationCellRenderer userAuthCellRenderer = new UserAuthorizationCellRenderer(this);
		this.setDefaultRenderer(String.class, userAuthCellRenderer);
		
		Iterator<TableColumn> it = this.getColumnModel().getColumns().asIterator();
		for(int i = 0; i < 6; i++)
		{
			it.next();
		}
		
		while(it.hasNext())
		{
			it.next().setPreferredWidth(130);
		}
		
		this.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
		this.setRowSelectionAllowed(true);
		this.setColumnSelectionAllowed(false);
		this.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		this.tableHeader.setReorderingAllowed(true);
	}
	
	public int tableRowToMessageId(int row)
	{
		return this.proxyTableModel.modelRowToMessageId(this.convertRowIndexToModel(row));
	}
	
	private IHttpRequestResponse getSelectedMessage(int row, int col)
	{
		int messageId = this.tableRowToMessageId(row);
		int modelCol = this.convertColumnIndexToModel(col);
		
		if(ProxyTableModel.isUserColumn(modelCol))
		{
			UserMessage userMessage = ProxyTableModel.getUserByColIndex(modelCol).getMessage(messageId);
			if(userMessage != null)
			{
				return userMessage.getMessage();
			}
			else return null;
		}
		else
		{
			return BurpExtender.instance.getAuthorize().getMessages().get(messageId).getMessage();
		}
	}
	
	public void changeSelection(int row, int col, boolean toggle, boolean extend)
	{
		super.changeSelection(row, col, toggle, extend);
		
		IHttpRequestResponse selectedMessageInfo = this.getSelectedMessage(row, col);
		
		byte[] request, response;
		
		if(selectedMessageInfo != null)
		{
			request = selectedMessageInfo.getRequest();
			response = selectedMessageInfo.getResponse();
		}
		else
		{
			request = response = "Message does not exist".getBytes();
		}
		
		this.requestViewer.setMessage(request, true);
		this.responseViewer.setMessage(response, false);
		
		this.messageEditor.onSelection(selectedMessageInfo);
	}
	
	public ProxyTableModel getModel()
	{
		return this.proxyTableModel;
	}

	@Override
	public void stateChanged(ChangeEvent e)
	{
		this.proxyTableModel.fireTableStructureChanged();
	}
}
