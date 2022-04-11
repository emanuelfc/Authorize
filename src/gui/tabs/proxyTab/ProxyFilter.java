package gui.tabs.proxyTab;

public class ProxyFilter
{
	private boolean scopeItemsOnly;
	
	private boolean statusCode_200;
	private boolean statusCode_300;
	private boolean statusCode_400;
	private boolean statusCode_500;
	
	private String searchTerm;
	private boolean isRegex;
	private boolean caseSensitive;
	private boolean negativeSearch;
	
	private boolean showExtensions;
	private String showExtensionsList;
	private boolean hideExtensions;
	private String hideExtensionsList;
	
	private boolean authorized;
	private boolean unauthorized;
	private boolean unknown;
	private boolean currentUser;
	private boolean disabled;
	private boolean error;
	
	public ProxyFilter()
	{
		this.scopeItemsOnly = false;
		
		this.statusCode_200 = true;
		this.statusCode_300 = true;
		this.statusCode_400 = true;
		this.statusCode_500 = true;
		
		this.authorized = true;
		this.unauthorized = true;
		this.unknown = true;
		this.currentUser = true;
		this.disabled = true;
		this.error = true;
	}
	
	public void filter(int row, int col)
	{
		
	}
}
