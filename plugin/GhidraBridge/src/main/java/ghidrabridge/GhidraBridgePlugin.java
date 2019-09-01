package ghidrabridge;

import docking.ActionContext;
import docking.action.DockingAction;
import docking.action.MenuData;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.framework.plugintool.util.ToolConstants;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(status = PluginStatus.UNSTABLE, 
	packageName = "GhidraBridge", 
	category = "GhidraBridge", 
	shortDescription = "Plugin short description goes here.", 
	description = "Plugin long description goes here.")
//@formatter:on
public class GhidraBridgePlugin extends ProgramPlugin {

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	// Note: when developing/installing the plugin - you need to go into the tool
	// and select the plugin from Configure->Unstable
	public GhidraBridgePlugin(PluginTool tool) {
		super(tool, true, true, true); // register for location, selection and highlight updates

		GhidraBridgePlugin plugin = this;
		DockingAction toggleAction = new DockingAction("Start/Stop GhidraBridge", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				BridgeControl.toggleBridge(plugin, this);
			}
		};
		// action.setToolBarData(new ToolBarData(Icons.STRONG_WARNING_ICON, "View")); -
		// tool bar is icon line just below file menu
		toggleAction.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, "GhidraBridge", "Start" }));
		tool.addAction(toggleAction);

		DockingAction restartAction = new DockingAction("Restart GhidraBridge", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				BridgeControl.restartBridge(plugin, toggleAction);
			}
		};
		restartAction
				.setMenuBarData(new MenuData(new String[] { ToolConstants.MENU_TOOLS, "GhidraBridge", "Restart" }));
		tool.addAction(restartAction);
	}

	@Override
	public void init() {
		super.init();
	}

}
