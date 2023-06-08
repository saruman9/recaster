/*
 * Copyright (c) 2020 Abc Xyz — All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package recaster;

import ghidra.MiscellaneousPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.options.Options;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.symbol.SourceType;

import java.util.ArrayList;
import java.util.List;

/**
 * RecasterPlugin
 * <p>
 * Recursively search dependencies of the variable and change their names and types.
 */
//@formatter:off
@PluginInfo(
        status = PluginStatus.UNSTABLE,
        packageName = MiscellaneousPluginPackage.NAME,
        category = PluginCategoryNames.ANALYSIS,
        shortDescription = "Recursively change names and types.",
        description = "Recursively search dependencies of the variable and change their " +
                "names and types."
)
//@formatter:on
public class RecasterPlugin extends ProgramPlugin implements OptionsChangeListener {
    private static final String MAIN_NAME = "Recaster";

    private static final String TYPE_NAME_OVERRIDE_OPTION_NAME = "Override name/type";
    private static final TypeNameOverrideOption TYPE_NAME_OVERRIDE_OPTION_DEFAULT =
            TypeNameOverrideOption.BOTH;

    private static final String SOURCE_TYPE_OVERRIDE_DEFAULT_OPTION_NAME = "Override DEFAULT";
    private static final String SOURCE_TYPE_OVERRIDE_ANALYSIS_OPTION_NAME = "Override ANALYSIS";
    private static final String SOURCE_TYPE_OVERRIDE_IMPORTED_OPTION_NAME = "Override IMPORTED";
    private static final String SOURCE_TYPE_OVERRIDE_USER_DEFINED_OPTION_NAME =
            "Override USER_DEFINED";

    private static final boolean SOURCE_TYPE_OVERRIDE_DEFAULT_OPTION_DEFAULT = true;
    private static final boolean SOURCE_TYPE_OVERRIDE_ANALYSIS_OPTION_DEFAULT = false;
    private static final boolean SOURCE_TYPE_OVERRIDE_IMPORTED_OPTION_DEFAULT = false;
    private static final boolean SOURCE_TYPE_OVERRIDE_USER_DEFINED_OPTION_DEFAULT = false;

    private TypeNameOverrideOption typeNameOverrideOption = TYPE_NAME_OVERRIDE_OPTION_DEFAULT;

    private List<SourceType> sourceTypeList = new ArrayList<>();

    /**
     * Plugin constructor.
     *
     * @param tool The plugin tool that this plugin is added to.
     */
    public RecasterPlugin(PluginTool tool) {
        super(tool);
        createActions();
        initializeOptionListeners();
        getOptions();
    }

    @Override
    protected void dispose() {
        ToolOptions options = tool.getOptions(MAIN_NAME);
        options.removeOptionsChangeListener(this);

        super.dispose();
    }

    private void createActions() {
        RecastForward recastForward = new RecastForward(tool, getName(), this);
        recastForward.init();
        recastForward.setEnabled(true);
        tool.addAction(recastForward);
        RecastBackward recastBackward = new RecastBackward(tool, getName(), this);
        recastBackward.init();
        recastBackward.setEnabled(true);
        tool.addAction(recastBackward);
    }

    private void initializeOptionListeners() {
        ToolOptions options = tool.getOptions(MAIN_NAME);

        options.registerOption(TYPE_NAME_OVERRIDE_OPTION_NAME, TYPE_NAME_OVERRIDE_OPTION_DEFAULT,
                               null, "Choose, what you want to override"
        );

        options.registerOption(SOURCE_TYPE_OVERRIDE_DEFAULT_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_DEFAULT_OPTION_DEFAULT,
                               null,
                               "Override variables with DEFAULT Source Type"
        );
        options.registerOption(SOURCE_TYPE_OVERRIDE_ANALYSIS_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_ANALYSIS_OPTION_DEFAULT,
                               null,
                               "Override variables with ANALYSIS Source Type"
        );
        options.registerOption(SOURCE_TYPE_OVERRIDE_IMPORTED_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_IMPORTED_OPTION_DEFAULT,
                               null,
                               "Override variables with IMPORTED Source Type"
        );
        options.registerOption(SOURCE_TYPE_OVERRIDE_USER_DEFINED_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_USER_DEFINED_OPTION_DEFAULT,
                               null,
                               "Override variables with USER_DEFINED Source Type"
        );

        options.addOptionsChangeListener(this);
    }

    void getOptions() {
        Options options = tool.getOptions(MAIN_NAME);

        typeNameOverrideOption =
                options.getEnum(TYPE_NAME_OVERRIDE_OPTION_NAME, TYPE_NAME_OVERRIDE_OPTION_DEFAULT);
        sourceTypeList.clear();
        if (options.getBoolean(SOURCE_TYPE_OVERRIDE_DEFAULT_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_DEFAULT_OPTION_DEFAULT
        )) {
            sourceTypeList.add(SourceType.DEFAULT);
        }
        if (options.getBoolean(SOURCE_TYPE_OVERRIDE_ANALYSIS_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_ANALYSIS_OPTION_DEFAULT
        )) {
            sourceTypeList.add(SourceType.ANALYSIS);
        }
        if (options.getBoolean(SOURCE_TYPE_OVERRIDE_IMPORTED_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_IMPORTED_OPTION_DEFAULT
        )) {
            sourceTypeList.add(SourceType.IMPORTED);
        }
        if (options.getBoolean(SOURCE_TYPE_OVERRIDE_USER_DEFINED_OPTION_NAME,
                               SOURCE_TYPE_OVERRIDE_USER_DEFINED_OPTION_DEFAULT
        )) {
            sourceTypeList.add(SourceType.USER_DEFINED);
        }
    }

    @Override
    public void optionsChanged(ToolOptions options, String optionName, Object oldValue,
                               Object newValue) {
        getOptions();

    }

    List<SourceType> getSourceTypeList() {
        return sourceTypeList;
    }

    TypeNameOverrideOption getTypeNameOverrideOption() {
        return typeNameOverrideOption;
    }
}
