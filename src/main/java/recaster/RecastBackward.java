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

import docking.ActionContext;
import docking.action.MenuData;
import generic.stl.Pair;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.util.datatype.DataTypeSelectionDialog;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.GlobalSymbolMap;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeException;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.data.DataTypeParser;
import ghidra.util.exception.AssertException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;

public class RecastBackward extends RecastForward {

    private static final String HELP_ANCHOR = "RecasterActionBackward";

    RecastBackward(PluginTool tool, String owner, RecasterPlugin plugin) {
        super(tool, owner, plugin, "RecastBackward");
    }

    public static HighSymbol findHighSymbolFromToken(ClangToken token, HighFunction highFunction) {
        if (highFunction == null) {
            return null;
        }
        HighVariable variable = token.getHighVariable();
        HighSymbol highSymbol;
        if (variable == null) {
            // Token may be from a variable reference, in which case we have to dig to find the actual symbol
            Function function = highFunction.getFunction();
            if (function == null) {
                return null;
            }
            Address storageAddress = getStorageAddress(token, function.getProgram());
            if (storageAddress == null) {
                return null;
            }
            highSymbol = findHighSymbol(storageAddress, highFunction);
        }
        else {
            highSymbol = variable.getSymbol();
        }
        return highSymbol;
    }

    private static Address getStorageAddress(ClangToken tokenAtCursor, Program program) {
        Varnode vnode = tokenAtCursor.getVarnode();
        Address storageAddress = null;
        if (vnode != null) {
            storageAddress = vnode.getAddress();
        }
        // op could be a PTRSUB, need to dig it out...
        else if (tokenAtCursor instanceof ClangVariableToken) {
            PcodeOp op = tokenAtCursor.getPcodeOp();
            storageAddress =
                HighFunctionDBUtil.getSpacebaseReferenceAddress(program.getAddressFactory(), op);
        }
        return storageAddress;
    }

    private static HighSymbol findHighSymbol(Address addr, HighFunction highFunction) {
        HighSymbol highSymbol;
        if (addr.isStackAddress()) {
            LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
            highSymbol = localSymbolMap.findLocal(addr, null);
        }
        else {
            GlobalSymbolMap gsym = highFunction.getGlobalSymbolMap();
            highSymbol = gsym.getSymbol(addr);
        }
        return highSymbol;
    }

    @Override
    public void init() {
        setPopupMenuData(new MenuData(new String[] { "Recast variable backward" }, "Decompile"));
        setHelpLocation(new HelpLocation(PLUGIN_NAME, HELP_ANCHOR));
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        DecompilerActionContext decompilerActionContext = (DecompilerActionContext) actionContext;
        if (decompilerActionContext.isDecompiling()) {
            Msg.showInfo(this, actionContext.getComponentProvider().getComponent(),
                "Decompiler Action Blocked",
                "You cannot perform Decompiler actions while the Decompiler is busy");
            return;
        }
        initDecompilerPanel(actionContext);

        ClangToken token = decompilerActionContext.getTokenAtCursor();
        PcodeOp pcodeOp = token.getPcodeOp();
        Varnode varnodeParameter = getVarnodeParameter(pcodeOp, 0);
        if (varnodeParameter == null) {
            varnodeParameter = token.getVarnode();
        }

        Pair<DataType, String> infoParameter = getInfoAboutParameter(varnodeParameter);
        if (infoParameter == null) {
            return;
        }

        DataType dataType = null;
        String name = null;
        if (plugin.getTypeNameOverrideOption() == TypeNameOverrideOption.BOTH) {
            dataType = infoParameter.first;
            name = infoParameter.second;
        }
        else if (plugin.getTypeNameOverrideOption() == TypeNameOverrideOption.ONLY_NAME) {
            name = infoParameter.second;
        }
        else if (plugin.getTypeNameOverrideOption() == TypeNameOverrideOption.ONLY_TYPE) {
            dataType = infoParameter.first;
        }

        int opcode = pcodeOp.getOpcode();
        if (opcode == PcodeOp.PTRSUB || opcode == PcodeOp.PTRADD) {
            if (dataType instanceof Pointer) {
                dataType = ((Pointer) dataType).getDataType();
                if (dataType.getLength() == 0) {
                    dataType = chooseDataType(tool, currentProgram, dataType);
                    if (dataType == null) {
                        return;
                    }
                }
            }
        }

        HighSymbol highSymbol =
            findHighSymbolFromToken(token, decompilerActionContext.getHighFunction());
        if (highSymbol == null) {
            return;
        }
        Symbol symbol = highSymbol.getSymbol();
        if (symbol != null && !(plugin.getSourceTypeList().contains(symbol.getSource()))) {
            return;
        }

        changeSymbol(currentProgram, highSymbol, token.getVarnode(), dataType, name);
    }

    private Pair<DataType, String> getInfoAboutParameter(Varnode varnodeParameter) {
        int numParam = Arrays.asList(callPCodeOp.getInputs()).indexOf(varnodeParameter) - 1;
        Function function = getFunctionByAddress(callPCodeOp.getInput(0).getAddress());

        if (numParam < 0) {
            showError(String.format("Can't find parameter varnode %s of CALL PCode: %s",
                varnodeParameter.toString(),
                callPCodeOp.toString()));
            return null;
        }
        Parameter parameter = function.getParameter(numParam);
        if (parameter == null) {
            showError(String.format("Function %s (%s) don't have enough parameters.",
                function.getName(),
                function.getEntryPoint()));
            return null;
        }
        return new Pair<>(parameter.getDataType(), parameter.getName());
    }

    private void changeSymbol(Program program,
            HighSymbol highSymbol,
            Varnode exactSpot,
            DataType dataType,
            String name) {
        HighFunction highFunction = highSymbol.getHighFunction();

        boolean commitRequired = checkFullCommit(highSymbol, highFunction);
        if (commitRequired) {
            exactSpot = null;        // Don't try to split out if commit is required
        }

        if (exactSpot != null) { // The user pointed at a particular usage, not just the vardecl
            try {
                HighVariable var = highFunction.splitOutMergeGroup(exactSpot.getHigh(), exactSpot);
                highSymbol = var.getSymbol();
            }
            catch (PcodeException e) {
                showError(e.getMessage());
                return;
            }
        }
        DataTypeManager dataTypeManager = program.getDataTypeManager();
        boolean successfulMod = false;
        int transaction = program.startTransaction("Retype Variable");
        try {
            if (dataType != null) {
                if (dataType.getDataTypeManager() != dataTypeManager) {
                    dataType = dataTypeManager.resolve(dataType, null);
                }
            }
            if (commitRequired) {
                // Don't use datatypes of other parameters if the datatypes were floating.
                // Datatypes were floating if signature source was DEFAULT
                boolean useDataTypes =
                    highFunction.getFunction().getSignatureSource() != SourceType.DEFAULT;
                try {
                    HighFunctionDBUtil.commitParamsToDatabase(highFunction,
                        useDataTypes,
                        SourceType.USER_DEFINED);
                    if (useDataTypes) {
                        HighFunctionDBUtil
                                .commitReturnToDatabase(highFunction, SourceType.USER_DEFINED);
                    }
                }
                catch (DuplicateNameException e) {
                    throw new AssertException("Unexpected exception", e);
                }
                catch (InvalidInputException e) {
                    showError(e.getMessage());
                }
            }
            HighFunctionDBUtil.updateDBVariable(highSymbol, name, dataType, SourceType.ANALYSIS);
            successfulMod = true;
        }
        catch (DuplicateNameException e) {
            showError(e.getMessage());
        }
        catch (InvalidInputException e) {
            showError(
                "Failed to re-type variable '" + highSymbol.getName() + "': " + e.getMessage());
        }
        finally {
            program.endTransaction(transaction, successfulMod);
        }
    }

    boolean checkFullCommit(HighSymbol highSymbol, HighFunction highFunction) {
        if (highSymbol != null && !highSymbol.isParameter()) {
            return false;
        }
        Function function = highFunction.getFunction();
        Parameter[] parameters = function.getParameters();
        LocalSymbolMap localSymbolMap = highFunction.getLocalSymbolMap();
        int numParams = localSymbolMap.getNumParams();
        if (numParams != parameters.length) {
            return true;
        }

        for (int i = 0; i < numParams; i++) {
            HighSymbol param = localSymbolMap.getParamSymbol(i);
            if (param.getCategoryIndex() != i) {
                return true;
            }
            VariableStorage storage = param.getStorage();
            // Don't compare using the equals method so that DynamicVariableStorage can match
            if (0 != storage.compareTo(parameters[i].getVariableStorage())) {
                return true;
            }
        }

        return false;
    }

    DataType chooseDataType(PluginTool tool, Program program, DataType currentDataType) {
        DataTypeManager dataTypeManager = program.getDataTypeManager();
        DataTypeSelectionDialog chooserDialog =
            new DataTypeSelectionDialog(tool,
                dataTypeManager,
                Integer.MAX_VALUE,
                DataTypeParser.AllowedDataTypes.FIXED_LENGTH);
        chooserDialog.setInitialDataType(currentDataType);
        tool.showDialog(chooserDialog);
        return chooserDialog.getUserChosenDataType();
    }
}
