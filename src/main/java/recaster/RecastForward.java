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
import docking.ComponentProvider;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.widgets.OptionDialog;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangStatement;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangVariableToken;
import ghidra.app.decompiler.component.DecompilerPanel;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.app.plugin.core.decompile.DecompilerProvider;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

public class RecastForward extends DockingAction {

    static final String PLUGIN_NAME = "Recaster";
    private static final String HELP_ANCHOR = "RecasterActionForward";
    final PluginTool tool;
    final RecasterPlugin plugin;
    DecompilerPanel decompilerPanel;
    Program currentProgram;
    PcodeOp callPCodeOp;

    RecastForward(PluginTool tool, String owner, RecasterPlugin plugin) {
        this(tool, owner, plugin, "RecastForward");
    }

    RecastForward(PluginTool tool, String owner, RecasterPlugin plugin, String actionName) {
        super(actionName, owner);
        this.tool = tool;
        this.plugin = plugin;
    }

    public void init() {
        setPopupMenuData(new MenuData(new String[]{"Recast variable forward"}, "Decompile"));
        setHelpLocation(new HelpLocation(PLUGIN_NAME, HELP_ANCHOR));
    }

    void initDecompilerPanel(ActionContext context) {
        ComponentProvider componentProvider = tool.getComponentProvider("Decompiler");
        currentProgram = ((DecompilerProvider) componentProvider).getProgram();
        // The context should be right after applying `isEnabledContext`
        DecompilerActionContext decompilerActionContext =
                (DecompilerActionContext) context.getContextObject();
        decompilerPanel = decompilerActionContext.getDecompilerPanel();
    }

    @Override
    public void actionPerformed(ActionContext actionContext) {
        DecompilerActionContext decompilerActionContext = (DecompilerActionContext) actionContext;
        if (decompilerActionContext.isDecompiling()) {
            Msg.showInfo(this, actionContext.getComponentProvider().getComponent(),
                         "Decompiler Action Blocked",
                         "You cannot perform Decompiler actions while the Decompiler is busy"
            );
            return;
        }
        initDecompilerPanel(actionContext);

        ClangToken token = decompilerActionContext.getTokenAtCursor();
        PcodeOp pcodeOp = token.getPcodeOp();
        int opcode = pcodeOp.getOpcode();
        if (opcode == PcodeOp.CALL) {
            Varnode varnode = token.getVarnode();
            HighVariable highVariable = varnode.getHigh();
            HighSymbol highSymbol = highVariable.getSymbol();
            if (highSymbol != null) {
                processCallPCode(varnode, highSymbol.getName(), highSymbol.getDataType());
            } else {
                processCallPCode(varnode, highVariable.getName(), highVariable.getDataType());
            }
        } else if (opcode == PcodeOp.CAST) {
            processOutputPCode(token);
        } else if (opcode == PcodeOp.PTRSUB) {
            processPtrSubPCode(token);
        } else if (opcode == PcodeOp.SUBPIECE || opcode == PcodeOp.PIECE ||
                   opcode == PcodeOp.INT_ZEXT) {
            processOutputWithSizeChange(token);
        } else if (opcode == PcodeOp.LOAD) {
            processLoadPCode(token);
        } else {
            Msg.showWarn(this,
                         decompilerPanel.getFieldPanel(),
                         PLUGIN_NAME,
                         String.format("PCodeOp %s not realized, but we try to change parameter " +
                                       "of the function. Please check the result.",
                                       pcodeOp.getMnemonic()
                         )
            );
            Msg.debug(this, pcodeOp.toString());
            processOutputPCode(token);
        }
    }

    private void processLoadPCode(ClangToken token) {
        PcodeOp pcodeOp = token.getPcodeOp();
        String name = token.getVarnode().getHigh().getSymbol().getName();
        DataType dataType = token.getPcodeOp().getOutput().getHigh().getSymbol().getDataType();
        debugPCode(pcodeOp, name, dataType);

        processCallPCode(getVarnodeParameter(pcodeOp, 0), name, dataType);
    }

    private void processPtrSubPCode(ClangToken token) {
        PcodeOp pcodeOp = token.getPcodeOp();
        Varnode outputVarnode = pcodeOp.getOutput();
        String name;
        DataType dataType;
        Structure structure = getStructure(token);
        if (structure != null) {
            int offset = (int) getFieldOffset(token);
            name = structure.getComponentAt(offset).getFieldName();
            dataType = structure.getComponentAt(offset).getDataType();
            if (name == null) {
                name = OptionDialog.showInputSingleLineDialog(this.decompilerPanel,
                                                              PLUGIN_NAME,
                                                              "Field name:",
                                                              "unknown"
                );
                if (name == null) {
                    return;
                }
                if (name.isBlank()) {
                    showError("Field's name can't be blank.");
                    return;
                }
            }
        } else {
            name = token.getText();
            HighVariable highVariable = outputVarnode.getHigh();
            HighSymbol highSymbol = highVariable.getSymbol();
            if (highSymbol != null) {
                dataType = highSymbol.getDataType();
            } else {
                dataType = highVariable.getDataType();
            }
        }
        debugPCode(pcodeOp, name, dataType);

        processCallPCode(getVarnodeParameter(pcodeOp, 0), name, dataType);
    }

    private void processOutputWithSizeChange(ClangToken token) {
        int yesNo = OptionDialog.showYesNoDialog(this.decompilerPanel,
                                                 PLUGIN_NAME,
                                                 "You will change size of parameter. Are you sure?"
        );
        if (yesNo != 1) {
            return;
        }
        processOutputPCode(token);
    }

    private void processOutputPCode(ClangToken token) {
        PcodeOp pcodeOp = token.getPcodeOp();
        HighVariable highVariable = token.getVarnode().getHigh();
        HighSymbol highSymbol = highVariable.getSymbol();
        String name;
        DataType dataType;
        if (highSymbol != null) {
            name = highSymbol.getName();
            dataType = highSymbol.getDataType();
        } else {
            name = highVariable.getName();
            dataType = highVariable.getDataType();
        }
        debugPCode(pcodeOp, name, dataType);

        processCallPCode(getVarnodeParameter(pcodeOp, 0), name, dataType);
    }

    private void processCallPCode(Varnode varnode,
                                  String name,
                                  DataType dataType) {
        if (varnode == null) {
            showError("Too much PCodes before CALL PCode!");
            return;
        }
        debugPCode(callPCodeOp, name, dataType);
        changeParameter(callPCodeOp, varnode, name, dataType);
    }

    private long getFieldOffset(ClangToken token) {
        PcodeOp pcodeOp = token.getPcodeOp();
        Varnode[] inputs = pcodeOp.getInputs();
        for (Varnode varnode : inputs) {
            HighVariable variable = varnode.getHigh();
            if (variable instanceof HighConstant) {
                return varnode.getOffset();
            }
        }
        return -1;
    }

    private Structure getStructure(ClangToken token) {
        Varnode varnode = token.getVarnode();
        if (varnode == null) {
            return null;
        }
        HighVariable highVariable = varnode.getHigh();
        if (highVariable == null) {
            return null;
        }
        DataType dataType = highVariable.getDataType();
        while (true) {
            if (dataType instanceof TypeDef) {
                dataType = ((TypeDef) dataType).getBaseDataType();
                continue;
            }
            if (dataType instanceof Pointer) {
                dataType = ((Pointer) dataType).getDataType();
                continue;
            }
            if (dataType instanceof Structure) {
                return (Structure) dataType;
            }
            return null;
        }
    }

    Varnode getVarnodeParameter(PcodeOp pcodeOp, int depth) {
        // TODO Delete depth? Why 5?
        if (depth > 5) {
            return null;
        }
        Varnode varnode = pcodeOp.getOutput();
        if (varnode == null) {
            return null;
        }
        Iterator<PcodeOp> pCodeOpIterator = varnode.getDescendants();
        while (pCodeOpIterator.hasNext()) {
            PcodeOp pCodeOpDescent = pCodeOpIterator.next();
            if (pCodeOpDescent == callPCodeOp) {
                return varnode;
            }
            Varnode newVarnode = getVarnodeParameter(pCodeOpDescent, depth + 1);
            if (newVarnode != null) {
                return newVarnode;
            }
        }
        return null;
    }

    private void changeParameter(PcodeOp callPCode,
                                 Varnode varnodeParameter,
                                 String name,
                                 DataType dataType) {
        int numParam = Arrays.asList(callPCode.getInputs()).indexOf(varnodeParameter) - 1;
        Function function = getFunctionByAddress(callPCode.getInput(0).getAddress());

        if (numParam < 0) {
            showError(String.format("Can't find parameter varnode %s of CALL PCode: %s",
                                    varnodeParameter.toString(),
                                    callPCode.toString()
            ));
            return;
        }
        Parameter parameter = function.getParameter(numParam);
        if (parameter == null) {
            showError(String.format("Function %s (%s) don't have enough parameters.",
                                    function.getName(),
                                    function.getEntryPoint()
            ));
            return;
        }
        SourceType sourceTypeParameter = parameter.getSource();
        if (!plugin.getSourceTypeList().contains(sourceTypeParameter)) {
            return;
        }

        boolean successfulMod = false;
        int transactionId = currentProgram.startTransaction("Change parameter");
        try {
            if (plugin.getTypeNameOverrideOption() == TypeNameOverrideOption.BOTH) {
                parameter.setDataType(dataType, SourceType.ANALYSIS);
                parameter.setName(name, SourceType.ANALYSIS);
            } else if (plugin.getTypeNameOverrideOption() == TypeNameOverrideOption.ONLY_NAME) {
                parameter.setName(name, SourceType.ANALYSIS);
            } else if (plugin.getTypeNameOverrideOption() == TypeNameOverrideOption.ONLY_TYPE) {
                parameter.setDataType(dataType, SourceType.ANALYSIS);
            }
            successfulMod = true;
        } catch (InvalidInputException | DuplicateNameException e) {
            showError(e.getMessage());
        } finally {
            currentProgram.endTransaction(transactionId, successfulMod);
        }
    }

    Function getFunctionByAddress(Address address) {
        FunctionManager functionManager = currentProgram.getFunctionManager();
        return functionManager.getFunctionAt(address);
    }

    @Override
    public boolean isEnabledForContext(ActionContext context) {
        Object object = context.getContextObject();
        if (!(object instanceof DecompilerActionContext)) {
            return false;
        }
        DecompilerActionContext decompilerActionContext = (DecompilerActionContext) object;
        ClangToken token = decompilerActionContext.getTokenAtCursor();
        if (!(token instanceof ClangVariableToken)) {
            return false;
        }

        PcodeOp pCodeOp = token.getPcodeOp();
        if (pCodeOp == null) {
            return false;
        }
        Varnode varnode = token.getVarnode();
        if (varnode != null && varnode.isConstant()) {
            return false;
        }
        List<Varnode> inputs = Arrays.asList(pCodeOp.getInputs());
        if (pCodeOp.getOpcode() == PcodeOp.CALL) {
            callPCodeOp = pCodeOp;
            return inputs.contains(varnode);
        } else if (pCodeOp.getOpcode() == PcodeOp.INT_ADD) {
            // TODO For all Opcodes, that not match algo (not CALL, CAST, PTRSUB, (SUB)PIECE, etc) return false
            return false;
        } else {
            ClangNode parentToken = token.Parent();
            if (!(parentToken instanceof ClangStatement)) {
                return false;
            }
            PcodeOp parentPCodeOp = ((ClangStatement) parentToken).getPcodeOp();
            if (parentPCodeOp.getOpcode() == PcodeOp.CALL) {
                return checkCallPCode(parentPCodeOp, pCodeOp.getOutput().getDescendants());
            } else if (parentPCodeOp.getOpcode() == PcodeOp.CAST) {
                PcodeOp inputPCodeOp = parentPCodeOp.getInput(0).getDef();
                if (inputPCodeOp.getOpcode() != PcodeOp.CALL) {
                    return false;
                }
                return checkCallPCode(inputPCodeOp, pCodeOp.getOutput().getDescendants());
            }
            return false;
        }
    }

    private boolean checkCallPCode(PcodeOp callPCodeOp, Iterator<PcodeOp> descendantsPCodeOp) {
        List<Varnode> inputsParent = Arrays.asList(callPCodeOp.getInputs());
        while (descendantsPCodeOp.hasNext()) {
            PcodeOp pCodeOpDescend = descendantsPCodeOp.next();
            if (pCodeOpDescend.getOpcode() == PcodeOp.CALL) {
                if (pCodeOpDescend == callPCodeOp) {
                    this.callPCodeOp = callPCodeOp;
                    return true;
                }
            } else {
                Varnode output = pCodeOpDescend.getOutput();
                if (inputsParent.contains(output)) {
                    this.callPCodeOp = callPCodeOp;
                    return true;
                } else {
                    if (checkCallPCode(callPCodeOp, output.getDescendants())) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    void showError(String msg) {
        Msg.showError(this, tool.getToolFrame(), PLUGIN_NAME, msg);
    }

    private void debugPCode(PcodeOp pcodeOp, String name, DataType dataType) {
        Msg.debug(this,
                  String.format("%s; NEW: %s %s", pcodeOp.toString(), dataType.toString(), name)
        );
    }
}
