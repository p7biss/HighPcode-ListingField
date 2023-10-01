/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.util.viewer.field;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.math.BigInteger;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.pcode.AttributedStringHighPcodeFormatter;
import ghidra.app.util.viewer.field.ListingColors.HighPcodeColors;
import ghidra.app.util.viewer.field.ListingColors.MnemonicColors; 
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.ProxyObj;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramLocation;
import ghidra.util.NumericUtilities;

/**
 * HighPcode field factory.
 */
public class HighPcodeFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "HighPCode";

	private final static String GROUP_TITLE = "HighPcode Field";
	public final static String DISPLAY_ALTERNATIVE_SYNTAX =
			GROUP_TITLE + Options.DELIMITER + "Display Alternative Syntax";
	public final static String MAX_DISPLAY_LINES_MSG =
			GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";

	public final static int MAX_DISPLAY_LINES = 50;

	boolean displayAlternativeSyntax = true;
	int maxDisplayLines = Integer.MAX_VALUE;

	private Program program;
	private DecompInterface ifc;
	private AttributedStringHighPcodeFormatter formatter;

	class PcodeOpPlusMessage {   // used for the alternative syntax
		PcodeOp pcodeOp = null;
		String  message = null;  // to store message related to pcodeOp (if any)

		public PcodeOpPlusMessage(PcodeOp op, String msg) {
			pcodeOp = op;
			message = msg;
		}
	}

	public HighPcodeFieldFactory() {
		super(FIELD_NAME);
		setWidth(300);
	}

	public HighPcodeFieldFactory(String name, FieldFormatModel model,
			ListingHighlightProvider highlightProvider, Options displayOptions, Options fieldOptions) {
		super(name, model, highlightProvider, displayOptions, fieldOptions);
		setWidth(300);

		style = displayOptions.getInt(OptionsGui.BYTES.getStyleOptionName(), -1);
		formatter = new AttributedStringHighPcodeFormatter();

		setOptions(fieldOptions);
		formatter.setFontMetrics(getMetrics());

		DecompileOptions options = new DecompileOptions();
		ifc = new DecompInterface();
		ifc.setOptions(options);
		ifc.setSimplificationStyle("decompile"); // show HighVar names
		//ifc.setSimplificationStyle("normalize");
	}

	@Override
	public FieldFactory newInstance(FieldFormatModel myModel, ListingHighlightProvider highlightProvider,
			ToolOptions options, ToolOptions fieldOptions) {
		return new HighPcodeFieldFactory(FIELD_NAME, myModel, highlightProvider, options, fieldOptions);
	}

	@Override
	public ListingField getField(ProxyObj<?> proxy, int varWidth) {
		Object obj = proxy.getObject();

		if (!enabled || !(obj instanceof Instruction)) {
			return null;
		}
		Instruction instruction = (Instruction) obj;
		program = instruction.getProgram();

		try {
			if (!ifc.openProgram(instruction.getProgram())) {
				throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
			}
		} catch (DecompileException e) {
			e.printStackTrace();
		}

		Function func = getFunc(instruction);
		if (func == null) {
			System.out.print("(func == null): No Function at current location\n");
			return null;
		}

		HighFunction highFunc = getHighFunc(instruction);

		ArrayList<TextFieldElement> textFieldElements = new ArrayList<>();

		if (displayAlternativeSyntax) {  // display alternative syntax (like 'Graph Control Flow') 
			List<PcodeOpPlusMessage> highPcodeOpsPlusMessages = getHighPcodeOpsPlusMsg(highFunc, instruction.getAddress());

			PcodeOpPlusMessage[] pcodeOpPlusMsgArray = highPcodeOpsPlusMessages.toArray(new PcodeOpPlusMessage[highPcodeOpsPlusMessages.size()]);

			int lineCnt = pcodeOpPlusMsgArray.length;

			for (int i = 0 ; i < lineCnt && i < maxDisplayLines ; i++) {
				AttributedString as = formatOp(pcodeOpPlusMsgArray[i]);
				textFieldElements.add(new TextFieldElement(as, i, 0));
			}
		}
		else {  // display Pcode syntax
			List<PcodeOp> highPcodeOps = getHighPcodeOps(highFunc, instruction.getAddress());

			List<AttributedString> highPcodeListing = formatter.formatOps(program.getLanguage(),
					program.getAddressFactory(), highPcodeOps);

			int lineCnt = highPcodeListing.size();
			for (int i = 0; i < lineCnt; i++) {
				textFieldElements.add(new TextFieldElement(highPcodeListing.get(i), i, 0));
			}
		}

		if (textFieldElements.size() > 0) {
			FieldElement[] fieldElements = textFieldElements.toArray(new FieldElement[textFieldElements.size()]);
			return ListingTextField.createMultilineTextField(this, proxy, fieldElements,
					startX + varWidth, width, Integer.MAX_VALUE, hlProvider);
		}
		return null;
	}

	List<PcodeOpPlusMessage> getHighPcodeOpsPlusMsg(HighFunction hf, Address address) {
		// PcodeOp.getSeqnum().getOrder() represents the order for execution of PcodeOp's.
		// Order of PcodeOp addresses ideally should correspond to PcodeOp.getSeqnum().getOrder().
		// Example: A and B are addresses. We expect the order A>B>B in a block. Issue: Occasionally B>A>B might occur!
		// So, when representing High Pcode on address level, an incorrect execution order might be represented.
		// In these cases, a warning message is added to the corresponding instructions A and B.

		List<PcodeOpPlusMessage> highPcodeOpsPlusMsg = new ArrayList<>();

		Iterator<PcodeBlockBasic> pblockIter = hf.getBasicBlocks().iterator();

		while (pblockIter.hasNext()) {
			PcodeBlockBasic block = pblockIter.next();
			Iterator<PcodeOp> opIter = block.getIterator();

			Address previousPcodeOpAddress = null;
			int linesToDisplay = 0;

			boolean addressOrderMismatch = addressOrderMismatch(block);
			int blockSize = -1;
			if (addressOrderMismatch) {
				blockSize = countBlockPcodeOps(block);
			}

			while (opIter.hasNext()) {
				PcodeOp pcodeOp = opIter.next();
				Address pcodeOpAddress = pcodeOp.getSeqnum().getTarget();
				String msg = null;

				if (pcodeOpAddress.equals(address)) {   // Then display this pcodeOp
					if (addressOrderMismatch) {         // Then display additional info
						msg = "(order " + pcodeOp.getSeqnum().getOrder() + ")";
						if (pcodeOp.getSeqnum().getOrder() == 0) {
							msg += " <BEGIN>";
						}
						else if (pcodeOp.getSeqnum().getOrder() == blockSize-1) {
							msg += " <END>";
						}
						if (previousPcodeOpAddress != null &&
								pcodeOpAddress.compareTo(previousPcodeOpAddress) < 0) {  // B in C>B.
							// Address B but based on order, it executes after C.
							msg += " INSTRUCTION EXECUTES AT " + previousPcodeOpAddress;
						}
						else if (previousPcodeOpAddress != null &&
								linesToDisplay > 0 &&
								pcodeOpAddress.compareTo(previousPcodeOpAddress) > 0) {  // Second B in B>A>B.
							// Previous address was A but prior to that we found B instruction.
							msg += " INSTRUCTION AT " + previousPcodeOpAddress + " EXECUTES PRIOR";
						}
					}
					highPcodeOpsPlusMsg.add(new PcodeOpPlusMessage(pcodeOp, msg));
					linesToDisplay++;
				}
				previousPcodeOpAddress = pcodeOpAddress;
			}
		}
		return highPcodeOpsPlusMsg;
	}

	int countBlockPcodeOps (PcodeBlockBasic block) {
		int count = 0;
		Iterator<PcodeOp> opIter = block.getIterator();
		while (opIter.hasNext()) {
			count++;
			opIter.next();
		}
		return count;
	}

	boolean addressOrderMismatch(PcodeBlockBasic block) {
		Iterator<PcodeOp> opIter = block.getIterator();

		Address previousPcodeOpAddress = null;

		while (opIter.hasNext()) {
			PcodeOp pcodeOp = opIter.next();
			Address pcodeOpAddress = pcodeOp.getSeqnum().getTarget();

			if (previousPcodeOpAddress != null && pcodeOpAddress.compareTo(previousPcodeOpAddress) < 0) {
				return true;  // addresses are not in order
			}
			previousPcodeOpAddress = pcodeOpAddress;
		}
		return false;
	}

	List<PcodeOp> getHighPcodeOps(HighFunction hf, Address address) {
		List<PcodeOp> highPcodeOps = new ArrayList<>();
		Iterator<PcodeBlockBasic> pblockIter = hf.getBasicBlocks().iterator();

		while (pblockIter.hasNext()) {
			PcodeBlockBasic block = pblockIter.next();
			Iterator<PcodeOp> opIter = block.getIterator();

			while (opIter.hasNext()) {
				PcodeOp pcodeOp = opIter.next();
				Address pcodeOpAddress = pcodeOp.getSeqnum().getTarget();

				if (pcodeOpAddress.equals(address)) {
					highPcodeOps.add(pcodeOp);   // to be displayed
				}
			}
		}
		return highPcodeOps;
	}

	private AttributedString formatOp(PcodeOpPlusMessage op) {
		List<AttributedString> lineList = new ArrayList<>();  // lineList will contain 1 line
		Varnode output = op.pcodeOp.getOutput();

		if (output != null) {
			lineList.add(translateVarnode(output, true));
			lineList.add(new AttributedString(" = ", ListingColors.SEPARATOR, getMetrics()));
		}
		lineList.add(formatOpMnemonic(op.pcodeOp));
		lineList.add(new AttributedString(" ", ListingColors.SEPARATOR, getMetrics()));

		Varnode[] inputs = op.pcodeOp.getInputs();
		for (int i = 0; i < inputs.length; i++) {
			if (i != 0) {
				lineList.add(new AttributedString(",", ListingColors.SEPARATOR, getMetrics()));
			}
			lineList.add(translateVarnode(inputs[i], true));
		}

		if (op.message != null) {
			lineList.add(new AttributedString(" ", ListingColors.BACKGROUND, getMetrics()));
			lineList.add(new AttributedString(op.message, ListingColors.SEPARATOR, getMetrics(), true, ListingColors.SEPARATOR));
		}
		return new CompositeAttributedString(lineList);
	}

	private AttributedString formatOpMnemonic(PcodeOp op) {
		List<AttributedString> lineList = new ArrayList<>();
		lineList.add(new AttributedString(op.getMnemonic(), MnemonicColors.NORMAL, getMetrics()));
		Varnode output = op.getOutput();
		String size = null;
		if (output != null) {
			switch (output.getSize()) {
			case 1:
				size = "b";
				break;
			case 2:
				size = "w";
				break;
			case 4:
				size = "d";
				break;
			case 8:
				size = "q";
			}
			if (size != null) {
				lineList.add(new AttributedString(".", ListingColors.SEPARATOR, getMetrics()));
				lineList.add(new AttributedString(size, MnemonicColors.NORMAL, getMetrics()));
			}
		}
		return new CompositeAttributedString(lineList);
	}

	private AttributedString translateVarnode(Varnode node, boolean useVarName) {
		if (node == null) {
			return new AttributedString("null", ListingColors.REF_BAD, getMetrics());
		}
		Address addr = node.getAddress();
		if (node.isConstant()) {
			String str = "#" + NumericUtilities.toHexString(addr.getOffset(), node.getSize());
			return new AttributedString(str, ListingColors.CONSTANT, getMetrics());
		}
		else if (node.isUnique()) {
			String str = "u_" + Long.toHexString(addr.getOffset());
			return new AttributedString(str, HighPcodeColors.VARNODE, getMetrics());
		}
		else if (addr.isRegisterAddress()) {
			Register reg = program.getRegister(addr, node.getSize());
			if (reg == null) {
				reg = program.getRegister(addr);
			}
			if (reg != null) {
				return new AttributedString(reg.getName(), ListingColors.REGISTER, getMetrics());
			}
		}
		else if (addr.isStackAddress()) {
			if (useVarName) {
				HighVariable var = node.getHigh();
				if (var != null) {
					return new AttributedString(var.getName(), HighPcodeColors.VARNODE, getMetrics());
				}
			}
			String str = "Stack[" + NumericUtilities.toSignedHexString(addr.getOffset()) + "]";
			return new AttributedString(str, HighPcodeColors.ADDRESS_SPACE, getMetrics());
		}
		else if (addr.isMemoryAddress()) {
			return new AttributedString(addr.toString(true), HighPcodeColors.ADDRESS_SPACE, getMetrics());
		}
		return new AttributedString(node.toString(), HighPcodeColors.VARNODE, getMetrics());
	}

	@Override
	public FieldLocation getFieldLocation(ListingField bf, BigInteger index, int fieldNum,
			ProgramLocation loc) {

		if (loc instanceof HighPcodeFieldLocation) {
			return new FieldLocation(index, fieldNum, ((HighPcodeFieldLocation) loc).getRow(),
					((HighPcodeFieldLocation) loc).getCharOffset());
		}
		return null;
	}

	@Override
	public ProgramLocation getProgramLocation(int row, int col, ListingField listingField) {
		ProxyObj<?> proxy = listingField.getProxy();
		Object obj = proxy.getObject();

		if (!(obj instanceof Instruction)) {
			return null;
		}
		if (row < 0 || col < 0) {
			return null;
		}

		Instruction instr = (Instruction) obj;
		Program prog = instr.getProgram();

		HighFunction highFunc = getHighFunc(instr);

		List<AttributedString> attributedStrings = formatter.formatOps(prog.getLanguage(),
				prog.getAddressFactory(), getHighPcodeOps(highFunc, instr.getAddress()));
		List<String> strings = new ArrayList<>(attributedStrings.size());
		for (AttributedString attributedString : attributedStrings) {
			strings.add(attributedString.getText());
		}

		return new HighPcodeFieldLocation(prog, instr.getAddress(), strings, row, col);
	}

	@Override
	public boolean acceptsType(int category, Class<?> proxyObjectClass) {
		return (CodeUnit.class.isAssignableFrom(proxyObjectClass) &&
				(category == FieldFormatModel.INSTRUCTION_OR_DATA ||
				category == FieldFormatModel.OPEN_DATA));
	}

	@Override
	public void displayOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.displayOptionsChanged(options, optionName, oldValue, newValue);
		formatter.setFontMetrics(getMetrics());
	}

	@Override
	public void fieldOptionsChanged(Options options, String optionName, Object oldValue,
			Object newValue) {
		super.fieldOptionsChanged(options, optionName, oldValue, newValue);

		if (options.getName().equals(GhidraOptions.CATEGORY_BROWSER_FIELDS)) {
			if (optionName.equals(MAX_DISPLAY_LINES_MSG) || optionName.equals(DISPLAY_ALTERNATIVE_SYNTAX)) {
				setOptions(options);
				model.update();
			}
		}
	}

	private void setOptions(Options fieldOptions) {
		fieldOptions.registerOption(DISPLAY_ALTERNATIVE_SYNTAX, true, null,
				"Graph Control Flow (alternative) style syntax. Shows warning when execution order deviates from address order. Warning is not shown for Pcode style syntax.");
		fieldOptions.registerOption(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES, null,
				"Max number line of High Pcode to display");

		displayAlternativeSyntax = fieldOptions.getBoolean(DISPLAY_ALTERNATIVE_SYNTAX, true);
		maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES);

		formatter.setOptions(maxDisplayLines, false);
	}

	private Function getFunc(Instruction instr) {
		FlatProgramAPI flat = new FlatProgramAPI (instr.getProgram());
		return flat.getFunctionContaining(instr.getAddress());
	}

	private HighFunction getHighFunc(Instruction instr) {
		Function function = getFunc(instr);

		DecompileResults res = ifc.decompileFunction(function, 30, null);
		return res.getHighFunction();
	}
}