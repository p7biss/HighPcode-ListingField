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

import java.util.*;
import java.math.BigInteger;
import java.time.LocalDateTime;

import docking.widgets.fieldpanel.field.*;
import docking.widgets.fieldpanel.support.FieldLocation;
import ghidra.GhidraOptions;
import ghidra.app.util.ListingHighlightProvider;
import ghidra.app.util.pcode.AttributedStringPcodeFormatter;
import ghidra.app.util.viewer.field.ListingColors.HighPcodeColors;
import ghidra.app.util.viewer.field.ListingColors.MnemonicColors; 
import ghidra.app.util.viewer.format.FieldFormatModel;
import ghidra.app.util.viewer.options.OptionsGui;
import ghidra.app.util.viewer.proxy.*;
import ghidra.framework.options.Options;
import ghidra.framework.options.ToolOptions;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.util.ProgramLocation;
import ghidra.util.NumericUtilities;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.flatapi.FlatProgramAPI;

/**
 * HighPcode field factory.
 */
public class HighPcodeFieldFactory extends FieldFactory {
	public static final String FIELD_NAME = "HighPCode";

	private final static String GROUP_TITLE = "HighPcode Field";
	public final static String DISPLAY_ALTERNATIVE_SYNTAX =
			GROUP_TITLE + Options.DELIMITER + "Display Alternative Syntax";
	public static final String DISPLAY_RAW_HIGHPCODE =
			GROUP_TITLE + Options.DELIMITER + "Display Raw HighPcode";
	public final static String MAX_DISPLAY_LINES_MSG =
			GROUP_TITLE + Options.DELIMITER + "Maximum Lines To Display";

	public final static int MAX_DISPLAY_LINES = 50;
	public final static boolean DEBUG_MODE = false;

	private AttributedStringPcodeFormatter formatter;
	boolean displayAlternativeSyntax = true;
	int maxDisplayLines = Integer.MAX_VALUE;

	//private Function funcGlobal;   WEGWEGWEG
	private HighFunction highGlobal;
	//private Instruction instruction;   WEGWEGWEG

	public HighPcodeFieldFactory() {
		super(FIELD_NAME);
		setWidth(300);
	}

	public HighPcodeFieldFactory(String name, FieldFormatModel model,
			ListingHighlightProvider highlightProvider, Options displayOptions, Options fieldOptions) {

		super(name, model, highlightProvider, displayOptions, fieldOptions);
		setWidth(300);

		style = displayOptions.getInt(OptionsGui.BYTES.getStyleOptionName(), -1);
		formatter = new AttributedStringPcodeFormatter();

		setOptions(fieldOptions);
		formatter.setFontMetrics(getMetrics());
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

		if(DEBUG_MODE){
			System.out.print("\n---------------------------------------------------------------- ");
			System.out.print("\n-------------- HighPcodeFieldFactory() getField() -------------- " + LocalDateTime.now().toLocalTime());
			System.out.print("\n------------- instruction address = " + instruction.getAddress() + "------------------- ");
			System.out.print("\n---------------------------------------------------------------- \n");
		}
		DecompInterface ifc = new DecompInterface();
		DecompileOptions options = new DecompileOptions();   // WAAROM NODIG?
		ifc.setOptions(options);

		//FlatProgramAPI flat = new FlatProgramAPI (instruction.getProgram());   WEGWEGWEG
		//Function func = flat.getFunctionContaining(instruction.getAddress());  WEGWEGWEG
		
		// ZOUDEN WE DIT WILLEN: ?
		
		Function func = getFunc(instruction);

		if (func == null) {
			System.out.print("(func == null): No Function at current location\n");
			return null;
		}
		try {
			highGlobal = getHighFunc(instruction);
		} catch (DecompileException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		ArrayList<TextFieldElement> textFieldElements = new ArrayList<>();
		List<PcodeOp> highPcodeOpList = getHighPcode(highGlobal, instruction.getAddress());

		if (displayAlternativeSyntax) {  // show alternative syntax (identical to 'Graph Control Flow' syntax)
			//List<PcodeOp> pcodeOpList = getHighPcode(instruction.getAddress());
			PcodeOp[] pcodeOpArray = highPcodeOpList.toArray(new PcodeOp[highPcodeOpList.size()]);

			int lineCnt = pcodeOpArray.length;
			for (int i = 0 ; i < lineCnt && i < maxDisplayLines ; i++) {
				AttributedString as = formatOp(pcodeOpArray[i]);
				textFieldElements.add(new TextFieldElement(as, i, 0));
			}
		}
		else {  // show Pcode syntax
			List<AttributedString> highPcodeListing = formatter.formatOps(instruction.getProgram().getLanguage(),
					//instruction.getProgram().getAddressFactory(), getHighPcode(instruction.getAddress()));
					instruction.getProgram().getAddressFactory(), highPcodeOpList);

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

	List<PcodeOp> getHighPcode(HighFunction hf, Address address) {    // HighFunction ook maar toegevoegd..
		List<PcodeOp> highPcodeOps = new ArrayList<>();

		//Iterator<PcodeBlockBasic> pblockIter = hfunc.getBasicBlocks().iterator();
		Iterator<PcodeBlockBasic> pblockIter = hf.getBasicBlocks().iterator();
		
		if(DEBUG_MODE){
			System.out.print("getHighPcode : address = " + address + "\n");
			//System.out.print("getHighPcode : hf = " + hf.toString() + "\n");
		}
		
		while (pblockIter.hasNext()) {
			PcodeBlockBasic block = pblockIter.next();
			Iterator<PcodeOp> opIter = block.getIterator();

			while (opIter.hasNext()) {
				PcodeOp op = opIter.next();
				Address op_address = op.getSeqnum().getTarget();
				
				if(DEBUG_MODE){
					System.out.print("getHighPcode : op_address = " + op_address + "\n");
				}
				
				if (op_address.equals(address)) {
					highPcodeOps.add(op);
				}
			}
		}
		return highPcodeOps;
	}

	private AttributedString formatOp(PcodeOp op) {
		List<AttributedString> lineList = new ArrayList<>();  // one line
		Varnode output = op.getOutput();

		if (output != null) {
			lineList.add(translateVarnode(output, true));
			lineList.add(new AttributedString(" = ", ListingColors.SEPARATOR, getMetrics()));
		}
		lineList.add(formatOpMnemonic(op));
		lineList.add(new AttributedString(" ", ListingColors.SEPARATOR, getMetrics()));
		
		Varnode[] inputs = op.getInputs();
		for (int i = 0; i < inputs.length; i++) {
			if (i != 0) {
				lineList.add(new AttributedString(",", ListingColors.SEPARATOR, getMetrics()));
			}
			lineList.add(translateVarnode(inputs[i], true));
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
		Program prog = highGlobal.getFunction().getProgram();
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
			Register reg = prog.getRegister(addr, node.getSize());
			if (reg == null) {
				reg = prog.getRegister(addr);
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
		Program program = instr.getProgram();
		HighFunction highFunc = null;
		
		try {  /// ZOJUIST TOEGEVOEGD    .................................
			highFunc = getHighFunc(instr);
		} catch (DecompileException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		if(DEBUG_MODE){
			System.out.print("getProgramLocation : highFunc = " + highFunc.toString() + "\n");
		}

		//List<PcodeOp> dinges = getHighPcode(highFunc, instr.getAddress());    // WEGWEGWEG
		
		if(DEBUG_MODE){
			System.out.print("getProgramLocation : getHighPcode(..) = " + getHighPcode(highFunc, instr.getAddress()) + "\n");
		}

		
		List<AttributedString> attributedStrings = formatter.formatOps(program.getLanguage(),
				//program.getAddressFactory(), getHighPcode(instr.getAddress()));
				program.getAddressFactory(), getHighPcode(highFunc, instr.getAddress()));
		List<String> strings = new ArrayList<>(attributedStrings.size());
		for (AttributedString attributedString : attributedStrings) {
			strings.add(attributedString.getText());
		}
		if(DEBUG_MODE){
			System.out.print("getProgramLocation : strings = " + strings + "\n");
		}

		//return new HighPcodeFieldLocation(program, instr.getMinAddress(), strings, row, col);   // ORIG; maar klopt dit wel?  WEGWEGWEG
		return new HighPcodeFieldLocation(program, instr.getAddress(), strings, row, col);
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
			if (optionName.equals(MAX_DISPLAY_LINES_MSG)
					|| optionName.equals(DISPLAY_RAW_HIGHPCODE)
					|| optionName.equals(DISPLAY_ALTERNATIVE_SYNTAX)) {
				setOptions(options);
				model.update();
			}
		}
	}

	private void setOptions(Options fieldOptions) {
		fieldOptions.registerOption(DISPLAY_ALTERNATIVE_SYNTAX, true, null,
				"Alternative syntax like in Graph Control Flow");
		fieldOptions.registerOption(DISPLAY_RAW_HIGHPCODE, false, null,
				"Display raw High Pcode (only affects standard High Pcode syntax)");
		fieldOptions.registerOption(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES, null,
				"Max number line of High Pcode to display");

		displayAlternativeSyntax = fieldOptions.getBoolean(DISPLAY_ALTERNATIVE_SYNTAX, true);
		boolean displayRaw = fieldOptions.getBoolean(DISPLAY_RAW_HIGHPCODE, false);
		maxDisplayLines = fieldOptions.getInt(MAX_DISPLAY_LINES_MSG, MAX_DISPLAY_LINES);

		formatter.setOptions(maxDisplayLines, displayRaw);
	}

	private Function getFunc(Instruction instr) {
		FlatProgramAPI flat = new FlatProgramAPI (instr.getProgram());
		
		//return flat.getFunctionContaining(instr.getAddress();    NOG AANPASSEN; HIERONDER WEG DUS
		
		Function func = flat.getFunctionContaining(instr.getAddress());
		return func;
	}
	
	
	private HighFunction getHighFunc(Instruction instr) throws DecompileException {
		DecompileOptions options = new DecompileOptions();
		DecompInterface ifc = new DecompInterface();
		ifc.setOptions(options);

		if (!ifc.openProgram(instr.getProgram())) {
			throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
		}
		ifc.setSimplificationStyle("decompile"); // show HighVar names
		//ifc.setSimplificationStyle("normalize");
		
		//FlatProgramAPI flat = new FlatProgramAPI (instr.getProgram());       // VERVANGEN DOOR getFunction()..
		//Function function = flat.getFunctionContaining(instr.getAddress());  // VERVANGEN DOOR getFunction()..
		
		Function function = getFunc(instr);

		DecompileResults res = ifc.decompileFunction(function, 30, null);  // hierbij de globale func vervangen door lokale (+flat geintroduceerd)
		return res.getHighFunction();
	}
}