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
import ghidra.framework.options.SaveState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;

public class HighPcodeFieldLocation extends ProgramLocation {

	private List<String> highPcodeStrings;

	public HighPcodeFieldLocation(Program program, Address addr, List<String> highPcodeStrings, int row,
			int charOffset) {
		super(program, addr, row, 0, charOffset);
		
		this.highPcodeStrings = highPcodeStrings;
	}

	/**
	 * Get the row within a group of pcode strings.
	 */
	public HighPcodeFieldLocation() {
		// for deserialization
	}

	public List<String> getHighPcodeStrings() {
		return Collections.unmodifiableList(highPcodeStrings);
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = super.hashCode();
		result = prime * result + ((highPcodeStrings == null) ? 0 : highPcodeStrings.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (!super.equals(obj))
			return false;
		if (getClass() != obj.getClass())
			return false;
		HighPcodeFieldLocation other = (HighPcodeFieldLocation) obj;
		if (highPcodeStrings == null) {
			if (other.highPcodeStrings != null)
				return false;
		}
		else if (!highPcodeStrings.equals(other.highPcodeStrings))
			return false;
		return true;
	}

	@Override
	public void saveState(SaveState obj) {
		super.saveState(obj);
		obj.putStrings("_HIGHPCODE_STRINGS", highPcodeStrings.toArray(new String[highPcodeStrings.size()]));
	}

	@Override
	public void restoreState(Program p, SaveState obj) {
		super.restoreState(p, obj);
		
		String[] strings = obj.getStrings("_HIGHPCODE_STRINGS", new String[0]);
		highPcodeStrings = new ArrayList<String>(strings.length);
		for (String string : strings) {
			highPcodeStrings.add(string);
		}
	}

	@Override
	public String toString() {
		return super.toString() + ", High Pcode sample: " + getHighPcodeSample();
	}

	private String getHighPcodeSample() {
		if (highPcodeStrings.size() == 0) {
			return "<no highPcode>";
		}
		return highPcodeStrings.get(0);
	}
}
