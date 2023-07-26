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

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.app.services.QueryData;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.util.ProgramLocation;
import ghidra.util.StringUtilities;

import java.awt.event.MouseEvent;
import java.util.List;

public class HighPcodeFieldMouseHandler implements FieldMouseHandlerExtension {

	private final static Class<?>[] SUPPORTED_CLASSES = new Class[] { HighPcodeFieldLocation.class };

	@Override
	public boolean fieldElementClicked(Object clickedObject, Navigatable sourceNavigatable,
			ProgramLocation programLocation, MouseEvent mouseEvent, ServiceProvider serviceProvider) {

		if (mouseEvent.getClickCount() != 2 || mouseEvent.getButton() != MouseEvent.BUTTON1) {
			return false;
		}

		HighPcodeFieldLocation highPcodeLocation = (HighPcodeFieldLocation) programLocation;
		List<String> highPcodeStrings = highPcodeLocation.getHighPcodeStrings();
		int row = highPcodeLocation.getRow();

		//System.out.print("fieldElementClicked : highPcodeLocation.getAddress = " + highPcodeLocation.getAddress() + "\n");
		//System.out.print("fieldElementClicked : aantal highPcodeStrings = " + highPcodeStrings.size() + "\n");
		//System.out.print("fieldElementClicked : getRow() = " + row + "\n");
		
		String highPcodeString = highPcodeStrings.get(row);
		int column = highPcodeLocation.getCharOffset();
		String word = StringUtilities.findWord(highPcodeString, column);

		return checkWord(word, serviceProvider, sourceNavigatable);
	}

	protected boolean checkWord(String wordString, ServiceProvider serviceProvider,
			Navigatable sourceNavigatable) {

		if (wordString == null) {
			return false;
		}

		ProgramLocation location = sourceNavigatable.getLocation();
		GoToService goToService = serviceProvider.getService(GoToService.class);
		if (goToService == null) {
			return false;
		}

		QueryData queryData = new QueryData(wordString, false);
		return goToService.goToQuery(sourceNavigatable, location.getAddress(), queryData, null, null);
	}

	@Override
	public Class<?>[] getSupportedProgramLocations() {
		return SUPPORTED_CLASSES;
	}
}
