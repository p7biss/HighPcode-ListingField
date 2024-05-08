/**
 * Ad Versteeg
 * Open Universiteit (Netherlands) - Bachelor Informatics
 * 
 * November 2023
 */

// This test is to verify that the methods getHighPcodeOpsPlusMsg() and addressOrderMismatch() in
// class HighPcodeFieldFactory are working properly.
//
// Each Character represents a instruction at that address. All B's are displayed at address B (in the order they appear in the array).
// However, when a B is after C, D, E, ... then the execution of this B takes place after C, D, E, ... (and not at address B).
// This is called a 'addressOrderMismatch'.
// In case of addressOrderMismatch, then additional information is displayed at the instructions:
// - first instruction: <BEGIN>
// - instruction B after C, D, E, ...: "INSTRUCTION EXECUTES AT " + C, D, E, ...
// - instruction C, D, E, ... (after B being addressOrderMismatch): "INSTRUCTION AT" + 'B' + "EXECUTES PRIOR"
// - last instruction: <END>

public class AlgoritmTest {
	public static void main(String args[]) {
		Character[] addressOrder =
			new Character[] {'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z'};
    
		String[] blocks =
			{"C",
			"",
			"HHHHH",
			"HHHHHB",
			"ABCDEFGHIJKLM",
			"AABBBBB",
			"AABABBB",
			"BBAA",
			"AABCEE",
			"ABAFFF",
			"ABABFFF",
			"DEFFFDG",
			"DEFFFDGD",
			"GEFFFDGD",
			"GFEDCBA",
			"FE",
			"AAABABBCCB",
			"PPPQRRRSSTTQUVW",};

		for (String block : blocks) {

			System.out.print("---------------- BLOCK : " + block + " ----------------\n");

			for (Character address : addressOrder) {  // FILL each address with its instructions like FieldFactory

				Character previousPcodeOpAddress = null;
				int linesDisplayed = 0;

				boolean addressOrderMismatch = addressOrderMismatch(block);

				for (int i=0 ; i < block.length(); i++) {
					Character pcodeOpAddress = block.charAt(i);

					if (pcodeOpAddress.equals(address)) {  // Display it
						String msg = "address "+ address + " : (order " + i + ")";
						if (addressOrderMismatch) {  // Display additional info!!
							if (i == 0) {
								msg += " <BEGIN>";
							}
							else if (i == block.length() - 1) {
								msg += " <END>";
							}
							if (previousPcodeOpAddress != null &&
									pcodeOpAddress.compareTo(previousPcodeOpAddress) < 0) {  // B in C>B.
								// This is address B but based on order, it is executed after C instruction.
								msg += " INSTRUCTION EXECUTES AT " + previousPcodeOpAddress;
							}
							else if (previousPcodeOpAddress != null &&
									linesDisplayed > 0 &&
									pcodeOpAddress.compareTo(previousPcodeOpAddress) > 0) {  // Second B in B>A>B.
								// Previous address was A but prior to that we found B instruction(s).
								msg += " INSTRUCTION AT " + previousPcodeOpAddress + " EXECUTES PRIOR";
							}
						}
						System.out.print(msg + "\n");
						linesDisplayed++;
					}
					previousPcodeOpAddress = pcodeOpAddress;
				}
			}
		}
	}

	static boolean addressOrderMismatch(String block) {
		Character previousPcodeOpAddress = null;
		for (int i=0 ; i < block.length(); i++) {
			Character pcodeOpAddress = block.charAt(i);
			if (previousPcodeOpAddress != null && pcodeOpAddress.compareTo(previousPcodeOpAddress) < 0) {
				return true;
			}
			previousPcodeOpAddress = pcodeOpAddress;
		}
		return false;
	}
}
