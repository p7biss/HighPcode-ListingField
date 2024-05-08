# HighPcode-ListingField
Repository contains the code for adding the HighPcode ListingField to Ghidra.

In Ghidra Issue #5545 (https://github.com/NationalSecurityAgency/ghidra/issues/5545) it is requested to add ListingField HighPcode to the CodeBrowser window.

This repository contains the files that can be used to make HighPcode available in the CodeBrowser.
Like the other ListingFields the functionality supports:
- Options - Listing Display (colors)
- Options - Listing Fields  (settings)

## HighPcode order inconsistency
The execution order of the HighPcode instructions sometimes deviates from the address based Listing window. In these cases, PcodeOp.getSeqnum().getOrder() does not align with 
PcodeOp addresses. To represent this situation in the Listing window, in case of an order inconsistency, additional information is added to the HighPcode listing field. 
This additional info shows the order number and info when (a) this instruction is processed at an other address, and (b) an instruction from another address is executed prior to this instruction.
A Java test program is available to test the order inconsistency algoritm. Chars in a string like "AABAACCCB" are considered HighPcode instructions in execution order and are outputted in address order.
The additional information is only available for the 'alternative' syntax style (see below). 

## Syntax styles:
Two HighPcode syntax styles are supported:
- 'alternative' syntax like Decompile window - arrow down (menu) - 'Graph Control Flow'.
- Pcode syntax.

The preferred syntax style can be set in: Options - Listing Fields - HighPcode Field.

## Remark
AttributedStringHighPcodeFormatter.java is similar to AttributedStringPcodeFormatter.java, so code is basically duplicated.
