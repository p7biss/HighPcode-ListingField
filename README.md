# HighPcode-ListingField
Repository contains the code for adding the HighPcode ListingField to Ghidra.

In Ghidra Issue #5545 (https://github.com/NationalSecurityAgency/ghidra/issues/5545) I suggest to add ListingField HighPcode to the CodeBrowser window.

This repository contains the files that can be used to add HighPcode to the CodeBrowser.
Like the other ListingFields the functionality supports:
- Options - Listing Display (colors)
- Options - Listing Fields  (settings)

Remarks:
Two HighPcode syntax styles are supported:
- 'alternative' syntax like Decompile window - arrow down (menu) - 'Graph Control Flow'. Using HighPcode colors.
- Pcode syntax. Using Pcode syntax and Pcode colors. Option 'Display Raw HighPcode' can be enabled/disabled.

The preferred syntax style can be set in: Options - Listing Fields - HighPcode Field.

AttributedStringHighPcodeFormatter.java is similar to AttributedStringPcodeFormatter.java, so code is basically duplicated.
