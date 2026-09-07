// EXPECTED_FINDINGS: []
// FP-trap: "DES" only inside a string literal / comment.
String label = "DES";
String commentMention = "we are NOT using DES here";
