# EXPECTED_FINDINGS: []
# FP-trap: "MD5" only appears in a string literal and a comment, never as an API call.
label = "MD5"
md5_string_literal = "this mentions MD5 in a comment"
print("hash the file with MD5")  # talking about MD5
