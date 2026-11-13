# PatchProof demo recording script.
#
# Record with: vhs demo/demo.tape
# Requires: https://github.com/charmbracelet/vhs (single binary)
#
# Output lands at demo/demo.gif — referenced at the top of the README.

Output demo/demo.gif

Set FontSize 20
Set Width 1200
Set Height 640
Set Padding 24
Set Shell pwsh
Set Theme "Catppuccin Mocha"

Type "patchproof run --app ./tests/fixtures/vuln-fastapi-sqli/app --poc ./tests/fixtures/vuln-fastapi-sqli/poc.txt"
Enter

# --- Stage: sandbox spin-up ---
Sleep 3s

# --- Stage: red baseline ---
Sleep 4s

# --- Stage: AI patch loop (LLM skipped in demo; hardcoded patch) ---
Sleep 4s

# --- Stage: green verdict + artifacts ---
Sleep 5s

Type "Get-Content patchproof-out/*/attestation.json"
Enter
Sleep 4s
