// Reads qmllint's --json report and fails on anything outside the few
// warnings every stock Omarchy QML file also produces:
//
//   missing-property on type "QObject"  Commons.Style groups (font, spacing)
//                                       and the injected `bar` are declared
//                                       as QtObject, so their members are
//                                       invisible to qmllint
//   uncreatable-type PanelWindow        Quickshell's type info marks it so
//   block-scope-var-declaration         the shell's `for (var i ...)` style
const fs = require("node:fs")

const report = JSON.parse(fs.readFileSync(process.argv[2], "utf8"))

function tolerated(warning) {
  if (warning.id === "block-scope-var-declaration") return true
  if (warning.id === "uncreatable-type") return /Type PanelWindow is not creatable/.test(warning.message)
  if (warning.id === "missing-property") return /not found on type "QObject"/.test(warning.message)
  if (warning.type === "info") return warning.id !== "unused-imports"
  return false
}

let failures = 0
let allowed = 0
for (const file of report.files || []) {
  const name = String(file.filename || "").split("/").pop()
  if (file.success === false && (file.warnings || []).length === 0) {
    console.log(`FAIL ${name}: qmllint could not process the file`)
    failures++
  }
  for (const warning of file.warnings || []) {
    if (tolerated(warning)) {
      allowed++
      continue
    }
    failures++
    console.log(`FAIL ${name}:${warning.line}:${warning.column} [${warning.id || warning.type}] ${warning.message.split("\n")[0]}`)
  }
}

console.log(`${(report.files || []).length} files, ${allowed} known-benign warnings, ${failures} failures`)
process.exit(failures > 0 ? 1 : 0)
