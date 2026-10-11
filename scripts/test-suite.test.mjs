// Import all suites explicitly; node:test runs the registered tests and sets exit status.
import '../src/safeContext/prepareSafeContext.test.ts'
import '../src/safeContext/gateway.test.ts'
import '../src/safeContext/claudeAnalyzer.test.ts'
import '../src/scanner/scanner.test.ts'
import '../src/scanner/quality.test.ts'
import '../src/app/app.test.ts'
