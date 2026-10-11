// Local Node test/CLI loader. Type checking is a separate required verification step.
// Works on Node distributions built without the optional native TypeScript parser.
import { registerHooks } from 'node:module'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
registerHooks({
  load(url, context, nextLoad) {
    if (!url.startsWith('file:') || !/\.tsx?$/.test(url)) return nextLoad(url, context)
    const source = ts.transpileModule(readFileSync(new URL(url), 'utf8'), {
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext, jsx: ts.JsxEmit.ReactJSX },
      fileName: new URL(url).pathname,
    }).outputText
    return { format: 'module', source, shortCircuit: true }
  },
})
