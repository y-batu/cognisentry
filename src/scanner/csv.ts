// Small RFC 4180 parser mirroring Python's csv.reader defaults (excel dialect):
// quoted fields, "" escapes, CRLF/LF/CR line ends, blank lines yield an empty row.

export function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let inQuotes = false
  let sawAny = false
  const n = text.length
  for (let i = 0; i < n; i++) {
    const ch = text[i]!
    sawAny = true
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"'
          i++
        } else inQuotes = false
      } else field += ch
      continue
    }
    if (ch === '"' && field === '') inQuotes = true
    else if (ch === ',') {
      row.push(field)
      field = ''
    } else if (ch === '\n' || ch === '\r') {
      if (ch === '\r' && text[i + 1] === '\n') i++
      if (row.length === 0 && field === '') rows.push([])
      else {
        row.push(field)
        rows.push(row)
      }
      row = []
      field = ''
      sawAny = false
    } else field += ch
  }
  if (inQuotes) throw new Error('CSV has an unterminated quoted field.')
  if (sawAny || field !== '' || row.length > 0) {
    row.push(field)
    rows.push(row)
  }
  return rows
}
