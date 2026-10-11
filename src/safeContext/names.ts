// Optional labels use a deliberately small vocabulary. Regex detection alone cannot
// distinguish arbitrary personal names or secrets from ordinary words.
const LABEL_WORDS = new Set(('revenue plan notes comments description region country category product price cost quantity amount score count total average min max date time year month day sales units duration status active enabled rate ratio percent percentage missing value metric number usd eur try shipping order business name müşteri sayısı').split(' '))
export function isSafeColumnName(name: string): boolean {
  if (!name || name.length > 64 || !/^[\p{L}][\p{L} _().%\-]*$/u.test(name)) return false
  const words = name.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[ _().%\-]+/).filter(Boolean)
  return words.length > 0 && words.length <= 4 && words.every(w => LABEL_WORDS.has(w))
}
