/** Primary language → ANSI code page, after Windows' LOCALE_IDEFAULTANSICODEPAGE. */
const LANGUAGE_CODE_PAGES: Readonly<Record<number, number>> = {
  0x01: 1256,
  0x02: 1251,
  0x05: 1250,
  0x08: 1253,
  0x0d: 1255,
  0x0e: 1250,
  0x11: 932,
  0x12: 949,
  0x15: 1250,
  0x18: 1250,
  0x19: 1251,
  0x1b: 1250,
  0x1c: 1250,
  0x1e: 874,
  0x1f: 1254,
  0x22: 1251,
  0x23: 1251,
  0x24: 1250,
  0x25: 1257,
  0x26: 1257,
  0x27: 1257,
  0x29: 1256,
  0x2a: 1258,
  0x2f: 1251,
  0x3f: 1251,
  0x40: 1251,
  0x44: 1251,
  0x50: 1251,
};

/** Code page implied by an LCID; null when the locale is neutral or unlisted. */
export const lcidCodePage = (lcid: number): number | null => {
  const language = lcid & 0x3ff;
  if (language === 0) return null;
  if (language === 0x04) return (lcid >> 10) % 64 === 0x01 ? 950 : 936;
  if (language === 0x1a) return (lcid >> 10) % 64 >= 0x03 ? 1251 : 1250;
  return LANGUAGE_CODE_PAGES[language] ?? null;
};

const DECODER_LABELS: Readonly<Record<number, string>> = {
  874: "windows-874",
  932: "shift_jis",
  936: "gbk",
  949: "euc-kr",
  950: "big5",
};
const decoders = new Map<number, TextDecoder>();
export const decoderFor = (codePage: number): TextDecoder => {
  let decoder = decoders.get(codePage);
  if (decoder === undefined) {
    decoder = new TextDecoder(
      DECODER_LABELS[codePage] ?? `windows-${String(codePage)}`,
    );
    decoders.set(codePage, decoder);
  }
  return decoder;
};
