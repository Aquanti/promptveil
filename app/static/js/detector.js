/**
 * PromptVeil 100% Client-Side Deterministic PII & Secret Detection Engine.
 * Runs exclusively in browser RAM with zero server egress.
 */

export const CATEGORIES = Object.freeze([
  { category: "API_KEY", tokenPrefix: "API_KEY", priority: 100, label: "API Key" },
  { category: "URL_TOKEN", tokenPrefix: "URL_TOKEN", priority: 96, label: "URL Token" },
  { category: "JWT", tokenPrefix: "JWT", priority: 95, label: "JWT Token" },
  { category: "IBAN", tokenPrefix: "IBAN", priority: 92, label: "IBAN" },
  { category: "RU_ACCOUNT", tokenPrefix: "BANK_ACC", priority: 91, label: "RU Bank Account" },
  { category: "RU_OMS", tokenPrefix: "OMS", priority: 91, label: "RU OMS Policy" },
  { category: "CREDIT_CARD", tokenPrefix: "CARD", priority: 90, label: "Credit Card" },
  { category: "RU_SNILS", tokenPrefix: "SNILS", priority: 89, label: "RU SNILS" },
  { category: "RU_INN", tokenPrefix: "INN", priority: 88, label: "RU INN" },
  { category: "RU_OGRN", tokenPrefix: "OGRN", priority: 88, label: "RU OGRN" },
  { category: "RU_PASSPORT", tokenPrefix: "PASSPORT", priority: 87, label: "RU Passport" },
  { category: "RU_BIK", tokenPrefix: "BIK", priority: 86, label: "RU BIK" },
  { category: "POSSIBLE_CARD", tokenPrefix: "POSSIBLE_CARD", priority: 84, label: "Possible card" },
  { category: "ENV_SECRET", tokenPrefix: "ENV_SECRET", priority: 82, label: ".env Secret" },
  { category: "CUSTOM", tokenPrefix: "CUSTOM", priority: 80, label: "Custom Rule" },
  { category: "EMAIL", tokenPrefix: "EMAIL", priority: 75, label: "Email" },
  { category: "PHONE", tokenPrefix: "PHONE", priority: 70, label: "Phone" },
  { category: "RU_ORG", tokenPrefix: "ORG", priority: 68, label: "RU Organizations" },
  { category: "RU_AUTO_PLATE", tokenPrefix: "PLATE", priority: 65, label: "RU Auto Plate" },
  { category: "RU_FIO", tokenPrefix: "FIO", priority: 64, label: "RU Full Name" },
  { category: "RU_ADDRESS", tokenPrefix: "ADDRESS", priority: 63, label: "RU Address" },
  { category: "IPV4", tokenPrefix: "IP", priority: 60, label: "IPv4" },
  { category: "UUID", tokenPrefix: "UUID", priority: 58, label: "UUID", secondary: true },
  { category: "HIGH_ENTROPY", tokenPrefix: "SECRET", priority: 50, label: "High Entropy" },
  { category: "SSN", tokenPrefix: "SSN", priority: 85, label: "US SSN", secondary: true },
]);

export const CATEGORY_MAP = Object.freeze(
  Object.fromEntries(CATEGORIES.map((item) => [item.category, item]))
);

/**
 * Escape only ECMAScript RegExp SyntaxCharacters so `new RegExp(..., "giu")`
 * never throws `SyntaxError: Invalid escape` in strict Unicode mode.
 */
export function escapeRegExp(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const IBAN_LENGTHS = Object.freeze({
  AL: 28, AD: 24, AT: 20, AZ: 28, BH: 22, BY: 28, BE: 16, BA: 20,
  BR: 29, BG: 22, CR: 22, HR: 21, CY: 28, CZ: 24, DK: 18, DO: 28,
  EG: 29, SV: 28, EE: 20, FO: 18, FI: 18, FR: 27, GE: 22, DE: 22,
  GI: 23, GR: 27, GL: 18, GT: 28, HU: 28, IS: 26, IQ: 23, IE: 22,
  IL: 23, IT: 27, JO: 30, KZ: 20, XK: 20, KW: 30, LV: 21, LB: 28,
  LY: 25, LI: 21, LT: 20, LU: 20, MK: 19, MT: 31, MR: 27, MU: 30,
  MC: 27, MD: 24, ME: 22, NL: 18, NO: 15, PK: 24, PS: 29, PL: 28,
  PT: 25, QA: 29, RO: 24, RU: 33, LC: 32, SM: 27, ST: 25, SA: 24,
  RS: 22, SC: 31, SK: 24, SI: 19, ES: 24, SD: 18, SE: 24, CH: 21,
  TL: 23, TN: 24, TR: 26, UA: 29, AE: 23, GB: 22, VA: 22, VG: 24,
});

const PLACEHOLDER_ENV_VALUES = new Set([
  "changeme",
  "change_me",
  "change-me",
  "your_key_here",
  "your-key-here",
  "your_api_key",
  "your_secret_here",
  "your_token_here",
  "placeholder",
  "example",
  "sample",
  "secret_here",
  "token_here",
  "password_here",
  "redacted",
  "undefined",
  "null",
  "none",
  "true",
  "false",
  "localhost",
  "bearer",
  "basic",
  "digest",
]);

export function luhnCheck(rawDigits) {
  const digits = String(rawDigits).replace(/[ -]/g, "");
  if (!/^\d{13,19}$/.test(digits) || /^0+$/.test(digits)) {
    return false;
  }
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (alternate) {
      n *= 2;
      if (n > 9) {
        n -= 9;
      }
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

export function isValidIban(candidate) {
  const compact = String(candidate).replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/.test(compact)) {
    return false;
  }
  const expectedLen = IBAN_LENGTHS[compact.slice(0, 2)];
  if (expectedLen && compact.length !== expectedLen) {
    return false;
  }
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let numeric = "";
  for (let i = 0; i < rearranged.length; i += 1) {
    const code = rearranged.charCodeAt(i);
    numeric += code >= 65 && code <= 90 ? String(code - 55) : rearranged[i];
  }
  try {
    return BigInt(numeric) % 97n === 1n;
  } catch {
    return false;
  }
}

function weightedMod10(digits, weights) {
  let sum = 0;
  for (let i = 0; i < weights.length; i += 1) {
    sum += Number(digits[i]) * weights[i];
  }
  return (sum % 11) % 10;
}

export function isValidRuInn(raw) {
  const digits = String(raw || "").trim();
  if (!/^\d{10}$|^\d{12}$/.test(digits)) return false;
  if (digits.startsWith("00") || /^(\d)\1+$/.test(digits)) return false;
  if (digits.length === 10) {
    const w10 = [2, 4, 10, 3, 5, 9, 4, 6, 8];
    return weightedMod10(digits, w10) === Number(digits[9]);
  }
  const w11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
  const w12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8];
  return (
    weightedMod10(digits, w11) === Number(digits[10]) &&
    weightedMod10(digits, w12) === Number(digits[11])
  );
}

export function isValidRuSnils(raw) {
  const digits = String(raw || "").replace(/\D/g, "");
  if (!/^\d{11}$/.test(digits)) return false;
  const num = Number(digits.slice(0, 9));
  if (num <= 1001998) return false;
  let sum = 0;
  for (let i = 0; i < 9; i += 1) {
    sum += Number(digits[i]) * (9 - i);
  }
  let expected = 0;
  if (sum < 100) {
    expected = sum;
  } else if (sum === 100 || sum === 101) {
    expected = 0;
  } else {
    const mod = sum % 101;
    expected = mod === 100 ? 0 : mod;
  }
  return expected === Number(digits.slice(9, 11));
}

export function isValidRuOgrn(raw) {
  const digits = String(raw || "").trim();
  if (/^[1256789]\d{12}$/.test(digits)) {
    try {
      return (BigInt(digits.slice(0, 12)) % 11n) % 10n === BigInt(digits[12]);
    } catch {
      return false;
    }
  }
  if (/^[34]\d{14}$/.test(digits)) {
    try {
      return (BigInt(digits.slice(0, 14)) % 13n) % 10n === BigInt(digits[14]);
    } catch {
      return false;
    }
  }
  return false;
}

export function isValidRuBik(raw) {
  const digits = String(raw || "").trim();
  if (!/^04\d{7}$/.test(digits) || digits === "040000000") return false;
  const tail = Number(digits.slice(6, 9));
  return tail <= 2 || tail >= 50;
}

const RU_BANK_WEIGHTS = Object.freeze([
  7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1, 3, 7, 1,
]);

export function isValidRuAccountWithBik(accountRaw, bikRaw) {
  const account = String(accountRaw || "").replace(/\s+/g, "");
  const bik = String(bikRaw || "").trim();
  if (!/^\d{20}$/.test(account) || !isValidRuBik(bik)) return false;
  const prefix = account.startsWith("301") ? `0${bik.slice(4, 6)}` : bik.slice(6, 9);
  const full = `${prefix}${account}`;
  let sum = 0;
  for (let i = 0; i < RU_BANK_WEIGHTS.length; i += 1) {
    sum += (Number(full[i]) * RU_BANK_WEIGHTS[i]) % 10;
  }
  return sum % 10 === 0;
}

function isValidRuPassportSeries(series4) {
  if (!/^\d{4}$/.test(series4) || series4.startsWith("00")) return false;
  const yr = Number(series4.slice(2, 4));
  return (yr >= 91 && yr <= 99) || (yr >= 0 && yr <= 30);
}

const URL_SECRET_PARAM_NAMES = new Set([
  "token",
  "access_token",
  "refresh_token",
  "auth",
  "api_key",
  "apikey",
  "key",
  "secret",
  "signature",
  "sig",
  "jwt",
  "session",
  "session_id",
  "sid",
  "password",
  "passwd",
  "pwd",
  "code",
  "x-amz-signature",
  "x-amz-credential",
]);

const VALID_RU_GIBDD_3DIGIT = new Set([
  "102", "113", "116", "121", "122", "123", "124", "125", "126",
  "134", "136", "138", "142", "147", "150", "152", "154", "159",
  "161", "163", "164", "173", "174", "177", "178", "186", "190",
  "193", "196", "197", "198", "199", "250", "252", "261", "277",
  "299", "550", "702", "716", "725", "750", "761", "763", "774",
  "777", "790", "797", "799", "977",
]);

function normalizeRuWord(word) {
  return String(word || "").trim().toLowerCase().replace(/ё/g, "е");
}

function buildRuFirstNameForms() {
  const forms = new Set();
  const addHardMale = (names) => {
    for (const raw of names) {
      const n = normalizeRuWord(raw);
      forms.add(n);
      for (const end of ["а", "у", "ом", "е"]) forms.add(n + end);
    }
  };
  const addSoftJMale = (stems) => {
    for (const stem of stems) {
      const s = normalizeRuWord(stem);
      forms.add(`${s}й`);
      for (const end of ["я", "ю", "ем", "е"]) forms.add(s + end);
    }
  };
  const addIyMale = (stems) => {
    for (const stem of stems) {
      const s = normalizeRuWord(stem);
      forms.add(`${s}ий`);
      for (const end of ["ия", "ию", "ием", "ии"]) forms.add(s + end);
    }
  };
  const addAFemaleOrMale = (stems) => {
    for (const raw of stems) {
      const n = normalizeRuWord(raw);
      const base = n.slice(0, -1);
      forms.add(n);
      for (const end of ["ы", "и", "е", "у", "ой", "ою"]) forms.add(base + end);
    }
  };
  const addYaFemale = (stems) => {
    for (const raw of stems) {
      const n = normalizeRuWord(raw);
      const base = n.slice(0, -1);
      forms.add(n);
      for (const end of ["и", "е", "ю", "ей", "ею"]) forms.add(base + end);
    }
  };
  const addIaFemale = (stems) => {
    for (const raw of stems) {
      const n = normalizeRuWord(raw);
      const base = n.slice(0, -2);
      forms.add(n);
      for (const end of ["ии", "ию", "ией", "иею"]) forms.add(base + end);
    }
  };

  addHardMale([
    "Иван", "Александр", "Владимир", "Виктор", "Роман", "Антон", "Артем",
    "Максим", "Денис", "Кирилл", "Вадим", "Константин", "Борис", "Глеб",
    "Егор", "Тимур", "Руслан", "Станислав", "Владислав", "Вячеслав", "Ярослав",
    "Степан", "Федор", "Петр", "Леонид", "Семен", "Олег", "Олега", "Данил",
    "Даниил", "Михаил", "Михаила", "Михаилу", "Михаилом", "Михаиле",
    "Павел", "Павла", "Павлу", "Павлом", "Павле", "Игорь", "Игоря", "Игорю",
    "Игорем", "Игоре", "Лев", "Льва", "Льву", "Львом", "Льве", "Филипп",
    "Герман", "Эдуард", "Альберт", "Артур", "Марат", "Ильдар", "Айрат",
  ]);
  addSoftJMale(["Алексе", "Серге", "Никола", "Андре", "Матве", "Тимофе"]);
  addIyMale([
    "Дмитр", "Евген", "Васил", "Юр", "Анатол", "Витал", "Валер",
    "Георг", "Григор", "Аркад", "Арсен", "Геннад", "Савел",
  ]);
  addAFemaleOrMale([
    "Никита", "Данила", "Анна", "Елена", "Ольга", "Татьяна", "Ирина",
    "Светлана", "Екатерина", "Марина", "Надежда", "Галина", "Людмила",
    "Валентина", "Тамара", "Оксана", "Алина", "Вероника", "Александра",
    "Кристина", "Маргарита", "Елизавета", "Алиса", "Диана", "Яна", "Ульяна",
    "Кира", "Вера", "Лариса", "Инна", "Зоя", "Нина", "Алла", "Раиса",
    "Дарья", "Наталья", "Софья", "Илья",
  ]);
  addYaFemale(["Дарья", "Наталья", "Софья", "Илья", "Любовь", "Любови"]);
  addIaFemale(["Мария", "Юлия", "Анастасия", "Ксения", "Виктория", "Валерия", "Евгения", "София", "Наталия"]);
  return forms;
}

const RU_FIRST_NAME_FORMS = buildRuFirstNameForms();
const RU_FIO_STOPWORDS = new Set([
  "договор", "контакт", "клиент", "директор", "кандидат", "менеджер",
  "руководитель", "специалист", "заказчик", "исполнитель", "подрядчик",
  "сотрудник", "представитель", "ответственный", "генеральный", "ооо",
  "пао", "зао", "оао", "нко", "ао", "ип", "республика", "область", "край",
  "район", "город", "улица", "проспект", "переулок", "бульвар", "шоссе",
  "площадь", "квартира", "корпус", "строение", "дом", "статья", "пункт",
  "раздел", "пример", "организация", "компания", "банк", "адрес", "реквизиты",
  "сторона", "полис", "паспорт", "снилс", "инн", "огрн", "бик",
  "подписант", "получатель", "отправитель", "куратор", "автор", "уважаемый",
  "уважаемая", "господин", "госпожа", "гр", "гр-н",
  "клиентов", "сотрудников", "партнеров", "договоров", "проектов",
  "документов", "товаров", "услуг", "заказов", "серверов", "вопросов",
  "ответов", "отчетов", "городов", "банков", "счетов", "платежей",
  "офисов", "регионов", "разделов", "пунктов", "листов", "файлов",
  "ключей", "токенов", "запросов", "инженеров", "юристов", "бухгалтеров",
  "директоров", "менеджеров", "руководителей", "специалистов", "заказчиков",
  "исполнителей", "подрядчиков", "представителей", "кандидатов", "авторов",
  "героев", "народов", "участников", "пользователей", "владельцев",
  "других", "новых", "первых", "вторых", "третьих", "многих", "всяких",
  "таких", "каких", "некоторых", "остальных", "данных", "наших", "ваших",
  "своих", "твоих", "моих", "этих", "больших", "малых", "старых",
  "добрых", "плохих", "хороших", "разных", "важных", "главных", "общих",
  "личных", "частных", "советский", "российский", "московский", "городской",
  "областной", "районный", "федеральный", "государственный", "технический",
  "коммерческий", "юридический", "финансовый", "медицинский", "банковский",
  "только", "однако", "сколько", "несколько", "далеко", "близко", "высоко",
  "низко", "глубоко", "широко", "легко", "редко", "яблоко", "молоко",
  "облако", "машина", "машины", "картина", "картины", "причина", "причины",
  "половина", "середина", "вершина", "глубина", "ширина", "мужчина",
  "женщина", "господина", "гражданина", "магазин", "термин", "бензин",
  "витамин", "киев", "ростов", "саратов", "тамбов", "псков", "харьков",
  "чернигов", "работает", "столица",
  "пациентов", "студентов", "инвесторов", "работников", "экспертов",
  "акционеров", "близких", "родных", "молодых", "больных", "живых",
  "святых", "взрослых", "знакомых", "слов", "снов", "отцов", "домов",
  "годов", "веков", "часов", "шагов", "дней", "друзей",
]);

function isRuPatronymic(word) {
  const norm = normalizeRuWord(word);
  return (
    norm.length >= 6 &&
    /(?:(?:ович|евич|ич)(?:а|у|ем|ом|е)?|(?:овн|евн|ичн|иничн)(?:а|у|е|ой|ою|ею|ы))$/.test(norm)
  );
}

function isCapitalizedRuSurnameCandidate(word) {
  const norm = normalizeRuWord(word);
  if (!norm || RU_FIO_STOPWORDS.has(norm) || norm.length < 2) {
    return false;
  }
  return /^[А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?$/.test(word);
}

function hasSingleRuSurnameSuffix(normPart) {
  if (!normPart || normPart.length < 4 || RU_FIO_STOPWORDS.has(normPart)) {
    return false;
  }
  if (/(?:ов|ев)(?:а|у|ым|ом|е|ой|ою|ы|ых|ыми)?$/.test(normPart)) {
    return true;
  }
  if (normPart.length >= 5 && /(?:ин|ын)(?:а|у|ым|ом|е|ой|ою|ы|ых|ыми)?$/.test(normPart)) {
    return true;
  }
  if (normPart.length >= 6 && /(?:ск|цк)(?:ий|ого|ому|им|ом|ая|ой|ую|ою|ие|их|ими)$/.test(normPart)) {
    return true;
  }
  if (normPart.length >= 5 && /енко$/.test(normPart)) {
    return true;
  }
  if (normPart.length >= 5 && /(?:чук|юк)(?:а|у|ом|е|ой)?$/.test(normPart)) {
    return true;
  }
  if (normPart.length >= 5 && /ко$/.test(normPart)) {
    return true;
  }
  if (normPart.length >= 5 && /(?:их|ых)$/.test(normPart)) {
    return true;
  }
  return false;
}

function hasRuSurnameSuffix(word) {
  const norm = normalizeRuWord(word);
  if (!norm || RU_FIO_STOPWORDS.has(norm)) {
    return false;
  }
  const parts = norm.split("-");
  return parts.some((part) => hasSingleRuSurnameSuffix(part));
}

export function isValidRuAutoPlate(raw) {
  const compact = String(raw || "")
    .trim()
    .replace(/\s+(?:RUS|РУС)$/i, "")
    .replace(/\s+/g, "");
  const m = compact.match(/^([АВЕКМНОРСТУХавекмнорстухABEKMHOPCTYX])(\d{3})([АВЕКМНОРСТУХавекмнорстухABEKMHOPCTYX]{2})(\d{2,3})$/u);
  if (!m) return false;
  const letters = `${m[1]}${m[3]}`;
  const isCyr = /^[АВЕКМНОРСТУХавекмнорстух]{3}$/u.test(letters);
  const isLatUpper = /^[ABEKMHOPCTYX]{3}$/.test(letters);
  if (!isCyr && !isLatUpper) return false;
  const reg = m[4];
  if (reg.length === 2) {
    return reg >= "01" && reg <= "99";
  }
  return VALID_RU_GIBDD_3DIGIT.has(reg);
}

export function shannonEntropy(str) {
  if (!str || str.length === 0) {
    return 0;
  }
  const freq = new Map();
  for (let i = 0; i < str.length; i += 1) {
    const ch = str[i];
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = str.length;
  for (const count of freq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function isPlaceholderEnvValue(value) {
  const lower = value.toLowerCase();
  if (PLACEHOLDER_ENV_VALUES.has(lower)) {
    return true;
  }
  if (/^(?:x+|y+|z+|\*+|\.+|0+)$/i.test(value)) {
    return true;
  }
  if (
    /^(?:your[_-].+|replace[_-].+|insert[_-].+|dummy[_-].+|test[_-](?:key|token|secret|pass).*|<.+>|\$\{.+\})$/i.test(
      value
    )
  ) {
    return true;
  }
  if (/^\[[A-Z_]+_\d+\]$/.test(value)) {
    return true;
  }
  return false;
}

function hasMixedCardSeparators(value) {
  return value.includes(" ") && value.includes("-");
}

function isValidCardFormat(value) {
  if (!value || hasMixedCardSeparators(value)) {
    return false;
  }
  if (!value.includes(" ") && !value.includes("-")) {
    return /^\d{13,19}$/.test(value);
  }
  const sig = value
    .split(/[ -]/)
    .map((group) => group.length)
    .join("-");
  return (
    sig === "4-4-4-4" ||
    sig === "4-6-5" ||
    sig === "4-6-4" ||
    sig === "4-4-4-1" ||
    sig === "4-4-4-5" ||
    sig === "4-4-4-6" ||
    sig === "4-4-4-7" ||
    sig === "4-4-4-4-3"
  );
}

function isValidCardDigits(value, skipLuhn = false) {
  if (!skipLuhn) {
    return luhnCheck(value);
  }
  const digits = String(value).replace(/[ -]/g, "");
  return /^\d{13,19}$/.test(digits) && !/^0+$/.test(digits);
}

function resolveCardSpan(text, matchIndex, raw, { skipLuhn = false } = {}) {
  // 1. Prefer stripping trailing hyphen/space numeric suffixes (e.g. -99, -00, -12-34)
  //    when doing so yields a valid 13-16 digit standard card grouping, preventing
  //    10% Luhn-collision absorption of trailing tags into 17-19 digit spans.
  let candidate = raw;
  while (true) {
    let stripped = candidate;
    while (/-\d+$/.test(stripped)) {
      stripped = stripped.replace(/-\d+$/, "");
      const digitsLen = stripped.replace(/[ -]/g, "").length;
      if (digitsLen < 13) {
        break;
      }
      if (digitsLen <= 16 && isValidCardFormat(stripped) && isValidCardDigits(stripped, skipLuhn)) {
        return { value: stripped, end: matchIndex + stripped.length };
      }
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
    const digitsLen = candidate.replace(/[ -]/g, "").length;
    if (digitsLen < 13) {
      break;
    }
    if (digitsLen <= 16 && isValidCardFormat(candidate) && isValidCardDigits(candidate, skipLuhn)) {
      return { value: candidate, end: matchIndex + candidate.length };
    }
  }

  // 2a. Otherwise accept the full match (or space-trimmed 17-19 digit card) if structurally valid.
  candidate = raw;
  while (candidate.replace(/[ -]/g, "").length >= 13) {
    if (isValidCardFormat(candidate) && isValidCardDigits(candidate, skipLuhn)) {
      return { value: candidate, end: matchIndex + candidate.length };
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
  }

  // 2b. If none matched, iteratively strip trailing -<digits> suffixes (and outer
  //     space-trimmed segments) for valid 17-18 digit PANs with hyphenated suffixes.
  candidate = raw;
  while (candidate.replace(/[ -]/g, "").length >= 17) {
    let stripped = candidate;
    while (/-\d+$/.test(stripped)) {
      stripped = stripped.replace(/-\d+$/, "");
      const digitsLen = stripped.replace(/[ -]/g, "").length;
      if (digitsLen < 17) {
        break;
      }
      if (digitsLen <= 18 && isValidCardFormat(stripped) && isValidCardDigits(stripped, skipLuhn)) {
        return { value: stripped, end: matchIndex + stripped.length };
      }
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
  }
  return null;
}

function resolveIbanSpan(text, matchIndex, raw) {
  const cc = raw.slice(0, 2).toUpperCase();
  const expectedLen = IBAN_LENGTHS[cc];
  if (expectedLen) {
    let nonSpaceCount = 0;
    let cut = -1;
    for (let i = 0; i < raw.length; i += 1) {
      if (raw[i] !== " ") {
        nonSpaceCount += 1;
        if (nonSpaceCount === expectedLen) {
          cut = i + 1;
          break;
        }
      }
    }
    if (cut <= 0) {
      return null;
    }
    const nextChar = text[matchIndex + cut] || "";
    if (/[A-Za-z0-9]/.test(nextChar)) {
      return null;
    }
    const candidate = raw.slice(0, cut);
    if (!isValidIban(candidate)) {
      return null;
    }
    return { value: candidate, end: matchIndex + cut };
  }

  // Fallback for unlisted synthetic country codes: progressive trailing group trim.
  let candidate = raw;
  while (candidate.replace(/\s+/g, "").length >= 15) {
    if (isValidIban(candidate)) {
      return { value: candidate, end: matchIndex + candidate.length };
    }
    const lastSpace = candidate.lastIndexOf(" ");
    if (lastSpace <= 0) {
      break;
    }
    candidate = candidate.slice(0, lastSpace);
  }
  return null;
}

function isHighEntropySecret(token) {
  if (token.length < 20) {
    return false;
  }
  if (/^(?:https?|ftp|wss?|postgres(?:ql)?|mysql|redis|mongodb(?:\+srv)?):\/\//i.test(token)) {
    return false;
  }
  if (
    /^(?:~?\/|\.\.?\/|[A-Za-z]:\\)/.test(token) ||
    token.includes("\\") ||
    (token.includes("/") && /\.[a-z0-9]{1,5}$/i.test(token))
  ) {
    return false;
  }
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(token)) {
    return false;
  }
  if (/^\[[A-Z_]+_\d+\]$/.test(token)) {
    return false;
  }

  let classes = 0;
  if (/[A-Z]/.test(token)) classes += 1;
  if (/[a-z]/.test(token)) classes += 1;
  if (/[0-9]/.test(token)) classes += 1;
  if (/[^A-Za-z0-9]/.test(token)) classes += 1;

  const isLongHex =
    /^[0-9a-fA-F]{32,}$/.test(token) && /[0-9]/.test(token) && /[a-fA-F]/.test(token);

  if (classes < 3 && !isLongHex) {
    return false;
  }

  return shannonEntropy(token) >= 3.8;
}

/**
 * Detect all 25 deterministic PII, credential, custom-rule, and high-entropy spans.
 * Returns non-overlapping entities sorted by start offset ascending.
 */
export function detectEntities(text, customRules = [], options = {}) {
  if (typeof text !== "string" || text.length === 0) {
    return [];
  }

  const detectUuid = Boolean(options?.detectUuid) || options?.sensitivity === "strict";
  const candidates = [];

  // 1. API_KEY (priority 100)
  const apiKeyRegex =
    /(?<![A-Za-z0-9_-])(?:(?:AKIA|ASIA)[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|(?:sk|rk|pk)_(?:live|test)_[0-9A-Za-z]{16,}|(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{22,}|xox[baprs]-[0-9A-Za-z-]{10,}|AIza[0-9A-Za-z_-]{35})(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(apiKeyRegex)) {
    candidates.push({
      category: "API_KEY",
      tokenPrefix: "API_KEY",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 100,
    });
  }

  // 1b. URL_TOKEN (priority 96, mask secret query/fragment parameter values inside HTTP(S) URLs)
  const urlTokenRegex = /https?:\/\/[^\s"'<>()]+/gi;
  for (const m of text.matchAll(urlTokenRegex)) {
    const cleanUrl = m[0].replace(/[.,;:!?}\]]+$/, "");
    const paramStart = cleanUrl.search(/[?#]/);
    if (paramStart < 0) continue;
    const paramSlice = cleanUrl.slice(paramStart);
    const paramRe = /[?&#]([A-Za-z0-9_.-]+)=([^&#\s"'<>]{6,})/g;
    for (const pm of paramSlice.matchAll(paramRe)) {
      const keyLower = pm[1].toLowerCase();
      const val = pm[2];
      if (!URL_SECRET_PARAM_NAMES.has(keyLower) || isPlaceholderEnvValue(val)) {
        continue;
      }
      const valStart = m.index + paramStart + pm.index + pm[0].length - val.length;
      candidates.push({
        category: "URL_TOKEN",
        tokenPrefix: "URL_TOKEN",
        value: val,
        start: valStart,
        end: valStart + val.length,
        priority: 96,
      });
    }
  }

  // 2. JWT (priority 95)
  const jwtRegex =
    /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{8,}(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(jwtRegex)) {
    candidates.push({
      category: "JWT",
      tokenPrefix: "JWT",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 95,
    });
  }

  // 3. CREDIT_CARD (priority 90, Luhn validated; reject labeled non-card RU IDs)
  const nonCardRuLabelRe =
    /(?<![\p{L}\p{N}_])(?:ОГРНИП|ОГРН|OGRN|ОМС|OMS|полис(?:\s+ОМС)?|мед(?:ицинск\w+)?\s+полис|ИНН|INN|СНИЛС|SNILS|БИК|BIK|BIC|р\/с|к\/с)[\s:№=-]*$/iu;
  const cardRegex =
    /(?<![A-Za-z\d+])(?<!\d[.-])(?:\d[ -]?){12,18}\d(?![A-Za-z\d])(?![.]\d)/g;
  let cardMatch;
  while ((cardMatch = cardRegex.exec(text)) !== null) {
    const resolved = resolveCardSpan(text, cardMatch.index, cardMatch[0]);
    if (resolved) {
      const lookback = text.slice(Math.max(0, cardMatch.index - 40), cardMatch.index);
      if (!nonCardRuLabelRe.test(lookback)) {
        candidates.push({
          category: "CREDIT_CARD",
          tokenPrefix: "CARD",
          value: resolved.value,
          start: cardMatch.index,
          end: resolved.end,
          priority: 90,
        });
      }
      cardRegex.lastIndex = resolved.end;
    } else {
      const sepIdx = cardMatch[0].search(/[ -]/);
      if (sepIdx >= 0) {
        cardRegex.lastIndex = cardMatch.index + sepIdx + 1;
      }
    }
  }

  // 4. IBAN (priority 92, ISO 7064 mod-97 via BigInt)
  const ibanRegex =
    /(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Za-z0-9])/g;
  let ibanMatch;
  while ((ibanMatch = ibanRegex.exec(text)) !== null) {
    const resolved = resolveIbanSpan(text, ibanMatch.index, ibanMatch[0]);
    if (resolved) {
      candidates.push({
        category: "IBAN",
        tokenPrefix: "IBAN",
        value: resolved.value,
        start: ibanMatch.index,
        end: resolved.end,
        priority: 92,
      });
      ibanRegex.lastIndex = resolved.end;
    } else {
      const spaceIdx = ibanMatch[0].indexOf(" ");
      if (spaceIdx >= 0) {
        ibanRegex.lastIndex = ibanMatch.index + spaceIdx + 1;
      }
    }
  }

  // 4b. RU_BIK (priority 86, context-gated; collected first for RU_ACCOUNT checksum validation)
  const validBiksInDoc = [];
  const ruBikRegex = /(?<![\p{L}\p{N}_])(?:БИК|BIK|BIC)[\s:№=-]*(04\d{7})(?![\d-])/giu;
  for (const m of text.matchAll(ruBikRegex)) {
    const bikVal = m[1];
    if (!isValidRuBik(bikVal)) continue;
    if (!validBiksInDoc.includes(bikVal)) {
      validBiksInDoc.push(bikVal);
    }
    const start = m.index + m[0].length - bikVal.length;
    candidates.push({
      category: "RU_BIK",
      tokenPrefix: "BIK",
      value: bikVal,
      start,
      end: start + bikVal.length,
      priority: 86,
    });
  }

  // 4c. RU_ACCOUNT (priority 91, 20-digit settlement/correspondent account validated against BIK or label)
  const ruAccRegex = /(?<![\d-])((?:40[1-9]|42[1-6]|301|302)(?: ?\d){17})(?![\d-])/g;
  const ruAccLabelRe =
    /(?:р\/с|р\.с\.|расч[её]тн\w*\s+сч[её]т|к\/с|к\.с\.|корр\w*\s+сч[её]т|сч[её]т)(?:\s*№|\s*[:=-]|\s)+$/iu;
  for (const m of text.matchAll(ruAccRegex)) {
    const rawVal = m[1];
    const compact = rawVal.replace(/\s+/g, "");
    if (!/^\d{20}$/.test(compact)) continue;
    const lookback = text.slice(Math.max(0, m.index - 45), m.index);
    const hasBiks = validBiksInDoc.length > 0;
    const ok = hasBiks
      ? validBiksInDoc.some((bik) => isValidRuAccountWithBik(compact, bik))
      : ruAccLabelRe.test(lookback);
    if (!ok) continue;
    candidates.push({
      category: "RU_ACCOUNT",
      tokenPrefix: "BANK_ACC",
      value: rawVal,
      start: m.index,
      end: m.index + rawVal.length,
      priority: 91,
    });
  }

  // 4d. RU_OMS (priority 91, Luhn + OMS context label so it outranks CREDIT_CARD)
  const ruOmsRegex = /(?<![\d-])(\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})(?![\d-])/g;
  const ruOmsLabelRe =
    /(?<![\p{L}\p{N}_])(?:ОМС|OMS|полис(?:\s+ОМС)?|мед(?:ицинск\w+)?\s+полис)[\s:№=-]*$/iu;
  for (const m of text.matchAll(ruOmsRegex)) {
    const rawVal = m[1];
    const digits = rawVal.replace(/\D/g, "");
    if (digits.length !== 16 || !luhnCheck(digits)) continue;
    const lookback = text.slice(Math.max(0, m.index - 40), m.index);
    if (!ruOmsLabelRe.test(lookback)) continue;
    candidates.push({
      category: "RU_OMS",
      tokenPrefix: "OMS",
      value: rawVal,
      start: m.index,
      end: m.index + rawVal.length,
      priority: 91,
    });
  }

  // 4e. RU_SNILS (priority 89, official PFR checksum)
  const ruSnilsHyphenRegex = /(?<![\d-])(\d{3}-\d{3}-\d{3}[ -]\d{2})(?![\d-])/g;
  for (const m of text.matchAll(ruSnilsHyphenRegex)) {
    const rawVal = m[1];
    if (!isValidRuSnils(rawVal)) continue;
    candidates.push({
      category: "RU_SNILS",
      tokenPrefix: "SNILS",
      value: rawVal,
      start: m.index,
      end: m.index + rawVal.length,
      priority: 89,
    });
  }
  const ruSnilsLabeledRegex =
    /(?<![\p{L}\p{N}_])(?:СНИЛС|SNILS)[\s:№=-]*(\d{3}\s\d{3}\s\d{3}\s\d{2}|\d{11})(?![\d-])/giu;
  for (const m of text.matchAll(ruSnilsLabeledRegex)) {
    const rawVal = m[1];
    if (!isValidRuSnils(rawVal)) continue;
    const start = m.index + m[0].length - rawVal.length;
    candidates.push({
      category: "RU_SNILS",
      tokenPrefix: "SNILS",
      value: rawVal,
      start,
      end: start + rawVal.length,
      priority: 89,
    });
  }

  // 4f. RU_OGRN / OGRNIP (priority 88, boosted to 91 when labeled)
  const ruOgrnRegex = /(?<![\d-])((?:[1256789]\d{12}|[34]\d{14}))(?![\d-])/g;
  const ruOgrnLabelRe = /(?<![\p{L}\p{N}_])(?:ОГРНИП|ОГРН|OGRN)[\s:№=-]*$/iu;
  for (const m of text.matchAll(ruOgrnRegex)) {
    const rawVal = m[1];
    if (!isValidRuOgrn(rawVal)) continue;
    const lookback = text.slice(Math.max(0, m.index - 25), m.index);
    const hasLabel = ruOgrnLabelRe.test(lookback);
    if (!hasLabel && /(?:timestamp|epoch|ts|ms)[\s:=]*$/iu.test(lookback)) {
      continue;
    }
    candidates.push({
      category: "RU_OGRN",
      tokenPrefix: "OGRN",
      value: rawVal,
      start: m.index,
      end: m.index + rawVal.length,
      priority: hasLabel ? 91 : 88,
    });
  }

  // 4g. RU_INN (priority 88, 10/12 digits with FNS checksum)
  const ruInnRegex = /(?<![\d-])(\d{10}|\d{12})(?![\d-])/g;
  for (const m of text.matchAll(ruInnRegex)) {
    const rawVal = m[1];
    if (!isValidRuInn(rawVal)) continue;
    const lookback = text.slice(Math.max(0, m.index - 25), m.index);
    if (/(?:timestamp|epoch|ts|port|бик|bik|bic)[\s:=]*$/iu.test(lookback)) {
      continue;
    }
    candidates.push({
      category: "RU_INN",
      tokenPrefix: "INN",
      value: rawVal,
      start: m.index,
      end: m.index + rawVal.length,
      priority: 88,
    });
  }

  // 4h. RU_PASSPORT (priority 87, context-gated RF series + number)
  const ruPassportRegex =
    /(?<![\p{L}\p{N}_])(?:паспорт(?:ные\s+данные|а|у|ом|е)?|удостоверение\s+личности|passport)(?:\s+РФ)?(?:\s+(?:сери[яи]|сер\.?))?[\s:№=-]*((?:\d{2}[ -]?\d{2})(?:\s*(?:№|N|номер)\s*|\s+)\d{6})(?![\d-])/giu;
  for (const m of text.matchAll(ruPassportRegex)) {
    const rawVal = m[1];
    const compact = rawVal.replace(/\D/g, "");
    if (compact.length !== 10 || !isValidRuPassportSeries(compact.slice(0, 4))) {
      continue;
    }
    const start = m.index + m[0].length - rawVal.length;
    candidates.push({
      category: "RU_PASSPORT",
      tokenPrefix: "PASSPORT",
      value: rawVal,
      start,
      end: start + rawVal.length,
      priority: 87,
    });
  }

  // 5. SSN (priority 85, secondary)
  const ssnRegex =
    /(?<![\d-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\d-])/g;
  for (const m of text.matchAll(ssnRegex)) {
    candidates.push({
      category: "SSN",
      tokenPrefix: "SSN",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 85,
    });
  }

  // 5b. POSSIBLE_CARD (priority 84 < CREDIT_CARD: 90, context-gated, skips Luhn)
  const possibleCardRegex =
    /(?<![\p{L}\p{N}_])(?:номер[ \t]+карт[ыа]?|№[ \t]*карт[ыа]?|карт(?:ой|ою|[аыуе])?|карточк(?:ой|ою|[аиуе])?|card(?:[ \t]+(?:number|no\.?|#))?)[ \t:№#=-]+((?:\d[ -]?){12,18}\d)(?![A-Za-z\d])(?![.]\d)/giu;
  const possibleCardSpans = [];
  for (const m of text.matchAll(possibleCardRegex)) {
    const rawDigits = m[1];
    const digitStart = m.index + m[0].length - rawDigits.length;
    const prefixLookback = text.slice(Math.max(0, m.index - 40), m.index);
    const digitLookback = text.slice(Math.max(0, digitStart - 40), digitStart);
    if (nonCardRuLabelRe.test(prefixLookback) || nonCardRuLabelRe.test(digitLookback)) {
      continue;
    }
    const resolved = resolveCardSpan(text, digitStart, rawDigits, { skipLuhn: true });
    if (!resolved) {
      continue;
    }
    const span = {
      category: "POSSIBLE_CARD",
      tokenPrefix: "POSSIBLE_CARD",
      value: resolved.value,
      start: digitStart,
      end: resolved.end,
      priority: 84,
    };
    possibleCardSpans.push(span);
    candidates.push(span);
  }
  if (possibleCardSpans.length > 0) {
    for (let i = candidates.length - 1; i >= 0; i -= 1) {
      const c = candidates[i];
      if (
        c.category === "CREDIT_CARD" &&
        possibleCardSpans.some((p) => c.start > p.start && c.start < p.end)
      ) {
        candidates.splice(i, 1);
      }
    }
  }

  // 6. ENV_SECRET (priority 82, RHS value only, single-line whitespace)
  const envSecretRegex =
    /^([ \t]*(?:export[ \t]+)?[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|TOKEN|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH|DSN|CONNECTION_STRING)[A-Z0-9_]*[ \t]*[:=][ \t]*)(?:"((?:[^"\\\r\n]|\\.)*)"|'((?:[^'\\\r\n]|\\.)*)'|([^\s'"#\r\n][^\s\r\n]{5,}))/gim;
  for (const m of text.matchAll(envSecretRegex)) {
    const isDoubleQuoted = m[2] !== undefined;
    const isSingleQuoted = m[3] !== undefined;
    const value = isDoubleQuoted ? m[2] : isSingleQuoted ? m[3] : m[4];
    if (!value || value.length < 6 || isPlaceholderEnvValue(value)) {
      continue;
    }
    const quoteOffset = isDoubleQuoted || isSingleQuoted ? 1 : 0;
    const start = m.index + m[1].length + quoteOffset;
    const end = start + value.length;
    if (
      !isDoubleQuoted &&
      !isSingleQuoted &&
      /^[ \t]*(?:proxy-)?authorization[ \t]*:[ \t]*$/i.test(m[1]) &&
      /^(?:bearer|basic|digest|token|apikey|api-key|custom|hmac|negotiate|ntlm)$/i.test(value) &&
      /^[ \t]+[^#\s]/.test(text.slice(end))
    ) {
      continue;
    }
    candidates.push({
      category: "ENV_SECRET",
      tokenPrefix: "ENV_SECRET",
      value,
      start,
      end,
      priority: 82,
    });
  }

  // 7. CUSTOM (priority 80, Unicode Cyrillic/EN boundary + combining mark guard)
  if (Array.isArray(customRules) && customRules.length > 0) {
    const activeRules = customRules
      .filter((r) => r && r.enabled !== false && typeof r.term === "string" && r.term.trim().length > 0)
      .sort((a, b) => b.term.trim().length - a.term.trim().length);

    for (const rule of activeRules) {
      const term = rule.term.trim();
      const rawRuleCat =
        typeof rule.category === "string" ? rule.category.trim().toUpperCase() : "";
      const ruleCategory = rawRuleCat || "CUSTOM";
      const flags = rule.caseSensitive ? "gu" : "giu";
      try {
        const re = new RegExp(
          `(?<![\\p{L}\\p{N}_\\p{M}])${escapeRegExp(term)}(?![\\p{L}\\p{N}_\\p{M}])`,
          flags
        );
        for (const m of text.matchAll(re)) {
          candidates.push({
            category: "CUSTOM",
            tokenPrefix: "CUSTOM",
            value: m[0],
            start: m.index,
            end: m.index + m[0].length,
            priority: 80,
            ruleId: rule.id || undefined,
            ruleCategory,
          });
        }
      } catch {
        // Skip invalid pattern safely without crashing detection pipeline.
      }
    }
  }

  // 8. EMAIL (priority 75)
  const emailRegex =
    /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}(?![A-Za-z0-9_-])/g;
  for (const m of text.matchAll(emailRegex)) {
    candidates.push({
      category: "EMAIL",
      tokenPrefix: "EMAIL",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 75,
    });
  }

  // 9. PHONE (priority 70, CIS/RU + international, 10..15 digits)
  const phoneRegex =
    /(?<![\p{L}\p{N}_.])(?<![\p{L}\p{N}]-)(?:\+\d{1,3}(?:[ -]?\(?\d{1,4}\)?){1,5}|\(?8\)?[ -]?\(?\d{3,4}\)?(?:[ -]?\d{2,4}){2,4}|89\d{9}|\(\d{3,4}\)[ -]?\d{2,4}(?:[ -]?\d{2,4}){1,3}|\d{3}[ -]\d{3}[ -]\d{4})(?![\p{L}\p{N}_-])(?![.]\d)/gu;
  for (const m of text.matchAll(phoneRegex)) {
    const val = m[0];
    const openParens = (val.match(/\(/g) || []).length;
    const closeParens = (val.match(/\)/g) || []).length;
    if (openParens !== closeParens) {
      continue;
    }
    const digits = val.replace(/\D/g, "");
    if (digits.length < 10 || digits.length > 15) {
      continue;
    }
    if (/^\d{4}[-/]\d{2}[-/]\d{2}/.test(val) || /^\d{2}\.\d{2}\.\d{4}/.test(val)) {
      continue;
    }
    candidates.push({
      category: "PHONE",
      tokenPrefix: "PHONE",
      value: val,
      start: m.index,
      end: m.index + val.length,
      priority: 70,
    });
  }

  // 9a. RU_ORG (priority 68 < CUSTOM: 80, > RU_FIO: 64)
  const ruOrgQuotedRegex =
    /(?<![\p{L}\p{N}_])(?:ООО|ПАО|ЗАО|ОАО|НКО|АО|ИП)[ \t]*(?:«[^«»\r\n]{1,120}»|"[^"\r\n]{1,120}"|„[^„“”"\r\n]{1,120}[“”"]|“[^“”\r\n]{1,120}”|'[^'\r\n]{1,120}')/gu;
  for (const m of text.matchAll(ruOrgQuotedRegex)) {
    candidates.push({
      category: "RU_ORG",
      tokenPrefix: "ORG",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 68,
    });
  }

  const ruIpInitialAfterRe =
    /(?<![\p{L}\p{N}_])(ИП[ \t]+([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?)[ \t]+[А-ЯЁ]\.[ \t]?[А-ЯЁ]\.)(?![\p{L}\p{N}_])/gu;
  for (const m of text.matchAll(ruIpInitialAfterRe)) {
    if (!isCapitalizedRuSurnameCandidate(m[2])) continue;
    candidates.push({
      category: "RU_ORG",
      tokenPrefix: "ORG",
      value: m[1],
      start: m.index,
      end: m.index + m[1].length,
      priority: 68,
    });
  }

  const ruIpInitialBeforeRe =
    /(?<![\p{L}\p{N}_])(ИП[ \t]+[А-ЯЁ]\.[ \t]?[А-ЯЁ]\.[ \t]+([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?))(?![\p{L}\p{N}_-])/gu;
  for (const m of text.matchAll(ruIpInitialBeforeRe)) {
    if (!isCapitalizedRuSurnameCandidate(m[2])) continue;
    candidates.push({
      category: "RU_ORG",
      tokenPrefix: "ORG",
      value: m[1],
      start: m.index,
      end: m.index + m[1].length,
      priority: 68,
    });
  }

  const ruIpFioRe =
    /(?<![\p{L}\p{N}_])(ИП[ \t]+([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?)[ \t]+([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?)(?:[ \t]+([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?))?)(?![\p{L}\p{N}_-])/gu;
  for (const m of text.matchAll(ruIpFioRe)) {
    const [, , w1, w2, w3] = m;
    const n1 = normalizeRuWord(w1);
    const n2 = normalizeRuWord(w2);
    if (w3) {
      const n3 = normalizeRuWord(w3);
      const valid3 =
        !RU_FIO_STOPWORDS.has(n1) &&
        !RU_FIO_STOPWORDS.has(n2) &&
        !RU_FIO_STOPWORDS.has(n3) &&
        ((isCapitalizedRuSurnameCandidate(w1) && RU_FIRST_NAME_FORMS.has(n2) && isRuPatronymic(w3)) ||
          (RU_FIRST_NAME_FORMS.has(n1) && isRuPatronymic(w2) && isCapitalizedRuSurnameCandidate(w3)));
      if (valid3) {
        candidates.push({
          category: "RU_ORG",
          tokenPrefix: "ORG",
          value: m[1],
          start: m.index,
          end: m.index + m[1].length,
          priority: 68,
        });
        continue;
      }
    }
    const w1Start = m[0].indexOf(w1, 2);
    const twoEnd = m.index + m[0].indexOf(w2, w1Start + w1.length) + w2.length;
    const valid2 =
      !RU_FIO_STOPWORDS.has(n1) &&
      !RU_FIO_STOPWORDS.has(n2) &&
      ((isCapitalizedRuSurnameCandidate(w1) && hasRuSurnameSuffix(w1) && RU_FIRST_NAME_FORMS.has(n2)) ||
        (RU_FIRST_NAME_FORMS.has(n1) &&
          (isRuPatronymic(w2) || (isCapitalizedRuSurnameCandidate(w2) && hasRuSurnameSuffix(w2)))));
    if (valid2) {
      const val2 = text.slice(m.index, twoEnd);
      candidates.push({
        category: "RU_ORG",
        tokenPrefix: "ORG",
        value: val2,
        start: m.index,
        end: twoEnd,
        priority: 68,
      });
    }
  }

  // 9b. RU_AUTO_PLATE (priority 65, GOST letters + official GIBDD region codes)
  const ruPlateRegex =
    /(?<![\p{L}\p{N}_-])([АВЕКМНОРСТУХABEKMHOPCTYX]\s?\d{3}\s?[АВЕКМНОРСТУХABEKMHOPCTYX]{2}\s?(?:0[1-9]|[1-9]\d|[1279]\d{2})(?:\s?(?:RUS|РУС))?)(?![\p{L}\p{N}_-])/giu;
  for (const m of text.matchAll(ruPlateRegex)) {
    const val = m[1];
    if (!isValidRuAutoPlate(val)) continue;
    candidates.push({
      category: "RU_AUTO_PLATE",
      tokenPrefix: "PLATE",
      value: val,
      start: m.index,
      end: m.index + val.length,
      priority: 65,
    });
  }

  // 9c. RU_FIO (priority 64 < CUSTOM: 80; 3-word FIO, Name+Patronymic, or Surname + Initials)
  const ruInitialAfterRe =
    /(?<![\p{L}\p{N}_])([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?\s+[А-ЯЁ]\.\s?[А-ЯЁ]\.)(?![\p{L}\p{N}_])/gu;
  for (const m of text.matchAll(ruInitialAfterRe)) {
    const surname = m[1].split(/\s+/)[0];
    if (!isCapitalizedRuSurnameCandidate(surname)) continue;
    candidates.push({
      category: "RU_FIO",
      tokenPrefix: "FIO",
      value: m[1],
      start: m.index,
      end: m.index + m[1].length,
      priority: 64,
    });
  }
  const ruInitialBeforeRe =
    /(?<![\p{L}\p{N}_])([А-ЯЁ]\.\s?[А-ЯЁ]\.\s+[А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?)(?![\p{L}\p{N}_])/gu;
  for (const m of text.matchAll(ruInitialBeforeRe)) {
    const parts = m[1].trim().split(/\s+/);
    const surname = parts[parts.length - 1];
    if (!isCapitalizedRuSurnameCandidate(surname)) continue;
    candidates.push({
      category: "RU_FIO",
      tokenPrefix: "FIO",
      value: m[1],
      start: m.index,
      end: m.index + m[1].length,
      priority: 64,
    });
  }
  const STREET_PREFIX_BEFORE_FIO_RE =
    /(?:^|[\s,(])(?:ул\.|улица|пр-т|пр\.|проспект|пер\.|переулок|б-р|бульвар|ш\.|шоссе|наб\.|набережная|пл\.|площадь)[ \t]+$/iu;
  const ruCapRunRe =
    /(?<![\p{L}\p{N}_-])([А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?(?:[ \t]+[А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?)+)(?![\p{L}\p{N}_-])/gu;
  const wordTokenRe = /[А-ЯЁ][а-яё]{1,}(?:-[А-ЯЁ][а-яё]{1,})?/gu;
  for (const runMatch of text.matchAll(ruCapRunRe)) {
    const runText = runMatch[1];
    const runBase = runMatch.index;
    const tokens = [];
    for (const wm of runText.matchAll(wordTokenRe)) {
      tokens.push({
        word: wm[0],
        norm: normalizeRuWord(wm[0]),
        start: runBase + wm.index,
        end: runBase + wm.index + wm[0].length,
      });
    }
    const precededByStreet =
      tokens.length > 0 &&
      STREET_PREFIX_BEFORE_FIO_RE.test(
        text.slice(Math.max(0, tokens[0].start - 20), tokens[0].start)
      );
    if (precededByStreet) {
      continue;
    }
    for (let i = 0; i < tokens.length; i += 1) {
      if (i + 2 < tokens.length) {
        const [t1, t2, t3] = [tokens[i], tokens[i + 1], tokens[i + 2]];
        if (
          !RU_FIO_STOPWORDS.has(t1.norm) &&
          !RU_FIO_STOPWORDS.has(t2.norm) &&
          !RU_FIO_STOPWORDS.has(t3.norm)
        ) {
          const isNamePatSur =
            RU_FIRST_NAME_FORMS.has(t1.norm) &&
            isRuPatronymic(t2.word) &&
            isCapitalizedRuSurnameCandidate(t3.word);
          const isSurNamePat =
            isCapitalizedRuSurnameCandidate(t1.word) &&
            RU_FIRST_NAME_FORMS.has(t2.norm) &&
            isRuPatronymic(t3.word);
          if (isNamePatSur || isSurNamePat) {
            candidates.push({
              category: "RU_FIO",
              tokenPrefix: "FIO",
              value: text.slice(t1.start, t3.end),
              start: t1.start,
              end: t3.end,
              priority: 64,
            });
          }
        }
      }
      if (i + 1 < tokens.length) {
        const [t1, t2] = [tokens[i], tokens[i + 1]];
        if (!RU_FIO_STOPWORDS.has(t1.norm) && !RU_FIO_STOPWORDS.has(t2.norm)) {
          const isNamePat = RU_FIRST_NAME_FORMS.has(t1.norm) && isRuPatronymic(t2.word);
          const isFirstSur =
            RU_FIRST_NAME_FORMS.has(t1.norm) &&
            isCapitalizedRuSurnameCandidate(t2.word) &&
            hasRuSurnameSuffix(t2.word);
          const isSurFirst =
            isCapitalizedRuSurnameCandidate(t1.word) &&
            hasRuSurnameSuffix(t1.word) &&
            RU_FIRST_NAME_FORMS.has(t2.norm);
          if (isNamePat || isFirstSur || isSurFirst) {
            candidates.push({
              category: "RU_FIO",
              tokenPrefix: "FIO",
              value: text.slice(t1.start, t2.end),
              start: t1.start,
              end: t2.end,
              priority: 64,
            });
          }
        }
      }
    }
  }

  // 9d. RU_ADDRESS (priority 63, street + house required, single-line, optional city capture)
  const MAJOR_RU_CITIES_RE_PART =
    "(?:Москва|Санкт-Петербург|Новосибирск|Екатеринбург|Казань|Нижний[ \\t]+Новгород|Челябинск|Самара|Омск|Ростов-на-Дону|Уфа|Красноярск|Воронеж|Пермь|Волгоград|Краснодар|Саратов|Тюмень|Тольятти|Ижевск|Барнаул|Ульяновск|Иркутск|Хабаровск|Ярославль|Владивосток|Махачкала|Томск|Оренбург|Кемерово|Новокузнецк|Рязань|Астрахань|Набережные[ \\t]+Челны|Пенза|Липецк|Киров|Чебоксары|Калининград|Тула|Курск|Ставрополь|Улан-Удэ|Тверь|Магнитогорск|Сочи|Иваново|Брянск|Белгород|Сургут|Владимир|Чита|Архангельск|Калуга|Смоленск|Волжский|Якутск|Саранск|Череповец|Вологда|Ор[её]л|Подольск|Мурманск|Грозный|Тамбов|Петрозаводск|Кострома|Нижневартовск|Новороссийск|Йошкар-Ола|Химки|Мытищи|Балашиха|Корол[её]в|Зеленоград|Минск|Алматы|Астана)";
  const ADDRESS_NON_CITY_WORDS = new Set([
    "привет", "здравствуйте", "офис", "адрес", "доставка", "компания",
    "организация", "филиал", "отдел", "склад", "россия", "беларусь",
    "казахстан", "срочно", "важно", "итого", "улица", "проспект",
    "переулок", "бульвар", "шоссе", "площадь", "набережная",
  ]);
  const STREET_TYPE_PART =
    "(?:[Уу]л\\.|[Уу]лица|[Пп]р-т|[Пп]р\\.|[Пп]роспект|[Пп]ер\\.|[Пп]ереулок|[Бб]-р|[Бб]ульвар|[Шш]\\.|[Шш]оссе|[Нн]аб\\.|[Нн]абережная|[Пп]л\\.|[Пп]лощадь)";
  const STREET_TYPE_WORD_GUARD =
    "(?!(?:Ул|Улица|Пр-т|Пр|Проспект|Пер|Переулок|Б-р|Бульвар|Ш|Шоссе|Наб|Набережная|Пл|Площадь)(?:$|[^\\p{L}\\p{N}_]))";
  const HOUSE_AND_UNIT_PART =
    ",?[ \\t]*(?:[Дд]\\.|[Дд]ом)[ \\t]*\\d+[А-ЯЁа-яё0-9/-]*(?:,?[ \\t]*(?:корп\\.|корпус|к\\.|стр\\.|строение|лит\\.|кв\\.|оф\\.|офис|пом\\.)[ \\t]*[А-ЯЁа-яё0-9-]+){0,3}";
  const ruAddressRegex = new RegExp(
    `(?<![\\p{L}\\p{N}_])` +
      `([1-6]\\d{5},[ \\t]*)?` +
      `((?:(?:[Гг]\\.?|[Гг]ород|[Пп]ос\\.|[Пп]гт\\.?|[Сс]\\.)[ \\t]*${STREET_TYPE_WORD_GUARD}[А-ЯЁ][а-яёА-ЯЁ-]+(?:[ \\t-]+(?:на|им\\.?|${STREET_TYPE_WORD_GUARD}[А-ЯЁ][а-яёА-ЯЁ-]+)){0,2}|${MAJOR_RU_CITIES_RE_PART})(?:,[ \\t]*|[ \\t]+))?` +
      `([А-ЯЁ][а-яё]{2,}(?:-[А-ЯЁа-яё]{2,})*,[ \\t]*)?` +
      `((?:${STREET_TYPE_PART}[ \\t]+[А-ЯЁ0-9][А-ЯЁа-яё0-9.\\-"«» ]{1,40}|[А-ЯЁ][А-ЯЁа-яё0-9.\\-"«»]+(?:[ \\t]+[А-ЯЁа-яё0-9.\\-"«»]+){0,2}[ \\t]+${STREET_TYPE_PART})${HOUSE_AND_UNIT_PART})` +
      `(?![\\p{L}\\p{N}_-])`,
    "gu"
  );
  for (const m of text.matchAll(ruAddressRegex)) {
    let startOffset = 0;
    if (m[3] && !m[2]) {
      const cityWord = m[3].replace(/,[ \t]*$/, "");
      const cityNorm = normalizeRuWord(cityWord);
      const beforeBareCity = text.slice(Math.max(0, m.index - 40), m.index);
      const precededByCapWord = /[А-ЯЁ][а-яё]+[ \t]+$/.test(beforeBareCity);
      if (
        precededByCapWord ||
        ADDRESS_NON_CITY_WORDS.has(cityNorm) ||
        RU_FIO_STOPWORDS.has(cityNorm) ||
        RU_FIRST_NAME_FORMS.has(cityNorm)
      ) {
        startOffset = m[0].length - m[4].length;
      }
    }
    const val = m[0].slice(startOffset);
    const start = m.index + startOffset;
    candidates.push({
      category: "RU_ADDRESS",
      tokenPrefix: "ADDRESS",
      value: val,
      start,
      end: start + val.length,
      priority: 63,
    });
  }

  // 10. IPV4 (priority 60)
  const ipv4Regex =
    /(?<![\p{L}\p{N}_.])(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?![\p{L}\p{N}_])(?![.]\d)/gu;
  for (const m of text.matchAll(ipv4Regex)) {
    candidates.push({
      category: "IPV4",
      tokenPrefix: "IP",
      value: m[0],
      start: m.index,
      end: m.index + m[0].length,
      priority: 60,
    });
  }

  // 10b. UUID (priority 58, secondary, gated by detectUuid / sensitivity=strict)
  if (detectUuid) {
    const uuidRegex =
      /(?<![A-Za-z0-9_-])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?![A-Za-z0-9_-])/gi;
    for (const m of text.matchAll(uuidRegex)) {
      candidates.push({
        category: "UUID",
        tokenPrefix: "UUID",
        value: m[0],
        start: m.index,
        end: m.index + m[0].length,
        priority: 58,
      });
    }
  }

  // 11. HIGH_ENTROPY (priority 50)
  const entropyRegex =
    /(?<=^|[\s"'`()[\]{}<>,;:=])([A-Za-z0-9_.~+/\\-]{20,}={0,2})(?=$|[\s"'`()[\]{}<>,;:=!?])/g;
  for (const m of text.matchAll(entropyRegex)) {
    const rawToken = m[1];
    const trimmed = rawToken.replace(/[.!?]+$/, "");
    if (!trimmed || !isHighEntropySecret(trimmed)) {
      continue;
    }
    // Ignore URL :port/path suffixes such as https://example.com:8443/v1/... or grpcs://host:9443/...
    if (m.index > 0 && text[m.index - 1] === ":" && /^\d{1,5}\//.test(trimmed)) {
      const lookback = text.slice(Math.max(0, m.index - 200), m.index);
      if (/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\s"'`()[\]{}<>,;=]+:$/.test(lookback)) {
        continue;
      }
    }
    candidates.push({
      category: "HIGH_ENTROPY",
      tokenPrefix: "SECRET",
      value: trimmed,
      start: m.index,
      end: m.index + trimmed.length,
      priority: 50,
    });
  }

  // Overlap resolution: priority DESC, span length DESC, start ASC.
  candidates.sort(
    (a, b) =>
      b.priority - a.priority ||
      b.end - b.start - (a.end - a.start) ||
      a.start - b.start
  );

  // Maintain accepted disjoint intervals in a deterministic AVL tree keyed by `start`
  // for O(k log k) worst-case insertion & predecessor/successor overlap checks.
  const heightOf = (node) => (node ? node.h : 0);
  const updateHeight = (node) => {
    const lh = node.left ? node.left.h : 0;
    const rh = node.right ? node.right.h : 0;
    node.h = (lh > rh ? lh : rh) + 1;
  };
  const rotateLeft = (x) => {
    const y = x.right;
    x.right = y.left;
    y.left = x;
    updateHeight(x);
    updateHeight(y);
    return y;
  };
  const rotateRight = (y) => {
    const x = y.left;
    y.left = x.right;
    x.right = y;
    updateHeight(y);
    updateHeight(x);
    return x;
  };

  let root = null;
  for (const candidate of candidates) {
    let cur = root;
    let pred = null;
    let succ = null;
    let overlaps = false;
    const path = [];

    while (cur !== null) {
      path.push(cur);
      if (candidate.start === cur.start) {
        overlaps = true;
        break;
      }
      if (candidate.start < cur.start) {
        succ = cur;
        cur = cur.left;
      } else {
        pred = cur;
        cur = cur.right;
      }
    }

    if (
      overlaps ||
      (pred !== null && pred.end > candidate.start) ||
      (succ !== null && candidate.end > succ.start)
    ) {
      continue;
    }

    const leaf = {
      start: candidate.start,
      end: candidate.end,
      item: candidate,
      left: null,
      right: null,
      h: 1,
    };
    if (path.length === 0) {
      root = leaf;
      continue;
    }

    const immediateParent = path[path.length - 1];
    if (candidate.start < immediateParent.start) {
      immediateParent.left = leaf;
    } else {
      immediateParent.right = leaf;
    }

    for (let i = path.length - 1; i >= 0; i -= 1) {
      const node = path[i];
      updateHeight(node);
      const bal = heightOf(node.left) - heightOf(node.right);
      let replacement = node;
      if (bal > 1) {
        if (candidate.start > node.left.start) {
          node.left = rotateLeft(node.left);
        }
        replacement = rotateRight(node);
      } else if (bal < -1) {
        if (candidate.start < node.right.start) {
          node.right = rotateRight(node.right);
        }
        replacement = rotateLeft(node);
      }
      if (replacement !== node) {
        if (i === 0) {
          root = replacement;
        } else {
          const parent = path[i - 1];
          if (parent.left === node) {
            parent.left = replacement;
          } else {
            parent.right = replacement;
          }
        }
        break;
      }
    }
  }

  const accepted = [];
  const stack = [];
  let cursor = root;
  while (cursor !== null || stack.length > 0) {
    while (cursor !== null) {
      stack.push(cursor);
      cursor = cursor.left;
    }
    cursor = stack.pop();
    accepted.push(cursor.item);
    cursor = cursor.right;
  }
  return accepted;
}
