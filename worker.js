// =====================================================================================
// CIGRAM ADS API — Cloudflare Worker (Module syntax) + Durable Objects
// نظام إعلانات الشركات: إعدادات، معلنون، حملات، مواد، /ads، تتبع، تقارير، محادثة لحظية.
//
// Bindings المطلوبة (انظر docs/DEPLOY.md):
//   Durable Objects : ADS_CORE (class AdsCore) ، CHAT_HUB (class ChatHub)  — كلاهما SQLite-backed (new_sqlite_classes)
//   R2 (اختياري)    : ADS_BUCKET  — وإن لم يوجد يُستخدم MOVIES_BUCKET تحت المسار ads/
//   Secrets          : ADMIN_TOKEN (نفس رمز الأدمن) ، CHAT_KEY (32 بايت base64 لتشفير الرسائل AES-GCM)
//   Secrets (مصادقة المستخدم — واحد منهما): JWT_SECRET  أو  AUTH_VERIFY_URL
//   اختياري          : PUBLIC_BASE ، PUSH_WEBHOOK_URL ، CHAT_RETENTION_DAYS
// =====================================================================================

const SLOTS = ["splash", "hero", "inline", "popup", "sticky", "sponsor"];
const STAGES = ["received", "review", "quoted", "awaiting_payment"];
const PAID = ["unpaid", "partial", "paid"];
const ACTIONS = ["link", "whatsapp", "call", "store", "copy", "none"];
const DAY_MS = 86400000;
const MAX_CAMPAIGN_DAYS = 800;
const MEDIA_PREFIX = "ads/creatives/";
const MAX_IMAGE_BYTES = 6 * 1024 * 1024;
const MAX_VIDEO_BYTES = 40 * 1024 * 1024;

class HttpError extends Error {
  constructor(status, code, message, extra) {
    super(message || code);
    this.status = status;
    this.code = code;
    this.extra = extra || {};
  }
}
function fail(status, code, message, extra) {
  throw new HttpError(status, code, message, extra);
}

// ------------------------------------------------------------------------ helpers
function corsHeaders(extra) {
  return Object.assign(
    {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      "access-control-allow-headers": "Content-Type, Authorization, X-Admin-Token",
      "access-control-max-age": "86400",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
    extra || {}
  );
}
function reply(body, status, extraHeaders) {
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: corsHeaders(Object.assign({ "content-type": "application/json; charset=utf-8" }, extraHeaders || {})),
  });
}
function errorBody(e) {
  if (e instanceof HttpError) {
    return [Object.assign({ ok: false, error: e.code, message: e.message }, e.extra), e.status];
  }
  return [{ ok: false, error: "internal_error", message: "حدث خطأ داخلي في الخادم." }, 500];
}

function cleanText(v, max) {
  if (v === null || v === undefined) return "";
  // إزالة محارف التحكم (عدا السطر الجديد والتبويب) لمنع حقن محارف غير مرئية
  let s = String(v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F‎‏‪-‮⁦-⁩]/g, "");
  s = s.trim();
  return max && s.length > max ? s.slice(0, max) : s;
}
function reqText(v, max, label) {
  const s = cleanText(v, max);
  if (!s) fail(400, "invalid_field", "الحقل «" + label + "» مطلوب.");
  return s;
}
function num(v, min, max, def) {
  if (v === null || v === undefined || v === "") return def;
  const n = Number(v);
  if (!isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}
function int(v, min, max, def) {
  const n = num(v, min, max, def);
  return n === undefined || n === null ? n : Math.round(n);
}
function bool(v, def) {
  if (v === true || v === "true" || v === 1 || v === "1") return true;
  if (v === false || v === "false" || v === 0 || v === "0") return false;
  return def;
}
function oneOf(v, list, def) {
  return list.indexOf(v) >= 0 ? v : def;
}
function strList(v, maxItems, maxLen) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const x of v) {
    const s = cleanText(x, maxLen);
    if (s && out.indexOf(s) < 0) out.push(s);
    if (out.length >= maxItems) break;
  }
  return out;
}
function round2(n) {
  return Math.round(n * 100) / 100;
}
function randId(prefix, bytes) {
  const a = new Uint8Array(bytes || 9);
  crypto.getRandomValues(a);
  return (prefix || "") + b64url(a);
}
function b64url(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBytes(str) {
  const s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
async function sha256Hex(text) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(d)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function timingSafeEqual(a, b) {
  a = String(a || "");
  b = String(b || "");
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return diff === 0;
}
function parseTime(v, def) {
  if (v === null || v === undefined || v === "") return def;
  if (typeof v === "number" && isFinite(v)) return Math.round(v);
  const s = String(v).trim();
  if (/^\d{10,14}$/.test(s)) return parseInt(s, 10);
  const t = Date.parse(s);
  return isNaN(t) ? def : t;
}
function dayKey(ms, offsetMin) {
  const d = new Date(ms + (offsetMin || 0) * 60000);
  return d.getUTCFullYear() + String(d.getUTCMonth() + 1).padStart(2, "0") + String(d.getUTCDate()).padStart(2, "0");
}
function hourOf(ms, offsetMin) {
  return new Date(ms + (offsetMin || 0) * 60000).getUTCHours();
}
function safeUrl(v, allowed) {
  const s = cleanText(v, 800);
  if (!s) return "";
  const ok = (allowed || ["https:"]).some((p) => s.toLowerCase().startsWith(p + "//") || s.toLowerCase().startsWith(p));
  if (!ok) fail(400, "invalid_url", "الرابط غير صالح (يجب أن يبدأ بـ https://).");
  if (/[\s"'<>]/.test(s)) fail(400, "invalid_url", "الرابط يحتوي على محارف غير مسموحة.");
  return s;
}
function digitsOnly(v, max) {
  return String(v || "").replace(/[^\d]/g, "").slice(0, max || 20);
}

// --------------------------------------------------------------- default settings
const IQ_CITIES = [
  ["baghdad", "بغداد"], ["basra", "البصرة"], ["nineveh", "نينوى"], ["erbil", "أربيل"],
  ["sulaymaniyah", "السليمانية"], ["duhok", "دهوك"], ["kirkuk", "كركوك"], ["najaf", "النجف"],
  ["karbala", "كربلاء"], ["babil", "بابل"], ["anbar", "الأنبار"], ["diyala", "ديالى"],
  ["saladin", "صلاح الدين"], ["wasit", "واسط"], ["dhi_qar", "ذي قار"], ["maysan", "ميسان"],
  ["muthanna", "المثنى"], ["qadisiyyah", "القادسية"], ["halabja", "حلبجة"],
];
const CITY_ALIASES = {
  baghdad: ["baghdad", "bagdad", "baghdad governorate"],
  basra: ["basra", "basrah", "al basrah"],
  nineveh: ["nineveh", "ninawa", "mosul", "nineveh governorate"],
  erbil: ["erbil", "arbil", "irbil", "hewler"],
  sulaymaniyah: ["sulaymaniyah", "sulaimani", "as sulaymaniyah", "slemani"],
  duhok: ["duhok", "dohuk", "dahuk"],
  kirkuk: ["kirkuk", "at ta'mim", "at tamim"],
  najaf: ["najaf", "an najaf"],
  karbala: ["karbala", "karbala'"],
  babil: ["babil", "babylon", "hillah", "al hillah"],
  anbar: ["anbar", "al anbar", "ramadi"],
  diyala: ["diyala", "diyalá", "baqubah"],
  saladin: ["saladin", "salah ad din", "salah al-din", "tikrit"],
  wasit: ["wasit", "kut"],
  dhi_qar: ["dhi qar", "dhi-qar", "thi qar", "nasiriyah"],
  maysan: ["maysan", "maysan governorate", "amarah"],
  muthanna: ["muthanna", "al muthanna", "samawah"],
  qadisiyyah: ["qadisiyyah", "al qadisiyah", "diwaniyah"],
  halabja: ["halabja"],
};

function defaultSettings() {
  const slot = (label, desc, suited, price, views, hint) => ({
    label, desc, suited, price_per_day: price, views_per_day: views, enabled: true, preview_hint: hint,
  });
  return {
    version: 1,
    updated_at: 0,
    currency: { code: "USD", symbol: "$", decimals: 0 },
    slots: {
      splash: slot("شاشة الافتتاح (Splash)", "إعلان بملء الشاشة لبضع ثوانٍ عند فتح التطبيق مع عدّاد وزر تخطي. أعلى ظهور وأقوى أثر.", "إطلاق منتج، عروض موسمية، علامات تجارية كبرى", 20, 4000, "full_screen"),
      hero: slot("البانر الرئيسي (Hero)", "بانر كبير أعلى الصفحة الرئيسية يتحرك تلقائياً بين الإعلانات ويتوقف عند اللمس.", "حملات الوعي بالعلامة، العروض الدائمة", 12, 6000, "top_banner"),
      inline: slot("بطاقة ضمن المحتوى (Inline)", "بطاقة إعلانية بين صفوف الأفلام والمسلسلات تشبه بطاقات المحتوى بوضوح علامة «إعلان».", "المتاجر والخدمات المحلية، تطبيقات", 7, 8000, "card"),
      popup: slot("نافذة منبثقة (Popup)", "نافذة تظهر مرة واحدة يومياً لكل مستخدم مع زر إغلاق واضح.", "عروض محدودة المدة، كوبونات", 10, 3000, "dialog"),
      sticky: slot("شريط ثابت (Sticky)", "شريط رفيع ثابت أسفل الشاشة يمكن للمستخدم إغلاقه.", "تذكير مستمر بالعلامة، روابط سريعة", 5, 7000, "bottom_bar"),
      sponsor: slot("رعاية (Sponsor)", "شعار «برعاية» بجانب قسم أو صفحة محددة بشكل أنيق وغير مزعج.", "رعاية أقسام، شراكات طويلة الأمد", 4, 5000, "badge"),
    },
    durations: [1, 3, 7, 30, 90, 180, 365],
    custom_days: { min: 1, max: 730 },
    discounts: [
      { min_days: 7, pct: 5 }, { min_days: 30, pct: 10 }, { min_days: 90, pct: 15 },
      { min_days: 180, pct: 20 }, { min_days: 365, pct: 30 },
    ],
    addons: {
      exclusive: { label: "حصرية المساحة", desc: "لا يظهر أي إعلان آخر في المساحة طوال مدة حملتك.", type: "pct", value: 50 },
      video: { label: "إعلان فيديو", desc: "عرض فيديو قصير بدل الصورة.", type: "flat", value: 15 },
      design: { label: "تصميم من فريقنا", desc: "نصمم لك المادة الإعلانية باحتراف.", type: "flat", value: 30 },
    },
    targeting: {
      cities: IQ_CITIES.map((c) => ({ id: c[0], ar: c[1], aliases: CITY_ALIASES[c[0]] || [] })),
      langs: [{ id: "ar", label: "العربية" }, { id: "ku", label: "الكردية" }, { id: "en", label: "الإنجليزية" }],
      city_pct: 15, lang_pct: 10, hours_pct: 10,
      city_reach_factor: 0.5, lang_reach_factor: 0.7, hours_reach_factor: 0.6,
    },
    rules: {
      accepted: [
        { title: "منتجات وخدمات قانونية", text: "متاجر، مطاعم، عيادات، مدارس، تطبيقات، خدمات مرخّصة وواضحة." },
        { title: "محتوى صادق", text: "ادعاءات يمكن إثباتها، أسعار وعروض حقيقية، وشروط واضحة." },
        { title: "صور بجودة عالية", text: "صور واضحة غير مشوشة، نصوص مقروءة، وهوية بصرية متسقة." },
      ],
      rejected: [
        { title: "المحتوى الجنسي", text: "أي صور أو نصوص أو إيحاءات جنسية." },
        { title: "الكحول والمخدرات", text: "الترويج للخمور أو المخدرات أو أدواتها." },
        { title: "القمار", text: "المراهنات وألعاب الحظ والمقامرة بأنواعها." },
        { title: "العنف والكراهية", text: "المحتوى العنيف أو التحريضي أو المسيء لأي فئة." },
        { title: "المنتجات المقلدة", text: "تقليد العلامات التجارية أو بيع منتجات مزيفة." },
        { title: "الادعاءات الكاذبة", text: "وعود مضللة، نتائج مضمونة غير واقعية، أو أسعار وهمية." },
        { title: "انتحال الهوية", text: "الظهور باسم شركة أو شخص آخر دون إذن." },
        { title: "المحتوى السياسي المحرّض", text: "الدعاية السياسية التحريضية أو المثيرة للفتنة." },
        { title: "إعلانات تحاكي واجهة التطبيق", text: "إعلان يبدو كزر أو إشعار أو رسالة نظام لخداع المستخدم." },
      ],
    },
    policies: [
      { id: "ads", title: "سياسة الإعلانات", body: "• تخضع كل مادة إعلانية للمراجعة اليدوية قبل النشر، ولا يظهر أي إعلان قبل الموافقة عليه.\n• نحتفظ بحق رفض أو إيقاف أي حملة تخالف قواعد الإعلان المقبول في أي وقت، مع بيان السبب.\n• يظهر على كل إعلان وسم «إعلان» ويستطيع المستخدم إخفاءه أو الإبلاغ عنه.\n• لا نضمن عدداً محدداً من النقرات؛ التقديرات المعروضة استرشادية مبنية على الأرقام الفعلية." },
      { id: "privacy", title: "الخصوصية وحماية البيانات", body: "• نحمي بيانات المعلن: لا نبيعها ولا نشاركها مع أي جهة.\n• بيانات مستخدمي التطبيق لا تُشارك ولا تُباع للمعلنين إطلاقاً؛ التقارير تحوي أرقاماً مجمّعة فقط (مشاهدات ونقرات).\n• نخزّن محادثات الإعلانات (نصوصاً وملفات) بصيغة مشفّرة لغرض توثيق الطلب والاتفاق ومتابعة الحملة وحل أي خلاف.\n• يمكنك طلب حذف محادثتك وملفاتك في أي وقت وسيُحذف كل شيء من خوادمنا.\n• التشفير: الاتصال عبر TLS والمخزّن مشفّر بخوادمنا، وليس تشفيراً طرفياً كاملاً." },
      { id: "terms", title: "الشروط والأحكام", body: "• يلتزم المعلن بصحة بياناته وملكيته لكل ما يرفعه من مواد.\n• يُعتمد السعر المتفق عليه في عرض السعر المقبول داخل المحادثة.\n• تبدأ الحملة في التاريخ المتفق عليه بعد اكتمال الدفع والموافقة على المادة.\n• لا نتحمل مسؤولية أي نزاع بين المعلن وعملائه." },
      { id: "payment", title: "الدفع والاسترجاع والإلغاء", body: "• يتم الدفع يدوياً بالطريقة المتفق عليها في المحادثة قبل بدء الحملة.\n• الإلغاء قبل بدء الحملة: استرجاع كامل المبلغ.\n• الإلغاء بعد البدء: يُسترجع ما يعادل الأيام غير المستهلكة بعد خصم رسوم التصميم إن وُجدت.\n• في حال رفض المادة لمخالفتها السياسات يُمنح المعلن فرصة لتعديلها دون رسوم إضافية." },
      { id: "ip", title: "حقوق الملكية والمواد الإعلانية", body: "• يمنح المعلن التطبيق ترخيصاً محدوداً لعرض مواده خلال مدة الحملة فقط.\n• تبقى حقوق الملكية للمعلن، ولا نستخدم موادهم خارج الحملة.\n• التصاميم التي ينجزها فريقنا تؤول ملكيتها للمعلن بعد اكتمال الدفع." },
    ],
    policies_version: 1,
    policies_updated_at: 0,
    faq: [
      { q: "كم يستغرق تجهيز الإعلان؟", a: "عادة خلال 24 ساعة من اكتمال المادة والدفع." },
      { q: "هل أستطيع تغيير الإعلان أثناء الحملة؟", a: "نعم، أرسل المادة الجديدة في المحادثة وسنراجعها ونستبدلها." },
      { q: "كيف أعرف نتيجة إعلاني؟", a: "من «إعلاناتي» ترى المشاهدات والنقرات ونسبة النقر بشكل يومي، ويمكنك تحميل تقرير." },
      { q: "هل ستصل بياناتي للمستخدمين؟", a: "لا. نعرض إعلانك فقط، ولا نشارك بيانات أي طرف." },
      { q: "ما طرق الدفع؟", a: "نتفق عليها في المحادثة وفق ما يناسبك." },
      { q: "هل يمكنني تجديد الحملة؟", a: "نعم، زر «تجديد» في إعلاناتي يرسل لنا الطلب مباشرة." },
    ],
    contact: { whatsapp: "", whatsapp_message: "مرحباً، أرغب بالإعلان في تطبيق سيجرام.", x_url: "", x_handle: "" },
    hours: { enabled: true, tz_offset_min: 180, from: "09:00", to: "22:00", days: [0, 1, 2, 3, 4, 6] },
    auto_reply: "شكراً لتواصلك. نحن خارج ساعات العمل حالياً وسنرد عليك فور عودتنا.",
    hero: { title: "اجعل علامتك أمام جمهور حقيقي", subtitle: "إعلانات مدروسة داخل تطبيق يشاهده الآلاف يومياً.", manual_users: 0, manual_daily_views: 0 },
  };
}

// حساب السعر — نفس المعادلة موثقة في docs ومنسوخة في تطبيق المستخدم لعرض فوري.
function computeQuote(settings, input) {
  const slotKey = oneOf(input.slot, SLOTS, null);
  if (!slotKey) fail(400, "invalid_slot", "اختر مساحة إعلانية صحيحة.");
  const slot = settings.slots[slotKey];
  if (!slot || slot.enabled === false) fail(400, "slot_disabled", "هذه المساحة غير متاحة حالياً.");
  const cd = settings.custom_days || { min: 1, max: 730 };
  const days = int(input.days, cd.min || 1, cd.max || 730, null);
  if (!days) fail(400, "invalid_days", "حدد مدة صحيحة بالأيام.");
  const base = round2(slot.price_per_day * days);
  let pct = 0;
  for (const d of settings.discounts || []) if (days >= d.min_days && d.pct > pct) pct = d.pct;
  const discount = round2((base * pct) / 100);
  const subtotal = round2(base - discount);
  const t = settings.targeting || {};
  const tg = input.targeting || {};
  const hasCity = Array.isArray(tg.cities) && tg.cities.length > 0;
  const hasLang = Array.isArray(tg.langs) && tg.langs.length > 0;
  const hasHours = !!(tg.hours && tg.hours.from !== undefined && tg.hours.to !== undefined && tg.hours !== null);
  const lines = [];
  let targeting = 0;
  if (hasCity) { const v = round2((subtotal * (t.city_pct || 0)) / 100); targeting += v; lines.push({ key: "city", amount: v }); }
  if (hasLang) { const v = round2((subtotal * (t.lang_pct || 0)) / 100); targeting += v; lines.push({ key: "lang", amount: v }); }
  if (hasHours) { const v = round2((subtotal * (t.hours_pct || 0)) / 100); targeting += v; lines.push({ key: "hours", amount: v }); }
  targeting = round2(targeting);
  const ad = input.addons || {};
  const addonLines = [];
  let addons = 0;
  for (const key of Object.keys(settings.addons || {})) {
    if (!bool(ad[key], false)) continue;
    const a = settings.addons[key];
    const v = a.type === "pct" ? round2((subtotal * a.value) / 100) : round2(a.value);
    addons += v;
    addonLines.push({ key, label: a.label, amount: v });
  }
  addons = round2(addons);
  const total = round2(subtotal + targeting + addons);
  let reach = (slot.views_per_day || 0) * days;
  if (hasCity) reach *= t.city_reach_factor || 1;
  if (hasLang) reach *= t.lang_reach_factor || 1;
  if (hasHours) reach *= t.hours_reach_factor || 1;
  reach = Math.round(reach);
  return {
    slot: slotKey, days, base, discount_pct: pct, discount, subtotal,
    targeting_total: targeting, targeting_lines: lines, addons_total: addons, addon_lines: addonLines,
    total, currency: settings.currency, estimated_views: reach,
    estimated_views_min: Math.round(reach * 0.8), estimated_views_max: Math.round(reach * 1.2),
  };
}

// =====================================================================================
// Durable Object: AdsCore — مصدر الحقيقة الوحيد للإعدادات والمعلنين والحملات والمواد والإحصاءات.
// كائن واحد (singleton) = اتساق قوي وبدون تعارض عدّادات. التخزين: SQLite-backed (يعمل في الخطة المجانية).
// =====================================================================================

function bucketOf(env) {
  return env.ADS_BUCKET || env.MOVIES_BUCKET || null;
}
function mediaUrl(origin, key) {
  if (!key) return "";
  if (key.indexOf(MEDIA_PREFIX) === 0) return origin + "/m/c/" + key.slice(MEDIA_PREFIX.length);
  if (key.indexOf("ads/logos/") === 0) return origin + "/m/l/" + key.slice("ads/logos/".length);
  return "";
}
function normName(s) {
  return String(s || "")
    .toLowerCase()
    .replace(/محافظة|governorate|province|state of/g, " ")
    .replace(/[^\p{L}\p{N}' ]/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
}
function resolveCity(settings, ...candidates) {
  const cities = (settings.targeting && settings.targeting.cities) || [];
  for (const raw of candidates) {
    const n = normName(raw);
    if (!n) continue;
    for (const c of cities) {
      if (normName(c.id) === n || normName(c.ar) === n) return c.id;
      for (const a of c.aliases || []) if (normName(a) === n) return c.id;
    }
  }
  return "";
}

function sanitizeTargeting(t) {
  t = t && typeof t === "object" ? t : {};
  let hours = null;
  if (t.hours && typeof t.hours === "object" && t.hours.from !== undefined && t.hours.to !== undefined) {
    const from = int(t.hours.from, 0, 23, null);
    const to = int(t.hours.to, 0, 24, null);
    if (from !== null && to !== null && from !== to) hours = { from, to };
  }
  return {
    cities: strList(t.cities, 30, 40).map((x) => x.toLowerCase()),
    langs: strList(t.langs, 10, 8).map((x) => x.toLowerCase().slice(0, 2)),
    hours,
    min_version: int(t.min_version, 0, 1e9, 0),
    max_version: int(t.max_version, 0, 1e9, 0),
  };
}
function inHours(h, hours) {
  if (!hours) return true;
  if (hours.from < hours.to) return h >= hours.from && h < hours.to;
  return h >= hours.from || h < hours.to; // يعبر منتصف الليل
}
function displayStage(c, now) {
  if (c.status === "rejected") return "rejected";
  if (c.status === "approved" || c.status === "paused") {
    if (c.status === "paused") return "paused";
    if (now < c.start_at) return "scheduled";
    if (now >= c.end_at) return "ended";
    return "running";
  }
  return c.order_stage || "received";
}

export class AdsCore {
  constructor(state, env) {
    this.state = state;
    this.s = state.storage;
    this.env = env;
    this._settings = null;
    this._cache = null;
    this._rl = new Map();
  }

  async fetch(request) {
    let body;
    try {
      body = await request.json();
    } catch (e) {
      return new Response(JSON.stringify({ ok: false, error: "invalid_json", message: "بيانات غير صالحة." }), { status: 400 });
    }
    try {
      const fn = this["op_" + body.op];
      if (typeof fn !== "function") fail(404, "unknown_op", "عملية غير معروفة.");
      const out = await fn.call(this, body.p || {});
      return new Response(JSON.stringify(Object.assign({ ok: true }, out || {})), { status: 200 });
    } catch (e) {
      const [b, st] = errorBody(e);
      if (!(e instanceof HttpError)) console.log("core_error", body && body.op, String(e && e.message));
      return new Response(JSON.stringify(b), { status: st });
    }
  }

  // ------------------------------------------------------------------ infra
  rl(key, limit, windowMs) {
    const now = Date.now();
    if (this._rl.size > 8000) this._rl.clear();
    let r = this._rl.get(key);
    if (!r || now > r.reset) {
      r = { n: 0, reset: now + windowMs };
      this._rl.set(key, r);
    }
    r.n++;
    return r.n <= limit;
  }
  async ensureAlarm() {
    try {
      if (!(await this.s.getAlarm())) await this.s.setAlarm(Date.now() + 3600000);
    } catch (e) { /* ignore */ }
  }
  async settings() {
    if (this._settings) return this._settings;
    const stored = (await this.s.get("settings")) || {};
    const d = defaultSettings();
    const merged = Object.assign({}, d, stored);
    for (const k of ["slots", "addons", "targeting", "contact", "hours", "hero", "rules", "currency", "custom_days"]) {
      merged[k] = Object.assign({}, d[k], stored[k] || {});
    }
    for (const k of Object.keys(d.slots)) merged.slots[k] = Object.assign({}, d.slots[k], (stored.slots || {})[k] || {});
    for (const k of Object.keys(d.addons)) merged.addons[k] = Object.assign({}, d.addons[k], (stored.addons || {})[k] || {});
    this._settings = merged;
    return merged;
  }
  async load() {
    if (this._cache) return this._cache;
    const camps = await this.s.list({ prefix: "camp:" });
    const crvs = await this.s.list({ prefix: "crv:" });
    this._cache = { camps, crvs };
    return this._cache;
  }
  dirty() {
    this._cache = null;
  }
  log(c, action, note) {
    c.log = Array.isArray(c.log) ? c.log : [];
    c.log.push({ t: Date.now(), a: action, n: cleanText(note, 200) });
    if (c.log.length > 60) c.log = c.log.slice(-60);
  }

  // ------------------------------------------------------------------ settings
  async op_settings_public(p) {
    const st = await this.settings();
    const now = Date.now();
    const out = JSON.parse(JSON.stringify(st));
    out.hero = await this.heroNumbers(st);
    out.server_time = now;
    return { settings: out };
  }
  async op_settings_admin() {
    const st = await this.settings();
    return { settings: st, hero_measured: await this.heroNumbers(Object.assign({}, st, { hero: Object.assign({}, st.hero, { manual_users: 0, manual_daily_views: 0 }) })) };
  }
  async heroNumbers(st) {
    const now = Date.now();
    const off = (st.hours && st.hours.tz_offset_min) || 180;
    let dauSum = 0, dauDays = 0, viewsSum = 0;
    for (let i = 1; i <= 7; i++) {
      const dk = dayKey(now - i * DAY_MS, off);
      const dau = await this.s.get("dau:" + dk);
      const views = await this.s.get("day:" + dk);
      if (dau) { dauSum += dau; dauDays++; }
      if (views) viewsSum += views;
    }
    const measuredUsers = dauDays ? Math.round(dauSum / dauDays) : 0;
    const measuredViews = dauDays ? Math.round(viewsSum / dauDays) : 0;
    const mu = (st.hero && st.hero.manual_users) || 0;
    const mv = (st.hero && st.hero.manual_daily_views) || 0;
    return {
      title: st.hero.title, subtitle: st.hero.subtitle,
      active_users: mu > 0 ? mu : measuredUsers,
      avg_daily_views: mv > 0 ? mv : measuredViews,
      source: mu > 0 || mv > 0 ? "manual" : "measured",
    };
  }
  async op_settings_set(p) {
    const cur = await this.settings();
    const patch = p.patch && typeof p.patch === "object" ? p.patch : {};
    const next = JSON.parse(JSON.stringify(cur));
    const d = defaultSettings();

    if (patch.currency) {
      next.currency = {
        code: cleanText(patch.currency.code, 6).toUpperCase() || "USD",
        symbol: cleanText(patch.currency.symbol, 6) || "$",
        decimals: int(patch.currency.decimals, 0, 3, 0),
      };
    }
    if (patch.slots && typeof patch.slots === "object") {
      for (const k of SLOTS) {
        const s = patch.slots[k];
        if (!s || typeof s !== "object") continue;
        const t = next.slots[k];
        if (s.label !== undefined) t.label = reqText(s.label, 60, "اسم المساحة");
        if (s.desc !== undefined) t.desc = cleanText(s.desc, 400);
        if (s.suited !== undefined) t.suited = cleanText(s.suited, 200);
        if (s.price_per_day !== undefined) t.price_per_day = num(s.price_per_day, 0, 1e7, t.price_per_day);
        if (s.views_per_day !== undefined) t.views_per_day = int(s.views_per_day, 0, 1e9, t.views_per_day);
        if (s.enabled !== undefined) t.enabled = bool(s.enabled, true);
      }
    }
    if (Array.isArray(patch.durations)) {
      const arr = patch.durations.map((x) => int(x, 1, 730, null)).filter((x) => x).slice(0, 12);
      if (arr.length) next.durations = Array.from(new Set(arr)).sort((a, b) => a - b);
    }
    if (patch.custom_days) {
      next.custom_days = { min: int(patch.custom_days.min, 1, 365, 1), max: int(patch.custom_days.max, 1, 730, 730) };
      if (next.custom_days.max < next.custom_days.min) next.custom_days.max = next.custom_days.min;
    }
    if (Array.isArray(patch.discounts)) {
      next.discounts = patch.discounts
        .map((x) => ({ min_days: int(x && x.min_days, 1, 730, 0), pct: num(x && x.pct, 0, 90, 0) }))
        .filter((x) => x.min_days > 0)
        .slice(0, 12)
        .sort((a, b) => a.min_days - b.min_days);
    }
    if (patch.addons && typeof patch.addons === "object") {
      for (const k of Object.keys(d.addons)) {
        const a = patch.addons[k];
        if (!a || typeof a !== "object") continue;
        const t = next.addons[k];
        if (a.label !== undefined) t.label = reqText(a.label, 50, "اسم الإضافة");
        if (a.desc !== undefined) t.desc = cleanText(a.desc, 200);
        if (a.type !== undefined) t.type = oneOf(a.type, ["pct", "flat"], t.type);
        if (a.value !== undefined) t.value = num(a.value, 0, 1e7, t.value);
      }
    }
    if (patch.targeting && typeof patch.targeting === "object") {
      const t = patch.targeting, n = next.targeting;
      for (const k of ["city_pct", "lang_pct", "hours_pct"]) if (t[k] !== undefined) n[k] = num(t[k], 0, 500, n[k]);
      for (const k of ["city_reach_factor", "lang_reach_factor", "hours_reach_factor"]) if (t[k] !== undefined) n[k] = num(t[k], 0.01, 1, n[k]);
      if (Array.isArray(t.cities)) {
        n.cities = t.cities.slice(0, 40).map((c) => ({
          id: cleanText(c && c.id, 30).toLowerCase().replace(/[^a-z0-9_]/g, ""),
          ar: cleanText(c && c.ar, 40),
          aliases: strList(c && c.aliases, 10, 40),
        })).filter((c) => c.id && c.ar);
      }
      if (Array.isArray(t.langs)) {
        n.langs = t.langs.slice(0, 12).map((l) => ({ id: cleanText(l && l.id, 8).toLowerCase(), label: cleanText(l && l.label, 30) })).filter((l) => l.id && l.label);
      }
    }
    if (patch.rules && typeof patch.rules === "object") {
      for (const k of ["accepted", "rejected"]) {
        if (Array.isArray(patch.rules[k])) {
          next.rules[k] = patch.rules[k].slice(0, 30).map((x) => ({ title: cleanText(x && x.title, 80), text: cleanText(x && x.text, 400) })).filter((x) => x.title);
        }
      }
    }
    if (Array.isArray(patch.faq)) {
      next.faq = patch.faq.slice(0, 30).map((x) => ({ q: cleanText(x && x.q, 200), a: cleanText(x && x.a, 1500) })).filter((x) => x.q && x.a);
    }
    if (patch.contact && typeof patch.contact === "object") {
      const c = patch.contact;
      if (c.whatsapp !== undefined) next.contact.whatsapp = digitsOnly(c.whatsapp, 18);
      if (c.whatsapp_message !== undefined) next.contact.whatsapp_message = cleanText(c.whatsapp_message, 300);
      if (c.x_url !== undefined) next.contact.x_url = c.x_url ? safeUrl(c.x_url, ["https:"]) : "";
      if (c.x_handle !== undefined) next.contact.x_handle = cleanText(c.x_handle, 40).replace(/^@/, "");
    }
    if (patch.hours && typeof patch.hours === "object") {
      const h = patch.hours;
      const hhmm = (v, def) => (/^([01]\d|2[0-3]):[0-5]\d$/.test(String(v || "")) ? String(v) : def);
      next.hours = {
        enabled: bool(h.enabled, next.hours.enabled),
        tz_offset_min: int(h.tz_offset_min, -720, 840, next.hours.tz_offset_min),
        from: hhmm(h.from, next.hours.from),
        to: hhmm(h.to, next.hours.to),
        days: Array.isArray(h.days) ? Array.from(new Set(h.days.map((x) => int(x, 0, 6, null)).filter((x) => x !== null))) : next.hours.days,
      };
    }
    if (patch.auto_reply !== undefined) next.auto_reply = cleanText(patch.auto_reply, 400);
    if (patch.hero && typeof patch.hero === "object") {
      const h = patch.hero;
      if (h.title !== undefined) next.hero.title = cleanText(h.title, 90);
      if (h.subtitle !== undefined) next.hero.subtitle = cleanText(h.subtitle, 200);
      if (h.manual_users !== undefined) next.hero.manual_users = int(h.manual_users, 0, 1e9, 0);
      if (h.manual_daily_views !== undefined) next.hero.manual_daily_views = int(h.manual_daily_views, 0, 1e10, 0);
    }
    if (Array.isArray(patch.policies)) {
      const before = JSON.stringify(cur.policies);
      next.policies = patch.policies.slice(0, 12).map((x, i) => ({
        id: cleanText(x && x.id, 20).replace(/[^a-z0-9_]/gi, "") || "p" + i,
        title: cleanText(x && x.title, 80),
        body: cleanText(x && x.body, 12000),
      })).filter((x) => x.title && x.body);
      if (JSON.stringify(next.policies) !== before && !bool(patch.keep_policies_version, false)) {
        next.policies_version = (cur.policies_version || 1) + 1;
        next.policies_updated_at = Date.now();
      }
    }
    if (bool(patch.bump_policies_version, false)) {
      next.policies_version = (next.policies_version || 1) + 1;
      next.policies_updated_at = Date.now();
    }
    next.version = (cur.version || 1) + 1;
    next.updated_at = Date.now();
    await this.s.put("settings", next);
    this._settings = null;
    return { settings: await this.settings() };
  }
  async op_quote(p) {
    const st = await this.settings();
    return { quote: computeQuote(st, p) };
  }

  // ------------------------------------------------------------------ advertisers
  async op_adv_list(p) {
    const m = await this.s.list({ prefix: "adv:" });
    const { camps } = await this.load();
    const now = Date.now();
    const q = cleanText(p.q, 60).toLowerCase();
    const out = [];
    for (const a of m.values()) {
      if (q && (a.name || "").toLowerCase().indexOf(q) < 0) continue;
      if (!p.archived && a.archived) continue;
      let count = 0, running = 0, paid = 0;
      for (const c of camps.values()) {
        if (c.advertiser_id !== a.id) continue;
        count++;
        paid += c.paid_amount || 0;
        if (displayStage(c, now) === "running") running++;
      }
      out.push(this.advView(a, p.origin, { campaigns: count, running, paid_total: round2(paid) }));
    }
    out.sort((x, y) => (y.updated_at || 0) - (x.updated_at || 0));
    return { advertisers: out };
  }
  advView(a, origin, extra) {
    return Object.assign({
      id: a.id, name: a.name, logo_key: a.logo_key || "", logo_url: mediaUrl(origin || "", a.logo_key),
      contact: a.contact || {}, notes: a.notes || "", user_key: a.user_key || "", banned: !!a.banned,
      archived: !!a.archived, tags: a.tags || [], created_at: a.created_at, updated_at: a.updated_at,
    }, extra || {});
  }
  async op_adv_get(p) {
    const a = await this.s.get("adv:" + p.id);
    if (!a) fail(404, "not_found", "المعلن غير موجود.");
    const { camps } = await this.load();
    const now = Date.now();
    const list = [];
    let paid = 0;
    for (const c of camps.values()) {
      if (c.advertiser_id !== a.id) continue;
      paid += c.paid_amount || 0;
      list.push({ id: c.id, name: c.name, slot: c.slot, stage: displayStage(c, now), start_at: c.start_at, end_at: c.end_at, price: c.price, paid_amount: c.paid_amount || 0, paid_status: c.paid_status });
    }
    list.sort((x, y) => y.start_at - x.start_at);
    return { advertiser: this.advView(a, p.origin, { campaigns: list.length, paid_total: round2(paid) }), campaigns: list };
  }
  async op_adv_save(p) {
    const existing = p.id ? await this.s.get("adv:" + p.id) : null;
    if (p.id && !existing) fail(404, "not_found", "المعلن غير موجود.");
    const now = Date.now();
    const c = p.contact && typeof p.contact === "object" ? p.contact : (existing && existing.contact) || {};
    let logo = existing ? existing.logo_key || "" : "";
    if (p.logo_key !== undefined) {
      logo = cleanText(p.logo_key, 200);
      if (logo && logo.indexOf("ads/logos/") !== 0) fail(400, "invalid_media", "مسار الشعار غير صالح.");
    }
    const a = {
      id: existing ? existing.id : randId("a_", 9),
      name: reqText(p.name !== undefined ? p.name : existing && existing.name, 100, "اسم الشركة"),
      logo_key: logo,
      contact: {
        phone: digitsOnly(c.phone, 18), whatsapp: digitsOnly(c.whatsapp, 18),
        email: cleanText(c.email, 120), website: cleanText(c.website, 200), address: cleanText(c.address, 200),
        person: cleanText(c.person, 80),
      },
      notes: p.notes !== undefined ? cleanText(p.notes, 3000) : (existing && existing.notes) || "",
      user_key: existing ? existing.user_key || "" : cleanText(p.user_key, 120),
      banned: p.banned !== undefined ? bool(p.banned, false) : !!(existing && existing.banned),
      archived: p.archived !== undefined ? bool(p.archived, false) : !!(existing && existing.archived),
      tags: p.tags !== undefined ? strList(p.tags, 10, 24) : (existing && existing.tags) || [],
      created_at: existing ? existing.created_at : now,
      updated_at: now,
    };
    await this.s.put("adv:" + a.id, a);
    if (a.user_key) await this.s.put("advuser:" + a.user_key, a.id);
    return { advertiser: this.advView(a, p.origin) };
  }
  async op_adv_ensure_user(p) {
    // ينشئ ملف معلن تلقائياً عند أول تواصل للمستخدم (لا يخزّن إلا ما أرسله المستخدم بنفسه)
    const key = cleanText(p.user_key, 120);
    if (!key) fail(400, "invalid_user", "مستخدم غير صالح.");
    const id = await this.s.get("advuser:" + key);
    if (id) {
      const a = await this.s.get("adv:" + id);
      if (a) return { advertiser: this.advView(a, p.origin), created: false };
    }
    const now = Date.now();
    const a = {
      id: randId("a_", 9), name: cleanText(p.name, 100) || "معلن جديد", logo_key: "",
      contact: { email: cleanText(p.email, 120) }, notes: "", user_key: key, banned: false, archived: false,
      tags: ["جديد"], created_at: now, updated_at: now,
    };
    await this.s.put("adv:" + a.id, a);
    await this.s.put("advuser:" + key, a.id);
    return { advertiser: this.advView(a, p.origin), created: true };
  }
  async op_adv_by_user(p) {
    const id = await this.s.get("advuser:" + cleanText(p.user_key, 120));
    if (!id) return { advertiser: null };
    const a = await this.s.get("adv:" + id);
    return { advertiser: a ? this.advView(a, p.origin) : null };
  }
  async op_adv_delete(p) {
    const a = await this.s.get("adv:" + p.id);
    if (!a) fail(404, "not_found", "المعلن غير موجود.");
    const { camps } = await this.load();
    const mine = [];
    for (const c of camps.values()) if (c.advertiser_id === a.id) mine.push(c);
    if (mine.length && !bool(p.force, false)) fail(409, "has_campaigns", "لدى المعلن حملات. أرشفه أو احذفه مع حملاته (force).", { campaigns: mine.length });
    for (const c of mine) await this.deleteCampaign(c);
    if (a.logo_key) await this.deleteMedia(a.logo_key, "");
    await this.s.delete("adv:" + a.id);
    if (a.user_key) await this.s.delete("advuser:" + a.user_key);
    return { deleted: true, user_key: a.user_key || "" };
  }

  // ------------------------------------------------------------------ campaigns
  campView(c, now, origin, advMap) {
    const adv = advMap ? advMap.get(c.advertiser_id) : null;
    return {
      id: c.id, advertiser_id: c.advertiser_id, advertiser_name: adv ? adv.name : "",
      name: c.name, slot: c.slot, start_at: c.start_at, end_at: c.end_at, duration_days: c.duration_days,
      price_calc: c.price_calc, price: c.price, price_manual: !!c.price_manual, currency: c.currency,
      paid_status: c.paid_status, paid_amount: c.paid_amount || 0,
      priority: c.priority, exclusive: !!(c.addons && c.addons.exclusive), addons: c.addons || {},
      daily_cap: c.daily_cap || 0, targeting: c.targeting, status: c.status, order_stage: c.order_stage,
      stage: displayStage(c, now), reject_reason: c.reject_reason || "", approved_at: c.approved_at || 0,
      notes: c.notes || "", report_token: c.report_token || "", reports: c.reports || 0,
      expiring_soon: c.status === "approved" && c.end_at > now && c.end_at - now <= 3 * DAY_MS,
      log: (c.log || []).slice(-20), created_at: c.created_at, updated_at: c.updated_at,
    };
  }
  async advMap() {
    const m = await this.s.list({ prefix: "adv:" });
    const out = new Map();
    for (const a of m.values()) out.set(a.id, a);
    return out;
  }
  async op_camp_list(p) {
    const { camps } = await this.load();
    const advs = await this.advMap();
    const now = Date.now();
    const q = cleanText(p.q, 60).toLowerCase();
    const out = [];
    for (const c of camps.values()) {
      if (p.advertiser_id && c.advertiser_id !== p.advertiser_id) continue;
      if (p.slot && c.slot !== p.slot) continue;
      const v = this.campView(c, now, p.origin, advs);
      if (p.stage && v.stage !== p.stage) continue;
      if (p.expiring && !v.expiring_soon) continue;
      if (q && (v.name + " " + v.advertiser_name).toLowerCase().indexOf(q) < 0) continue;
      const tot = (await this.s.get("tot:" + c.id)) || { i: 0, c: 0, u: 0 };
      v.totals = { impressions: tot.i, clicks: tot.c, unique: tot.u };
      v.creatives_count = 0;
      out.push(v);
    }
    const { crvs } = await this.load();
    const counts = {};
    for (const r of crvs.values()) counts[r.campaign_id] = (counts[r.campaign_id] || 0) + 1;
    for (const v of out) v.creatives_count = counts[v.id] || 0;
    out.sort((a, b) => b.updated_at - a.updated_at);
    return { campaigns: out.slice(0, int(p.limit, 1, 500, 200)) };
  }
  async op_camp_get(p) {
    const c = await this.s.get("camp:" + p.id);
    if (!c) fail(404, "not_found", "الحملة غير موجودة.");
    const advs = await this.advMap();
    const { crvs } = await this.load();
    const list = [];
    for (const r of crvs.values()) if (r.campaign_id === c.id) list.push(this.crvView(r, p.origin));
    list.sort((a, b) => a.sort - b.sort);
    const tot = (await this.s.get("tot:" + c.id)) || { i: 0, c: 0, u: 0 };
    const v = this.campView(c, Date.now(), p.origin, advs);
    v.totals = { impressions: tot.i, clicks: tot.c, unique: tot.u };
    return { campaign: v, creatives: list };
  }
  async op_camp_save(p) {
    const st = await this.settings();
    const existing = p.id ? await this.s.get("camp:" + p.id) : null;
    if (p.id && !existing) fail(404, "not_found", "الحملة غير موجودة.");
    const advId = cleanText(p.advertiser_id !== undefined ? p.advertiser_id : existing && existing.advertiser_id, 40);
    const adv = advId ? await this.s.get("adv:" + advId) : null;
    if (!adv) fail(400, "invalid_advertiser", "اختر معلناً صحيحاً.");
    const slot = oneOf(p.slot !== undefined ? p.slot : existing && existing.slot, SLOTS, null);
    if (!slot) fail(400, "invalid_slot", "اختر مساحة إعلانية.");
    const now = Date.now();
    const start = parseTime(p.start_at, existing ? existing.start_at : null);
    if (!start) fail(400, "invalid_time", "حدد تاريخ البداية.");
    let end = null;
    if (p.end_at !== undefined && p.end_at !== null && p.end_at !== "") end = parseTime(p.end_at, null);
    else if (p.days !== undefined && p.days !== null && p.days !== "") end = start + int(p.days, 1, MAX_CAMPAIGN_DAYS, 1) * DAY_MS;
    else if (existing) end = existing.end_at;
    if (!end || end <= start) fail(400, "invalid_time", "تاريخ النهاية يجب أن يكون بعد البداية.");
    if (end - start > MAX_CAMPAIGN_DAYS * DAY_MS) fail(400, "invalid_time", "المدة أطول من الحد المسموح.");
    const days = Math.max(1, Math.round((end - start) / DAY_MS));
    const targeting = p.targeting !== undefined ? sanitizeTargeting(p.targeting) : (existing && existing.targeting) || sanitizeTargeting({});
    const addIn = p.addons && typeof p.addons === "object" ? p.addons : (existing && existing.addons) || {};
    const addons = { exclusive: bool(p.exclusive !== undefined ? p.exclusive : addIn.exclusive, false), video: bool(addIn.video, false), design: bool(addIn.design, false) };
    let calc = 0;
    try {
      calc = computeQuote(st, { slot, days, targeting, addons }).total;
    } catch (e) {
      if (!(e instanceof HttpError)) throw e;
    }
    let price, manual = false;
    if (p.price !== undefined && p.price !== null && p.price !== "") {
      price = round2(num(p.price, 0, 1e9, calc));
      manual = round2(price) !== round2(calc);
    } else if (existing && existing.price_manual) {
      price = existing.price;
      manual = true;
    } else price = calc;
    let paidStatus = oneOf(p.paid_status !== undefined ? p.paid_status : existing && existing.paid_status, PAID, "unpaid");
    let paidAmount = p.paid_amount !== undefined && p.paid_amount !== "" ? round2(num(p.paid_amount, 0, 1e9, 0)) : existing ? existing.paid_amount || 0 : 0;
    if (paidStatus === "paid" && paidAmount < price) paidAmount = price;
    if (paidStatus === "unpaid") paidAmount = 0;
    const c = {
      id: existing ? existing.id : randId("c_", 9),
      advertiser_id: adv.id,
      name: reqText(p.name !== undefined ? p.name : existing && existing.name, 120, "اسم الحملة"),
      slot, start_at: start, end_at: end, duration_days: days,
      price_calc: calc, price, price_manual: manual, currency: st.currency.code,
      paid_status: paidStatus, paid_amount: paidAmount,
      priority: int(p.priority !== undefined ? p.priority : existing && existing.priority, 1, 10, 5),
      addons,
      daily_cap: int(p.daily_cap !== undefined ? p.daily_cap : existing && existing.daily_cap, 0, 50, 0),
      targeting,
      status: existing ? existing.status : "draft",
      order_stage: oneOf(p.order_stage !== undefined ? p.order_stage : existing && existing.order_stage, STAGES, "received"),
      reject_reason: existing ? existing.reject_reason || "" : "",
      approved_at: existing ? existing.approved_at || 0 : 0,
      notes: p.notes !== undefined ? cleanText(p.notes, 3000) : (existing && existing.notes) || "",
      report_token: existing ? existing.report_token || "" : "",
      reports: existing ? existing.reports || 0 : 0,
      expiry_warned: existing && existing.end_at === end ? !!existing.expiry_warned : false,
      source_order: cleanText(p.source_order, 60) || (existing && existing.source_order) || "",
      log: existing ? existing.log || [] : [],
      created_at: existing ? existing.created_at : now,
      updated_at: now,
    };
    if (c.status === "approved") await this.checkExclusive(c);
    this.log(c, existing ? "edit" : "create", "");
    await this.s.put("camp:" + c.id, c);
    this.dirty();
    await this.ensureAlarm();
    return { campaign: this.campView(c, now, p.origin, new Map([[adv.id, adv]])) };
  }
  async checkExclusive(c) {
    const { camps } = await this.load();
    for (const o of camps.values()) {
      if (o.id === c.id || o.status !== "approved" || o.slot !== c.slot) continue;
      const overlap = o.start_at < c.end_at && c.start_at < o.end_at;
      if (!overlap) continue;
      const oEx = !!(o.addons && o.addons.exclusive);
      const cEx = !!(c.addons && c.addons.exclusive);
      if (oEx || cEx) {
        fail(409, "exclusive_conflict", "تعارض حصرية: الحملة «" + o.name + "» تشغل نفس المساحة في فترة متداخلة.", { conflict_id: o.id });
      }
    }
  }
  async op_camp_action(p) {
    const c = await this.s.get("camp:" + p.id);
    if (!c) fail(404, "not_found", "الحملة غير موجودة.");
    const now = Date.now();
    const act = cleanText(p.action, 20);
    let extra = {};
    if (act === "approve") {
      const { crvs } = await this.load();
      let n = 0;
      for (const r of crvs.values()) if (r.campaign_id === c.id && r.active !== false) n++;
      if (!n) fail(400, "no_creative", "أضف مادة إعلانية فعّالة واحدة على الأقل قبل الموافقة.");
      if (c.end_at <= now) fail(400, "already_ended", "الحملة منتهية؛ مدّد أو جدّد قبل الموافقة.");
      const st = await this.settings();
      if (!st.slots[c.slot] || st.slots[c.slot].enabled === false) fail(400, "slot_disabled", "المساحة غير مفعّلة.");
      await this.checkExclusive(c);
      c.status = "approved";
      c.reject_reason = "";
      c.approved_at = now;
      if (!c.report_token) await this.makeReportToken(c);
      this.log(c, "approve", "");
    } else if (act === "reject") {
      const reason = reqText(p.reason, 400, "سبب الرفض");
      c.status = "rejected";
      c.reject_reason = reason;
      this.log(c, "reject", reason);
    } else if (act === "pause") {
      if (c.status !== "approved") fail(400, "bad_state", "يمكن إيقاف الحملة المعتمدة فقط.");
      c.status = "paused";
      this.log(c, "pause", cleanText(p.reason, 200));
    } else if (act === "resume") {
      if (c.status !== "paused") fail(400, "bad_state", "الحملة ليست موقوفة.");
      c.status = "approved";
      await this.checkExclusive(c);
      this.log(c, "resume", "");
    } else if (act === "extend") {
      const d = int(p.days, 1, 730, null);
      if (!d) fail(400, "invalid_days", "عدد الأيام غير صحيح.");
      const base = c.end_at > now ? c.end_at : now;
      c.end_at = base + d * DAY_MS;
      c.duration_days = Math.max(1, Math.round((c.end_at - c.start_at) / DAY_MS));
      c.expiry_warned = false;
      if (c.status === "approved") await this.checkExclusive(c);
      this.log(c, "extend", d + " يوم");
    } else if (act === "renew") {
      const d = int(p.days, 1, 730, c.duration_days);
      const copy = JSON.parse(JSON.stringify(c));
      copy.id = randId("c_", 9);
      copy.start_at = c.end_at > now ? c.end_at : now;
      copy.end_at = copy.start_at + d * DAY_MS;
      copy.duration_days = d;
      copy.status = "draft";
      copy.order_stage = "quoted";
      copy.paid_status = "unpaid";
      copy.paid_amount = 0;
      copy.reject_reason = "";
      copy.approved_at = 0;
      copy.report_token = "";
      copy.reports = 0;
      copy.expiry_warned = false;
      copy.log = [];
      copy.created_at = now;
      copy.updated_at = now;
      copy.name = c.name.replace(/ \(تجديد\)$/, "") + " (تجديد)";
      const st = await this.settings();
      try { copy.price_calc = computeQuote(st, { slot: copy.slot, days: d, targeting: copy.targeting, addons: copy.addons }).total; } catch (e) { /* keep */ }
      copy.price = copy.price_calc;
      copy.price_manual = false;
      this.log(copy, "renew_from", c.id);
      await this.s.put("camp:" + copy.id, copy);
      const { crvs } = await this.load();
      let sort = 0;
      for (const r of crvs.values()) {
        if (r.campaign_id !== c.id) continue;
        const nr = Object.assign({}, r, { id: randId("v_", 9), campaign_id: copy.id, created_at: now, updated_at: now, sort: sort++ });
        await this.s.put("crv:" + nr.id, nr);
      }
      this.log(c, "renewed", copy.id);
      extra = { renewed_id: copy.id };
    } else if (act === "stage") {
      c.order_stage = oneOf(p.stage, STAGES, c.order_stage);
      this.log(c, "stage", c.order_stage);
    } else if (act === "delete") {
      await this.deleteCampaign(c);
      this.dirty();
      return { deleted: true };
    } else if (act === "new_report_token") {
      await this.makeReportToken(c, true);
    } else fail(400, "unknown_action", "إجراء غير معروف.");
    c.updated_at = now;
    await this.s.put("camp:" + c.id, c);
    this.dirty();
    const advs = await this.advMap();
    return Object.assign({ campaign: this.campView(c, now, p.origin, advs) }, extra);
  }
  async makeReportToken(c, rotate) {
    if (c.report_token && rotate) await this.s.delete("rt:" + c.report_token);
    if (c.report_token && !rotate) return;
    const bytes = new Uint8Array(24);
    crypto.getRandomValues(bytes);
    c.report_token = b64url(bytes);
    await this.s.put("rt:" + c.report_token, c.id);
  }
  async deleteCampaign(c) {
    const { crvs } = await this.load();
    for (const r of Array.from(crvs.values())) {
      if (r.campaign_id !== c.id) continue;
      await this.s.delete("crv:" + r.id);
      this.dirty();
      await this.deleteMedia(r.media_key, r.id);
      await this.deleteMedia(r.thumb_key, r.id);
    }
    const stats = await this.s.list({ prefix: "stat:" + c.id + ":" });
    const keys = Array.from(stats.keys());
    for (let i = 0; i < keys.length; i += 120) await this.s.delete(keys.slice(i, i + 120));
    await this.s.delete("tot:" + c.id);
    if (c.report_token) await this.s.delete("rt:" + c.report_token);
    await this.s.delete("camp:" + c.id);
    this.dirty();
  }
  async mediaInUse(key, exceptId) {
    const { crvs } = await this.load();
    for (const r of crvs.values()) if (r.id !== exceptId && (r.media_key === key || r.thumb_key === key)) return true;
    return false;
  }
  async deleteMedia(key, exceptId) {
    if (!key) return;
    if (await this.mediaInUse(key, exceptId)) return;
    const b = bucketOf(this.env);
    if (!b) return;
    try { await b.delete(key); } catch (e) { /* ignore */ }
  }

  // ------------------------------------------------------------------ creatives
  crvView(r, origin) {
    return {
      id: r.id, campaign_id: r.campaign_id, type: r.type, media_key: r.media_key || "", media_url: mediaUrl(origin, r.media_key),
      thumb_key: r.thumb_key || "", thumb_url: mediaUrl(origin, r.thumb_key), title: r.title, body: r.body, cta: r.cta,
      action: r.action, bg_color: r.bg_color || "", text_color: r.text_color || "", active: r.active !== false,
      sort: r.sort || 0, created_at: r.created_at, updated_at: r.updated_at,
    };
  }
  async op_crv_save(p) {
    const existing = p.id ? await this.s.get("crv:" + p.id) : null;
    if (p.id && !existing) fail(404, "not_found", "المادة غير موجودة.");
    const campId = cleanText(p.campaign_id !== undefined ? p.campaign_id : existing && existing.campaign_id, 40);
    const camp = await this.s.get("camp:" + campId);
    if (!camp) fail(400, "invalid_campaign", "الحملة غير موجودة.");
    const type = oneOf(p.type !== undefined ? p.type : existing && existing.type, ["image", "video", "text"], null);
    if (!type) fail(400, "invalid_type", "نوع المادة غير صحيح.");
    const b = bucketOf(this.env);
    const checkKey = async (k, prefixes, label) => {
      k = cleanText(k, 200);
      if (!k) return "";
      if (!prefixes.some((x) => k.indexOf(x) === 0) || k.indexOf("..") >= 0) fail(400, "invalid_media", "مسار " + label + " غير صالح.");
      if (b) {
        const head = await b.head(k);
        if (!head) fail(400, "media_missing", label + " غير موجود في التخزين. ارفعه أولاً.");
      }
      return k;
    };
    const mediaKey = await checkKey(p.media_key !== undefined ? p.media_key : existing && existing.media_key, [MEDIA_PREFIX], "الوسائط");
    const thumbKey = await checkKey(p.thumb_key !== undefined ? p.thumb_key : existing && existing.thumb_key, [MEDIA_PREFIX], "الصورة المصغّرة");
    if ((type === "image" || type === "video") && !mediaKey) fail(400, "media_required", "ارفع الصورة أو الفيديو.");
    const a = p.action && typeof p.action === "object" ? p.action : (existing && existing.action) || { type: "none" };
    const at = oneOf(a.type, ACTIONS, "none");
    const action = { type: at, value: "", extra: "" };
    if (at === "link") action.value = safeUrl(a.value, ["https:"]);
    else if (at === "store") action.value = safeUrl(a.value, ["https:", "market:"]);
    else if (at === "whatsapp") { action.value = digitsOnly(a.value, 18); action.extra = cleanText(a.extra, 300); if (!action.value) fail(400, "invalid_action", "أدخل رقم واتساب."); }
    else if (at === "call") { action.value = digitsOnly(a.value, 18); if (!action.value) fail(400, "invalid_action", "أدخل رقم الاتصال."); }
    else if (at === "copy") { action.value = cleanText(a.value, 60); if (!action.value) fail(400, "invalid_action", "أدخل نص الكوبون."); }
    if (at === "link" && !action.value) fail(400, "invalid_action", "أدخل الرابط.");
    if (at === "store" && !action.value) fail(400, "invalid_action", "أدخل رابط المتجر.");
    const color = (v) => (/^#[0-9a-fA-F]{6}$/.test(String(v || "")) ? String(v) : "");
    const now = Date.now();
    const r = {
      id: existing ? existing.id : randId("v_", 9),
      campaign_id: camp.id, type, media_key: mediaKey, thumb_key: thumbKey,
      title: cleanText(p.title !== undefined ? p.title : existing && existing.title, 80),
      body: cleanText(p.body !== undefined ? p.body : existing && existing.body, 300),
      cta: cleanText(p.cta !== undefined ? p.cta : existing && existing.cta, 24),
      action, bg_color: color(p.bg_color !== undefined ? p.bg_color : existing && existing.bg_color),
      text_color: color(p.text_color !== undefined ? p.text_color : existing && existing.text_color),
      active: p.active !== undefined ? bool(p.active, true) : existing ? existing.active !== false : true,
      sort: int(p.sort !== undefined ? p.sort : existing && existing.sort, 0, 999, 0),
      created_at: existing ? existing.created_at : now, updated_at: now,
    };
    if (type === "text" && !r.title && !r.body) fail(400, "empty_creative", "أضف عنواناً أو نصاً.");
    await this.s.put("crv:" + r.id, r);
    this.dirty();
    if (existing) {
      if (existing.media_key && existing.media_key !== r.media_key) await this.deleteMedia(existing.media_key, r.id);
      if (existing.thumb_key && existing.thumb_key !== r.thumb_key) await this.deleteMedia(existing.thumb_key, r.id);
    }
    camp.updated_at = now;
    this.log(camp, existing ? "creative_edit" : "creative_add", r.id);
    await this.s.put("camp:" + camp.id, camp);
    this.dirty();
    return { creative: this.crvView(r, p.origin) };
  }
  async op_crv_delete(p) {
    const r = await this.s.get("crv:" + p.id);
    if (!r) fail(404, "not_found", "المادة غير موجودة.");
    await this.s.delete("crv:" + r.id);
    this.dirty();
    await this.deleteMedia(r.media_key, r.id);
    await this.deleteMedia(r.thumb_key, r.id);
    return { deleted: true };
  }

  // ------------------------------------------------------------------ serving
  async op_serve(p) {
    const st = await this.settings();
    const { camps, crvs } = await this.load();
    const now = Date.now();
    const off = st.hours.tz_offset_min || 180;
    const hourNow = hourOf(now, off);
    const slot = oneOf(p.slot, SLOTS, null);
    if (!slot) fail(400, "invalid_slot", "مساحة غير معروفة.");
    const city = resolveCity(st, p.city, p.region, p.region2);
    const lang = cleanText(p.lang, 8).toLowerCase().slice(0, 2);
    const ver = int(p.app_version, 0, 1e9, 0);
    const byCamp = new Map();
    for (const r of crvs.values()) {
      if (r.active === false) continue;
      if (!byCamp.has(r.campaign_id)) byCamp.set(r.campaign_id, []);
      byCamp.get(r.campaign_id).push(r);
    }
    let boundary = now + 3600000;
    let hoursUsed = false;
    const matched = [];
    for (const c of camps.values()) {
      if (c.slot !== slot || c.status !== "approved") continue;
      if (c.start_at > now && c.start_at < boundary) boundary = c.start_at;
      if (c.end_at > now && c.end_at < boundary) boundary = c.end_at;
      if (c.start_at > now || c.end_at <= now) continue;
      const t = c.targeting || {};
      if (t.hours) hoursUsed = true;
      if (t.cities && t.cities.length && (!city || t.cities.indexOf(city) < 0)) continue;
      if (t.langs && t.langs.length && (!lang || t.langs.indexOf(lang) < 0)) continue;
      if (!inHours(hourNow, t.hours)) continue;
      if (t.min_version && ver < t.min_version) continue;
      if (t.max_version && (!ver || ver > t.max_version)) continue;
      const list = byCamp.get(c.id);
      if (!list || !list.length) continue;
      matched.push({ c, list });
    }
    if (hoursUsed) {
      const nextHour = now - (((now + off * 60000) % 3600000) + 3600000) % 3600000 + 3600000;
      if (nextHour < boundary) boundary = nextHour;
    }
    let pool = matched;
    const ex = matched.filter((m) => m.c.addons && m.c.addons.exclusive);
    if (ex.length) pool = ex;
    const ads = [];
    pool.sort((a, b) => b.c.priority - a.c.priority || a.c.created_at - b.c.created_at);
    for (const m of pool) {
      const sorted = m.list.slice().sort((a, b) => (a.sort || 0) - (b.sort || 0));
      for (const r of sorted) {
        ads.push({
          campaign_id: m.c.id, creative_id: r.id, slot, type: r.type, priority: m.c.priority,
          exclusive: !!(m.c.addons && m.c.addons.exclusive), daily_cap: m.c.daily_cap || 0,
          start_at: m.c.start_at, end_at: m.c.end_at,
          media_url: mediaUrl(p.origin, r.media_key), thumb_url: mediaUrl(p.origin, r.thumb_key),
          title: r.title, body: r.body, cta: r.cta, action: r.action,
          bg_color: r.bg_color || "", text_color: r.text_color || "",
        });
        if (ads.length >= 14) break;
      }
      if (ads.length >= 14) break;
    }
    const ttl = Math.max(1, Math.min(45, Math.floor((boundary - now) / 1000)));
    return { server_time: now, slot, ttl, ads };
  }

  // ------------------------------------------------------------------ tracking
  async op_track(p) {
    const events = Array.isArray(p.events) ? p.events.slice(0, 20) : [];
    const device = String(p.device || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
    if (!device) fail(400, "invalid_device", "معرّف الجهاز مفقود.");
    if (!this.rl("dev:" + device, 120, 60000) || !this.rl("ip:" + (p.ip || ""), 400, 60000)) fail(429, "rate_limited", "طلبات كثيرة.");
    const st = await this.settings();
    const off = st.hours.tz_offset_min || 180;
    const { camps, crvs } = await this.load();
    const now = Date.now();
    const day = dayKey(now, off);
    let accepted = 0;
    // نشاط يومي (DAU) — مرة واحدة لكل جهاز في اليوم
    const ddD = "dd:d:" + day + ":" + device;
    if (!(await this.s.get(ddD))) {
      await this.s.put(ddD, now + 2 * DAY_MS);
      await this.s.put("dau:" + day, ((await this.s.get("dau:" + day)) || 0) + 1);
    }
    for (const ev of events) {
      if (!ev || typeof ev !== "object") continue;
      const type = ev.t === "click" ? "c" : ev.t === "imp" ? "i" : null;
      if (!type) continue;
      const c = camps.get("camp:" + cleanText(ev.cid, 40));
      if (!c || c.status !== "approved" || c.start_at > now + 60000 || c.end_at < now - 60000) continue;
      const crid = cleanText(ev.crid, 40);
      if (crid && !(crvs.get("crv:" + crid) || {}).campaign_id) continue;
      if (crid && crvs.get("crv:" + crid).campaign_id !== c.id) continue;
      const win = type === "i" ? Math.floor(now / 1800000) : Math.floor(now / 10000);
      const ddKey = "dd:" + type + ":" + c.id + ":" + device + ":" + win;
      if (await this.s.get(ddKey)) continue; // مكرر
      await this.s.put(ddKey, now + (type === "i" ? 1800000 : 10000) + 60000);
      const sk = "stat:" + c.id + ":" + day;
      const row = (await this.s.get(sk)) || { i: 0, c: 0, u: 0 };
      const tot = (await this.s.get("tot:" + c.id)) || { i: 0, c: 0, u: 0 };
      row[type === "i" ? "i" : "c"]++;
      tot[type === "i" ? "i" : "c"]++;
      if (type === "i") {
        const ddU = "dd:u:" + c.id + ":" + day + ":" + device;
        if (!(await this.s.get(ddU))) {
          await this.s.put(ddU, now + 2 * DAY_MS);
          row.u++;
          tot.u++;
        }
        await this.s.put("day:" + day, ((await this.s.get("day:" + day)) || 0) + 1);
      }
      await this.s.put(sk, row);
      await this.s.put("tot:" + c.id, tot);
      accepted++;
    }
    await this.ensureAlarm();
    return { accepted };
  }
  async op_report_ad(p) {
    const device = String(p.device || "").replace(/[^A-Za-z0-9_-]/g, "").slice(0, 64);
    if (!device) fail(400, "invalid_device", "معرّف الجهاز مفقود.");
    if (!this.rl("rep:" + device, 5, 3600000)) fail(429, "rate_limited", "طلبات كثيرة.");
    const c = await this.s.get("camp:" + cleanText(p.campaign_id, 40));
    if (!c) fail(404, "not_found", "الإعلان غير موجود.");
    const now = Date.now();
    const key = "dd:r:" + c.id + ":" + device;
    if (await this.s.get(key)) return { duplicate: true };
    await this.s.put(key, now + DAY_MS);
    const id = randId("r_", 8);
    await this.s.put("rep:" + id, { id, campaign_id: c.id, reason: oneOf(p.reason, ["misleading", "inappropriate", "annoying", "other"], "other"), note: cleanText(p.note, 300), at: now });
    c.reports = (c.reports || 0) + 1;
    await this.s.put("camp:" + c.id, c);
    this.dirty();
    return { reported: true };
  }
  async op_reports_list(p) {
    const m = await this.s.list({ prefix: "rep:", limit: 300 });
    return { reports: Array.from(m.values()).sort((a, b) => b.at - a.at) };
  }
  async op_reports_clear(p) {
    const m = await this.s.list({ prefix: "rep:" });
    const keys = [];
    for (const [k, v] of m) if (v.campaign_id === p.campaign_id) keys.push(k);
    for (let i = 0; i < keys.length; i += 120) await this.s.delete(keys.slice(i, i + 120));
    const c = await this.s.get("camp:" + p.campaign_id);
    if (c) { c.reports = 0; await this.s.put("camp:" + c.id, c); this.dirty(); }
    return { cleared: keys.length };
  }

  // ------------------------------------------------------------------ reports
  async buildReport(c, advs) {
    const st = await this.settings();
    const off = st.hours.tz_offset_min || 180;
    const rows = await this.s.list({ prefix: "stat:" + c.id + ":" });
    const daily = [];
    for (const [k, v] of rows) daily.push({ d: k.split(":")[2], i: v.i, c: v.c, u: v.u });
    daily.sort((a, b) => (a.d < b.d ? -1 : 1));
    const tot = (await this.s.get("tot:" + c.id)) || { i: 0, c: 0, u: 0 };
    const adv = advs ? advs.get(c.advertiser_id) : await this.s.get("adv:" + c.advertiser_id);
    const best = daily.reduce((m, r) => (r.i > (m ? m.i : -1) ? r : m), null);
    return {
      name: c.name, advertiser: adv ? adv.name : "", slot: c.slot, slot_label: st.slots[c.slot] ? st.slots[c.slot].label : c.slot,
      start_at: c.start_at, end_at: c.end_at, stage: displayStage(c, Date.now()),
      impressions: tot.i, clicks: tot.c, unique: tot.u, ctr: tot.i ? round2((tot.c / tot.i) * 100) : 0,
      daily, best_day: best ? best.d : "", tz_offset_min: off, generated_at: Date.now(),
    };
  }
  async op_report_admin(p) {
    const c = await this.s.get("camp:" + p.id);
    if (!c) fail(404, "not_found", "الحملة غير موجودة.");
    return { report: await this.buildReport(c, null), report_token: c.report_token || "" };
  }
  async op_report_public(p) {
    const tok = cleanText(p.token, 80);
    const id = tok ? await this.s.get("rt:" + tok) : null;
    const c = id ? await this.s.get("camp:" + id) : null;
    if (!c) fail(404, "not_found", "التقرير غير موجود أو أُلغي رابطه.");
    return { report: await this.buildReport(c, null) };
  }

  // ------------------------------------------------------------------ advertiser (user) views
  async op_me_campaigns(p) {
    const key = cleanText(p.user_key, 120);
    const id = key ? await this.s.get("advuser:" + key) : null;
    if (!id) return { advertiser: null, campaigns: [] };
    const adv = await this.s.get("adv:" + id);
    const st = await this.settings();
    const { camps } = await this.load();
    const now = Date.now();
    const out = [];
    for (const c of camps.values()) {
      if (c.advertiser_id !== id) continue;
      const stage = displayStage(c, now);
      const rep = await this.buildReport(c, new Map([[id, adv]]));
      out.push({
        id: c.id, name: c.name, slot: c.slot, slot_label: st.slots[c.slot] ? st.slots[c.slot].label : c.slot,
        stage, start_at: c.start_at, end_at: c.end_at, price: c.price, currency: c.currency,
        paid_status: c.paid_status, paid_amount: c.paid_amount || 0,
        reject_reason: stage === "rejected" ? c.reject_reason || "" : "",
        renewable: stage === "running" || stage === "ended",
        stats: { impressions: rep.impressions, clicks: rep.clicks, unique: rep.unique, ctr: rep.ctr, daily: rep.daily.slice(-30) },
        report_url: c.report_token ? p.origin + "/report/" + c.report_token : "",
        updated_at: c.updated_at,
      });
    }
    out.sort((a, b) => b.updated_at - a.updated_at);
    return { advertiser: adv ? this.advView(adv, p.origin) : null, campaigns: out };
  }
  async op_consent_get(p) {
    const v = await this.s.get("consent:" + cleanText(p.user_key, 120));
    const st = await this.settings();
    return { consent: v || null, current_version: st.policies_version, valid: !!(v && v.version === st.policies_version) };
  }
  async op_consent_set(p) {
    const st = await this.settings();
    const version = int(p.version, 1, 1e6, 0);
    if (version !== st.policies_version) fail(409, "policies_changed", "تغيّرت السياسات. أعد قراءتها ثم وافق.", { current_version: st.policies_version });
    const v = { version, at: Date.now() };
    await this.s.put("consent:" + cleanText(p.user_key, 120), v);
    return { consent: v, valid: true };
  }
  async op_consent_delete(p) {
    await this.s.delete("consent:" + cleanText(p.user_key, 120));
    return {};
  }

  // ------------------------------------------------------------------ overview
  async op_overview(p) {
    const { camps } = await this.load();
    const advs = await this.advMap();
    const now = Date.now();
    const counts = {};
    const expiring = [];
    let revenue = 0, outstanding = 0, flagged = 0, running = 0;
    for (const c of camps.values()) {
      const stg = displayStage(c, now);
      counts[stg] = (counts[stg] || 0) + 1;
      revenue += c.paid_amount || 0;
      if (c.status === "approved" || c.status === "paused") outstanding += Math.max(0, (c.price || 0) - (c.paid_amount || 0));
      if (c.reports > 0) flagged++;
      if (stg === "running") running++;
      if (c.status === "approved" && c.end_at > now && c.end_at - now <= 3 * DAY_MS) {
        const a = advs.get(c.advertiser_id);
        expiring.push({ id: c.id, name: c.name, advertiser_name: a ? a.name : "", end_at: c.end_at });
      }
    }
    const hero = await this.heroNumbers(await this.settings());
    return { counts, running, expiring, revenue: round2(revenue), outstanding: round2(outstanding), flagged, advertisers: advs.size, hero };
  }

  async op_authfail(p) {
    const ok = this.rl("af:" + cleanText(p.ip, 60), 20, 600000);
    return { blocked: !ok };
  }

  // ------------------------------------------------------------------ housekeeping (alarm)
  async alarm() {
    const now = Date.now();
    let more = false;
    try {
      const rows = await this.s.list({ prefix: "dd:", limit: 3000 });
      const dead = [];
      for (const [k, v] of rows) if (typeof v === "number" && v < now) dead.push(k);
      for (let i = 0; i < dead.length; i += 120) await this.s.delete(dead.slice(i, i + 120));
      if (rows.size >= 3000 && dead.length > 1500) more = true;
      // حذف عدادات اليوم القديمة جداً (> 120 يوم)
      const old = dayKey(now - 120 * DAY_MS, 180);
      for (const pre of ["dau:", "day:"]) {
        const m = await this.s.list({ prefix: pre });
        const del = [];
        for (const k of m.keys()) if (k.slice(pre.length) < old) del.push(k);
        if (del.length) await this.s.delete(del.slice(0, 120));
      }
      // تنبيه قبل الانتهاء بثلاثة أيام (مرة واحدة لكل حملة)
      const { camps } = await this.load();
      for (const c of camps.values()) {
        if (c.status === "approved" && !c.expiry_warned && c.end_at > now && c.end_at - now <= 3 * DAY_MS) {
          c.expiry_warned = true;
          this.log(c, "expiring_soon", "");
          await this.s.put("camp:" + c.id, c);
          this.dirty();
          await this.pushWebhook({ type: "ad_expiring", campaign_id: c.id, name: c.name, end_at: c.end_at });
        }
      }
    } catch (e) {
      console.log("alarm_error", String(e && e.message));
    }
    await this.s.setAlarm(now + (more ? 60000 : 3600000));
  }
  async pushWebhook(payload) {
    const url = this.env.PUSH_WEBHOOK_URL;
    if (!url) return;
    try {
      await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(payload) });
    } catch (e) { /* best-effort */ }
  }
}

// =====================================================================================
// المصادقة (مستخدم + أدمن) والوسائط والمسارات
// =====================================================================================

function clientIp(request) {
  return request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "0.0.0.0";
}
function bearerOf(request) {
  const h = (request.headers.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  return h || (request.headers.get("x-admin-token") || "").trim();
}
function originOf(request, env) {
  if (env.PUBLIC_BASE) return String(env.PUBLIC_BASE).replace(/\/+$/, "");
  return new URL(request.url).origin;
}
async function readJson(request, maxBytes) {
  const len = parseInt(request.headers.get("content-length") || "0", 10);
  if (len > (maxBytes || 300000)) fail(413, "too_large", "حجم الطلب كبير جداً.");
  let text = "";
  try {
    text = await request.text();
  } catch (e) {
    fail(400, "invalid_json", "بيانات غير صالحة.");
  }
  if (text.length > (maxBytes || 300000)) fail(413, "too_large", "حجم الطلب كبير جداً.");
  if (!text.trim()) return {};
  try {
    const v = JSON.parse(text);
    return v && typeof v === "object" ? v : {};
  } catch (e) {
    fail(400, "invalid_json", "بيانات غير صالحة.");
  }
}
function coreStub(env) {
  return env.ADS_CORE.get(env.ADS_CORE.idFromName("core"));
}
async function core(env, op, p) {
  const r = await coreStub(env).fetch("https://core/op", { method: "POST", body: JSON.stringify({ op, p: p || {} }) });
  const body = await r.json();
  if (!body.ok) fail(r.status || 500, body.error || "error", body.message || "فشل الطلب.", body.conflict_id ? { conflict_id: body.conflict_id } : body.current_version ? { current_version: body.current_version } : {});
  return body;
}

// ---------------------------------------------------------------- admin auth
async function requireAdmin(request, env) {
  const ip = clientIp(request);
  const tok = bearerOf(request);
  if (!env.ADMIN_TOKEN) fail(503, "admin_not_configured", "لم يُضبط ADMIN_TOKEN في الـ Worker.");
  const ok = tok && timingSafeEqual(tok, env.ADMIN_TOKEN);
  if (!ok) {
    const r = await coreStub(env).fetch("https://core/op", { method: "POST", body: JSON.stringify({ op: "authfail", p: { ip } }) });
    const b = await r.json().catch(() => ({}));
    if (b && b.blocked) fail(429, "too_many_attempts", "محاولات كثيرة خاطئة. حاول لاحقاً.");
    fail(401, "unauthorized", "رمز الإدارة غير صحيح.");
  }
}

// ---------------------------------------------------------------- user auth
const _authCache = new Map();
async function userKeyOf(id, email) {
  const base = id ? "id:" + id : "email:" + String(email || "").toLowerCase();
  return "u_" + (await sha256Hex("cigram-ads-user|" + base)).slice(0, 28);
}
async function verifyJwtHS256(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[0])));
    if (!header || header.alg !== "HS256") return null;
    const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("HMAC", key, b64urlToBytes(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
    if (!ok) return null;
    const claims = JSON.parse(new TextDecoder().decode(b64urlToBytes(parts[1])));
    if (claims.exp && Date.now() / 1000 > claims.exp) return null;
    if (claims.nbf && Date.now() / 1000 < claims.nbf) return null;
    return claims;
  } catch (e) {
    return null;
  }
}
function pickUser(obj) {
  if (!obj || typeof obj !== "object") return null;
  const cand = [obj, obj.user, obj.data, obj.profile].filter((x) => x && typeof x === "object");
  for (const o of cand) {
    const id = o.sub || o.user_id || o.uid || o.id || "";
    const email = o.email || "";
    if (id || email) return { id: String(id || ""), email: String(email || "").toLowerCase(), name: String(o.name || o.username || o.display_name || "").slice(0, 100) };
  }
  return null;
}
async function verifyUser(request, env) {
  const tok = bearerOf(request);
  if (!tok || tok.length > 4000) fail(401, "login_required", "سجّل الدخول أولاً.");
  // توكنات cigram-auth-api جلسات عشوائية (ليست JWT): التحقق الصحيح هو نداء /me. إن لم يُضبط AUTH_VERIFY_URL نستخدم الافتراضي.
  const verifyUrl = String(env.AUTH_VERIFY_URL || "https://cigram-auth-api.wwq-mixtv.workers.dev/me").trim();
  const ck = await sha256Hex(tok);
  const hit = _authCache.get(ck);
  if (hit && hit.exp > Date.now()) return hit.user;
  let user = null;
  if (env.JWT_SECRET) {
    const claims = await verifyJwtHS256(tok, env.JWT_SECRET);
    if (claims) user = pickUser(claims);
  }
  if (!user && verifyUrl) {
    try {
      // Worker→Worker على نفس الحساب عبر workers.dev قد يُرفض (خطأ 1042)؛ الـ Service Binding باسم AUTH_API يتجاوز ذلك.
      const vreq = { headers: { authorization: "Bearer " + tok, accept: "application/json" } };
      const r = env.AUTH_API && typeof env.AUTH_API.fetch === "function" ? await env.AUTH_API.fetch(verifyUrl, vreq) : await fetch(verifyUrl, vreq);
      if (r.ok) user = pickUser(await r.json());
    } catch (e) { /* خادم الحسابات غير متاح */ }
  }
  if (!user) fail(401, "invalid_token", "انتهت الجلسة. سجّل الدخول من جديد.");
  user.key = await userKeyOf(user.id, user.email);
  if (_authCache.size > 2000) _authCache.clear();
  _authCache.set(ck, { user, exp: Date.now() + 5 * 60000 });
  return user;
}

// ---------------------------------------------------------------- media
function sniffMedia(b) {
  if (b.length < 12) return null;
  const eq = (off, arr) => arr.every((v, i) => b[off + i] === v);
  if (eq(0, [0xff, 0xd8, 0xff])) return { mime: "image/jpeg", ext: "jpg", kind: "image" };
  if (eq(0, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])) return { mime: "image/png", ext: "png", kind: "image" };
  if (eq(0, [0x47, 0x49, 0x46, 0x38])) return { mime: "image/gif", ext: "gif", kind: "image" };
  if (eq(0, [0x52, 0x49, 0x46, 0x46]) && eq(8, [0x57, 0x45, 0x42, 0x50])) return { mime: "image/webp", ext: "webp", kind: "image" };
  if (eq(4, [0x66, 0x74, 0x79, 0x70])) return { mime: "video/mp4", ext: "mp4", kind: "video" };
  if (eq(0, [0x1a, 0x45, 0xdf, 0xa3])) return { mime: "video/webm", ext: "webm", kind: "video" };
  return null;
}
async function uploadAdMedia(request, env, url) {
  const b = bucketOf(env);
  if (!b) fail(500, "no_bucket", "لا يوجد R2 Bucket (ADS_BUCKET أو MOVIES_BUCKET).");
  const kind = oneOf(url.searchParams.get("kind"), ["creative", "thumb", "logo"], "creative");
  const len = parseInt(request.headers.get("content-length") || "0", 10);
  const limit = kind === "creative" ? MAX_VIDEO_BYTES : MAX_IMAGE_BYTES;
  if (len > limit) fail(413, "too_large", "الملف أكبر من الحد المسموح.");
  const buf = new Uint8Array(await request.arrayBuffer());
  if (!buf.length) fail(400, "empty_body", "الملف فارغ.");
  if (buf.length > limit) fail(413, "too_large", "الملف أكبر من الحد المسموح.");
  const t = sniffMedia(buf);
  if (!t) fail(415, "unsupported_type", "نوع الملف غير مدعوم (صورة JPG/PNG/WEBP/GIF أو فيديو MP4/WEBM).");
  if (t.kind === "video" && kind !== "creative") fail(415, "unsupported_type", "الشعار والصورة المصغّرة يجب أن تكون صورة.");
  if (t.kind === "image" && buf.length > MAX_IMAGE_BYTES) fail(413, "too_large", "الصورة أكبر من 6MB.");
  const prefix = kind === "logo" ? "ads/logos/" : MEDIA_PREFIX;
  const key = prefix + randId("", 14) + "." + t.ext;
  await b.put(key, buf, { httpMetadata: { contentType: t.mime, cacheControl: "public, max-age=31536000, immutable" } });
  return { key, url: mediaUrl(originOf(request, env), key), mime: t.mime, kind: t.kind, size: buf.length };
}
async function serveMedia(request, env, prefix, file) {
  const b = bucketOf(env);
  if (!b || !/^[A-Za-z0-9_-]{6,40}\.(jpg|png|webp|gif|mp4|webm)$/.test(file)) return new Response("Not found", { status: 404, headers: corsHeaders() });
  const key = prefix + file;
  const range = request.headers.get("range");
  let opts;
  let start = 0, end = null;
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (m && (m[1] || m[2])) {
      const head = await b.head(key);
      if (!head) return new Response("Not found", { status: 404, headers: corsHeaders() });
      const size = head.size;
      if (m[1] === "") { start = Math.max(0, size - parseInt(m[2], 10)); end = size - 1; }
      else { start = parseInt(m[1], 10); end = m[2] ? Math.min(size - 1, parseInt(m[2], 10)) : size - 1; }
      if (start >= size || end < start) return new Response("Range Not Satisfiable", { status: 416, headers: corsHeaders({ "content-range": "bytes */" + size }) });
      opts = { range: { offset: start, length: end - start + 1 } };
      const obj = await b.get(key, opts);
      if (!obj) return new Response("Not found", { status: 404, headers: corsHeaders() });
      return new Response(obj.body, {
        status: 206,
        headers: corsHeaders({
          "content-type": (obj.httpMetadata && obj.httpMetadata.contentType) || "application/octet-stream",
          "content-range": "bytes " + start + "-" + end + "/" + size, "content-length": String(end - start + 1),
          "accept-ranges": "bytes", "cache-control": "public, max-age=86400",
        }),
      });
    }
  }
  const obj = await b.get(key);
  if (!obj) return new Response("Not found", { status: 404, headers: corsHeaders() });
  return new Response(obj.body, {
    status: 200,
    headers: corsHeaders({
      "content-type": (obj.httpMetadata && obj.httpMetadata.contentType) || "application/octet-stream",
      "content-length": String(obj.size), "accept-ranges": "bytes", "cache-control": "public, max-age=86400",
      etag: obj.httpEtag || "",
    }),
  });
}

// ---------------------------------------------------------------- public report page
function esc(s) {
  return String(s === undefined || s === null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function fmtDate(ms, off) {
  const d = new Date(ms + (off || 0) * 60000);
  return d.getUTCFullYear() + "/" + String(d.getUTCMonth() + 1).padStart(2, "0") + "/" + String(d.getUTCDate()).padStart(2, "0");
}
function stageLabel(s) {
  return { received: "مستلم", review: "قيد المراجعة", quoted: "عرض سعر", awaiting_payment: "بانتظار الدفع", scheduled: "مجدول", running: "يعمل", ended: "منتهي", rejected: "مرفوض", paused: "متوقف" }[s] || s;
}
function renderReportHtml(r) {
  const max = Math.max(1, ...r.daily.map((d) => d.i));
  const bw = r.daily.length ? Math.max(4, Math.min(28, Math.floor(560 / r.daily.length) - 3)) : 10;
  const bars = r.daily.map((d, i) => {
    const h = Math.round((d.i / max) * 120);
    const x = i * (bw + 3);
    return '<rect x="' + x + '" y="' + (130 - h) + '" width="' + bw + '" height="' + h + '" rx="3" fill="#26A5B5"><title>' + esc(d.d) + " — " + d.i + " مشاهدة / " + d.c + " نقرة</title></rect>";
  }).join("");
  const w = Math.max(200, r.daily.length * (bw + 3));
  const tile = (n, l) => '<div class="t"><b>' + esc(Number(n).toLocaleString("en-US")) + "</b><span>" + esc(l) + "</span></div>";
  return '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<meta name="robots" content="noindex,nofollow"><title>تقرير حملة — ' + esc(r.name) + "</title><style>" +
    ":root{color-scheme:dark light;--bg:#0B2733;--card:#102F3B;--tx:#fff;--mu:#8FA1AA;--ac:#26A5B5;--st:#1F4553}" +
    "@media(prefers-color-scheme:light){:root{--bg:#f4f8fa;--card:#fff;--tx:#10222b;--mu:#5a6c75;--st:#d6e2e8}}" +
    "body{margin:0;background:var(--bg);color:var(--tx);font-family:system-ui,Segoe UI,Tahoma,sans-serif;padding:20px}" +
    ".w{max-width:760px;margin:auto}h1{font-size:22px;margin:0 0 4px}p.s{color:var(--mu);margin:0 0 20px}" +
    ".g{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}" +
    ".t,.c{background:var(--card);border:1px solid var(--st);border-radius:16px;padding:16px}.t b{display:block;font-size:28px;color:var(--ac)}.t span{color:var(--mu);font-size:13px}" +
    ".c{overflow-x:auto}.m{color:var(--mu);font-size:13px;margin-top:16px;text-align:center}</style></head><body><div class=\"w\">" +
    "<h1>" + esc(r.name) + '</h1><p class="s">' + esc(r.advertiser) + " · " + esc(r.slot_label) + " · " + esc(stageLabel(r.stage)) + " · " + esc(fmtDate(r.start_at, r.tz_offset_min)) + " ← " + esc(fmtDate(r.end_at, r.tz_offset_min)) + "</p>" +
    '<div class="g">' + tile(r.impressions, "مشاهدات") + tile(r.clicks, "نقرات") + tile(r.ctr + "%", "نسبة النقر") + tile(r.unique, "وصول فريد (يومي)") + "</div>" +
    '<div class="c"><b>المشاهدات اليومية</b><br><svg viewBox="0 0 ' + w + ' 140" width="' + w + '" height="140" role="img" aria-label="رسم المشاهدات اليومية">' + bars + "</svg></div>" +
    '<p class="m">تقرير للقراءة فقط · أُنشئ ' + esc(fmtDate(r.generated_at, r.tz_offset_min)) + " · أرقام مجمّعة فقط، لا تتضمن أي بيانات شخصية.</p></div></body></html>";
}

// ---------------------------------------------------------------- router
async function handleRequest(request, env, ctx) {
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders() });
  const url = new URL(request.url);
  const path = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;
  const origin = originOf(request, env);
  const q = (k) => url.searchParams.get(k) || "";

  if (method === "GET" && (path === "/" || path === "/health")) return reply({ ok: true, service: "cigram-ads-api", time: Date.now() });
  if (!env.ADS_CORE) return reply({ ok: false, error: "missing_binding", message: "Durable Object ADS_CORE غير مربوط." }, 500);

  // ---------- media (عام للمواد الإعلانية فقط)
  let m;
  if (method === "GET" && (m = /^\/m\/(c|l)\/([^/]+)$/.exec(path))) return serveMedia(request, env, m[1] === "c" ? MEDIA_PREFIX : "ads/logos/", m[2]);

  // ---------- public
  if (method === "GET" && path === "/ads/config") {
    const r = await core(env, "settings_public", {});
    return reply({ ok: true, settings: r.settings }, 200, { "cache-control": "public, max-age=30" });
  }
  if (method === "POST" && path === "/ads/quote") {
    const body = await readJson(request, 20000);
    return reply({ ok: true, quote: (await core(env, "quote", body)).quote });
  }
  if (method === "GET" && path === "/ads") {
    const slot = oneOf(q("slot"), SLOTS, null);
    if (!slot) return reply({ ok: false, error: "invalid_slot", message: "مساحة غير معروفة." }, 400);
    const cf = request.cf || {};
    const params = {
      slot, city: cleanText(q("city"), 40), lang: cleanText(q("lang"), 8).toLowerCase(),
      app_version: int(q("app_version"), 0, 1e9, 0), region: cleanText(cf.region, 40), region2: cleanText(cf.city, 40), origin,
    };
    const ck = new Request(url.origin + "/__ads?" + ["slot", "city", "lang", "app_version", "region", "region2"].map((k) => k + "=" + encodeURIComponent(params[k])).join("&"));
    const cache = typeof caches !== "undefined" && caches.default ? caches.default : null;
    if (cache) {
      const hit = await cache.match(ck);
      if (hit) return new Response(hit.body, { status: 200, headers: corsHeaders({ "content-type": "application/json; charset=utf-8", "x-cache": "HIT" }) });
    }
    const r = await core(env, "serve", params);
    const body = JSON.stringify({ ok: true, server_time: r.server_time, slot: r.slot, ttl: r.ttl, ads: r.ads });
    if (cache && ctx && ctx.waitUntil) {
      ctx.waitUntil(cache.put(ck, new Response(body, { headers: { "content-type": "application/json", "cache-control": "public, max-age=" + r.ttl } })));
    }
    return new Response(body, { status: 200, headers: corsHeaders({ "content-type": "application/json; charset=utf-8", "x-cache": "MISS" }) });
  }
  if (method === "POST" && path === "/ads/track") {
    const body = await readJson(request, 20000);
    const r = await core(env, "track", { events: body.events, device: body.device, ip: clientIp(request) });
    return reply({ ok: true, accepted: r.accepted });
  }
  if (method === "POST" && path === "/ads/report") {
    const body = await readJson(request, 5000);
    await core(env, "report_ad", { campaign_id: body.campaign_id, reason: body.reason, note: body.note, device: body.device });
    return reply({ ok: true });
  }
  if (method === "GET" && (m = /^\/report\/([A-Za-z0-9_-]{20,60})(\.json)?$/.exec(path))) {
    try {
      const r = await core(env, "report_public", { token: m[1] });
      if (m[2]) return reply({ ok: true, report: r.report });
      return new Response(renderReportHtml(r.report), {
        status: 200,
        headers: corsHeaders({ "content-type": "text/html; charset=utf-8", "content-security-policy": "default-src 'none'; style-src 'unsafe-inline'; img-src data:", "x-robots-tag": "noindex" }),
      });
    } catch (e) {
      if (e instanceof HttpError && !m[2]) return new Response("<!doctype html><meta charset=utf-8><body dir=rtl style='font-family:sans-serif;padding:40px'>التقرير غير موجود أو أُلغي رابطه.", { status: 404, headers: corsHeaders({ "content-type": "text/html; charset=utf-8" }) });
      throw e;
    }
  }

  // ---------- user (يتطلب تسجيل دخول)
  if (path === "/ads/consent" || path === "/me/campaigns") {
    const user = await verifyUser(request, env);
    if (method === "GET" && path === "/ads/consent") return reply(await core(env, "consent_get", { user_key: user.key }));
    if (method === "POST" && path === "/ads/consent") {
      const body = await readJson(request, 2000);
      return reply(await core(env, "consent_set", { user_key: user.key, version: body.version }));
    }
    if (method === "GET" && path === "/me/campaigns") return reply(await core(env, "me_campaigns", { user_key: user.key, origin }));
  }

  // ---------- chat (المرحلة ج) — يُعرَّف في 30-chat.js
  if (typeof routeChat === "function") {
    const res = await routeChat(request, env, ctx, url, path);
    if (res) return res;
  }

  // ---------- admin
  if (path.indexOf("/admin/") === 0) {
    await requireAdmin(request, env);
    if (method === "GET" && path === "/admin/overview") return reply(await core(env, "overview", {}));
    if (path === "/admin/settings") {
      if (method === "GET") return reply(await core(env, "settings_admin", {}));
      if (method === "POST") {
        const body = await readJson(request, 200000);
        return reply(await core(env, "settings_set", { patch: body.patch || body }));
      }
    }
    if (method === "GET" && path === "/admin/advertisers") return reply(await core(env, "adv_list", { q: q("q"), archived: q("archived") === "1", origin }));
    if (method === "GET" && path === "/admin/advertisers/get") return reply(await core(env, "adv_get", { id: q("id"), origin }));
    if (method === "POST" && path === "/admin/advertisers/save") return reply(await core(env, "adv_save", Object.assign(await readJson(request, 20000), { origin })));
    if (method === "POST" && path === "/admin/advertisers/delete") {
      const body = await readJson(request, 2000);
      const r = await core(env, "adv_delete", { id: body.id, force: body.force });
      if (r.user_key && typeof purgeChatForUser === "function") await purgeChatForUser(env, r.user_key);
      return reply({ ok: true, deleted: true });
    }
    if (method === "GET" && path === "/admin/campaigns") {
      return reply(await core(env, "camp_list", { q: q("q"), stage: q("stage"), slot: q("slot"), advertiser_id: q("advertiser_id"), expiring: q("expiring") === "1", limit: q("limit"), origin }));
    }
    if (method === "GET" && path === "/admin/campaigns/get") return reply(await core(env, "camp_get", { id: q("id"), origin }));
    if (method === "GET" && path === "/admin/campaigns/report") return reply(await core(env, "report_admin", { id: q("id") }));
    if (method === "POST" && path === "/admin/campaigns/save") return reply(await core(env, "camp_save", Object.assign(await readJson(request, 30000), { origin })));
    if (method === "POST" && path === "/admin/campaigns/action") {
      const r = await core(env, "camp_action", Object.assign(await readJson(request, 5000), { origin }));
      if (r.campaign && ctx && ctx.waitUntil && typeof notifyCampaignChange === "function") ctx.waitUntil(notifyCampaignChange(env, r.campaign).catch(() => {}));
      return reply(r);
    }
    if (method === "POST" && path === "/admin/creatives/save") return reply(await core(env, "crv_save", Object.assign(await readJson(request, 20000), { origin })));
    if (method === "POST" && path === "/admin/creatives/delete") return reply(await core(env, "crv_delete", await readJson(request, 2000)));
    if (method === "POST" && path === "/admin/media") return reply(Object.assign({ ok: true }, await uploadAdMedia(request, env, url)));
    if (method === "GET" && path === "/admin/ad-reports") return reply(await core(env, "reports_list", {}));
    if (method === "POST" && path === "/admin/ad-reports/clear") return reply(await core(env, "reports_clear", await readJson(request, 2000)));
  }

  return reply({ ok: false, error: "not_found", message: "المسار غير موجود." }, 404);
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (e) {
      const [b, st] = errorBody(e);
      if (!(e instanceof HttpError)) console.log("worker_error", request.method, new URL(request.url).pathname, String(e && e.message));
      return reply(b, st);
    }
  },
};
// =====================================================================================
// المرحلة ج — المحادثة اللحظية بين المعلن والإدارة (ChatHub) + الوسائط المشفّرة
//
// التشفير (بصدق):
//   • النقل: TLS (HTTPS / WSS) بين التطبيق والـ Worker.
//   • التخزين: كل رسالة تُشفَّر AES-256-GCM بـ IV عشوائي (12 بايت) خاص بها، والمفتاح يُشتق بـ HKDF-SHA256
//     من السر CHAT_KEY (Secret في Cloudflare) مع «بصمة المحادثة» كـ AAD. وسائط المحادثة تُشفَّر قطعةً قطعة
//     (كل قطعة IV عشوائي + AAD = معرّف الملف + رقم القطعة) قبل دخولها R2.
//   • هذا «تشفير أثناء النقل وعند التخزين» وليس تشفيراً طرفاً-لطرف: الـ Worker يرى النص لحظة المعالجة،
//     ومن يملك CHAT_KEY يستطيع فك التخزين. لذلك لا يدّعي التطبيق E2E (انظر docs/SECURITY.md للخطة الاختيارية).
// =====================================================================================

const CHAT_MAX_TEXT = 4000;
const CHAT_PART_SIZE = 1024 * 1024; // قطعة الرفع (نص صريح) = 1MB
const CHAT_MAX_FILE = 25 * 1024 * 1024;
const CHAT_STATUSES = ["open", "pending", "quoted", "won", "closed"];
const CHAT_TYPES = ["text", "image", "video", "voice", "file", "quote", "order", "system"];
const CHAT_MEDIA_TTL_MS = 60 * 60 * 1000;
const CHAT_MEDIA_PREFIX = "ads/chat/";

// ------------------------------------------------------------------ crypto helpers
function toB64(bytes) {
  let s = "";
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
}
function fromB64(str) {
  const bin = atob(String(str || ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
const _chatKeyCache = new Map();
async function chatMaster(env) {
  if (!env.CHAT_KEY) fail(503, "chat_not_configured", "لم يُضبط السر CHAT_KEY في الـ Worker.");
  let raw;
  try { raw = fromB64(String(env.CHAT_KEY).trim()); } catch (e) { raw = null; }
  if (!raw || raw.length < 32) fail(503, "chat_key_invalid", "CHAT_KEY يجب أن يكون 32 بايت على الأقل بصيغة base64.");
  return raw;
}
async function chatDerive(env, info, usage, algo) {
  const ck = info + "|" + usage + "|" + String(env.CHAT_KEY).length;
  if (_chatKeyCache.has(ck)) return _chatKeyCache.get(ck);
  const raw = await chatMaster(env);
  const base = await crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode("cigram-ads-chat-v1"), info: new TextEncoder().encode(info) },
    base, algo, false, [usage]
  );
  if (_chatKeyCache.size > 500) _chatKeyCache.clear();
  _chatKeyCache.set(ck, key);
  return key;
}
const _aes = { name: "AES-GCM", length: 256 };
async function encJson(env, thread, obj) {
  const key = await chatDerive(env, "msg|" + thread, "encrypt", _aes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(thread) }, key, new TextEncoder().encode(JSON.stringify(obj)));
  return { iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
}
async function decJson(env, thread, enc) {
  if (!enc || !enc.iv) return {};
  try {
    const key = await chatDerive(env, "msg|" + thread, "decrypt", _aes);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromB64(enc.iv), additionalData: new TextEncoder().encode(thread) }, key, fromB64(enc.ct));
    return JSON.parse(new TextDecoder().decode(pt));
  } catch (e) {
    return { text: "[تعذّر فك تشفير الرسالة]", broken: true };
  }
}
async function mediaPartEncrypt(env, mediaId, n, bytes) {
  const key = await chatDerive(env, "media|" + mediaId, "encrypt", _aes);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(mediaId + ":" + n) }, key, bytes));
  const out = new Uint8Array(12 + ct.length);
  out.set(iv, 0);
  out.set(ct, 12);
  return out;
}
async function mediaPartDecrypt(env, mediaId, n, blob) {
  const key = await chatDerive(env, "media|" + mediaId, "decrypt", _aes);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: blob.subarray(0, 12), additionalData: new TextEncoder().encode(mediaId + ":" + n) }, key, blob.subarray(12)));
}
async function mediaSign(env, mediaId, thread, exp) {
  const raw = await chatDerive(env, "sign", "sign", { name: "HMAC", hash: "SHA-256", length: 256 }).catch(async () => null);
  const key = raw || null;
  if (!key) fail(503, "chat_not_configured", "CHAT_KEY غير مضبوط.");
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(mediaId + "|" + thread + "|" + exp));
  return b64url(new Uint8Array(sig));
}

// ------------------------------------------------------------------ misc
function inWorkHours(st, now) {
  const h = st && st.hours;
  if (!h || !h.enabled) return true;
  const d = new Date(now + (h.tz_offset_min || 0) * 60000);
  const dow = d.getUTCDay();
  if (Array.isArray(h.days) && h.days.indexOf(dow) < 0) return false;
  const mins = d.getUTCHours() * 60 + d.getUTCMinutes();
  const p = (s) => { const m = /^(\d{1,2}):(\d{2})$/.exec(String(s || "")); return m ? parseInt(m[1], 10) * 60 + parseInt(m[2], 10) : null; };
  const a = p(h.from), b = p(h.to);
  if (a === null || b === null) return true;
  return a <= b ? mins >= a && mins < b : mins >= a || mins < b;
}
function previewOf(type, text) {
  if (type === "image") return "📷 صورة";
  if (type === "video") return "🎬 فيديو";
  if (type === "voice") return "🎤 رسالة صوتية";
  if (type === "file") return "📎 ملف";
  if (type === "quote") return "💰 عرض سعر";
  if (type === "order") return "📝 طلب إعلان";
  return String(text || "").replace(/\s+/g, " ").slice(0, 80);
}
function padSeq(n) { return String(n).padStart(10, "0"); }
function sniffChatFile(b, kind) {
  const eq = (off, arr) => b.length >= off + arr.length && arr.every((v, i) => b[off + i] === v);
  const img = sniffMedia(b);
  if (kind === "voice") {
    if (eq(4, [0x66, 0x74, 0x79, 0x70])) return { mime: "audio/mp4", ext: "m4a", kind: "voice" };
    if (eq(0, [0xff, 0xf1]) || eq(0, [0xff, 0xf9])) return { mime: "audio/aac", ext: "aac", kind: "voice" };
    if (eq(0, [0x4f, 0x67, 0x67, 0x53])) return { mime: "audio/ogg", ext: "ogg", kind: "voice" };
    if (eq(0, [0x1a, 0x45, 0xdf, 0xa3])) return { mime: "audio/webm", ext: "webm", kind: "voice" };
    if (eq(0, [0x23, 0x21, 0x41, 0x4d, 0x52])) return { mime: "audio/amr", ext: "amr", kind: "voice" };
    return null;
  }
  if (img) return { mime: img.mime, ext: img.ext, kind: img.kind };
  if (kind === "file") {
    if (eq(0, [0x25, 0x50, 0x44, 0x46])) return { mime: "application/pdf", ext: "pdf", kind: "file" };
    if (eq(0, [0x50, 0x4b, 0x03, 0x04])) return { mime: "application/zip", ext: "zip", kind: "file" };
    if (eq(0, [0xd0, 0xcf, 0x11, 0xe0])) return { mime: "application/msword", ext: "doc", kind: "file" };
  }
  return null;
}
function cleanName(s) {
  return String(s || "ملف").replace(/[\u0000-\u001f\\/:*?"<>|]/g, "_").slice(0, 80) || "ملف";
}

// =====================================================================================
// Durable Object — ChatHub (نسخة واحدة "hub": تسلسل مضمون للرسائل + مقابس WebSocket)
// =====================================================================================
export class ChatHub {
  constructor(state, env) {
    this.state = state;
    this.s = state.storage;
    this.env = env;
    this._rl = new Map();
    this._lastPush = new Map();
    try {
      if (typeof WebSocketRequestResponsePair !== "undefined" && state.setWebSocketAutoResponse) state.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
    } catch (e) { /* ignore */ }
  }
  rl(key, limit, windowMs) {
    const now = Date.now();
    if (this._rl.size > 5000) this._rl.clear();
    let r = this._rl.get(key);
    if (!r || now > r.reset) { r = { n: 0, reset: now + windowMs }; this._rl.set(key, r); }
    r.n++;
    return r.n <= limit;
  }
  async fetch(request) {
    if ((request.headers.get("upgrade") || "").toLowerCase() === "websocket") return this.handleWs(request);
    let body;
    try { body = await request.json(); } catch (e) { return new Response(JSON.stringify({ ok: false, error: "bad_request" }), { status: 400 }); }
    try {
      const fn = this["op_" + body.op];
      if (typeof fn !== "function") fail(404, "unknown_op", "عملية غير معروفة.");
      const out = await fn.call(this, body.p || {});
      return new Response(JSON.stringify(Object.assign({ ok: true }, out || {})), { status: 200 });
    } catch (e) {
      const [b, st] = errorBody(e);
      if (!(e instanceof HttpError)) console.log("ChatHub error", e && e.stack);
      return new Response(JSON.stringify(b), { status: st });
    }
  }

  // ------------------------------------------------------------ sockets
  socketsOf(tag) {
    let list = [];
    try { list = this.state.getWebSockets(tag) || []; } catch (e) { list = []; }
    return list.filter((w) => w.readyState === undefined || w.readyState === 1);
  }
  adminOnline() { return this.socketsOf("a").length > 0; }
  userOnline(thread) { return this.socketsOf("u:" + thread).length > 0; }
  push(tag, ev) {
    const data = JSON.stringify(ev);
    for (const w of this.socketsOf(tag)) { try { w.send(data); } catch (e) { /* ignore */ } }
  }
  emit(thread, ev, sides) {
    if (!sides || sides.indexOf("admin") >= 0) this.push("a", ev);
    if (!sides || sides.indexOf("user") >= 0) this.push("u:" + thread, ev);
  }
  async handleWs(request) {
    const side = request.headers.get("x-side") === "admin" ? "admin" : "user";
    const thread = String(request.headers.get("x-thread") || "");
    if (side === "user" && !thread) return new Response("bad", { status: 400 });
    const pair = new WebSocketPair();
    const client = pair[0], server = pair[1];
    this.state.acceptWebSocket(server, [side === "admin" ? "a" : "u:" + thread]);
    server.serializeAttachment({ side, thread });
    try { server.send(JSON.stringify({ t: "hello", side, server_time: Date.now() })); } catch (e) { /* ignore */ }
    if (side === "user") {
      const t = await this.s.get("t:" + thread);
      if (t) { t.user_seen = Date.now(); await this.s.put("t:" + thread, t); }
      this.push("a", { t: "presence", thread, side: "user", online: true });
    } else {
      this.push("a", { t: "presence", side: "admin", online: true });
      await this.broadcastAdminPresence();
    }
    return new Response(null, { status: 101, webSocket: client });
  }
  async broadcastAdminPresence() {
    const online = this.adminOnline();
    try {
      for (const w of this.state.getWebSockets()) {
        const a = w.deserializeAttachment ? w.deserializeAttachment() : null;
        if (a && a.side === "user") { try { w.send(JSON.stringify({ t: "presence", side: "admin", online })); } catch (e) { /* ignore */ } }
      }
    } catch (e) { /* ignore */ }
  }
  async webSocketMessage(ws, message) {
    if (typeof message !== "string" || message.length > 2000) return;
    if (message === "ping") { try { ws.send("pong"); } catch (e) { /* */ } return; }
    let m;
    try { m = JSON.parse(message); } catch (e) { return; }
    const a = ws.deserializeAttachment ? ws.deserializeAttachment() : null;
    if (!a || !m) return;
    if (m.t === "typing") {
      if (!this.rl("typ:" + (a.thread || "a"), 30, 10000)) return;
      if (a.side === "user") this.push("a", { t: "typing", thread: a.thread, side: "user", on: !!m.on });
      else if (m.thread) this.push("u:" + String(m.thread), { t: "typing", thread: String(m.thread), side: "admin", on: !!m.on });
    } else if (m.t === "read") {
      const thread = a.side === "user" ? a.thread : String(m.thread || "");
      if (thread) { try { await this.op_read({ thread, side: a.side, upto: m.upto }); } catch (e) { /* ignore */ } }
    } else if (m.t === "ping") {
      try { ws.send(JSON.stringify({ t: "pong", server_time: Date.now() })); } catch (e) { /* */ }
    }
  }
  async webSocketClose(ws) {
    try { ws.close(1000, "bye"); } catch (e) { /* ignore */ }
    const a = ws.deserializeAttachment ? ws.deserializeAttachment() : null;
    if (!a) return;
    if (a.side === "user") {
      const t = await this.s.get("t:" + a.thread);
      if (t) { t.user_seen = Date.now(); await this.s.put("t:" + a.thread, t); }
      if (!this.socketsOf("u:" + a.thread).filter((w) => w !== ws).length) this.push("a", { t: "presence", thread: a.thread, side: "user", online: false, last_seen: Date.now() });
    } else {
      const others = this.socketsOf("a").filter((w) => w !== ws);
      if (!others.length) {
        try {
          for (const w of this.state.getWebSockets()) {
            const x = w.deserializeAttachment ? w.deserializeAttachment() : null;
            if (x && x.side === "user") { try { w.send(JSON.stringify({ t: "presence", side: "admin", online: false })); } catch (e) { /* */ } }
          }
        } catch (e) { /* */ }
      }
    }
  }
  async webSocketError(ws) { await this.webSocketClose(ws); }

  // ------------------------------------------------------------ push (webhook) — اختياري
  async notify(side, thread, title, body) {
    const url = this.env.PUSH_WEBHOOK_URL;
    if (!url) return;
    const k = side + ":" + thread;
    const last = this._lastPush.get(k) || 0;
    if (Date.now() - last < 30000) return;
    this._lastPush.set(k, Date.now());
    if (this._lastPush.size > 3000) this._lastPush.clear();
    const p = fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ kind: "chat", to: side, user_key: side === "user" ? thread : undefined, thread, title, body }) }).catch(() => {});
    try { this.state.waitUntil(p); } catch (e) { /* ignore */ }
  }

  // ------------------------------------------------------------ threads
  async getThread(id, create, info) {
    let t = await this.s.get("t:" + id);
    if (!t && create) {
      const now = Date.now();
      t = {
        id, user_key: id, adv_id: (info && info.adv_id) || "", name: cleanText(info && info.name, 100) || "معلن", email: cleanText(info && info.email, 120),
        status: "open", tags: [], assigned: "", notes: "", banned: false, archived: false, muted: false,
        created: now, last_ts: now, last_seq: 0, last_from: "", prev_enc: null, unread_admin: 0, unread_user: 0,
        user_seen: 0, admin_seen: 0, auto_reply_at: 0,
      };
      await this.s.put("t:" + id, t);
    }
    return t || null;
  }
  async threadView(t, origin) {
    let prev = "";
    if (t.prev_enc) prev = (await decJson(this.env, t.id, t.prev_enc)).text || "";
    return {
      id: t.id, adv_id: t.adv_id, name: t.name, email: t.email, status: t.status, tags: t.tags, assigned: t.assigned, notes: t.notes,
      banned: !!t.banned, archived: !!t.archived, created: t.created, last_ts: t.last_ts, last_seq: t.last_seq, last_from: t.last_from,
      preview: prev, unread_admin: t.unread_admin, unread_user: t.unread_user, user_seen: t.user_seen,
      online: this.userOnline(t.id),
    };
  }
  userThreadView(t) {
    return { id: t.id, status: t.status, last_seq: t.last_seq, unread: t.unread_user, banned: !!t.banned, created: t.created };
  }
  async op_thread_open(p) {
    const id = cleanText(p.user_key, 120);
    if (!id) fail(400, "invalid_user", "مستخدم غير صالح.");
    const t = await this.getThread(id, true, p);
    if (p.name && t.name !== cleanText(p.name, 100) && t.name === "معلن") { t.name = cleanText(p.name, 100); await this.s.put("t:" + id, t); }
    return { thread: this.userThreadView(t) };
  }
  async op_threads_list(p) {
    const all = await this.s.list({ prefix: "t:" });
    const q = cleanText(p.q, 60).toLowerCase();
    const out = [];
    for (const t of all.values()) {
      if (p.archived ? !t.archived : t.archived) continue;
      if (p.status && t.status !== p.status) continue;
      if (p.unread && !t.unread_admin) continue;
      if (p.tag && (t.tags || []).indexOf(p.tag) < 0) continue;
      if (p.assigned && t.assigned !== p.assigned) continue;
      if (q && (t.name || "").toLowerCase().indexOf(q) < 0 && (t.email || "").toLowerCase().indexOf(q) < 0 && (t.tags || []).join(" ").toLowerCase().indexOf(q) < 0) continue;
      out.push(t);
    }
    out.sort((a, b) => (b.unread_admin ? 1 : 0) - (a.unread_admin ? 1 : 0) || b.last_ts - a.last_ts);
    const lim = int(p.limit, 1, 300, 100);
    const views = [];
    let totalUnread = 0;
    for (const t of all.values()) if (!t.archived) totalUnread += t.unread_admin || 0;
    for (const t of out.slice(0, lim)) views.push(await this.threadView(t));
    return { threads: views, unread_total: totalUnread, admin_online: this.adminOnline() };
  }
  async op_unread_total() {
    const all = await this.s.list({ prefix: "t:" });
    let n = 0, threads = 0;
    for (const t of all.values()) if (!t.archived && t.unread_admin) { n += t.unread_admin; threads++; }
    return { unread: n, threads };
  }
  async op_thread_update(p) {
    const t = await this.s.get("t:" + p.thread);
    if (!t) fail(404, "not_found", "المحادثة غير موجودة.");
    if (p.status !== undefined) t.status = oneOf(p.status, CHAT_STATUSES, t.status);
    if (p.tags !== undefined) t.tags = strList(p.tags, 10, 24);
    if (p.assigned !== undefined) t.assigned = cleanText(p.assigned, 40);
    if (p.notes !== undefined) t.notes = cleanText(p.notes, 3000);
    if (p.banned !== undefined) t.banned = bool(p.banned, false);
    if (p.archived !== undefined) t.archived = bool(p.archived, false);
    if (p.name !== undefined && cleanText(p.name, 100)) t.name = cleanText(p.name, 100);
    if (p.adv_id !== undefined) t.adv_id = cleanText(p.adv_id, 40);
    await this.s.put("t:" + t.id, t);
    this.emit(t.id, { t: "thread", thread: t.id, status: t.status, banned: !!t.banned }, ["admin", "user"]);
    return { thread: await this.threadView(t) };
  }

  // ------------------------------------------------------------ messages
  async viewMsg(m, origin) {
    const d = await decJson(this.env, m.thread, m.enc);
    const v = { seq: m.seq, id: m.id, from: m.from, type: m.type, ts: m.ts, delivered: m.delivered || 0, read: m.read || 0, deleted: !!m.deleted };
    if (m.deleted) { v.text = ""; return v; }
    v.text = d.text || "";
    if (d.reply) v.reply = d.reply;
    if (d.quote) v.quote = Object.assign({}, d.quote, { state: m.qstate || "pending" });
    if (d.order) v.order = d.order;
    if (d.media) {
      v.media = Object.assign({}, d.media);
      const exp = Date.now() + CHAT_MEDIA_TTL_MS;
      const sig = await mediaSign(this.env, d.media.id, m.thread, exp);
      v.media.url = origin + "/chat/media/" + d.media.id + "?t=" + encodeURIComponent(m.thread) + "&exp=" + exp + "&sig=" + sig;
    }
    return v;
  }
  async op_messages(p) {
    const thread = cleanText(p.thread, 120);
    const t = await this.s.get("t:" + thread);
    if (!t) return { messages: [], thread: null };
    const side = p.side === "admin" ? "admin" : "user";
    const limit = int(p.limit, 1, 100, 40);
    let rows;
    const after = int(p.after, 0, 1e12, 0);
    if (after > 0) {
      const all = await this.s.list({ prefix: "m:" + thread + ":", start: "m:" + thread + ":" + padSeq(after + 1), limit });
      rows = [...all.values()];
    } else {
      const before = int(p.before, 0, 1e12, 0);
      const opts = { prefix: "m:" + thread + ":", reverse: true, limit };
      if (before) opts.end = "m:" + thread + ":" + padSeq(before);
      const all = await this.s.list(opts);
      rows = [...all.values()].reverse();
    }
    // تأكيد التسليم للرسائل القادمة من الطرف الآخر
    const other = side === "admin" ? "user" : "admin";
    let upto = 0;
    const now = Date.now();
    for (const m of rows) {
      if (m.from === other && !m.delivered) { m.delivered = now; upto = Math.max(upto, m.seq); await this.s.put("m:" + thread + ":" + padSeq(m.seq), m); }
    }
    if (upto) this.emit(thread, { t: "delivered", thread, upto, ts: now }, [other]);
    const out = [];
    for (const m of rows) out.push(await this.viewMsg(m, p.origin));
    return { messages: out, thread: side === "admin" ? await this.threadView(t) : this.userThreadView(t), admin_online: this.adminOnline() };
  }
  async op_send(p) {
    const side = p.side === "admin" ? "admin" : "user";
    const thread = cleanText(p.thread, 120);
    const t = await this.getThread(thread, side === "user", p);
    if (!t) fail(404, "not_found", "المحادثة غير موجودة.");
    if (side === "user" && t.banned) fail(403, "banned", "تم تقييد المحادثة من قبل الإدارة.");
    if (!this.rl("send:" + side + ":" + thread, side === "user" ? 20 : 120, 60000)) fail(429, "rate_limited", "رسائل كثيرة. انتظر قليلاً.");
    const type = oneOf(p.type, CHAT_TYPES, "text");
    if (type === "system") fail(400, "invalid_type", "نوع غير مسموح.");
    if (side === "user" && (type === "quote")) fail(403, "forbidden", "غير مسموح.");
    const clientId = cleanText(p.client_id, 40);
    if (clientId) {
      const dup = await this.s.get("cid:" + thread + ":" + clientId);
      if (dup) {
        const m = await this.s.get("m:" + thread + ":" + padSeq(dup));
        if (m) return { message: await this.viewMsg(m, p.origin), duplicate: true };
      }
    }
    const text = cleanText(p.text, CHAT_MAX_TEXT);
    const payload = {};
    if (text) payload.text = text;
    if (p.reply_to) {
      const rs = int(p.reply_to, 1, 1e12, 0);
      const rm = rs ? await this.s.get("m:" + thread + ":" + padSeq(rs)) : null;
      if (rm && !rm.deleted) {
        const rd = await decJson(this.env, thread, rm.enc);
        payload.reply = { seq: rm.seq, from: rm.from, preview: previewOf(rm.type, rd.text) };
      }
    }
    if (type === "image" || type === "video" || type === "voice" || type === "file") {
      const meta = await this.s.get("media:" + cleanText(p.media_id, 40));
      if (!meta || meta.thread !== thread || !meta.complete) fail(400, "media_not_ready", "الملف لم يكتمل رفعه.");
      if (meta.used) fail(400, "media_used", "هذا الملف مُرسل سابقاً.");
      meta.used = true;
      await this.s.put("media:" + meta.id, meta);
      payload.media = { id: meta.id, kind: meta.kind, mime: meta.mime, size: meta.size, name: meta.name, dur: meta.dur || 0, wave: meta.wave || [], w: meta.w || 0, h: meta.h || 0 };
      if (meta.kind !== type) payload.media.kind = meta.kind;
    } else if (type === "quote") {
      const qd = p.quote || {};
      payload.quote = {
        slot: cleanText(qd.slot, 20), slot_label: cleanText(qd.slot_label, 60), days: int(qd.days, 1, MAX_CAMPAIGN_DAYS, 1),
        total: num(qd.total, 0, 1e9, 0), currency: cleanText(qd.currency, 8) || "USD", note: cleanText(qd.note, 600),
        campaign_id: cleanText(qd.campaign_id, 40), expires_at: qd.expires_at ? parseTime(qd.expires_at, 0) || 0 : 0,
      };
      if (!payload.quote.total) fail(400, "invalid_quote", "أدخل مبلغ عرض السعر.");
      if (!text) payload.text = "عرض سعر: " + (payload.quote.slot_label || payload.quote.slot) + " — " + payload.quote.days + " يوم";
    } else if (type === "order") {
      const o = p.order && typeof p.order === "object" ? p.order : null;
      if (!o) fail(400, "invalid_order", "الطلب غير صالح.");
      const js = JSON.stringify(o);
      if (js.length > 6000) fail(413, "too_large", "الطلب كبير.");
      payload.order = JSON.parse(js);
      if (!text) payload.text = "طلب إعلان جديد";
    } else if (!text) fail(400, "empty_message", "اكتب رسالة أولاً.");
    const now = Date.now();
    t.last_seq += 1;
    const m = {
      seq: t.last_seq, thread, id: randId("m_", 8), from: side, type, ts: now, client_id: clientId, enc: await encJson(this.env, thread, payload),
      delivered: (side === "user" ? this.adminOnline() : this.userOnline(thread)) ? now : 0, read: 0, deleted: false, qstate: type === "quote" ? "pending" : undefined,
    };
    await this.s.put("m:" + thread + ":" + padSeq(m.seq), m);
    if (clientId) await this.s.put("cid:" + thread + ":" + clientId, m.seq);
    t.last_ts = now;
    t.last_from = side;
    t.prev_enc = await encJson(this.env, thread, { text: previewOf(type, payload.text) });
    if (side === "user") {
      t.unread_admin = (t.unread_admin || 0) + 1;
      if (t.status === "closed" || t.status === "won") t.status = "open";
    } else {
      t.unread_user = (t.unread_user || 0) + 1;
      if (type === "quote") t.status = "quoted";
      else if (t.status === "open") t.status = "pending";
    }
    const view = await this.viewMsg(m, p.origin);
    // رد آلي خارج الدوام / عند عدم اتصال الإدارة (مرة كل 6 ساعات)
    let auto = null;
    if (side === "user" && !this.adminOnline() && now - (t.auto_reply_at || 0) > 6 * 3600000) {
      try {
        const st = (await this.env.ADS_CORE.get(this.env.ADS_CORE.idFromName("core")).fetch("https://core/op", { method: "POST", body: JSON.stringify({ op: "settings_public", p: {} }) }).then((r) => r.json())).settings;
        if (st && st.auto_reply && (!inWorkHours(st, now))) {
          t.last_seq += 1;
          const am = { seq: t.last_seq, thread, id: randId("m_", 8), from: "admin", type: "system", ts: now + 1, enc: await encJson(this.env, thread, { text: cleanText(st.auto_reply, 600), auto: true }), delivered: this.userOnline(thread) ? now : 0, read: 0, deleted: false };
          await this.s.put("m:" + thread + ":" + padSeq(am.seq), am);
          t.auto_reply_at = now;
          t.unread_user = (t.unread_user || 0) + 1;
          auto = await this.viewMsg(am, p.origin);
        }
      } catch (e) { /* الرد الآلي اختياري */ }
    }
    await this.s.put("t:" + thread, t);
    const tv = await this.threadView(t);
    this.emit(thread, { t: "msg", thread, msg: view, thread_info: tv }, side === "user" ? ["admin", "user"] : ["user", "admin"]);
    if (auto) this.emit(thread, { t: "msg", thread, msg: auto, thread_info: tv }, ["admin", "user"]);
    if (side === "user" && !this.adminOnline()) await this.notify("admin", thread, "رسالة جديدة من معلن", t.name + ": " + previewOf(type, payload.text));
    if (side === "admin" && !this.userOnline(thread)) await this.notify("user", thread, "رسالة من إدارة Cigram", previewOf(type, payload.text));
    return { message: view, auto, thread: side === "admin" ? tv : this.userThreadView(t) };
  }
  async op_read(p) {
    const thread = cleanText(p.thread, 120);
    const t = await this.s.get("t:" + thread);
    if (!t) return {};
    const side = p.side === "admin" ? "admin" : "user";
    const other = side === "admin" ? "user" : "admin";
    const upto = int(p.upto, 0, 1e12, t.last_seq) || t.last_seq;
    const now = Date.now();
    const rows = await this.s.list({ prefix: "m:" + thread + ":", reverse: true, limit: 120 });
    let changed = 0;
    for (const m of rows.values()) {
      if (m.seq > upto || m.from !== other || m.read) continue;
      m.read = now;
      if (!m.delivered) m.delivered = now;
      await this.s.put("m:" + thread + ":" + padSeq(m.seq), m);
      changed++;
    }
    if (side === "admin") { t.unread_admin = 0; t.admin_seen = now; } else { t.unread_user = 0; t.user_seen = now; }
    await this.s.put("t:" + thread, t);
    this.emit(thread, { t: "read", thread, side, upto, ts: now }, [other]);
    if (side === "user") this.push("a", { t: "thread_unread", thread, unread_admin: t.unread_admin });
    return { changed };
  }
  async op_delete_msg(p) {
    const thread = cleanText(p.thread, 120);
    const key = "m:" + thread + ":" + padSeq(int(p.seq, 1, 1e12, 0));
    const m = await this.s.get(key);
    if (!m) fail(404, "not_found", "الرسالة غير موجودة.");
    if (m.deleted) return {};
    const d = await decJson(this.env, thread, m.enc);
    if (d.media) await this.dropMedia(d.media.id);
    m.deleted = true;
    m.enc = await encJson(this.env, thread, {});
    await this.s.put(key, m);
    this.emit(thread, { t: "deleted", thread, seq: m.seq }, ["admin", "user"]);
    return {};
  }
  async op_quote_respond(p) {
    const thread = cleanText(p.thread, 120);
    const key = "m:" + thread + ":" + padSeq(int(p.seq, 1, 1e12, 0));
    const m = await this.s.get(key);
    if (!m || m.type !== "quote" || m.deleted) fail(404, "not_found", "عرض السعر غير موجود.");
    if (m.qstate && m.qstate !== "pending") fail(409, "already_answered", "تم الرد على هذا العرض مسبقاً.");
    const d = await decJson(this.env, thread, m.enc);
    if (d.quote && d.quote.expires_at && d.quote.expires_at < Date.now()) fail(410, "quote_expired", "انتهت صلاحية عرض السعر.");
    const accept = !!p.accept;
    m.qstate = accept ? "accepted" : "declined";
    await this.s.put(key, m);
    const t = await this.s.get("t:" + thread);
    if (t) { t.status = accept ? "won" : "pending"; await this.s.put("t:" + thread, t); }
    const sys = await this.op_send_system({ thread, text: accept ? "✅ وافق المعلن على عرض السعر." : "❌ رفض المعلن عرض السعر.", origin: p.origin });
    this.emit(thread, { t: "quote_state", thread, seq: m.seq, state: m.qstate }, ["admin", "user"]);
    return { state: m.qstate, message: sys };
  }
  async op_send_system(p) {
    const thread = cleanText(p.thread, 120);
    const t = await this.s.get("t:" + thread);
    if (!t) return null;
    const now = Date.now();
    t.last_seq += 1;
    const m = { seq: t.last_seq, thread, id: randId("m_", 8), from: "admin", type: "system", ts: now, enc: await encJson(this.env, thread, { text: cleanText(p.text, 300), sys: true }), delivered: now, read: now, deleted: false };
    await this.s.put("m:" + thread + ":" + padSeq(m.seq), m);
    t.last_ts = now;
    t.unread_admin = (t.unread_admin || 0) + 1;
    await this.s.put("t:" + thread, t);
    const view = await this.viewMsg(m, p.origin || "");
    this.emit(thread, { t: "msg", thread, msg: view, thread_info: await this.threadView(t) }, ["admin", "user"]);
    return view;
  }
  async op_find_order(p) {
    const thread = cleanText(p.thread, 120);
    const t = await this.s.get("t:" + thread);
    if (!t) fail(404, "not_found", "المحادثة غير موجودة.");
    const rows = await this.s.list({ prefix: "m:" + thread + ":", reverse: true, limit: 200 });
    for (const m of rows.values()) {
      if (m.type !== "order" || m.deleted) continue;
      if (p.seq && m.seq !== int(p.seq, 1, 1e12, 0)) continue;
      const d = await decJson(this.env, thread, m.enc);
      if (d.order) return { order: d.order, seq: m.seq, thread: await this.threadView(t) };
    }
    fail(404, "no_order", "لا يوجد طلب إعلان في هذه المحادثة.");
  }
  async op_export(p) {
    const thread = cleanText(p.thread, 120);
    const t = await this.s.get("t:" + thread);
    if (!t) fail(404, "not_found", "المحادثة غير موجودة.");
    const rows = await this.s.list({ prefix: "m:" + thread + ":", limit: 5000 });
    const out = [];
    for (const m of rows.values()) {
      const v = await this.viewMsg(m, p.origin || "");
      if (v.media) delete v.media.url;
      out.push(v);
    }
    return { thread: await this.threadView(t), messages: out, exported_at: Date.now() };
  }

  // ------------------------------------------------------------ media meta
  async op_media_init(p) {
    const thread = cleanText(p.thread, 120);
    const t = await this.getThread(thread, false);
    if (!t) fail(404, "not_found", "ابدأ المحادثة أولاً.");
    if (p.side === "user" && t.banned) fail(403, "banned", "تم تقييد المحادثة.");
    if (!this.rl("up:" + thread, 30, 600000)) fail(429, "rate_limited", "رفع ملفات كثير. انتظر قليلاً.");
    const size = Math.floor(Number(p.size) || 0);
    if (size < 1 || size > CHAT_MAX_FILE) fail(413, "too_large", "الملف فارغ أو أكبر من 25MB.");
    const kind = oneOf(p.kind, ["image", "video", "voice", "file"], "file");
    const id = randId("f", 14).replace(/[^A-Za-z0-9]/g, "x");
    const meta = {
      id, thread, owner: p.side === "admin" ? "admin" : "user", kind, size, name: cleanName(p.name), mime: "", parts: Math.ceil(size / CHAT_PART_SIZE),
      dur: int(p.dur, 0, 3600000, 0), w: int(p.w, 0, 20000, 0), h: int(p.h, 0, 20000, 0),
      wave: Array.isArray(p.wave) ? p.wave.slice(0, 64).map((x) => int(x, 0, 255, 0)) : [], created: Date.now(), complete: false, used: false, got: 0,
    };
    await this.s.put("media:" + id, meta);
    await this.ensureAlarm();
    return { media_id: id, part_size: CHAT_PART_SIZE, parts: meta.parts };
  }
  async op_media_meta(p) {
    const meta = await this.s.get("media:" + cleanText(p.id, 40));
    if (!meta) fail(404, "not_found", "الملف غير موجود.");
    if (p.thread && meta.thread !== p.thread) fail(403, "forbidden", "غير مسموح.");
    return { meta };
  }
  async op_media_set(p) {
    const meta = await this.s.get("media:" + cleanText(p.id, 40));
    if (!meta) fail(404, "not_found", "الملف غير موجود.");
    Object.assign(meta, p.patch || {});
    await this.s.put("media:" + meta.id, meta);
    return { meta };
  }
  async dropMedia(id) {
    const meta = await this.s.get("media:" + id);
    if (!meta) return;
    const b = bucketOf(this.env);
    if (b) for (let i = 0; i < meta.parts; i++) { try { await b.delete(CHAT_MEDIA_PREFIX + id + "/" + i); } catch (e) { /* ignore */ } }
    await this.s.delete("media:" + id);
  }
  async op_purge(p) {
    const thread = cleanText(p.thread, 120);
    const msgs = await this.s.list({ prefix: "m:" + thread + ":" });
    const keys = [];
    for (const [k, m] of msgs) {
      keys.push(k);
      if (m.client_id) keys.push("cid:" + thread + ":" + m.client_id);
    }
    const metas = await this.s.list({ prefix: "media:" });
    for (const meta of metas.values()) if (meta.thread === thread) await this.dropMedia(meta.id);
    for (let i = 0; i < keys.length; i += 100) await this.s.delete(keys.slice(i, i + 100));
    await this.s.delete("t:" + thread);
    try { for (const w of this.socketsOf("u:" + thread)) w.close(1000, "purged"); } catch (e) { /* ignore */ }
    this.push("a", { t: "thread_gone", thread });
    return { purged: keys.length };
  }
  async op_presence(p) {
    const st = p.settings || null;
    const now = Date.now();
    let state = "offline";
    if (this.adminOnline()) state = "online";
    else if (st && !inWorkHours(st, now)) state = "off_hours";
    return { state };
  }
  async op_templates_get() {
    return { templates: (await this.s.get("templates")) || [] };
  }
  async op_templates_set(p) {
    const list = (Array.isArray(p.templates) ? p.templates : []).slice(0, 30).map((t) => ({ title: cleanText(t.title, 40), body: cleanText(t.body, 1200) })).filter((t) => t.title && t.body);
    await this.s.put("templates", list);
    return { templates: list };
  }
  async ensureAlarm() {
    try { if (!(await this.s.getAlarm())) await this.s.setAlarm(Date.now() + 6 * 3600000); } catch (e) { /* ignore */ }
  }
  async alarm() {
    // تنظيف الملفات المرفوعة ولم تُرسل خلال 24 ساعة، وحذف المحادثات المؤرشفة القديمة إن حُدّد CHAT_RETENTION_DAYS
    const now = Date.now();
    const metas = await this.s.list({ prefix: "media:" });
    for (const meta of metas.values()) if (!meta.used && now - meta.created > 24 * 3600000) await this.dropMedia(meta.id);
    const days = parseInt(this.env.CHAT_RETENTION_DAYS || "0", 10);
    if (days > 0) {
      const all = await this.s.list({ prefix: "t:" });
      for (const t of all.values()) if (t.archived && now - t.last_ts > days * DAY_MS) await this.op_purge({ thread: t.id });
    }
    try { await this.s.setAlarm(now + 6 * 3600000); } catch (e) { /* ignore */ }
  }
}

// =====================================================================================
// المسارات
// =====================================================================================
function hubStub(env) {
  if (!env.CHAT_HUB) fail(503, "chat_not_configured", "لم يُربط Durable Object باسم CHAT_HUB.");
  return env.CHAT_HUB.get(env.CHAT_HUB.idFromName("hub"));
}
async function hub(env, op, p) {
  const r = await hubStub(env).fetch("https://hub/op", { method: "POST", body: JSON.stringify({ op, p: p || {} }) });
  const body = await r.json();
  if (!body.ok) fail(r.status || 500, body.error || "error", body.message || "فشل الطلب.");
  return body;
}
async function chatWsForward(request, env, side, thread) {
  if ((request.headers.get("upgrade") || "").toLowerCase() !== "websocket") fail(426, "upgrade_required", "هذا المسار للاتصال اللحظي فقط.");
  const h = new Headers(request.headers);
  h.set("x-side", side);
  h.set("x-thread", thread || "");
  h.delete("authorization");
  return hubStub(env).fetch(new Request("https://hub/ws", { headers: h }));
}
async function requireConsent(env, userKey) {
  const c = await core(env, "consent_get", { user_key: userKey });
  if (!c.valid) fail(403, "consent_required", "يجب الموافقة على سياسات الإعلانات الحالية قبل التواصل.", { current_version: c.current_version });
}
function userNameOf(user) {
  return user.name || (user.email ? user.email.split("@")[0] : "") || "معلن";
}

async function chatUploadRoutes(request, env, url, path, method, scope) {
  // scope = { side, thread }
  const q = (k) => url.searchParams.get(k) || "";
  const b = bucketOf(env);
  if (!b) fail(500, "no_bucket", "لا يوجد R2 Bucket.");
  if (method === "POST" && path === "/init") {
    const body = await readJson(request, 20000);
    const r = await hub(env, "media_init", Object.assign({}, body, { side: scope.side, thread: scope.thread }));
    return reply(r);
  }
  if (method === "PUT" && path === "/part") {
    const id = q("id"), n = parseInt(q("n"), 10);
    const m = (await hub(env, "media_meta", { id, thread: scope.thread })).meta;
    if (m.complete) fail(409, "already_complete", "اكتمل الملف.");
    if (!(n >= 0 && n < m.parts)) fail(400, "bad_part", "رقم القطعة غير صحيح.");
    const len = parseInt(request.headers.get("content-length") || "0", 10);
    if (len > CHAT_PART_SIZE) fail(413, "too_large", "القطعة أكبر من 1MB.");
    const buf = new Uint8Array(await request.arrayBuffer());
    const expect = n === m.parts - 1 ? m.size - n * CHAT_PART_SIZE : CHAT_PART_SIZE;
    if (buf.length !== expect) fail(400, "bad_part_size", "حجم القطعة غير مطابق للمتوقع.");
    if (n === 0) {
      const t = sniffChatFile(buf, m.kind);
      if (!t) fail(415, "unsupported_type", "نوع الملف غير مدعوم.");
      if (m.kind !== "file" && t.kind !== m.kind) fail(415, "unsupported_type", "الملف لا يطابق النوع المعلن.");
      await hub(env, "media_set", { id, patch: { mime: t.mime, kind: t.kind, ext: t.ext } });
    }
    await b.put(CHAT_MEDIA_PREFIX + id + "/" + n, await mediaPartEncrypt(env, id, n, buf), { httpMetadata: { contentType: "application/octet-stream" } });
    return reply({ ok: true, n });
  }
  if (method === "GET" && path === "/status") {
    const id = q("id");
    const m = (await hub(env, "media_meta", { id, thread: scope.thread })).meta;
    const have = [];
    for (let i = 0; i < m.parts; i++) if (await b.head(CHAT_MEDIA_PREFIX + id + "/" + i)) have.push(i);
    return reply({ ok: true, parts: m.parts, have, complete: !!m.complete });
  }
  if (method === "POST" && path === "/complete") {
    const id = q("id");
    const m = (await hub(env, "media_meta", { id, thread: scope.thread })).meta;
    for (let i = 0; i < m.parts; i++) if (!(await b.head(CHAT_MEDIA_PREFIX + id + "/" + i))) fail(409, "missing_parts", "قطع ناقصة. أعد رفع القطع الناقصة.", { missing: i });
    if (!m.mime) fail(400, "unsupported_type", "نوع الملف غير معروف.");
    await hub(env, "media_set", { id, patch: { complete: true } });
    return reply({ ok: true, media_id: id });
  }
  return null;
}

async function serveChatMedia(request, env, id, url) {
  const thread = url.searchParams.get("t") || "";
  const exp = parseInt(url.searchParams.get("exp") || "0", 10);
  const sig = url.searchParams.get("sig") || "";
  if (!/^f[A-Za-z0-9]{6,30}$/.test(id) || !thread || !(exp > Date.now()) || exp > Date.now() + 2 * CHAT_MEDIA_TTL_MS) return new Response("Forbidden", { status: 403, headers: corsHeaders() });
  const good = await mediaSign(env, id, thread, exp);
  if (!timingSafeEqual(good, sig)) return new Response("Forbidden", { status: 403, headers: corsHeaders() });
  let meta;
  try { meta = (await hub(env, "media_meta", { id, thread })).meta; } catch (e) { return new Response("Not found", { status: 404, headers: corsHeaders() }); }
  if (!meta.complete) return new Response("Not found", { status: 404, headers: corsHeaders() });
  const b = bucketOf(env);
  let start = 0, end = meta.size - 1, status = 200;
  const range = request.headers.get("range");
  if (range) {
    const m = /^bytes=(\d*)-(\d*)$/.exec(range.trim());
    if (m && (m[1] || m[2])) {
      if (m[1] === "") { start = Math.max(0, meta.size - parseInt(m[2], 10)); }
      else { start = parseInt(m[1], 10); if (m[2]) end = Math.min(end, parseInt(m[2], 10)); }
      if (start >= meta.size || end < start) return new Response("Range Not Satisfiable", { status: 416, headers: corsHeaders({ "content-range": "bytes */" + meta.size }) });
      status = 206;
    }
  }
  const first = Math.floor(start / CHAT_PART_SIZE), last = Math.floor(end / CHAT_PART_SIZE);
  const { readable, writable } = new TransformStream();
  const writer = writable.getWriter();
  (async () => {
    try {
      for (let i = first; i <= last; i++) {
        const o = await b.get(CHAT_MEDIA_PREFIX + id + "/" + i);
        if (!o) throw new Error("missing part");
        const blob = new Uint8Array(await (o.arrayBuffer ? o.arrayBuffer() : new Response(o.body).arrayBuffer()));
        const plain = await mediaPartDecrypt(env, id, i, blob);
        const s = i === first ? start - i * CHAT_PART_SIZE : 0;
        const e = i === last ? end - i * CHAT_PART_SIZE + 1 : plain.length;
        await writer.write(plain.subarray(s, e));
      }
      await writer.close();
    } catch (e) {
      try { await writer.abort(e); } catch (x) { /* ignore */ }
    }
  })();
  const headers = {
    "content-type": meta.mime || "application/octet-stream", "content-length": String(end - start + 1), "accept-ranges": "bytes",
    "cache-control": "private, max-age=600", "content-security-policy": "default-src 'none'; sandbox",
    "content-disposition": (meta.kind === "file" ? "attachment" : "inline") + "; filename*=UTF-8''" + encodeURIComponent(meta.name || "file"),
  };
  if (status === 206) headers["content-range"] = "bytes " + start + "-" + end + "/" + meta.size;
  return new Response(readable, { status, headers: corsHeaders(headers) });
}

async function purgeChatForUser(env, userKey) {
  if (!env.CHAT_HUB) return;
  try { await hub(env, "purge", { thread: userKey }); } catch (e) { /* ignore */ }
}

async function notifyCampaignChange(env, c) {
  // رسالة نظام تلقائية في محادثة المعلن عند تغيّر حالة حملته
  if (!env.CHAT_HUB || !c || !c.advertiser_id) return;
  const adv = (await core(env, "adv_get", { id: c.advertiser_id, origin: "" })).advertiser;
  const key = adv && adv.user_key;
  if (!key) return;
  const lines = {
    approved: "✅ تمت الموافقة على حملتك «" + c.name + "» وهي الآن مجدولة/فعّالة حسب التاريخ.",
    rejected: "❌ تم رفض حملتك «" + c.name + "»." + (c.reject_reason ? " السبب: " + c.reject_reason : ""),
    paused: "⏸ تم إيقاف حملتك «" + c.name + "» مؤقتاً.",
  };
  let text = lines[c.status];
  if (!text) return;
  const t = await hub(env, "thread_open", { user_key: key, name: adv.name }).catch(() => null);
  if (!t) return;
  await hub(env, "send_system", { thread: key, text });
}

async function routeChat(request, env, ctx, url, path) {
  const method = request.method;
  const origin = originOf(request, env);
  const q = (k) => url.searchParams.get(k) || "";

  // ---------- عام
  if (method === "GET" && path === "/chat/presence") {
    let st = null;
    try { st = (await core(env, "settings_public", {})).settings; } catch (e) { /* ignore */ }
    if (!env.CHAT_HUB) return reply({ ok: true, state: "offline" });
    return reply(await hub(env, "presence", { settings: st && { hours: st.hours } }));
  }
  let m;
  if (method === "GET" && (m = /^\/chat\/media\/([A-Za-z0-9]+)$/.exec(path))) return serveChatMedia(request, env, m[1], url);

  // ---------- المستخدم
  if (path.indexOf("/chat/") === 0) {
    const user = await verifyUser(request, env);
    const thread = user.key;
    if (method === "GET" && path === "/chat/ws") return chatWsForward(request, env, "user", thread);
    if (method === "GET" && path === "/chat/thread") return reply(await hub(env, "thread_open", { user_key: thread, name: userNameOf(user), email: user.email }));
    if (method === "GET" && path === "/chat/messages") {
      return reply(await hub(env, "messages", { thread, side: "user", after: q("after"), before: q("before"), limit: q("limit"), origin }));
    }
    if (method === "GET" && path === "/chat/unread") {
      const t = await hub(env, "thread_open", { user_key: thread, name: userNameOf(user), email: user.email });
      return reply({ ok: true, unread: t.thread.unread, last_seq: t.thread.last_seq });
    }
    if (method === "POST" && path === "/chat/send") {
      await requireConsent(env, thread);
      const body = await readJson(request, 12000);
      let adv = null;
      try { adv = (await core(env, "adv_ensure_user", { user_key: thread, name: userNameOf(user), email: user.email, origin })).advertiser; } catch (e) { /* ignore */ }
      const r = await hub(env, "send", { side: "user", thread, name: userNameOf(user), email: user.email, adv_id: adv && adv.id, client_id: body.client_id, type: body.type, text: body.text, media_id: body.media_id, reply_to: body.reply_to, order: body.order, origin });
      return reply(r);
    }
    if (method === "POST" && path === "/chat/read") {
      const body = await readJson(request, 1000);
      return reply(await hub(env, "read", { thread, side: "user", upto: body.upto }));
    }
    if (method === "POST" && path === "/chat/quote/respond") {
      const body = await readJson(request, 1000);
      const r = await hub(env, "quote_respond", { thread, seq: body.seq, accept: body.accept, origin });
      return reply(r);
    }
    if (method === "POST" && path === "/chat/delete-all") {
      await purgeChatForUser(env, thread);
      return reply({ ok: true });
    }
    if (path.indexOf("/chat/upload/") === 0) {
      await requireConsent(env, thread);
      const r = await chatUploadRoutes(request, env, url, path.slice("/chat/upload".length), method, { side: "user", thread });
      if (r) return r;
    }
    return null;
  }

  // ---------- الأدمن
  if (path.indexOf("/admin/chat/") === 0) {
    await requireAdmin(request, env);
    const sub = path.slice("/admin/chat".length);
    if (method === "GET" && sub === "/ws") return chatWsForward(request, env, "admin", "");
    if (method === "GET" && sub === "/threads") return reply(await hub(env, "threads_list", { q: q("q"), status: q("status"), unread: q("unread") === "1", tag: q("tag"), assigned: q("assigned"), archived: q("archived") === "1", limit: q("limit") }));
    if (method === "GET" && sub === "/unread") return reply(await hub(env, "unread_total", {}));
    if (method === "GET" && sub === "/messages") return reply(await hub(env, "messages", { thread: q("thread"), side: "admin", after: q("after"), before: q("before"), limit: q("limit"), origin }));
    if (method === "POST" && sub === "/send") {
      const body = await readJson(request, 12000);
      return reply(await hub(env, "send", Object.assign({}, body, { side: "admin", origin })));
    }
    if (method === "POST" && sub === "/read") {
      const body = await readJson(request, 1000);
      return reply(await hub(env, "read", { thread: body.thread, side: "admin", upto: body.upto }));
    }
    if (method === "POST" && sub === "/thread") return reply(await hub(env, "thread_update", await readJson(request, 8000)));
    if (method === "POST" && sub === "/delete-message") return reply(await hub(env, "delete_msg", await readJson(request, 1000)));
    if (method === "POST" && sub === "/purge") {
      const body = await readJson(request, 1000);
      return reply(await hub(env, "purge", { thread: body.thread }));
    }
    if (method === "GET" && sub === "/export") return reply(await hub(env, "export", { thread: q("thread"), origin }));
    if (method === "GET" && sub === "/templates") return reply(await hub(env, "templates_get", {}));
    if (method === "POST" && sub === "/templates") return reply(await hub(env, "templates_set", await readJson(request, 40000)));
    if (method === "POST" && sub === "/convert-order") {
      const body = await readJson(request, 2000);
      const f = await hub(env, "find_order", { thread: body.thread, seq: body.seq });
      const o = f.order || {};
      let adv = (await core(env, "adv_by_user", { user_key: body.thread, origin })).advertiser;
      if (!adv) adv = (await core(env, "adv_ensure_user", { user_key: body.thread, name: f.thread.name, email: f.thread.email, origin })).advertiser;
      const start = Date.now() + DAY_MS;
      const camp = await core(env, "camp_save", {
        advertiser_id: adv.id, name: "طلب: " + (o.slot_label || o.slot || "إعلان"), slot: o.slot, start_at: start, days: o.days || 7,
        targeting: { cities: o.cities || [], langs: o.langs || [], hours: o.hours || null }, addons: o.addons || {}, source_order: "chat:" + body.thread.slice(-8) + ":" + f.seq, origin,
      });
      await hub(env, "send_system", { thread: body.thread, text: "📝 أُنشئت مسودة حملة من طلبك وهي قيد المراجعة.", origin });
      return reply({ ok: true, campaign: camp.campaign });
    }
    if (path.indexOf("/admin/chat/upload/") === 0) {
      // الأدمن يمرّر thread في الـ query لكل نداءات الرفع
      const thread = q("thread");
      if (!thread) fail(400, "thread_required", "حدد المحادثة (thread).");
      const r = await chatUploadRoutes(request, env, url, path.slice("/admin/chat/upload".length), method, { side: "admin", thread });
      if (r) return r;
    }
  }
  return null;
}
