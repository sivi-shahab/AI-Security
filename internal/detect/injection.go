package detect

import "regexp"

// Prompt-injection heuristics, English and Indonesian (spec FR-PSEC-1/2/5/6). Deterministic L1 signal only:
// the L2 classifier (ticket 10) adds what phrasing-based rules miss. Each rule's confidence is the weight of
// its attack type; types combine as 1 - Π(1 - w) (aggregate).
//
// Weights: overriding instructions or forging role markers is rarely innocent (0.85, 0.7). Addressing the AI
// from inside data is a strong indirect-injection tell (0.6), as are hidden ASCII (0.6) and a markdown image
// that would ship data to a URL (0.6). Steering a tool ("transfer … to …") is common in honest banking text,
// so alone (0.35) it stays under every threshold.

const injectionPrefix = "INJECTION."

func inj(typ string, anchors []string, re string, w float64) rule {
	return rule{injectionPrefix + typ, anchors, true, regexp.MustCompile(`(?i)^` + re), w, nil}
}

const aiNoun = `(?:ai|assistant|agent|model|llm|chatbot|bot|asisten|agen)s?\b`

var injectionRules = []rule{
	inj("instruction_override",
		[]string{"ignore", "disregard", "forget", "override", "abaikan", "lupakan", "acuhkan", "hiraukan"},
		`(?:ignore|disregard|forget|override|abaikan|lupakan|acuhkan|hiraukan)\b[^.\n]{0,40}?\b(?:instructions?|directions?|prompts?|rules?|guidelines?|guardrails?|instruksi|perintah|arahan|aturan|everything|semua(?:nya)?)\b`, 0.85),
	inj("instruction_override",
		[]string{"new", "updated", "revised", "real", "actual", "instruksi"},
		`(?:(?:new|updated|revised|real|actual)\s+(?:system\s+)?instructions?|instruksi\s+(?:baru|sebenarnya|terbaru))\s*:`, 0.85),
	inj("role_confusion", []string{"<|"}, `<\|(?:im_start|im_end|system|assistant|user|endoftext|eot_id|start_header_id)\|?>`, 0.7),
	inj("role_confusion", []string{"###"}, `###\s*(?:system|instructions?|assistant)\b`, 0.7),
	inj("role_confusion", []string{"<system", "</system", "<user", "</user", "<assistant", "</assistant", "<<sys>>"}, `(?:</?(?:system|user|assistant)>|<<sys>>)`, 0.7),
	inj("role_confusion", []string{"[system", "[/system", "[inst]", "[/inst]"}, `\[/?(?:system|inst)\]`, 0.7),
	inj("ai_directive",
		[]string{"important", "urgent", "attention", "note", "message", "instruction", "todo", "catatan", "pesan", "perhatian", "penting"},
		`(?:important|urgent|attention|note|message|instructions?|todo|catatan|pesan|perhatian|penting)\s*[!:]?\s*(?:to|for|untuk|kepada|bagi)\s+(?:the\s+|any\s+|all\s+|para\s+)?`+aiNoun, 0.6),
	inj("ai_directive", []string{"you"}, `you,?\s+(?:the\s+|an?\s+)?(?:ai|llm)\s+(?:assistant|agent|model)\b`, 0.6),
	inj("ai_directive", []string{"before you"}, `before\s+you\s+(?:can\s+)?(?:solve|complete|do|finish|continue(?:\s+with)?)\s+(?:the|my|your)\s+task`, 0.6),
	inj("ai_directive", []string{"the task"}, `the\s+task\s+(?:that\s+)?i\s+(?:gave|asked|assigned)\s+(?:to\s+)?you`, 0.6),
	inj("ai_directive", []string{"dear", "hey", "hi", "hello", "halo", "hai", "yth"}, `(?:dear|hey|hi|hello|halo|hai|yth\.?)\s+`+aiNoun, 0.6),
	inj("ai_directive", []string{"if you are", "when you are"}, `(?:if|when)\s+you\s+are\s+(?:an?\s+)?(?:ai|assistant|agent|llm|language model|chatbot)\b`, 0.6),
	inj("ai_directive", []string{"jika anda", "jika kamu", "apabila anda", "kalau anda", "kalau kamu"},
		`(?:jika|apabila|kalau)\s+(?:anda|kamu)\s+(?:adalah\s+)?(?:sebuah\s+|seorang\s+)?(?:ai|asisten|agen|model)\b`, 0.6),
	inj("ai_directive", []string{"do not", "don't", "never"}, `(?:do\s+not|don't|never)\s+(?:tell|inform|mention|reveal|show|notify)\s+(?:this\s+(?:to\s+)?)?(?:the\s+)?user`, 0.6),
	inj("ai_directive", []string{"jangan"}, `jangan\s+(?:beri\s?tahu|memberi\s?tahu(?:kan)?|bilang|kasih\s+tahu|sampaikan|tampilkan|informasikan)\s+(?:ini\s+|hal\s+ini\s+)?(?:ke(?:pada)?\s+)?(?:pengguna|user|nasabah)`, 0.6),
	inj("ai_directive", []string{"before you", "before answer", "before respond", "before repl"}, `before\s+(?:you\s+)?(?:answer|respond|reply|replie)`, 0.6),
	inj("ai_directive", []string{"sebelum"}, `sebelum\s+(?:menjawab|merespons|merespon|membalas)`, 0.6),
	inj("tool_steering", []string{"call", "invoke", "execute", "panggil", "jalankan"},
		"(?:call|invoke|execute|panggil|jalankan)\\s+(?:the\\s+)?[`\"']?[a-z_][\\w.\\-]*[`\"']?\\s+(?:tool|function|fungsi|api)\\b", 0.35),
	inj("tool_steering", []string{"send", "transfer", "forward", "wire", "email", "kirim", "teruskan"},
		`(?:send|transfer|forward|wire|email|kirim(?:kan)?|transfer(?:kan)?|teruskan)\b(?:[^.\n]|\.\d){0,60}?\b(?:to|ke|kepada)\s+(?:this|the following|berikut|rekening|account|address|alamat|[\w.+-]+@[\w-]+\.)`, 0.35),
	inj("exfil_link", []string{"!["}, `!\[[^\]\n]{0,100}\]\(\s*https?://[^)\s]+\?[^)\s]*=[^)\s]*\)`, 0.6),
	inj("exfil_link", []string{"<img"}, `<img\b[^>]{0,200}\bsrc\s*=\s*["']?https?://[^"'\s>]+\?[^"'\s>]*=`, 0.6),
}
