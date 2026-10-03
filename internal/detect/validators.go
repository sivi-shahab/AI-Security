package detect

// Structural validators for Indonesian identifiers and card numbers (spec FR-CLS-1). Input is digits only.

func num(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		n = n*10 + int(s[i]-'0')
	}
	return n
}

// provinces: the two-digit Kemendagri province codes a NIK/KK starts with.
var provinces = map[string]bool{}

func init() {
	for _, r := range [][2]int{{11, 19}, {21, 21}, {31, 36}, {51, 53}, {61, 65}, {71, 76}, {81, 82}, {91, 96}} {
		for p := r[0]; p <= r[1]; p++ {
			provinces[string(rune('0'+p/10))+string(rune('0'+p%10))] = true
		}
	}
}

// validNIK: PP KK CC DDMMYY SSSS. Province is a real code, regency and district are non-zero, DDMMYY is a
// birth date (day + 40 for women), serial is non-zero. The year is two digits, so 29 Feb always passes.
func validNIK(d string) bool { return regionDate(d, true) }

// validKK: same layout as NIK, but DDMMYY is the issue date (no +40).
func validKK(d string) bool { return regionDate(d, false) }

func regionDate(d string, female bool) bool {
	if len(d) != 16 || !provinces[d[:2]] || d[2:4] == "00" || d[4:6] == "00" || d[12:] == "0000" {
		return false
	}
	day, mon := num(d[6:8]), num(d[8:10])
	if female && day > 40 {
		day -= 40
	}
	return mon >= 1 && mon <= 12 && day >= 1 && day <= [...]int{31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31}[mon-1]
}

func luhn(d string) bool {
	sum := 0
	for i := len(d) - 1; i >= 0; i-- {
		v := int(d[i] - '0')
		if (len(d)-i)%2 == 0 {
			if v *= 2; v > 9 {
				v -= 9
			}
		}
		sum += v
	}
	return sum%10 == 0
}

// validNPWP: 15 digits whose 9th is the Luhn check digit of the first 8; the 16-digit form (2024+) of a
// non-individual is "0" + the 15 digits (an individual's 16-digit NPWP is their NIK).
func validNPWP(d string) bool {
	if len(d) == 16 && d[0] == '0' {
		d = d[1:]
	}
	return len(d) == 15 && luhn(d[:9])
}

// validPAN: Luhn plus an issuer prefix whose length rules the number satisfies.
func validPAN(d string) bool {
	n := len(d)
	if n < 13 || n > 19 || !luhn(d) {
		return false
	}
	p2, p3, p4 := num(d[:2]), num(d[:3]), num(d[:4])
	switch {
	case d[0] == '4': // Visa
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720: // Mastercard
		return n == 16
	case p2 == 34, p2 == 37: // Amex
		return n == 15
	case p4 >= 3528 && p4 <= 3589, // JCB
		p4 == 6011, p3 >= 644 && p3 <= 649, p2 == 65, // Discover
		p2 == 62,   // UnionPay
		p4 == 9360: // GPN (Gerbang Pembayaran Nasional)
		return n >= 16
	case p2 == 36, p2 == 38, p2 == 39, p3 >= 300 && p3 <= 305: // Diners
		return n >= 14
	}
	return false
}

// mobilePrefixes: 8xy after the leading 0 of Indonesian mobile numbers (Telkomsel, Indosat, XL/Axis, Tri, Smartfren).
var mobilePrefixes = map[string]bool{}

func init() {
	for _, r := range [][2]int{{811, 819}, {821, 823}, {831, 833}, {838, 838}, {851, 853}, {855, 859}, {877, 878}, {881, 889}, {895, 899}} {
		for p := r[0]; p <= r[1]; p++ {
			mobilePrefixes[string(rune('0'+p/100))+string(rune('0'+p/10%10))+string(rune('0'+p%10))] = true
		}
	}
}

// validMobile: 08xy… (10–13 digits) or the same after country code 62.
func validMobile(d string) bool {
	if len(d) > 2 && d[:2] == "62" {
		d = "0" + d[2:]
	}
	return len(d) >= 10 && len(d) <= 13 && d[0] == '0' && mobilePrefixes[d[1:4]]
}

// accountLengths: account-number length per bank where it is fixed. Banks not listed fall back to 10–16
// digits with context. ponytail: five largest banks only; add a bank when its format is confirmed.
var accountLengths = map[string]int{"bca": 10, "bni": 10, "bsi": 10, "mandiri": 13, "bri": 15}
