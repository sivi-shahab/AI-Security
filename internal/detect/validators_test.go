package detect

import "testing"

func TestValidators(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) bool
		in   string
		want bool
	}{
		{"NIK male", validNIK, "3201011505900001", true},
		{"NIK female (+40)", validNIK, "3201015505900001", true},
		{"NIK 29 Feb", validNIK, "3201012902000001", true},
		{"NIK female 29 Feb", validNIK, "3201016902000001", true},
		{"NIK bad province", validNIK, "4001011505900001", false},
		{"NIK province 20", validNIK, "2001011505900001", false},
		{"NIK new Papua province", validNIK, "9601011505900001", true},
		{"NIK zero regency", validNIK, "3200011505900001", false},
		{"NIK zero district", validNIK, "3201001505900001", false},
		{"NIK day 32", validNIK, "3201013205900001", false},
		{"NIK day 0", validNIK, "3201010005900001", false},
		{"NIK female day 72", validNIK, "3201017205900001", false},
		{"NIK 30 Feb", validNIK, "3201013002900001", false},
		{"NIK 31 Apr", validNIK, "3201013104900001", false},
		{"NIK month 13", validNIK, "3201011513900001", false},
		{"NIK zero serial", validNIK, "3201011505900000", false},
		{"NIK 15 digits", validNIK, "320101150590001", false},
		{"KK", validKK, "3201011505900001", true},
		{"KK no +40", validKK, "3201015505900001", false},

		{"NPWP 15", validNPWP, "092542943407000", true},
		{"NPWP 15 second", validNPWP, "010000131093000", true},
		{"NPWP bad check digit", validNPWP, "092542944407000", false},
		{"NPWP 16 = 0 + 15", validNPWP, "0092542943407000", true},
		{"NPWP 16 not 0-prefixed", validNPWP, "1092542943407000", false},
		{"NPWP 14", validNPWP, "09254294340700", false},

		{"PAN Visa 16", validPAN, "4111111111111111", true},
		{"PAN Visa 13", validPAN, "4222222222222", true},
		{"PAN Visa bad Luhn", validPAN, "4111111111111112", false},
		{"PAN Visa 15", validPAN, "411111111111116", false},
		{"PAN Mastercard 5", validPAN, "5555555555554444", true},
		{"PAN Mastercard 2-series", validPAN, "2223003122003222", true},
		{"PAN Amex", validPAN, "378282246310005", true},
		{"PAN Amex 16", validPAN, "3782822463100055", false},
		{"PAN JCB", validPAN, "3530111333300000", true},
		{"PAN Discover", validPAN, "6011111111111117", true},
		{"PAN UnionPay", validPAN, "6200000000000005", true},
		{"PAN Diners 14", validPAN, "36227206271667", true},
		{"PAN unknown issuer", validPAN, "1234567812345670", false},
		{"PAN 12 digits", validPAN, "411111111113", false},
		{"PAN 20 digits", validPAN, "41111111111111111113", false},

		{"mobile 08", validMobile, "081234567890", true},
		{"mobile 62", validMobile, "6281234567890", true},
		{"mobile Tri", validMobile, "089612345678", true},
		{"mobile shortest", validMobile, "0811234567", true},
		{"mobile too long", validMobile, "08123456789012", false},
		{"mobile too short", validMobile, "081234567", false},
		{"mobile unknown prefix 0820", validMobile, "082012345678", false},
		{"landline", validMobile, "0215551234", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%s: %s = %v, want %v", c.name, c.in, got, c.want)
		}
	}
}
