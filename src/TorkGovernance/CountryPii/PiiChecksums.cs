using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace TorkGovernance.CountryPii;

/// <summary>
/// Check digits for the country registry.
///
/// The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
/// the eleven that reduce to them; the other nine are marked kind:"custom" and
/// carry no specification, so they are ported here by hand from the cloud's
/// lib/pii/checksums.ts -- the single implementation the cloud and the country
/// corpus both use. Keeping the arithmetic identical is what makes a receipt
/// block from this SDK byte-identical to one from the JavaScript SDK.
///
/// Every method is pure: a string in, a bool out. No I/O, no clock.
/// </summary>
public static class PiiChecksums
{
    private static string DigitsOf(string s)
    {
        var chars = s.Where(char.IsAsciiDigit).ToArray();
        return new string(chars);
    }

    /// <summary>Remainder of a long decimal digit string modulo m, digit by digit.</summary>
    private static int ModDigits(string digits, int m)
    {
        var r = 0;
        foreach (var ch in digits)
        {
            r = (r * 10 + (ch - '0')) % m;
        }
        return r;
    }

    private static bool AllSameDigit(string d) => d.Length > 0 && d.All(c => c == d[0]);

    /// <summary>Luhn / ISO-IEC 7812-1 mod-10.</summary>
    public static bool Luhn(string input)
    {
        var d = DigitsOf(input);
        if (d.Length < 2) return false;
        var sum = 0;
        var dbl = false;
        for (var i = d.Length - 1; i >= 0; i--)
        {
            var n = d[i] - '0';
            if (dbl)
            {
                n *= 2;
                if (n > 9) n -= 9;
            }
            sum += n;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }

    private static readonly int[][] VerhoeffMul =
    {
        new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        new[] { 1, 2, 3, 4, 0, 6, 7, 8, 9, 5 },
        new[] { 2, 3, 4, 0, 1, 7, 8, 9, 5, 6 },
        new[] { 3, 4, 0, 1, 2, 8, 9, 5, 6, 7 },
        new[] { 4, 0, 1, 2, 3, 9, 5, 6, 7, 8 },
        new[] { 5, 9, 8, 7, 6, 0, 4, 3, 2, 1 },
        new[] { 6, 5, 9, 8, 7, 1, 0, 4, 3, 2 },
        new[] { 7, 6, 5, 9, 8, 2, 1, 0, 4, 3 },
        new[] { 8, 7, 6, 5, 9, 3, 2, 1, 0, 4 },
        new[] { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0 },
    };

    private static readonly int[][] VerhoeffPerm =
    {
        new[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 },
        new[] { 1, 5, 7, 6, 2, 8, 3, 0, 9, 4 },
        new[] { 5, 8, 0, 3, 7, 9, 6, 1, 4, 2 },
        new[] { 8, 9, 1, 6, 0, 4, 3, 5, 2, 7 },
        new[] { 9, 4, 5, 3, 1, 2, 6, 8, 7, 0 },
        new[] { 4, 2, 8, 6, 5, 7, 3, 9, 0, 1 },
        new[] { 2, 7, 9, 3, 8, 0, 6, 4, 1, 5 },
        new[] { 7, 0, 4, 6, 9, 1, 3, 2, 5, 8 },
    };

    /// <summary>Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018).</summary>
    public static bool Verhoeff(string input)
    {
        var d = DigitsOf(input);
        var c = 0;
        for (var i = 0; i < d.Length; i++)
        {
            var digit = d[d.Length - 1 - i] - '0';
            c = VerhoeffMul[c][VerhoeffPerm[i % 8][digit]];
        }
        return c == 0;
    }

    /// <summary>Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10, sum mod 11 == 0.</summary>
    public static bool AuTfn(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 9) return false;
        int[] w = { 1, 4, 3, 7, 5, 8, 6, 9, 10 };
        var sum = 0;
        for (var i = 0; i < 9; i++) sum += (d[i] - '0') * w[i];
        return sum % 11 == 0;
    }

    /// <summary>Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19, mod 89.</summary>
    public static bool AuAbn(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 11) return false;
        int[] w = { 10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19 };
        var sum = (d[0] - '0' - 1) * w[0];
        for (var i = 1; i < 11; i++) sum += (d[i] - '0') * w[i];
        return sum % 89 == 0;
    }

    /// <summary>Australian Medicare card number (Services Australia).</summary>
    public static bool AuMedicare(string input)
    {
        var d = DigitsOf(input);
        if (d.Length < 10) return false;
        if (!"23456".Contains(d[0])) return false;
        int[] w = { 1, 3, 7, 9, 1, 3, 7, 9 };
        var sum = 0;
        for (var i = 0; i < 8; i++) sum += (d[i] - '0') * w[i];
        return sum % 10 == d[8] - '0';
    }

    /// <summary>UK NHS number (NHS Data Model and Dictionary): weights 10..2, check = 11 - (sum mod 11).</summary>
    public static bool UkNhs(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 10) return false;
        var sum = 0;
        for (var i = 0; i < 9; i++) sum += (d[i] - '0') * (10 - i);
        var check = 11 - (sum % 11);
        if (check == 11) check = 0;
        if (check == 10) return false;
        return check == d[9] - '0';
    }

    /// <summary>Brazil CPF (Receita Federal): two sequential mod-11 check digits.</summary>
    public static bool BrCpf(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 11 || AllSameDigit(d)) return false;

        int Calc(int len)
        {
            var sum = 0;
            for (var i = 0; i < len; i++) sum += (d[i] - '0') * (len + 1 - i);
            var r = (sum * 10) % 11;
            return r == 10 ? 0 : r;
        }

        return Calc(9) == d[9] - '0' && Calc(10) == d[10] - '0';
    }

    /// <summary>Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight vectors.</summary>
    public static bool BrCnpj(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 14 || AllSameDigit(d)) return false;

        int Calc(int[] weights)
        {
            var sum = 0;
            for (var i = 0; i < weights.Length; i++) sum += (d[i] - '0') * weights[i];
            var r = sum % 11;
            return r < 2 ? 0 : 11 - r;
        }

        return Calc(new[] { 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2 }) == d[12] - '0'
            && Calc(new[] { 6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2 }) == d[13] - '0';
    }

    /// <summary>Japan My Number (MIC Ordinance No. 85 of 2014).</summary>
    public static bool JpMyNumber(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 12) return false;
        var sum = 0;
        for (var n = 1; n <= 11; n++)
        {
            var p = d[11 - n] - '0';
            var q = n <= 6 ? n + 1 : n - 5;
            sum += p * q;
        }
        var r = sum % 11;
        var check = r <= 1 ? 0 : 11 - r;
        return check == d[11] - '0';
    }

    private static readonly Regex CnShape = new(@"^\d{17}[\dX]$", RegexOptions.Compiled);

    /// <summary>China resident ID (GB 11643-1999): ISO 7064 MOD 11-2, check character may be X.</summary>
    public static bool CnResidentId(string input)
    {
        var s = new string(input.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        if (!CnShape.IsMatch(s)) return false;
        int[] w = { 7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2 };
        var sum = 0;
        for (var i = 0; i < 17; i++) sum += (s[i] - '0') * w[i];
        return "10X98765432"[sum % 11] == s[17];
    }

    /// <summary>
    /// Korea RRN, for numbers issued before 20 Oct 2020.
    ///
    /// ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
    /// assigned and carry no check digit.
    /// </summary>
    public static bool KrRrn(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 13) return false;
        int[] w = { 2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5 };
        var sum = 0;
        for (var i = 0; i < 12; i++) sum += (d[i] - '0') * w[i];
        return (11 - (sum % 11)) % 10 == d[12] - '0';
    }

    private static readonly Regex SgShape = new(@"^[STFGM]\d{7}[A-Z]$", RegexOptions.Compiled);

    /// <summary>Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent letter table.</summary>
    public static bool SgNric(string input)
    {
        var s = new string(input.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        if (!SgShape.IsMatch(s)) return false;
        int[] w = { 2, 7, 6, 5, 4, 3, 2 };
        var sum = 0;
        for (var i = 0; i < 7; i++) sum += (s[1 + i] - '0') * w[i];
        var prefix = s[0];
        if (prefix is 'T' or 'G') sum += 4;
        if (prefix == 'M') sum += 3;
        var table = prefix is 'S' or 'T' ? "JZIHGFEDCBA" : prefix == 'M' ? "KLJNPQRTUWX" : "XWUTRQPNMLK";
        return table[sum % 11] == s[8];
    }

    private static readonly Dictionary<char, int> CfOdd = new()
    {
        ['0'] = 1, ['1'] = 0, ['2'] = 5, ['3'] = 7, ['4'] = 9, ['5'] = 13, ['6'] = 15,
        ['7'] = 17, ['8'] = 19, ['9'] = 21,
        ['A'] = 1, ['B'] = 0, ['C'] = 5, ['D'] = 7, ['E'] = 9, ['F'] = 13, ['G'] = 15,
        ['H'] = 17, ['I'] = 19, ['J'] = 21, ['K'] = 2, ['L'] = 4, ['M'] = 18, ['N'] = 20,
        ['O'] = 11, ['P'] = 3, ['Q'] = 6, ['R'] = 8, ['S'] = 12, ['T'] = 14, ['U'] = 16,
        ['V'] = 10, ['W'] = 22, ['X'] = 25, ['Y'] = 24, ['Z'] = 23,
    };

    private static readonly Regex CfShape =
        new(@"^[A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z]$", RegexOptions.Compiled);

    /// <summary>Italy codice fiscale (Agenzia delle Entrate): odd/even tables, mod 26, check letter.</summary>
    public static bool ItCodiceFiscale(string input)
    {
        var s = new string(input.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        if (!CfShape.IsMatch(s)) return false;
        var sum = 0;
        for (var i = 0; i < 15; i++)
        {
            var c = s[i];
            if (i % 2 == 0) sum += CfOdd[c];
            else if (char.IsAsciiDigit(c)) sum += c - '0';
            else sum += c - 'A';
        }
        return (char)('A' + (sum % 26)) == s[15];
    }

    private static readonly Regex NirShape =
        new(@"^[12]\d{2}\d{2}(\d{2}|2A|2B)\d{3}\d{3}\d{2}$", RegexOptions.Compiled);

    /// <summary>France NIR (Insee): 97-complement, Corsican 2A/2B mapped to 19/18 first.</summary>
    public static bool FrNir(string input)
    {
        var s = new string(input.Where(c => !char.IsWhiteSpace(c)).ToArray()).ToUpperInvariant();
        if (!NirShape.IsMatch(s)) return false;
        var idxA = s.IndexOf("2A", StringComparison.Ordinal);
        if (idxA >= 0) s = s.Remove(idxA, 2).Insert(idxA, "19");
        var idxB = s.IndexOf("2B", StringComparison.Ordinal);
        if (idxB >= 0) s = s.Remove(idxB, 2).Insert(idxB, "18");
        var body = s[..13];
        var key = int.Parse(s[13..]);
        return 97 - ModDigits(body, 97) == key;
    }

    /// <summary>Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits.</summary>
    public static bool DeSteuerId(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 11 || d[0] == '0') return false;
        var product = 10;
        for (var i = 0; i < 10; i++)
        {
            var sum = (d[i] - '0' + product) % 10;
            if (sum == 0) sum = 10;
            product = (sum * 2) % 11;
        }
        var check = 11 - product;
        if (check == 10) check = 0;
        return check == d[10] - '0';
    }

    /// <summary>Thailand national ID (DOPA): weights 13..2, check = (11 - sum mod 11) mod 10.</summary>
    public static bool ThNationalId(string input)
    {
        var d = DigitsOf(input);
        if (d.Length != 13) return false;
        var sum = 0;
        for (var i = 0; i < 12; i++) sum += (d[i] - '0') * (13 - i);
        return (11 - (sum % 11)) % 10 == d[12] - '0';
    }

    /// <summary>Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- community-sourced.</summary>
    public static bool CaSin(string input) => DigitsOf(input).Length == 9 && Luhn(input);

    /// <summary>South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits.</summary>
    public static bool ZaId(string input) => DigitsOf(input).Length == 13 && Luhn(input);

    /// <summary>UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory.</summary>
    public static bool AeEmiratesId(string input)
    {
        var d = DigitsOf(input);
        return d.Length == 15 && d.StartsWith("784", StringComparison.Ordinal) && Luhn(d);
    }

    /// <summary>Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory.</summary>
    public static bool SaNationalId(string input)
    {
        var d = DigitsOf(input);
        return d.Length == 10 && (d[0] == '1' || d[0] == '2') && Luhn(d);
    }

    /// <summary>Keyed by the bundle's Checksum field.</summary>
    public static readonly IReadOnlyDictionary<string, Func<string, bool>> Functions =
        new Dictionary<string, Func<string, bool>>
        {
            ["luhn"] = Luhn,
            ["verhoeff"] = Verhoeff,
            ["au_tfn"] = AuTfn,
            ["au_abn"] = AuAbn,
            ["au_medicare"] = AuMedicare,
            ["uk_nhs"] = UkNhs,
            ["br_cpf"] = BrCpf,
            ["br_cnpj"] = BrCnpj,
            ["jp_my_number"] = JpMyNumber,
            ["cn_resident_id"] = CnResidentId,
            ["kr_rrn"] = KrRrn,
            ["sg_nric"] = SgNric,
            ["it_codice_fiscale"] = ItCodiceFiscale,
            ["fr_nir"] = FrNir,
            ["de_steuer_id"] = DeSteuerId,
            ["th_national_id"] = ThNationalId,
            ["ca_sin"] = CaSin,
            ["za_id"] = ZaId,
            ["ae_emirates_id"] = AeEmiratesId,
            ["sa_national_id"] = SaNationalId,
        };
}
