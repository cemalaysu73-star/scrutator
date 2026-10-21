"""`scrutator audit-letter`: a fill-in authorisation letter and the engagement file that goes with it.

The letter is a template, not legal advice: it states so at the top, in both languages. Fields that were not given
are left as `<fill in: ...>` placeholders, and `scrutator audit` refuses an engagement file that still holds one, so an
unsigned template can never authorise an audit.
"""

from __future__ import annotations

from datetime import date

PLACEHOLDER = "<fill in"

_EN = """\
TEMPLATE — NOT LEGAL ADVICE. Have it reviewed by counsel in your jurisdiction before use.

AUTHORISATION FOR A PASSIVE EXTERNAL EXPOSURE REVIEW
Reference: {reference}

{client} ("the Client") authorises {auditor} ("the Reviewer") to carry out a passive review of the Client's
publicly visible internet infrastructure, on the terms below.

1. Scope. The following domains and the names under them:
{domains}
   Nothing outside this list is in scope. Names of third parties found during the review (cloud providers, suppliers)
   are recorded as references only and are not reviewed.

2. Period. From {start} to {end} inclusive.

3. Permitted activity: PASSIVE ONLY. The Reviewer may read public records about the domains in scope: certificate
   transparency logs, DNS (ordinary lookups of the Client's names, as any visitor makes), domain and IP registration
   data, routing data, web archives and passive-DNS and name aggregators.
   Not permitted: port or vulnerability scanning, sending traffic to the Client's systems beyond ordinary DNS lookups,
   login attempts, exploitation or confirmation of any weakness (including claiming a subdomain), social engineering,
   and any lookup of a person, e-mail address or credential.

4. Deliverable. A written report and a signed evidence bundle, delivered to the Client contact below only.

5. Data. The Reviewer processes the collected records only for this review, keeps them for {retention} after
   delivery unless the Client asks for earlier deletion, and does not disclose them to third parties. Where personal
   data is incidentally collected, the Reviewer acts as processor on the Client's instructions (KVKK / GDPR).

6. Findings are reported to the Client only. If the Reviewer finds a weakness in a third party's service, it is
   reported through that party's published disclosure channel without naming the Client, or not at all.

7. Client contact for this review: {client_contact}
   Reviewer contact: {auditor_contact}

Signed for the Client, by a person entitled to authorise testing of the systems in scope:

Name: {signatory}          Role: {signatory_role}

Signature: ______________________          Date: ______________

Signed for the Reviewer:

Name: ______________________          Signature: ______________________          Date: ______________
"""

_TR = """\
ŞABLONDUR — HUKUKİ TAVSİYE DEĞİLDİR. Kullanmadan önce yetkili bir hukukçuya inceletin.

PASİF DIŞ SALDIRI YÜZEYİ İNCELEMESİ İÇİN YETKİ BELGESİ
Referans: {reference}

{client} ("Kurum"), {auditor} ("İnceleyen") tarafına, Kurumun herkese açık internet altyapısının aşağıdaki
koşullarla pasif olarak incelenmesi için yetki verir.

1. Kapsam. Aşağıdaki alan adları ve bunların altındaki adlar:
{domains}
   Bu listenin dışındaki hiçbir şey kapsamda değildir. İnceleme sırasında görülen üçüncü tarafların adları (bulut
   sağlayıcıları, tedarikçiler) yalnızca referans olarak kaydedilir, incelenmez.

2. Süre. {start} ile {end} tarihleri arası (her iki gün dahil).

3. İzin verilen faaliyet: YALNIZCA PASİF. İnceleyen, kapsamdaki alan adları hakkındaki kamusal kayıtları okuyabilir:
   sertifika şeffaflığı kayıtları, DNS (herhangi bir ziyaretçinin yaptığı olağan sorgular), alan adı ve IP kayıt
   verileri, yönlendirme verileri, web arşivleri, pasif DNS ve ad toplayıcıları.
   İzin verilmeyenler: port ya da zafiyet taraması, olağan DNS sorguları dışında Kurumun sistemlerine trafik
   gönderilmesi, oturum açma girişimi, herhangi bir zafiyetin istismarı ya da doğrulanması (bir alt alan adının
   sahiplenilmesi dahil), sosyal mühendislik ve herhangi bir kişinin, e-posta adresinin ya da kimlik bilgisinin sorgulanması.

4. Teslim. Yazılı bir rapor ve imzalı bir kanıt paketi, yalnızca aşağıdaki Kurum irtibat kişisine teslim edilir.

5. Veriler. İnceleyen, toplanan kayıtları yalnızca bu inceleme için işler, Kurum daha önce silinmesini istemedikçe
   teslimden sonra {retention} saklar ve üçüncü taraflara açıklamaz. Kişisel verinin tesadüfen toplanması halinde
   İnceleyen, Kurumun talimatıyla veri işleyen sıfatıyla hareket eder (KVKK / GDPR).

6. Bulgular yalnızca Kuruma raporlanır. İnceleyen bir üçüncü tarafın servisinde zafiyet bulursa, Kurumu anmadan o
   tarafın yayımladığı bildirim kanalıyla bildirir ya da hiç bildirmez.

7. Bu inceleme için Kurum irtibatı: {client_contact}
   İnceleyen irtibatı: {auditor_contact}

Kurum adına, kapsamdaki sistemlerin test edilmesine yetki vermeye yetkili kişi tarafından imzalanmıştır:

Ad Soyad: {signatory}          Unvan: {signatory_role}

İmza: ______________________          Tarih: ______________

İnceleyen adına:

Ad Soyad: ______________________          İmza: ______________________          Tarih: ______________
"""

_YAML = """\
# Engagement file for `scrutator audit --engagement` (and `scrutator exposure`).
# Fill in every <fill in: ...> field from the SIGNED letter; scrutator refuses a file that still holds one.
# Its sha256 is written to the scan's signed audit log before the first lookup.
organisation: {client_yaml}
domains: [{domains_yaml}]
authorised_by: {{name: {signatory_yaml}, role: {signatory_role_yaml}}}
start: {start}
end: {end}
purpose: {purpose_yaml}
reference: {reference_yaml}
"""


def _fill(value: str | None, what: str) -> str:
    return value.strip() if value and value.strip() else f"<fill in: {what}>"


def _yaml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ") + '"'


def make_letter(*, lang: str, client: str | None, domains: list[str], start: date | None, end: date | None,
                auditor: str | None, auditor_contact: str | None, client_contact: str | None, signatory: str | None,
                signatory_role: str | None, reference: str | None, retention: str | None) -> tuple[str, str]:
    """The letter (plain text) and the engagement YAML that goes with it."""
    if lang not in ("en", "tr"):
        raise ValueError("language must be en or tr")
    tr = lang == "tr"
    values = {
        "client": _fill(client, "kurumun tam ticari unvanı" if tr else "client's legal name"),
        "auditor": _fill(auditor, "inceleyenin adı / şirketi" if tr else "reviewer's name or company"),
        "reference": _fill(reference, "referans" if tr else "reference"),
        "start": start.isoformat() if start else ("<fill in: başlangıç YYYY-AA-GG>" if tr else "<fill in: start YYYY-MM-DD>"),
        "end": end.isoformat() if end else ("<fill in: bitiş YYYY-AA-GG>" if tr else "<fill in: end YYYY-MM-DD>"),
        "client_contact": _fill(client_contact, "ad, e-posta" if tr else "name, e-mail"),
        "auditor_contact": _fill(auditor_contact, "ad, e-posta" if tr else "name, e-mail"),
        "signatory": _fill(signatory, "imzalayanın adı" if tr else "signatory's name"),
        "signatory_role": _fill(signatory_role, "imzalayanın unvanı" if tr else "signatory's role"),
        "retention": _fill(retention, "saklama süresi, ör. 90 gün" if tr else "retention period, e.g. 90 days"),
    }
    listed = domains or ["<fill in: alan-adi.com.tr>" if tr else "<fill in: example.com>"]
    values["domains"] = "\n".join(f"   - {d}" for d in listed)
    letter = (_TR if tr else _EN).format(**values)
    engagement = _YAML.format(
        client_yaml=_yaml_str(values["client"]),
        domains_yaml=", ".join(_yaml_str(d) for d in listed),
        signatory_yaml=_yaml_str(values["signatory"]), signatory_role_yaml=_yaml_str(values["signatory_role"]),
        start=values["start"] if start else _yaml_str(values["start"]), end=values["end"] if end else _yaml_str(values["end"]),
        purpose_yaml=_yaml_str("Passive external exposure review" + (f", engagement {reference}" if reference else "")),
        reference_yaml=_yaml_str(values["reference"]),
    )
    return letter, engagement
