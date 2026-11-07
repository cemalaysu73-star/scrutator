"""The fixed text of an audit, in English and Turkish.

Only fixed text lives here: headings, labels, the methodology, the limits, the glossary, the rule titles and remediation
advice. Nothing here is a claim about a client. The per-finding explanation (what the cited evidence shows) is written
by the risk rules in English and is shown as such in a Turkish report, labelled as the rule's own wording.
"""

LANGS = ("en", "tr")

TEXT = {
    "en": {
        "doc_title": "External exposure audit",
        "confidential": "Confidential",
        "prepared_for": "Prepared for",
        "prepared_by": "Prepared by",
        "date": "Date",
        "reference": "Engagement reference",
        "scope": "Scope",
        "self_title": "External exposure self-assessment",
        "contact": "Contact",
        "toc": "Contents",
        "s_auth": "Authorisation",
        "s_exec": "Executive summary",
        "s_risks": "Findings and remediation, in priority order",
        "s_inventory": "Asset inventory",
        "s_limits": "What was not tested",
        "s_method": "Methodology",
        "s_glossary": "Glossary",
        "s_evidence": "Evidence appendix",
        "auth_client": (
            "This review was carried out under a written authorisation from {organisation}, signed by {name} ({role}), "
            "in force from {start} to {end}, for the domains listed above and for this purpose: {purpose}"
        ),
        "auth_self": (
            "This is a self-assessment: the person who ran it attested that they own or control the domains listed "
            "above. No third party authorised it, and it is not an audit of anyone else's systems."
        ),
        "auth_recorded_signed": (
            "The authorisation (its SHA-256 {sha}) was written to the scan's hash-chained audit log before the first "
            "lookup, and that log is inside the signed evidence bundle."
        ),
        "auth_recorded_late": (
            "The authorisation (its SHA-256 {sha}) was recorded when this report was made; the scan itself was run "
            "before it was recorded, so the signed bundle does not contain it."
        ),
        "auth_self_recorded": "The self-attestation was written to the scan's signed audit log before the first lookup.",
        "auth_self_late": "The self-attestation was recorded when this report was made, after the scan.",
        "auth_passive": "Permitted activity: passive collection of public records only.",
        "auth_active": (
            "Permitted activity: passive collection of public records and, because this authorisation covers it, a limited "
            "active confirmation: TCP connection checks on a fixed list of ports, TLS handshakes and one HTTP request for "
            "the home page, only to the addresses that the client's own names resolve to. No login attempt, exploit, "
            "fuzzing or brute force was made."
        ),
        "exec_scope_active": "{auditor} reviewed the internet footprint of {client} ({domains}) on {date}, using public records and, under the authorisation recorded below, a limited set of connection checks to the addresses of those names (TCP connect, TLS handshake, one HTTP request): no login attempts, no exploitation.",
        "exec_active": "Active checks made during the review: {checks} connection check(s) on {addresses} address(es) found {open} port(s) open, {closed} closed and {filtered} unanswered; {skipped} address(es) on shared platforms or in non-public ranges were not probed.",
        "s_active": "Active confirmation",
        "active_intro": "These results are checks made by this tool at the time shown in each record, not third-party data. 'Unanswered' means no reply within the timeout: it can be the client's firewall or the tester's own network.",
        "col_open": "Open now",
        "col_closed": "Closed",
        "col_unanswered": "Unanswered",
        "active_skipped": "Addresses that were not probed, and why:",
        "active_cap": "Connection cap: {cap}. Ports left out of the plan because of the cap: {not_planned}.",
        "col_basis": "How established",
        "basis_checked": "Checked now: a connection check made by this tool at {when} UTC.",
        "basis_both": "Checked now ({when} UTC); also reported earlier by a third party ({who}).",
        "basis_third": "Reported earlier by a third party ({who}); not checked now.",
        "not_tested_intro_active": "This review was passive except for the authorised active confirmation described above. It did not:",
        "not_tested_active": [
            "try to log in, guess credentials or test anonymous access to any service (a banner is read, never answered);",
            "send exploit or vulnerability payloads, fuzz, or enumerate directories or files;",
            "probe any address other than those the client's names resolve to, any shared platform (CDN, hosting platform) or any non-public address;",
            "scan UDP, or any port outside the fixed list and the ports a passive source reported open;",
            "test web applications, APIs, logins or authentication beyond one request for the home page;",
            "look at internal networks, endpoints, cloud accounts or source code;",
            "look up any person, e-mail address or credential, or use breach data;",
            "test phishing resistance, physical security or staff awareness.",
        ],
        "method_active": (
            "After the passive collection, and only under the authorisation recorded above, the tool made a bounded number of "
            "connections to the addresses that the client's names resolved to: a TCP connect check per port (the greeting, if any, "
            "was read and nothing was sent), a TLS handshake on open TLS ports, and one HTTP request for the home page. Each "
            "result is an evidence record, and the plan (which addresses and ports, which were skipped and why) is itself a "
            "record written before the first connection."
        ),
        "exec_note": "Each numbered statement cites the evidence records it rests on (appendix).",
        "exec_ai": "Statements marked * were reworded by a language model and checked against their evidence by an independent verifier; the original wording is in audit.json.",
        "col_priority": "Priority",
        "col_severity": "Severity",
        "col_finding": "Finding",
        "col_affected": "Affected",
        "col_evidence_says": "What the evidence shows",
        "col_fix": "Remediation",
        "col_effort": "Effort (estimate)",
        "col_mapping": "Informational mapping",
        "col_records": "Evidence",
        "col_name": "Name",
        "col_addresses": "Addresses",
        "col_providers": "Providers",
        "col_networks": "Networks",
        "col_source": "Source",
        "col_state": "Outcome",
        "col_id": "Record",
        "col_request": "Request",
        "col_collected": "Collected (UTC)",
        "no_risks": "No issue covered by the rules of this review was found. That is not proof that there is none: see What was not tested.",
        "mapping_note": (
            "The framework references are an informational mapping, not a certification, an audit opinion or a legal "
            "conclusion. References marked (unverified), including every ISO/IEC 27001 reference, could not be read at "
            "an authoritative public source and must be checked against the framework itself."
        ),
        "rule_wording": "",
        "effort_note": "Effort is the auditor's estimate of the work to fix, not a measurement.",
        "inventory_note": (
            "Names that public DNS resolves or that a certificate dated in the last 90 days names (verified). Names that "
            "only third-party lists mention are counted below, not listed here."
        ),
        "inventory_more": "{n} more verified {names} are in the technical annex.",
        "claimed_line": "Unconfirmed names (only lists mention them): {claimed}. Retired names (DNS says they do not exist): {stale}. Covered only by a wildcard record: {wildcard}.",
        "not_tested_intro": "This review is passive. It did not:",
        "not_tested": [
            "scan ports or services, or send any request to the client's systems other than ordinary DNS lookups of their names;",
            "test web applications, APIs, logins or authentication;",
            "attempt to exploit, confirm or reproduce any weakness (a takeover candidate is reported, never claimed);",
            "look at internal networks, endpoints, cloud accounts or source code;",
            "look up any person, e-mail address or credential, or use breach data;",
            "test phishing resistance, physical security or staff awareness.",
        ],
        "coverage_intro": "Public sources asked and how they answered during the review:",
        "coverage_off": "Sources not used: {list}.",
        "coverage_deadline": "The review hit its time limit; lookups still running were stopped and are missing.",
        "coverage_cap": "The review reached its cap of {cap} recorded names; {dropped} name(s) given by sources were not recorded.",
        "coverage_none_failed": "Every source that was asked answered.",
        "coverage_limit": (
            "Names that no certificate log, archive or aggregator has ever seen cannot appear in this report. A finding "
            "reflects public records at the time they were collected; the client's systems may have changed since."
        ),
        "src_ok": "answered",
        "src_failed": "failed",
        "src_down": "stopped after repeated failures",
        "src_idle": "not needed",
        "method_paras": [
            "Scrutator asked public sources what they know about the domains in scope: certificate transparency logs, "
            "DNS, registration data (RDAP), routing data, web archives and passive-DNS and name aggregators. It did not "
            "contact the client's systems except through ordinary DNS lookups.",
            "Every answer was stored unchanged as an evidence record addressed by its SHA-256 hash. Findings and risks "
            "are derived from those records by deterministic rules; a risk cannot exist without the records it cites. "
            "A name is verified when DNS resolves it or a recent certificate names it, and only claimed when only a "
            "list mentions it.",
            "The records, the derived report and a hash-chained log of every lookup were sealed in a proof bundle and "
            "signed with an Ed25519 key. The bundle can be checked by anyone, offline, with the commands in the appendix.",
        ],
        "method_facts": "Tool {tool}; risk rules {ruleset}; knowledge packs {packs}; scan started {started}; report made {generated}.",
        "method_sources": "Sources used: {list}.",
        "glossary": [
            ("DNS", "The internet's directory: it turns names such as www.example.com into addresses."),
            ("CNAME (alias)", "A DNS record saying a name is another name. If the target disappears, whoever claims it may control the alias."),
            ("Subdomain takeover", "Taking control of a name whose alias points at a cloud resource that no longer exists."),
            ("SPF", "A DNS record listing which servers may send e-mail for a domain."),
            ("DMARC", "A DNS record telling receivers what to do with mail that fails SPF/DKIM checks, and where to report it."),
            ("CAA", "A DNS record naming the certificate authorities allowed to issue certificates for a domain."),
            ("Certificate transparency", "Public logs of every TLS certificate issued; they reveal names a company uses."),
            ("RDAP", "The modern registration database for domains and IP networks (successor of WHOIS)."),
            ("Verified / claimed", "Verified: DNS or a recent certificate supports the name. Claimed: only a list mentions it."),
            ("Evidence record", "The unchanged answer of a source, identified by its SHA-256 hash."),
            ("Proof bundle", "A signed file with the report, every evidence record and the lookup log; any change is detected."),
            ("SHA-256", "A fingerprint of a file: changing one bit changes it completely."),
            ("Ed25519", "The signature scheme used to seal the bundle; the key fingerprint identifies the signer."),
        ],
        "evidence_intro": (
            "This report was made from the signed proof bundle below. Give the client the bundle with this report; it "
            "holds every record this report cites."
        ),
        "bundle_file": "Bundle file",
        "bundle_sha": "Bundle SHA-256",
        "bundle_key": "Signing key fingerprint",
        "bundle_records": "Evidence records in the bundle",
        "verify_title": "How the client or their auditor verifies this report offline, in three commands",
        "verify_steps": [
            "Check that the bundle is the one this report names (Windows: certutil -hashfile proof.scrutator SHA256):",
            "Check the signature, the hash chain of the lookup log and every record, and that the findings follow from the records:",
            "Check that every number, finding and sentence of this report is what the bundle implies:",
        ],
        "verify_install": "Scrutator is open source (Apache-2.0); install it with pip from the wheel or the project. None of the three commands uses the network.",
        "cited_records": "Records cited by this report",
        "cited_more": "{n} more cited {records} are listed in the technical annex and in the bundle.",
        "annex": "The interactive technical annex (technical-annex.html) shows every name, finding and record with its evidence.",
        "page": "page",
        "sev": {"high": "High", "medium": "Medium", "low": "Low", "info": "Info"},
        "effort": {"low": "Low", "medium": "Medium", "high": "High"},
        "exec_scope": "{auditor} reviewed the public internet footprint of {client} ({domains}) on {date}, using public records only: no scanning, no login attempts, no exploitation.",
        "exec_verified": "The review confirmed {n} internet-facing {names} under these domains that {resolve} in public DNS or {appear} in a recent certificate.",
        "exec_claimed": "Third-party lists mention {n} more {names} that public DNS does not confirm; {they} kept as unconfirmed and not counted as findings.",
        "exec_risks": "{n} {issues} found: {high} high, {medium} medium, {low} low and {info} informational.",
        "exec_norisk": "No issue covered by the rules of this review was found among the {n} verified {names}.",
        "exec_top": "Priority {p}: {title} ({affected}). {fix}",
        "exec_coverage": "{failed} of {asked} public sources did not answer in full during the review; what they hold is not reflected here.",
        "reviewer": "The reviewer",
        "records_n": "{n} records",
        "record_1": "1 record",
        "exec_proof": "Every statement about the client's systems cites the records it rests on, sealed in a signed bundle that the client or their auditor can verify offline.",
    },
    "tr": {
        "doc_title": "Dış saldırı yüzeyi denetimi",
        "confidential": "Gizli",
        "prepared_for": "Hazırlanan kurum",
        "prepared_by": "Hazırlayan",
        "date": "Tarih",
        "reference": "Sözleşme referansı",
        "scope": "Kapsam",
        "self_title": "Dış saldırı yüzeyi öz değerlendirmesi",
        "contact": "İletişim",
        "toc": "İçindekiler",
        "s_auth": "Yetkilendirme",
        "s_exec": "Yönetici özeti",
        "s_risks": "Bulgular ve iyileştirme, öncelik sırasıyla",
        "s_inventory": "Varlık envanteri",
        "s_limits": "Neler test edilmedi",
        "s_method": "Yöntem",
        "s_glossary": "Sözlük",
        "s_evidence": "Kanıt eki",
        "auth_client": (
            "Bu inceleme, {organisation} kurumunun {name} ({role}) tarafından imzalanan, {start} ile {end} arasında "
            "geçerli yazılı yetkisiyle, yukarıdaki alan adları için ve şu amaçla yapılmıştır: {purpose}"
        ),
        "auth_self": (
            "Bu bir öz değerlendirmedir: incelemeyi yapan kişi, yukarıdaki alan adlarının sahibi olduğunu ya da "
            "bunları yönettiğini beyan etmiştir. Üçüncü bir taraf yetki vermemiştir; başkasının sistemlerinin denetimi değildir."
        ),
        "auth_recorded_signed": (
            "Yetki belgesi (SHA-256 özeti {sha}) ilk sorgudan önce taramanın zincirleme özetli denetim kaydına "
            "yazılmıştır; bu kayıt imzalı kanıt paketinin içindedir."
        ),
        "auth_recorded_late": (
            "Yetki belgesi (SHA-256 özeti {sha}) bu rapor hazırlanırken kaydedilmiştir; tarama kayıttan önce "
            "yapıldığı için imzalı paket bu belgeyi içermez."
        ),
        "auth_self_recorded": "Öz beyan, ilk sorgudan önce taramanın imzalı denetim kaydına yazılmıştır.",
        "auth_self_late": "Öz beyan, taramadan sonra, bu rapor hazırlanırken kaydedilmiştir.",
        "auth_passive": "İzin verilen faaliyet: yalnızca kamuya açık kayıtların pasif olarak toplanması.",
        "auth_active": (
            "İzin verilen faaliyet: kamuya açık kayıtların pasif toplanması ve, bu yetki kapsadığı için, sınırlı bir aktif "
            "doğrulama: sabit bir port listesinde TCP bağlantı denemeleri, TLS el sıkışmaları ve ana sayfa için tek bir HTTP "
            "isteği; yalnızca kurumun kendi adlarının çözümlendiği adreslere. Oturum açma denemesi, istismar, fuzzing ya da "
            "kaba kuvvet yapılmadı."
        ),
        "exec_scope_active": "{auditor}, {client} ({domains}) kurumunun internet ayak izini {date} tarihinde kamuya açık kayıtlarla ve aşağıda kayıtlı yetki kapsamında bu adların adreslerine yapılan sınırlı bağlantı denemeleriyle (TCP bağlantısı, TLS el sıkışması, tek HTTP isteği) inceledi: oturum açma denemesi ve istismar yok.",
        "exec_active": "İnceleme sırasında yapılan aktif denemeler: {addresses} adreste {checks} bağlantı denemesi; {open} port açık, {closed} kapalı, {filtered} yanıtsız; paylaşımlı platformlardaki ya da genel olmayan aralıklardaki {skipped} adres denenmedi.",
        "s_active": "Aktif doğrulama",
        "active_intro": "Bu sonuçlar, her kayıtta gösterilen zamanda bu aracın yaptığı denemelerdir; üçüncü taraf verisi değildir. 'Yanıtsız', zaman aşımı içinde yanıt gelmediği anlamına gelir: kurumun güvenlik duvarı ya da test yapanın kendi ağı olabilir.",
        "col_open": "Şu an açık",
        "col_closed": "Kapalı",
        "col_unanswered": "Yanıtsız",
        "active_skipped": "Denenmeyen adresler ve nedenleri:",
        "active_cap": "Bağlantı üst sınırı: {cap}. Üst sınır nedeniyle plan dışı kalan portlar: {not_planned}.",
        "col_basis": "Nasıl saptandı",
        "basis_checked": "Şimdi denendi: bu aracın {when} UTC tarihinde yaptığı bağlantı denemesi.",
        "basis_both": "Şimdi denendi ({when} UTC); daha önce üçüncü bir taraf da bildirmişti ({who}).",
        "basis_third": "Daha önce üçüncü bir taraf bildirdi ({who}); şimdi denenmedi.",
        "not_tested_intro_active": "Bu inceleme, yukarıda anlatılan yetkili aktif doğrulama dışında pasiftir. Şunları yapmadı:",
        "not_tested_active": [
            "bir hizmette oturum açmayı, parola tahmin etmeyi ya da anonim erişimi denemek (başlık okunur, yanıtlanmaz);",
            "istismar ya da zafiyet yükü göndermek, fuzzing yapmak, dizin ya da dosya taramak;",
            "kurumun adlarının çözümlendiği adresler dışında bir adresi, paylaşımlı bir platformu (CDN, barındırma platformu) ya da genel olmayan bir adresi denemek;",
            "UDP ya da sabit liste ve pasif kaynağın açık bildirdiği portlar dışında bir port taramak;",
            "ana sayfa için tek istek dışında web uygulamalarını, API'leri, girişleri ya da kimlik doğrulamayı test etmek;",
            "iç ağlara, uç noktalara, bulut hesaplarına ya da kaynak koda bakmak;",
            "herhangi bir kişiyi, e-posta adresini ya da kimlik bilgisini aramak ya da ihlal verisi kullanmak;",
            "oltalamaya dirençi, fiziksel güvenliği ya da personel farkındalığını test etmek.",
        ],
        "method_active": (
            "Pasif toplamadan sonra ve yalnızca yukarıda kayıtlı yetki kapsamında, araç kurumun adlarının çözümlendiği adreslere "
            "sınırlı sayıda bağlantı yaptı: port başına bir TCP bağlantı denemesi (varsa karşılama satırı okundu, hiçbir şey "
            "gönderilmedi), açık TLS portlarında bir TLS el sıkışması ve ana sayfa için bir HTTP isteği. Her sonuç bir kanıt "
            "kaydıdır; plan (hangi adresler ve portlar, hangileri neden atlandı) ilk bağlantıdan önce yazılan bir kayıttır."
        ),
        "exec_note": "Numaralı her ifade dayandığı kanıt kayıtlarını gösterir (ek).",
        "exec_ai": "* işaretli ifadeler bir dil modeliyle sadeleştirilmiş ve bağımsız bir doğrulayıcıyla kanıtlarına karşı denetlenmiştir; özgün metin audit.json dosyasındadır.",
        "col_priority": "Öncelik",
        "col_severity": "Önem",
        "col_finding": "Bulgu",
        "col_affected": "Etkilenen",
        "col_evidence_says": "Kanıtın gösterdiği (kuralın İngilizce metni)",
        "col_fix": "İyileştirme",
        "col_effort": "Efor (tahmin)",
        "col_mapping": "Bilgi amaçlı eşleme",
        "col_records": "Kanıt",
        "col_name": "Ad",
        "col_addresses": "Adresler",
        "col_providers": "Sağlayıcılar",
        "col_networks": "Ağlar",
        "col_source": "Kaynak",
        "col_state": "Sonuç",
        "col_id": "Kayıt",
        "col_request": "İstek",
        "col_collected": "Toplanma (UTC)",
        "no_risks": "Bu incelemenin kurallarının kapsadığı bir sorun bulunmadı. Bu, hiç sorun olmadığının kanıtı değildir: Neler test edilmedi bölümüne bakınız.",
        "mapping_note": (
            "Çerçeve referansları bilgi amaçlı bir eşlemedir; sertifikasyon, denetim görüşü ya da hukuki sonuç değildir. "
            "(doğrulanmadı) olarak işaretli referanslar, tüm ISO/IEC 27001 referansları dahil, yetkili ve herkese açık "
            "bir kaynaktan okunamamıştır ve çerçevenin kendisiyle karşılaştırılmalıdır."
        ),
        "rule_wording": "",
        "effort_note": "Efor, düzeltme işinin denetçi tarafından yapılan tahminidir; bir ölçüm değildir.",
        "inventory_note": (
            "Kamusal DNS'in çözümlediği ya da son 90 gün içinde tarihli bir sertifikanın adını verdiği adlar (doğrulanmış). "
            "Yalnızca üçüncü taraf listelerin andığı adlar aşağıda sayılmış, burada listelenmemiştir."
        ),
        "inventory_more": "{n} doğrulanmış ad daha teknik ektedir.",
        "claimed_line": "Doğrulanmamış adlar (yalnızca listeler anıyor): {claimed}. Kullanımdan kalkmış adlar (DNS yok diyor): {stale}. Yalnızca joker kayıtla örtülen: {wildcard}.",
        "not_tested_intro": "Bu inceleme pasiftir. Şunlar yapılmamıştır:",
        "not_tested": [
            "port ya da servis taraması; adlarının olağan DNS sorguları dışında kurumun sistemlerine herhangi bir istek;",
            "web uygulaması, API, oturum açma ya da kimlik doğrulama testi;",
            "herhangi bir zafiyeti istismar etme, doğrulama ya da yeniden üretme girişimi (ele geçirme adayı yalnızca raporlanır, asla ele geçirilmez);",
            "iç ağ, uç nokta, bulut hesabı ya da kaynak kodu incelemesi;",
            "herhangi bir kişinin, e-posta adresinin ya da kimlik bilgisinin sorgulanması ya da sızıntı verisi kullanımı;",
            "oltalama direnci, fiziksel güvenlik ya da personel farkındalığı testi.",
        ],
        "coverage_intro": "İnceleme sırasında sorgulanan kamusal kaynaklar ve verdikleri yanıt:",
        "coverage_off": "Kullanılmayan kaynaklar: {list}.",
        "coverage_deadline": "İnceleme zaman sınırına ulaştı; sürmekte olan sorgular durduruldu ve eksiktir.",
        "coverage_cap": "İnceleme {cap} kayıtlı ad sınırına ulaştı; kaynakların verdiği {dropped} ad kaydedilmedi.",
        "coverage_none_failed": "Sorgulanan her kaynak yanıt verdi.",
        "coverage_limit": (
            "Hiçbir sertifika kaydının, arşivin ya da toplayıcının görmediği adlar bu raporda yer alamaz. Bir bulgu, "
            "kamusal kayıtların toplandıkları andaki durumunu yansıtır; kurumun sistemleri o zamandan beri değişmiş olabilir."
        ),
        "src_ok": "yanıt verdi",
        "src_failed": "başarısız",
        "src_down": "art arda hatalardan sonra durduruldu",
        "src_idle": "gerekmedi",
        "method_paras": [
            "Scrutator, kapsamdaki alan adları hakkında kamusal kaynakların bildiklerini sordu: sertifika şeffaflığı "
            "kayıtları, DNS, kayıt verileri (RDAP), yönlendirme verileri, web arşivleri, pasif DNS ve ad toplayıcıları. "
            "Olağan DNS sorguları dışında kurumun sistemleriyle temas kurmadı.",
            "Her yanıt, SHA-256 özetiyle adreslenen bir kanıt kaydı olarak değiştirilmeden saklandı. Bulgular ve riskler "
            "bu kayıtlardan deterministik kurallarla türetilir; bir risk dayandığı kayıtlar olmadan var olamaz. Bir ad, "
            "DNS onu çözümlediğinde ya da yakın tarihli bir sertifika onu andığında doğrulanmış; yalnızca bir liste "
            "andığında ise yalnızca iddia edilmiş sayılır.",
            "Kayıtlar, türetilen rapor ve her sorgunun zincirleme özetli kaydı bir kanıt paketinde mühürlendi ve Ed25519 "
            "anahtarıyla imzalandı. Paket, ekteki komutlarla herkes tarafından çevrimdışı denetlenebilir.",
        ],
        "method_facts": "Araç {tool}; risk kuralları {ruleset}; bilgi paketleri {packs}; tarama başlangıcı {started}; rapor tarihi {generated}.",
        "method_sources": "Kullanılan kaynaklar: {list}.",
        "glossary": [
            ("DNS", "İnternetin rehberi: www.example.com gibi adları adreslere çevirir."),
            ("CNAME (takma ad)", "Bir adın başka bir ad olduğunu söyleyen DNS kaydı. Hedef ortadan kalkarsa, onu sahiplenen takma adı yönetebilir."),
            ("Alt alan adı ele geçirme", "Takma adı artık var olmayan bir bulut kaynağını gösteren bir adın denetimini ele geçirmek."),
            ("SPF", "Bir alan adı adına hangi sunucuların e-posta gönderebileceğini listeleyen DNS kaydı."),
            ("DMARC", "Alıcılara SPF/DKIM denetimini geçemeyen postayla ne yapacaklarını ve nereye raporlayacaklarını söyleyen DNS kaydı."),
            ("CAA", "Bir alan adı için sertifika verebilecek sertifika otoritelerini belirten DNS kaydı."),
            ("Sertifika şeffaflığı", "Verilen her TLS sertifikasının herkese açık kayıtları; bir şirketin kullandığı adları ortaya çıkarır."),
            ("RDAP", "Alan adları ve IP ağları için güncel kayıt veritabanı (WHOIS'in halefi)."),
            ("Doğrulanmış / iddia edilen", "Doğrulanmış: DNS ya da yakın tarihli bir sertifika adı destekliyor. İddia edilen: yalnızca bir liste anıyor."),
            ("Kanıt kaydı", "Bir kaynağın değiştirilmemiş yanıtı; SHA-256 özetiyle tanımlanır."),
            ("Kanıt paketi", "Rapor, tüm kanıt kayıtları ve sorgu kaydını içeren imzalı dosya; her değişiklik fark edilir."),
            ("SHA-256", "Bir dosyanın parmak izi: tek bir biti değiştirmek onu tamamen değiştirir."),
            ("Ed25519", "Paketi mühürlemek için kullanılan imza yöntemi; anahtar parmak izi imzalayanı tanımlar."),
        ],
        "evidence_intro": (
            "Bu rapor aşağıdaki imzalı kanıt paketinden üretilmiştir. Paketi bu raporla birlikte kuruma verin; raporun "
            "dayandığı her kayıt paketin içindedir."
        ),
        "bundle_file": "Paket dosyası",
        "bundle_sha": "Paketin SHA-256 özeti",
        "bundle_key": "İmza anahtarı parmak izi",
        "bundle_records": "Paketteki kanıt kaydı sayısı",
        "verify_title": "Kurum ya da denetçisi bu raporu çevrimdışı, üç komutla nasıl doğrular",
        "verify_steps": [
            "Paketin bu raporda adı geçen paket olduğunu denetleyin (Windows: certutil -hashfile proof.scrutator SHA256):",
            "İmzayı, sorgu kaydının özet zincirini, her kaydı ve bulguların kayıtlardan çıktığını denetleyin:",
            "Bu rapordaki her sayının, bulgunun ve cümlenin paketten çıkan sonuç olduğunu denetleyin:",
        ],
        "verify_install": "Scrutator açık kaynaklıdır (Apache-2.0); wheel dosyasından ya da projeden pip ile kurulur. Üç komutun hiçbiri ağ kullanmaz.",
        "cited_records": "Bu raporun dayandığı kayıtlar",
        "cited_more": "Dayanılan {n} kayıt daha teknik ekte ve pakette listelenmiştir.",
        "annex": "Etkileşimli teknik ek (technical-annex.html), her adı, bulguyu ve kaydı kanıtıyla birlikte gösterir.",
        "page": "sayfa",
        "sev": {"high": "Yüksek", "medium": "Orta", "low": "Düşük", "info": "Bilgi"},
        "effort": {"low": "Düşük", "medium": "Orta", "high": "Yüksek"},
        "exec_scope": "{auditor}, {client} kurumunun internete açık kamusal ayak izini ({domains}) {date} tarihinde yalnızca kamusal kayıtlarla inceledi: tarama, oturum açma girişimi ya da istismar yapılmadı.",
        "exec_verified": "İnceleme, bu alan adları altında kamusal DNS'te çözümlenen ya da yakın tarihli bir sertifikada geçen {n} internete açık adı doğruladı.",
        "exec_claimed": "Üçüncü taraf listeler, kamusal DNS'in doğrulamadığı {n} ad daha anıyor; bunlar doğrulanmamış olarak tutuldu ve bulgu sayılmadı.",
        "exec_risks": "{n} sorun bulundu: {high} yüksek, {medium} orta, {low} düşük ve {info} bilgi düzeyinde.",
        "exec_norisk": "Doğrulanmış {n} ad arasında bu incelemenin kurallarının kapsadığı bir sorun bulunmadı.",
        "exec_top": "Öncelik {p}: {title} ({affected}). {fix}",
        "exec_coverage": "Sorgulanan {asked} kamusal kaynaktan {failed} tanesi inceleme sırasında tam yanıt vermedi; tuttukları bilgi burada yansıtılmamıştır.",
        "reviewer": "İnceleme ekibi",
        "records_n": "{n} kayıt",
        "record_1": "1 kayıt",
        "exec_proof": "Kurumun sistemleri hakkındaki her ifade dayandığı kayıtları gösterir; kayıtlar, kurumun ya da denetçisinin çevrimdışı doğrulayabileceği imzalı bir pakette mühürlenmiştir.",
    },
}

# Turkish titles and remediation advice of the risk rules (risk/catalog.py holds the English ones).
RULES_TR = {
    "dangling-cname-claimable": ("Artık var olmayan, sahiplenilebilir bir servise işaret eden CNAME",
                                 "CNAME kaydını silin ya da servisteki kaynağı yeniden oluşturarak adı yeniden sahiplenin. Bu ada güvenen diğer şeyleri (çerezler, OAuth yönlendirmeleri, SPF) denetleyin."),
    "dangling-cname-known-service": ("Ele geçirmelerle bilinen bir serviste artık var olmayan bir ana makineye işaret eden CNAME",
                                     "CNAME kaydını silin ya da servisteki kaynağı yeniden oluşturun. Yetkili bir değerlendirmede, sahiplenilebilirliği aktif bir kontrolle doğrulayın."),
    "dangling-cname": ("Var olmayan bir ana makineye işaret eden CNAME",
                       "Hedef artık kullanılmıyorsa CNAME kaydını silin ya da hedefi geri getirin."),
    "spf-allows-all": ("SPF kaydı her göndericiye izin veriyor",
                       "Kaydı -all ile (geçiş sırasında ~all ile) bitirin ve yalnızca kullandığınız göndericileri listeleyin."),
    "spf-neutral-all": ("SPF kaydı listelenmeyen göndericiler hakkında tavır almıyor",
                        "Kaydı -all ile (geçiş sırasında ~all ile) bitirin."),
    "spf-softfail-all": ("SPF kaydı listelenmeyen göndericileri yumuşak başarısız sayıyor",
                         "Gönderici listesi tamamlandığında -all'a geçin ve bir DMARC politikası yayımlayın."),
    "spf-no-all": ("SPF kaydının varsayılan sonucu yok",
                   "Kaydı -all ile (geçiş sırasında ~all ile) bitirin."),
    "spf-multiple-records": ("Birden fazla SPF kaydı",
                             "Kayıtları tek bir kayıtta birleştirin."),
    "spf-too-many-lookups": ("SPF kaydı ondan fazla DNS sorgusu gerektiriyor",
                             "Kullanılmayan include'ları kaldırın, include'ları ip4/ip6 aralıklarıyla değiştirin ya da kaydı düzleştirin."),
    "dmarc-missing": ("DMARC kaydı olmayan e-posta alan adı",
                      "_dmarc.<alan adı> altında p=none ve rapor adresleriyle başlayan bir DMARC kaydı yayımlayın, ardından quarantine ve reject'e geçin."),
    "dmarc-monitoring-only": ("DMARC politikası yalnızca izleme amaçlı",
                              "Raporlar yalnızca meşru göndericileri gösterdiğinde p=quarantine'e, ardından p=reject'e geçin."),
    "caa-missing": ("Alan adı kökünde CAA kaydı yok",
                    "Kullandığınız sertifika otoritelerini belirten CAA kayıtları yayımlayın."),
    "domain-expired": ("Alan adı kaydının süresi dolmuş",
                       "Alan adını hemen yenileyin ya da süresinin dolmasının amaçlandığını doğrulayıp ona bağlı olanları kaldırın."),
    "domain-expiring": ("Alan adı kaydının süresi 30 gün içinde doluyor",
                        "Alan adını yenileyin ve otomatik yenilemeyi açın."),
    "forgotten-name": ("Unutulmuş bir test ya da hazırlık sistemine benzeyen ad",
                       "Sistemin hâlâ gerekli ve bakımlı olduğunu doğrulayın; değilse DNS kaydını ve sistemi kaldırın."),
    "exposed-risky-service": ("İnternete açık bir veritabanı, uzaktan yönetim ya da dosya paylaşım portu",
                              "Portun şu anda açık olup olmadığını sahibiyle doğrulayın; açıksa güvenlik duvarında kapatın ya da bilinen adreslerle sınırlayın ve kimlik doğrulama zorunlu kılın."),
    "concentration-dns": ("Tüm adlar tek bir DNS sağlayıcısına bağlı",
                          "Farklı bir ağda ikincil bir DNS sağlayıcısı düşünün ve hesabı güçlü kimlik doğrulamayla koruyun."),
    "concentration-edge": ("Birçok ad tek bir CDN ya da barındırma sağlayıcısına bağlı",
                           "Sağlayıcının kesinti ve olay süreçlerini bilin; kritik adlar için bir alternatif gerekip gerekmediğini değerlendirin."),
    "ghost-hostname": ("Bir sertifika ya da arşiv, DNS'in tanımadığı bir ana makineyi anıyor",
                       "Adın hâlâ bir yerde (sertifika, bağlantı, yapılandırma) anılıp anılmadığını ve DNS'in ya da sertifikanın temizlenmesi gerekip gerekmediğini denetleyin."),
    "numbering-gap": ("Numaralı bir ad dizisinde boşluk",
                      "Eksik numaranın kullanımdan kalkmış ya da listelenmemiş bir sistem olup olmadığını denetleyin."),
    "source-disagreement": ("Kayıt verisi ile DNS ad sunucuları konusunda uyuşmuyor",
                            "Kayıt kuruluşundaki yetkilendirmeyi ve bölgenin NS kayıtlarını aynı yapın."),
    "brand-handle-unregistered": ("Kurumun kullandığı bir platformda marka kullanıcı adı kayıtlı değil",
                                  "Kullanıcı adını kaydedin (ya da geri alın) ve sitedeki bağlantıyı düzeltin ya da kaldırın. Harekete geçmeden önce platformun hesap sayfasını oturum açıkken denetleyin."),
    "brand-lookalike-handle": ("Kurumun kullandığı bir platformda markaya benzeyen bir hesap var",
                               "Hesaba elle bakın. Sizin değilse ve sizi taklit ediyorsa platformun taklit bildirimi sürecini kullanın; en yakın benzerleri kendiniz kaydetmeyi düşünün."),
}

# The auditor's estimate of the work a fix takes (low: one DNS or registrar change; medium: a change that needs a
# rollout or coordination; high: a project). An estimate, labelled as such wherever it is shown.
EFFORT = {
    "dangling-cname-claimable": "low", "dangling-cname-known-service": "low", "dangling-cname": "low",
    "spf-allows-all": "low", "spf-neutral-all": "low", "spf-softfail-all": "medium", "spf-no-all": "low",
    "spf-multiple-records": "low", "spf-too-many-lookups": "medium", "dmarc-missing": "medium",
    "dmarc-monitoring-only": "medium", "caa-missing": "low", "domain-expired": "low", "domain-expiring": "low",
    "forgotten-name": "medium", "exposed-risky-service": "medium", "concentration-dns": "high",
    "concentration-edge": "high", "ghost-hostname": "low", "numbering-gap": "low", "source-disagreement": "low",
    "brand-handle-unregistered": "low", "brand-lookalike-handle": "medium",
    "stale-exposure-data": "low", "tls-cert-expired": "low", "tls-cert-expiring": "low", "tls-hostname-mismatch": "low",
    "tls-legacy-protocol": "medium", "http-no-https-redirect": "low", "http-missing-hsts": "low",
    "http-missing-security-headers": "medium", "server-banner-discloses-version": "medium",
}
EFFORT_RANK = {"low": 0, "medium": 1, "high": 2}


def plural(lang: str, n: int) -> dict:
    """The words of a sentence that change with a count (English only; Turkish nouns stay singular after a number)."""
    one = n == 1
    if lang != "en":
        return {"names": "ad", "issues": "sorun", "records": "kayıt", "resolve": "", "appear": "", "they": ""}
    return {"names": "name" if one else "names", "issues": "issue was" if one else "issues were", "records": "record" if one else "records",
            "resolve": "resolves" if one else "resolve", "appear": "appears" if one else "appear", "they": "it is" if one else "they are"}
