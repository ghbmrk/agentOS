#!/usr/bin/env python3
"""Frozen synthetic corpus for the S9 embedder comparison. Deterministic (seed 9).
No real data: every name, number and address is invented. Writes corpus.json.
Each query names its correct source ref; categories are reported separately."""
import json, random

# (topic id, doc, plain query, paraphrase query (no content word shared with the doc), typo query, Spanish query)
T = [
 ("boiler", "The boiler service is booked for Tuesday and the engineer needs access to the cellar.", "boiler service date", "when is the heating appliance maintenance visit", "bolier servise date", "cuándo es la revisión de la caldera"),
 ("passport", "Your passport renewal application was received and the new document will ship in ten working days.", "passport renewal status", "travel document replacement progress", "pasport renewel status", "estado de la renovación del pasaporte"),
 ("dentist", "Reminder: dental check-up with Dr Okafor on the 14th at 09:30, please arrive early.", "dentist appointment time", "when do I see the tooth doctor", "dentits apointment time", "hora de la cita con el dentista"),
 ("invoice", "Invoice 4471 from Northwind Supplies for 1,280 euros is due at the end of the month.", "Northwind invoice amount", "how much do I owe the stationery vendor", "Northwnd invoce amount", "importe de la factura de Northwind"),
 ("flight", "Your flight to Lisbon departs at 06:55 from terminal 2, check-in closes 45 minutes before.", "Lisbon flight departure", "what time does my plane to Portugal leave", "Lisbn flihgt departure", "salida del vuelo a Lisboa"),
 ("lease", "The lease for the Hartley Street flat ends on 31 March and renewal requires two months notice.", "Hartley Street lease end", "when does my rental contract for the apartment expire", "Hartley Steet leese end", "fin del contrato de alquiler del piso"),
 ("wifi", "The new router password is on the sticker under the unit; the guest network is separate.", "router password location", "where do I find the internet box login key", "ruter pasword location", "contraseña del router wifi"),
 ("insurance", "Car insurance renews on 2 June; the premium rose by eight percent because of the claim.", "car insurance renewal premium", "why did my vehicle cover cost more this year", "car insurence renewel premuim", "renovación del seguro del coche"),
 ("recipe", "Grandma's lentil soup needs two onions, a carrot, red lentils and a spoon of cumin.", "lentil soup recipe", "how do I cook the pulse stew from my relative", "lentl soop recipie", "receta de la sopa de lentejas"),
 ("school", "Parents evening for year 5 is on Thursday at 18:00 in the main hall.", "parents evening year 5", "when can I meet my child's teacher", "perents evning year 5", "reunión de padres de quinto"),
 ("tax", "The accountant needs your signed return by 20 January so it can be filed before the deadline.", "tax return deadline", "when must the revenue paperwork be handed over", "tax retrun deadlin", "plazo de la declaración de impuestos"),
 ("plumber", "The plumber found a slow leak under the kitchen sink and will return with a new valve.", "plumber kitchen sink leak", "who is fixing the dripping pipe in the cooking area", "plummer kichen sink leek", "fontanero fuga bajo el fregadero"),
 ("library", "Library notice: 'The Long Road' is overdue by six days, fines accrue daily.", "library book overdue", "late fee for the borrowed novel", "libary bok overdue", "libro de la biblioteca retrasado"),
 ("vet", "Biscuit's vaccination booster is due next week; the vet has Wednesday slots free.", "Biscuit vaccination vet", "when does the dog need its jab", "Biscut vacination vett", "vacuna de refuerzo del perro"),
 ("gym", "Your gym membership will be frozen from 1 July to 31 August at no charge.", "gym membership freeze", "pausing my fitness club subscription over summer", "gim membrship freeze", "congelar la cuota del gimnasio"),
 ("bank", "Your card ending 0042 was blocked after an unusual payment; call the number on the back.", "bank card blocked", "why can't I pay with my debit plastic", "bank crd blokced", "tarjeta bancaria bloqueada"),
 ("conference", "Registration for the Rotterdam robotics conference closes on 5 September; early rate is 340 euros.", "Rotterdam robotics conference registration", "sign up deadline for the machines symposium in the Netherlands", "Roterdam robotcs confrence registration", "inscripción al congreso de robótica de Róterdam"),
 ("parcel", "Your parcel is out for delivery; the courier will leave it with the neighbour at number 12 if you are out.", "parcel delivery neighbour", "where will the package be left if nobody is home", "parcle delivry neigbour", "paquete entrega vecino"),
 ("wedding", "Priya and Tom's wedding is on 12 October at the old mill; the dress code is garden formal.", "Priya Tom wedding dress code", "what should I wear to the marriage ceremony", "Priya Tom weding dres code", "código de vestimenta de la boda"),
 ("mortgage", "The mortgage fixed rate ends in November; the broker suggests comparing offers in September.", "mortgage fixed rate ends", "my home loan interest deal is expiring soon", "morgage fixd rate ends", "fin del tipo fijo de la hipoteca"),
 ("garden", "Plant the tulip bulbs before the first frost, about ten centimetres deep.", "tulip bulbs planting depth", "how far down should the spring flowers go in the soil", "tulpi bulbs planing depth", "profundidad para plantar tulipanes"),
 ("laptop", "The laptop warranty covers the battery for 24 months; keep the receipt for the claim.", "laptop battery warranty", "is the notebook power cell guaranteed", "laptpo batery warrenty", "garantía de la batería del portátil"),
 ("visa", "Your visa appointment is at the consulate on 3 November; bring two photos and the signed form.", "visa appointment consulate", "what to bring to the embassy interview", "vissa apointment consulat", "cita de visado en el consulado"),
 ("book", "Book club picks 'The Salt Garden' for March; we meet at Dana's on the first Friday.", "book club March pick", "which novel are we reading together next spring", "bok clb Marsh pick", "libro del club de lectura de marzo"),
]
rnd = random.Random(9)
docs, queries = [], []
def doc(ref, acct, text, kind="mail"): docs.append({"ref": ref, "account": acct, "kind": kind, "text": text})
def q(cat, text, correct): queries.append({"id": f"{cat}-{len(queries)}", "cat": cat, "text": text, "correct": correct})
for t, d, plain, para, typo, es in T:
    doc(t, "a", d)
    q("plain", plain, t); q("paraphrase", para, t); q("misspelled", typo, t); q("other-language", es, t)
# quoted duplicate threads: replies quote the original in full; the original is the correct source
for t, d, plain, *_ in T[:8]:
    for i in range(2): doc(f"{t}-re{i}", "a", f"Thanks, noted. {rnd.choice(['Will do.','Sounds good.','See you then.'])}\n> " + d.replace(". ", ".\n> "))
    q("quoted-dup", plain, t)
# old/new versions: same document, one value changed; the newer is correct
for i, (t, d, plain, *_) in enumerate(T[8:16]):
    doc(f"{t}-old", "a", d.replace("next week", "last year").replace("the 14th", "the 3rd").replace("Tuesday", "Monday") + " (superseded)")
    docs[[x["ref"] for x in docs].index(t)]["text"] += " Updated version."
    q("versions", "latest " + plain, t)
# two accounts: same topic, different detail, query names the account's own entity
for t, d, plain, *_ in T[16:24]:
    doc(t + "-b", "b", d.replace("your", "the office").replace("Your", "The office") + " Reference: Meridian Ltd.")
    q("two-accounts", plain + " personal", t)
    q("two-accounts", plain + " Meridian", t + "-b")
# distractors: recombined sentences from the same vocabulary, so BM25 has noise to rank
V = sorted({w.strip(".,:'") .lower() for _, d, *_ in T for w in d.split() if len(w) > 3})
for i in range(260):
    doc(f"noise{i}", rnd.choice("ab"), " ".join(rnd.choice(V) for _ in range(rnd.randint(14, 26))).capitalize() + ".")
rnd.shuffle(docs)
json.dump({"docs": docs, "queries": queries}, open("corpus.json", "w"), indent=0, ensure_ascii=False)
from collections import Counter
print(len(docs), "docs", len(queries), "queries", dict(Counter(x["cat"] for x in queries)))
