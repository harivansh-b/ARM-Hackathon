"""Generate 90 synthetic SMS (68 legitimate, 22 scam; 30 each of en / hinglish / hi) in Person C's JSONL schema.
Each template is its own campaign, so campaign-based splits stay leak-free. Run: python3 eval/make_extra_samples.py"""
import json, random, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "person-c"))
from guardian_models.dataset import load_jsonl  # noqa: E402

rnd = random.Random(7)
BANKS = ["HDFC Bank", "SBI", "ICICI Bank", "Axis Bank", "Kotak Bank", "Bank of Baroda"]
MERCH = ["Amazon", "Flipkart", "Swiggy", "Zomato", "Myntra", "BigBasket"]
PERS = ["Rahul K", "Priya S", "Anil M", "Sneha R"]
AMT = ["450.00", "799", "1,250.00", "2,300.00", "5,000.00", "15,000.00"]
BIG = ["5 lakh", "10 lakh", "25 lakh"]
TLD = ["top", "xyz", "cfd", "icu"]


def fill(t):
    bank = rnd.choice(BANKS)
    return t.format(bank=bank, bank_l=bank.split()[0].lower(), merchant=rnd.choice(MERCH), person=rnd.choice(PERS), amt=rnd.choice(AMT),
                    big=rnd.choice(BIG), bal=rnd.choice(["18,420.10", "41,230.55", "7,905.00"]), ac=rnd.randint(1000, 9999),
                    otp=rnd.randint(100000, 999999), ref=rnd.randint(610000000, 699999999), date=rnd.choice(["12-Nov-26", "13-Nov-26", "14-Nov-26"]),
                    vpa=rnd.choice(["shop@okicici", "store@ybl", "pay@paytm"]), tld=rnd.choice(TLD), brand=rnd.choice(["india-post", "dhl", "bluedart"]),
                    code=rnd.choice(["3xYzQ", "4kPmW", "2aBcD"]), num=f"98{rnd.randint(10000000, 99999999)}")


T = {  # (category, label, template)
"en": [("otp",0,"{otp} is your one-time password for {bank} NetBanking. Never share this OTP with anyone."),
("otp",0,"Use OTP {otp} to authorise your payment of Rs {amt} at {merchant}. Valid for 5 minutes. Do not share."),
("otp",0,"Your {merchant} verification code is {otp}. It expires in 10 minutes. Do not share this code."),
("otp",0,"OTP for {bank} card transaction of INR {amt} is {otp}. If you did not initiate this, call the number on the back of your card."),
("bank_debit",0,"Rs {amt} debited from A/c XX{ac} on {date} to VPA {vpa}. UPI Ref {ref}. If not you, contact your bank branch. -{bank}"),
("bank_debit",0,"INR {amt} spent on {bank} Card XX{ac} at {merchant} on {date}. Not you? Block your card in the {bank} app."),
("bank_debit",0,"Alert: Rs {amt} withdrawn at ATM on {date} from A/c XX{ac}. Avl Bal Rs {bal}. -{bank}"),
("bank_credit",0,"Rs {amt} credited to your A/c XX{ac} on {date}. Avl Bal Rs {bal}. -{bank}"),
("bank_credit",0,"Salary of Rs {amt} credited to A/c XX{ac} on {date}. Thank you for banking with {bank}."),
("bank_credit",0,"Your FD has matured and Rs {bal} is credited to A/c XX{ac}. -{bank}"),
("upi",0,"You have received Rs {amt} from {person} via UPI. Ref {ref}. Check balance in your bank app."),
("upi",0,"Rs {amt} paid to {merchant} via UPI. Txn ID {ref}. Check status in the app."),
("upi",0,"UPI mandate of Rs {amt} for {merchant} is scheduled for {date}. Manage it in your bank app."),
("delivery",0,"Your {merchant} order is out for delivery today. Track it in the {merchant} app."),
("delivery",0,"{merchant}: package AWB {ref} will arrive today between 2-6 PM. Keep Rs {amt} ready for COD."),
("delivery",0,"Your parcel was delivered on {date}. Thank you for shopping with {merchant}."),
("kyc_legit",0,"Dear customer, your KYC has been successfully updated. Thank you for banking with {bank}."),
("kyc_legit",0,"Your re-KYC request is received. If not already done, visit your home branch with ID proof. -{bank}"),
("tax",0,"Income Tax Dept: your ITR for AY 2025-26 has been processed. Refund, if any, will be credited to your registered account."),
("utility",0,"Your electricity bill of Rs {amt} for Oct-26 is generated. Due date {date}. Pay through the official app."),
("utility",0,"Your broadband bill of Rs {amt} is due on {date}. Pay in the provider's app or website."),
("travel",0,"PNR {ref}: your train departs on {date} at 06:40. Coach S4 Seat 32. Happy journey! -IRCTC"),
("recharge",0,"Your recharge of Rs {amt} was successful. Validity 28 days. Thank you."),
("kyc_scam",1,"Dear customer your {bank} account will be blocked today. Update KYC immediately at http://{bank_l}-kyc-verify.{tld}/login"),
("prize",1,"Congratulations! You won Rs {big} in the lucky draw. Send your bank details and OTP to claim your prize now."),
("electricity",1,"Your electricity will be disconnected tonight 9:30pm due to unpaid bill. Pay now: http://bit.ly/{code} or call {num} immediately."),
("courier",1,"Your parcel is held at customs. Pay Rs {amt} clearance fee at http://{brand}-track.{tld}/pay to release it."),
("upi_refund",1,"Your UPI refund of Rs {amt} is pending. Enter your UPI PIN at http://refund-{bank_l}.{tld} to receive the money."),
("loan",1,"Pre-approved loan of Rs {big} in 5 minutes. No documents. Apply at http://{brand}-loan.{tld} and pay the processing fee."),
("sim_scam",1,"Your SIM will be deactivated in 2 hours due to incomplete KYC. Call {num} now to avoid disconnection.")],
"hinglish": [("otp",0,"Aapka {bank} OTP {otp} hai. Ise kisi ke saath share na karein. 10 minute tak valid."),
("otp",0,"{otp} aapka {merchant} verification code hai. Kisi ko na batayein."),
("otp",0,"Rs {amt} ke payment ke liye OTP {otp} use karein. Ise share na karein. -{bank}"),
("otp",0,"{bank} card transaction ka OTP {otp} hai. Aapne yeh nahi kiya to bank ke official number par sampark karein."),
("bank_debit",0,"A/c XX{ac} se Rs {amt} debit hue {date} ko. UPI Ref {ref}. Aap nahi the to apni bank branch se sampark karein. -{bank}"),
("bank_debit",0,"Aapke {bank} card XX{ac} se {merchant} par Rs {amt} kharch hue. Yeh aap nahi the to app mein card block karein."),
("bank_debit",0,"ATM se Rs {amt} nikale gaye {date} ko. Balance Rs {bal}. -{bank}"),
("bank_credit",0,"Aapke account XX{ac} mein Rs {amt} credit hue {date} ko. Balance Rs {bal}. -{bank}"),
("bank_credit",0,"Aapki salary Rs {amt} account XX{ac} mein aa gayi hai. {bank} ke saath banking ke liye dhanyavaad."),
("bank_credit",0,"Aapki FD mature ho gayi aur Rs {bal} account XX{ac} mein credit hue. -{bank}"),
("upi",0,"Aapko {person} se UPI se Rs {amt} mile hain. Ref {ref}. Balance bank app mein dekhein."),
("upi",0,"{merchant} ko UPI se Rs {amt} ka payment hua. Txn ID {ref}."),
("upi",0,"{merchant} ke liye Rs {amt} ka UPI mandate {date} ko hoga. Bank app mein manage karein."),
("delivery",0,"Aapka {merchant} order aaj deliver hoga. Track karne ke liye {merchant} app kholen."),
("delivery",0,"{merchant}: parcel AWB {ref} aaj 2-6 baje tak pahunchega. COD ke liye Rs {amt} taiyar rakhein."),
("delivery",0,"Aapka parcel {date} ko deliver ho gaya. {merchant} se kharidari ke liye dhanyavaad."),
("kyc_legit",0,"Priya graahak, aapka KYC safaltapoorvak update ho gaya hai. {bank} ke saath banking ke liye dhanyavaad."),
("kyc_legit",0,"Aapki re-KYC request mil gayi hai. Agar baaki hai to ID proof ke saath apni home branch jaayein. -{bank}"),
("tax",0,"Income Tax Dept: aapka ITR AY 2025-26 process ho gaya hai. Refund agar hai to registered account mein aayega."),
("utility",0,"Aapka bijli bill Rs {amt} generate ho gaya hai. Last date {date}. Official app se pay karein."),
("utility",0,"Aapka broadband bill Rs {amt} {date} tak due hai. Provider ke app ya website par pay karein."),
("travel",0,"PNR {ref}: aapki train {date} ko 06:40 baje chalegi. Coach S4 Seat 32. Shubh yatra! -IRCTC"),
("recharge",0,"Aapka Rs {amt} ka recharge safal raha. Validity 28 din. Dhanyavaad."),
("kyc_scam",1,"Aapka {bank} account aaj band ho jayega. Turant KYC update karein http://{bank_l}-kyc-verify.{tld}/login"),
("prize",1,"Badhai ho! Aapne Rs {big} ka inaam jeeta hai. Claim ke liye apna bank account number aur OTP abhi bhejein."),
("electricity",1,"Aapki bijli aaj raat 9:30 baje bill na bharne se kat jayegi. Abhi pay karein: http://bit.ly/{code} ya {num} par turant call karein."),
("courier",1,"Aapka parcel customs mein ruka hai. Release ke liye Rs {amt} fee yahan bharein http://{brand}-track.{tld}/pay"),
("upi_refund",1,"Aapka UPI refund Rs {amt} pending hai. Paisa paane ke liye apna UPI PIN yahan daalein http://refund-{bank_l}.{tld}"),
("loan",1,"Rs {big} ka loan 5 minute mein pre-approved! Koi document nahi. Apply karein http://{brand}-loan.{tld} aur processing fee bharein."),
("sim_scam",1,"Aapka SIM 2 ghante mein band ho jayega kyunki KYC adhura hai. Abhi {num} par call karein.")],
"hi": [("otp",0,"आपका {bank} OTP {otp} है। इसे किसी के साथ साझा न करें। 10 मिनट तक मान्य।"),
("otp",0,"{otp} आपका {merchant} सत्यापन कोड है। इसे किसी को न बताएं।"),
("otp",0,"Rs {amt} के भुगतान के लिए OTP {otp} का उपयोग करें। इसे साझा न करें। -{bank}"),
("otp",0,"{bank} कार्ड लेनदेन का OTP {otp} है। यदि यह आपने नहीं किया तो बैंक के आधिकारिक नंबर पर संपर्क करें।"),
("bank_debit",0,"खाता XX{ac} से Rs {amt} डेबिट हुए {date} को। UPI संदर्भ {ref}। आप नहीं थे तो अपनी बैंक शाखा से संपर्क करें। -{bank}"),
("bank_debit",0,"आपके {bank} कार्ड XX{ac} से {merchant} पर Rs {amt} खर्च हुए। यह आप नहीं थे तो ऐप में कार्ड ब्लॉक करें।"),
("bank_debit",0,"ATM से Rs {amt} निकाले गए {date} को। शेष राशि Rs {bal}। -{bank}"),
("bank_credit",0,"आपके खाते XX{ac} में Rs {amt} जमा हुए {date} को। शेष राशि Rs {bal}। -{bank}"),
("bank_credit",0,"आपका वेतन Rs {amt} खाते XX{ac} में जमा हो गया है। {bank} के साथ बैंकिंग के लिए धन्यवाद।"),
("bank_credit",0,"आपकी FD परिपक्व हो गई और Rs {bal} खाते XX{ac} में जमा हुए। -{bank}"),
("upi",0,"आपको {person} से UPI द्वारा Rs {amt} प्राप्त हुए। संदर्भ {ref}। शेष राशि बैंक ऐप में देखें।"),
("upi",0,"{merchant} को UPI से Rs {amt} का भुगतान हुआ। लेनदेन आईडी {ref}।"),
("upi",0,"{merchant} के लिए Rs {amt} का UPI मैंडेट {date} को होगा। इसे बैंक ऐप में प्रबंधित करें।"),
("delivery",0,"आपका {merchant} ऑर्डर आज डिलीवर होगा। ट्रैक करने के लिए {merchant} ऐप खोलें।"),
("delivery",0,"{merchant}: पार्सल AWB {ref} आज दोपहर 2-6 बजे के बीच पहुंचेगा। COD के लिए Rs {amt} तैयार रखें।"),
("delivery",0,"आपका पार्सल {date} को डिलीवर हो गया। {merchant} से खरीदारी के लिए धन्यवाद।"),
("kyc_legit",0,"प्रिय ग्राहक, आपका KYC सफलतापूर्वक अपडेट हो गया है। {bank} के साथ बैंकिंग के लिए धन्यवाद।"),
("kyc_legit",0,"आपका री-KYC अनुरोध प्राप्त हुआ। यदि बाकी है तो ID प्रमाण के साथ अपनी होम शाखा जाएं। -{bank}"),
("tax",0,"आयकर विभाग: आपका ITR AY 2025-26 प्रोसेस हो गया है। रिफंड, यदि है, तो पंजीकृत खाते में आएगा।"),
("utility",0,"आपका बिजली बिल Rs {amt} जनरेट हुआ है। अंतिम तिथि {date}। आधिकारिक ऐप से भुगतान करें।"),
("travel",0,"PNR {ref}: आपकी ट्रेन {date} को 06:40 बजे रवाना होगी। कोच S4 सीट 32। शुभ यात्रा! -IRCTC"),
("recharge",0,"आपका Rs {amt} का रिचार्ज सफल रहा। वैधता 28 दिन। धन्यवाद।"),
("kyc_scam",1,"प्रिय ग्राहक, आपका {bank} खाता आज बंद हो जाएगा। तुरंत KYC अपडेट करें: http://{bank_l}-kyc-verify.{tld}/login"),
("prize",1,"बधाई हो! आपने Rs {big} का इनाम जीता है। दावा करने के लिए अपना बैंक खाता नंबर और OTP अभी भेजें।"),
("electricity",1,"आपकी बिजली आज रात 9:30 बजे बिल न भरने से कट जाएगी। अभी भुगतान करें: http://bit.ly/{code} या {num} पर तुरंत कॉल करें।"),
("courier",1,"आपका पार्सल कस्टम में रुका है। रिलीज़ के लिए Rs {amt} शुल्क यहां भरें http://{brand}-track.{tld}/pay"),
("upi_refund",1,"आपका UPI रिफंड Rs {amt} लंबित है। पैसा पाने के लिए अपना UPI PIN यहां डालें http://refund-{bank_l}.{tld}"),
("loan",1,"Rs {big} का लोन 5 मिनट में पूर्व-स्वीकृत! कोई दस्तावेज़ नहीं। आवेदन करें http://{brand}-loan.{tld} और प्रोसेसिंग शुल्क भरें।"),
("sim_scam",1,"आपका SIM 2 घंटे में बंद हो जाएगा क्योंकि KYC अधूरा है। अभी {num} पर कॉल करें।"),
("tax_scam",1,"आयकर विभाग: आपका Rs {amt} का रिफंड स्वीकृत है। रद्द होने से बचने के लिए अभी http://incometax-refund.{tld} पर बैंक विवरण सत्यापित करें।")],
}
out, n = [], 0
for lang, items in T.items():
    for i, (cat, label, tpl) in enumerate(items):
        n += 1
        out.append({"id": f"x2-{n:03d}", "campaign": f"x2:{lang}:{cat}-{i}", "label": label, "language": lang, "category": cat,
                    "source": "synthetic-template", "collection_date": "2026-11-14", "text": fill(tpl)})
path = Path(__file__).with_name("extra_samples.jsonl")
path.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in out) + "\n", encoding="utf-8")
rows = load_jsonl(path)  # validates against Person C's schema
print(len(rows), "rows;", sum(r.label for r in rows), "scam;", len({r.text for r in rows}), "unique texts")
