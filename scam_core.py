import re
import os
import numpy as np
from typing import Dict, List, Tuple

# ==================== CONFIGURATION ====================

MODEL_PATH = "scamy_model.pkl"

# Enhanced multilingual scam detection rules
# Format: (pattern, points, reason)
RULES: List[Tuple[str, int, str]] = [
    # English patterns - Financial & Payment
    (r"\b(otp|one time password|verification code)\b", 40, "OTP requested"),
    (r"\b(upi|paytm|phonepe|gpay|google pay|bank|transfer|send money|payment)\b", 35, "Money transfer requested"),
    (r"\b(account.*?(suspend|block|lock|close)|suspend.*?account)\b", 40, "Account threat"),
    (r"\b(refund|cashback|credit).*\b(pending|available|claim|process)\b", 35, "Refund bait"),
    (r"\b(kyc|know your customer|verification pending|update.*?kyc)\b", 40, "KYC fraud attempt"),
    
    # English patterns - Urgency & Action
    (r"\b(urgent|immediately|act now|asap|hurry|within.*?(hour|minute)|expire.*?(today|soon))\b", 30, "False urgency"),
    (r"\b(click|tap|open|download|install).*\b(link|here|below|attachment)\b", 30, "Suspicious link action"),
    (r"\b(verify|confirm|update|validate).*\b(account|card|details|information|identity)\b", 35, "Verification request"),
    
    # English patterns - Rewards & Prizes
    (r"\b(prize|winner|lottery|reward|gift|congratulations|won|selected)\b", 35, "Prize/reward claim"),
    (r"\b(free|claim.*?free|limited.*?offer|exclusive.*?offer)\b", 25, "Free offer bait"),
    
    # English patterns - Technical Indicators
    (r"(http|https|www|bit\.ly|tinyurl|goo\.gl|t\.co|rb\.gy|cutt\.ly|short\.link)", 35, "Contains suspicious link"),
    (r"(\.xyz|\.tk|\.ml|\.ga|\.cf|\.gq)(/|\b)", 30, "Suspicious domain"),
    (r"\b\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{4}\b", 20, "Phone number found"),
    
    # Hindi patterns (Devanagari script)
    (r"(ओटीपी|वन टाइम पासवर्ड)", 40, "OTP मांगा गया"),
    (r"(तुरंत|अभी|जल्दी|शीघ्र)", 30, "झूठी जल्दबाजी"),
    (r"(पैसे|भुगतान|बैंक|यूपीआई|पेटीएम|फोनपे|गूगल पे)", 35, "पैसे की मांग"),
    (r"(लिंक|क्लिक|खोलें|डाउनलोड)", 30, "संदिग्ध लिंक"),
    (r"(इनाम|पुरस्कार|लॉटरी|जीत|विजेता)", 35, "इनाम का झांसा"),
    (r"(खाता.*?(बंद|लॉक|निलंबित)|केवाईसी|सत्यापन)", 40, "खाता धमकी"),
    
    # Bengali patterns
    (r"(ওটিপি|ওয়ান টাইম পাসওয়ার্ড)", 40, "OTP চাওয়া হয়েছে"),
    (r"(টাকা|ব্যাংক|পেমেন্ট|ইউপিআই)", 35, "অর্থের অনুরোধ"),
    (r"(জরুরী|এখনই|তাড়াতাড়ি)", 30, "মিথ্যা জরুরিতা"),
    (r"(লিংক|ক্লিক|খুলুন)", 30, "সন্দেহজনক লিংক"),
    
    # Tamil patterns
    (r"(ஓடிபி|ஒருமுறை கடவுச்சொல்)", 40, "OTP கேட்கப்பட்டது"),
    (r"(பணம்|வங்கி|பணம் அனுப்ப)", 35, "பணம் கோரப்படுகிறது"),
    (r"(உடனடியாக|இப்போதே|அவசரம்)", 30, "தவறான அவசரம்"),
    (r"(லிங்க்|கிளிக்|திற)", 30, "சந்தேகத்திற்குரிய இணைப்பு"),
    
    # Telugu patterns
    (r"(ఓటీపీ|వన్ టైమ్ పాస్వర్డ్)", 40, "OTP అడిగారు"),
    (r"(డబ్బు|బ్యాంక్|చెల్లింప్)", 35, "డబ్బు అడుగుతున్నారు"),
    (r"(తొందరగా|ఇప్పుడే|వెంటనే)", 30, "తప్పుడు అత్యవసరత"),
    
    # Marathi patterns
    (r"(ओटीपी|वन टाइम पासवर्ड)", 40, "OTP विचारले"),
    (r"(पैसे|बँक|पेमेंट)", 35, "पैश्याची मागणी"),
    (r"(तातडीने|आत्ता|लवकर)", 30, "खोटी तात्काळता"),
    
    # Gujarati patterns
    (r"(ઓટીપી|વન ટાઇમ પાસવર્ડ)", 40, "OTP માંગવામાં આવ્યો"),
    (r"(પૈસા|બેંક|પેમેન્ટ)", 35, "પૈસાની માંગ"),
    
    # Advanced patterns
    (r"\b(call.*?back|callback|contact.*?(urgent|immediate))\b", 28, "Urgent callback request"),
    (r"\b(expire|expir(ing|ed)|valid.*?(till|until))\b", 25, "Expiration pressure"),
    (r"\b(confirm.*?identity|verify.*?you|security.*?check)\b", 35, "Identity verification scam"),
    (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", 30, "Card number pattern detected"),
    (r"(?i)(dear customer|valued customer|dear user|dear sir)", 20, "Generic greeting"),
]

# ==================== ML MODEL LOADING ====================

def load_model():
    """Load ML model if available"""
    try:
        if os.path.exists(MODEL_PATH):
            import joblib
            model = joblib.load(MODEL_PATH)
            print(f"✅ ML model loaded from {MODEL_PATH}")
            return model
        else:
            print(f"⚠️  ML model not found at {MODEL_PATH}")
            print("   Run train_models.py first to train the model")
            print("   Using rule-based detection only")
            return None
    except Exception as e:
        print(f"⚠️  Error loading ML model: {e}")
        print("   Falling back to rule-based detection")
        return None

# Load model once at startup
ML_MODEL = load_model()

# ==================== ANALYSIS FUNCTIONS ====================

def extract_urls(text: str) -> List[str]:
    """Extract URLs from text"""
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    short_url_pattern = r'\b(?:bit\.ly|tinyurl\.com|goo\.gl|t\.co|rb\.gy|cutt\.ly)/[a-zA-Z0-9]+'
    
    urls = re.findall(url_pattern, text)
    urls.extend(re.findall(short_url_pattern, text))
    return urls

def extract_phone_numbers(text: str) -> List[str]:
    """Extract phone numbers from text"""
    # Indian phone number patterns
    patterns = [
        r'\+91[\s-]?\d{10}',
        r'\b\d{10}\b',
        r'\d{3,4}[-.\s]?\d{3,4}[-.\s]?\d{4}'
    ]
    
    phones = []
    for pattern in patterns:
        phones.extend(re.findall(pattern, text))
    return phones

def check_suspicious_patterns(text: str) -> Tuple[int, List[str]]:
    """Check text against suspicious patterns"""
    score = 0
    reasons = []
    text_lower = text.lower()
    
    # Apply all rules
    matched_patterns = set()
    for pattern, points, reason in RULES:
        if re.search(pattern, text, re.IGNORECASE):
            # Avoid duplicate reasons
            if reason not in matched_patterns:
                score += points
                reasons.append(reason)
                matched_patterns.add(reason)
    
    # Additional heuristics
    
    # Check for multiple exclamation marks
    if text.count('!') >= 3:
        score += 20
        if "Excessive exclamation marks" not in matched_patterns:
            reasons.append("Excessive exclamation marks")
            matched_patterns.add("Excessive exclamation marks")
    
    # Check for all caps (more than 50% of text)
    if len(text) > 10:
        caps_ratio = sum(1 for c in text if c.isupper()) / len(text)
        if caps_ratio > 0.5:
            score += 25
            if "Excessive capitalization" not in matched_patterns:
                reasons.append("Excessive capitalization")
                matched_patterns.add("Excessive capitalization")
    
    return score, reasons

def get_ml_prediction(text: str) -> Tuple[str, float]:
    """Get ML model prediction if available"""
    if ML_MODEL is None:
        return 'UNKNOWN', 0.0
    
    try:
        # Get prediction
        prediction = ML_MODEL.predict([text])[0]
        
        # Get probabilities
        probabilities = ML_MODEL.predict_proba([text])[0]
        
        # Get confidence (max probability)
        confidence = float(probabilities.max())
        
        return prediction, confidence
        
    except Exception as e:
        print(f"ML prediction error: {e}")
        return 'UNKNOWN', 0.0

def analyze_message(text: str) -> Dict:
    """
    Analyze message for scam indicators
    
    Args:
        text: Message text to analyze
        
    Returns:
        Dictionary with analysis results
    """
    # Input validation
    if not text or not isinstance(text, str):
        return {
            'label': 'INVALID INPUT',
            'risk_score': 0,
            'reasons': ['No text provided'],
            'ml_confidence': 0.0,
            'details': {}
        }
    
    text = text.strip()
    
    if len(text) < 3:
        return {
            'label': 'TOO SHORT',
            'risk_score': 0,
            'reasons': ['Message too short to analyze'],
            'ml_confidence': 0.0,
            'details': {'text_length': len(text)}
        }
    
    # Rule-based scoring
    rule_score, rule_reasons = check_suspicious_patterns(text)
    
    # ML-based prediction
    ml_prediction, ml_confidence = get_ml_prediction(text)
    
    # Extract URLs and phone numbers
    urls = extract_urls(text)
    phones = extract_phone_numbers(text)
    
    # Combine ML and rule-based results
    reasons = list(rule_reasons)  # Start with rule-based reasons
    
    # Add URL/phone findings to reasons if not already mentioned
    if urls and not any('link' in r.lower() for r in reasons):
        reasons.append(f"Found {len(urls)} link(s)")
    
    if phones and len(phones) > 1 and not any('phone' in r.lower() for r in reasons):
        reasons.append(f"Multiple phone numbers detected")
    
    # Determine final label and score
    if ML_MODEL is not None and ml_prediction in ['SCAM', 'SAFE']:
        # Use ML prediction as primary indicator
        if ml_prediction == 'SCAM':
            # ML says SCAM
            if ml_confidence >= 0.8:
                label = "LIKELY SCAM 🚨"
                risk_score = int(70 + (ml_confidence - 0.8) * 150)  # 70-100
                severity = "high"
            elif ml_confidence >= 0.6:
                label = "SUSPICIOUS ⚠️"
                risk_score = int(40 + (ml_confidence - 0.6) * 150)  # 40-70
                severity = "medium"
            else:
                label = "SUSPICIOUS ⚠️"
                risk_score = int(30 + ml_confidence * 50)  # 30-50
                severity = "medium"
            
            # Boost score if rules also detected issues
            if rule_score > 50:
                risk_score = min(risk_score + 10, 100)
                
        else:  # SAFE
            # ML says SAFE
            if rule_score >= 70:
                # Rules strongly disagree - mark as suspicious
                label = "SUSPICIOUS ⚠️"
                risk_score = int((rule_score + 40) / 2)  # Average with lower bound
                severity = "medium"
            elif rule_score >= 40:
                label = "SUSPICIOUS ⚠️"
                risk_score = int(rule_score * 0.7)  # Reduce rule score influence
                severity = "medium"
            else:
                label = "SAFE ✅"
                risk_score = int(rule_score * 0.5)  # Minimal score
                severity = "low"
    else:
        # Fallback to rule-based only
        if rule_score >= 70:
            label = "LIKELY SCAM 🚨"
            severity = "high"
        elif rule_score >= 40:
            label = "SUSPICIOUS ⚠️"
            severity = "medium"
        else:
            label = "SAFE ✅"
            severity = "low"
        risk_score = min(rule_score, 100)
    
    # Add helpful context if no reasons found
    if not reasons:
        if label == "SAFE ✅":
            reasons = ["No obvious scam indicators detected"]
        else:
            reasons = ["Detected suspicious patterns"]
    
    return {
        'label': label,
        'risk_score': risk_score,
        'severity': severity,
        'reasons': reasons[:5],  # Limit to top 5 reasons
        'ml_confidence': ml_confidence,
        'ml_prediction': ml_prediction if ML_MODEL else 'N/A',
        'details': {
            'rule_score': rule_score,
            'text_length': len(text),
            'urls_found': len(urls),
            'phones_found': len(phones),
            'urls': urls[:3],  # Return first 3 URLs
            'language_detected': detect_language(text)
        }
    }

def detect_language(text: str) -> str:
    """Detect primary language of text"""
    # Simple heuristic based on Unicode ranges
    if re.search(r'[\u0900-\u097F]', text):
        return 'Hindi/Marathi'
    elif re.search(r'[\u0980-\u09FF]', text):
        return 'Bengali'
    elif re.search(r'[\u0B80-\u0BFF]', text):
        return 'Tamil'
    elif re.search(r'[\u0C00-\u0C7F]', text):
        return 'Telugu'
    elif re.search(r'[\u0A80-\u0AFF]', text):
        return 'Gujarati'
    else:
        return 'English'

# ==================== TESTING ====================

if __name__ == '__main__':
    """Test the scam detection"""
    print("=" * 60)
    print("🧪 Testing Scam Detection Core")
    print("=" * 60)
    
    test_messages = [
        "Hello, how are you?",
        "Your OTP is 123456. Share it immediately to claim prize!",
        "URGENT: Your bank account will be suspended. Click here to verify",
        "Hi mom, can we talk later?",
        "Congratulations! You won 10 lakh rupee. Send 500 processing fee to claim",
        "आपका OTP है 123456। तुरंत शेयर करें",
        "FREE iPhone! Click now: bit.ly/get-free",
        "Dear customer, your account will be blocked. Call 9876543210 immediately.",
        "Meeting at 5pm. See you there!",
        "WINNER!!! CLAIM YOUR PRIZE NOW!!! bit.ly/prize123 URGENT!!!",
        "Your electricity bill of ₹1200 has been paid successfully.",
        "Dear customer, KYC pending. Update immediately or account blocked today."
    ]
    
    for i, msg in enumerate(test_messages, 1):
        print(f"\n{'─'*60}")
        print(f"{i}. Testing: {msg[:60]}...")
        result = analyze_message(msg)
        print(f"   Label: {result['label']}")
        print(f"   Risk Score: {result['risk_score']}/100")
        print(f"   ML Prediction: {result.get('ml_prediction', 'N/A')}")
        print(f"   ML Confidence: {result['ml_confidence']:.3f}")
        print(f"   Reasons: {', '.join(result['reasons'][:2])}")
    
    print("\n" + "=" * 60)