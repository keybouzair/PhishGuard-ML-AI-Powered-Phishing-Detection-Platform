import asyncio
from typing import Dict, Any, List
from core.logger import get_logger, log_execution_time

logger = get_logger("services.user_behavior_model")


class BehavioralUserRiskModel:
    """
    Ultra Feature 6: Behavioral User Risk Model
    Tracks employee clicks, submissions, and risky browsing patterns over time
    to generate risk profiles and tailored security training recommendations.
    """

    def __init__(self):
        # In production this would be backed by Redis or Postgres
        self.user_history_db = {}
        logger.info("BehavioralUserRiskModel initialized")

    async def log_user_action(self, email: str, action: str, risk_score: float):
        """
        Record a user activity (e.g., clicked a link, submitted a form).
        """
        if email not in self.user_history_db:
            self.user_history_db[email] = {
                "unsafe_clicks": 0,
                "phishing_submissions": 0,
                "history": []
            }
            
        record = self.user_history_db[email]
        record["history"].append({"action": action, "risk_score": risk_score})
        
        if "click" in action and risk_score > 60:
            record["unsafe_clicks"] += 1
        elif "submit" in action and risk_score > 60:
            record["phishing_submissions"] += 1
            
        logger.info(f"Logged {action} for user {email}")

    @log_execution_time(logger)
    async def generate_user_risk_profile(self, email: str) -> Dict[str, str]:
        """
        Analyze the user's recent history to assign a risk tier and training task.
        """
        record = self.user_history_db.get(email)
        
        if not record:
            return {
                "user_risk_level": "LOW",
                "training_recommendation": "Maintain standard yearly compliance training."
            }

        unsafe_clicks = record["unsafe_clicks"]
        submissions = record["phishing_submissions"]
        
        # Simple heuristic model
        if submissions >= 1 or unsafe_clicks >= 3:
            level = "HIGH"
            training = "Immediate mandatory 1-on-1 coaching regarding credential theft and visual impersonation."
        elif unsafe_clicks >= 1:
            level = "MEDIUM"
            training = "Enroll in Interactive 'Spot the Phish' module #4. Monitor closely."
        else:
            level = "LOW"
            training = "Maintain standard yearly compliance training."

        result = {
            "user_risk_level": level,
            "training_recommendation": training
        }
        
        logger.info(f"Generated user profile for {email}: {level}", extra={"extra_fields": result})
        return result


# Export singleton
user_behavior_model = BehavioralUserRiskModel()
