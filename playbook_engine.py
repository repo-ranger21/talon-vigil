import joblib
from db_manager import Playbook, PlaybookStep, UserEnvironment, IOC, ThreatActor, Campaign
from flask import current_app
from sqlalchemy.orm import selectinload

def get_relevant_threat_actors(user_env, industry=None):
    # Find ThreatActors whose known_ttps or campaigns match the user's environment or industry
    actors = ThreatActor.query.all()
    relevant = []
    for actor in actors:
        for campaign in actor.campaigns:
            if industry and industry in (campaign.industry_targets or []):
                relevant.append(actor)
            # Could match on IOC types, TTPs, etc.
    return relevant

def generate_proactive_playbooks_for_user(user_id, industry, environment):
    """
    For each relevant threat actor/campaign, generate playbook steps before any IOC is detected.
    """
    relevant_actors = get_relevant_threat_actors(environment, industry)
    proactive_playbooks = []
    for actor in relevant_actors:
        ttps = actor.known_ttps or []
        # For each TTP, suggest generic pre-emptive steps (could map to MITRE mitigations)
        steps = []
        for ttp in ttps:
            steps.append({"instruction": f"Review and harden controls against MITRE TTP {ttp}", "action_type": "mitigation", "confidence": 0.8})
        playbook = Playbook(
            user_id=user_id,
            title=f"Proactive Defense Against {actor.name}",
            description=f"Recommended actions based on threat actor {actor.name} targeting your industry.",
            status="Proactive"
        )
        # Save playbook, add steps, etc.
        proactive_playbooks.append(playbook)
    return proactive_playbooks

# ML Model Inference for Playbook Step Ranking
def load_playbook_ml_model():
    try:
        model_path = current_app.config.get("PLAYBOOK_ML_MODEL_PATH", "playbook_ml_model.pkl")
        model = joblib.load(model_path)
        return model
    except Exception:
        return None

def generate_playbooks_for_user(user_id, iocs, user_env, industry):
    """
    Use ML model to rank/select playbook steps based on historical effectiveness.
    """
    model = load_playbook_ml_model()
    steps = []
    for ioc in iocs:
        # Feature vector: [ioc_type, vt_score, abuse_confidence, tool_type, tool_name, ...]
        features = extract_features(ioc, user_env)
        if model:
            predictions = model.predict_proba([features])[0]
            # Rank/sort steps by predicted success/confidence
            top_steps = sorted(zip(ALL_POSSIBLE_STEPS, predictions), key=lambda x: -x[1])
            for step, conf in top_steps[:3]:
                steps.append({"instruction": step, "confidence": conf})
        else:
            # Fallback: rule-based
            steps.append({"instruction": f"Default step for {ioc.value}", "confidence": 0.5})
    # Save playbook and steps, annotate with confidence
    return steps

def extract_features(ioc, user_env):
    # Example: convert IOC and user environment to ML features
    return [
        ioc.type,
        int(ioc.vt_score.split('/')[0]) if ioc.vt_score else 0,
        ioc.abuse_confidence or 0,
        user_env.tool_type if user_env else "",
        user_env.tool_name if user_env else "",
    ]