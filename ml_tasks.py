"""
Celery task for periodic training of playbook refinement ML model.
"""
from celery import shared_task
from db_manager import PlaybookStep, PlaybookFeedback, IOC, UserEnvironment
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier

@shared_task
def train_playbook_refinement_model():
    # Gather historical playbook step and feedback data
    data = []
    labels = []
    for step in PlaybookStep.query.options(selectinload(PlaybookStep.playbook)).all():
        playbook = step.playbook
        feedbacks = playbook.feedback_entries
        # Features: IOC type, tool type, step, avg rating, completion
        ioc = playbook.ioc
        env = UserEnvironment.query.filter_by(user_id=playbook.user_id).first()
        features = [
            ioc.type if ioc else "",
            int(ioc.vt_score.split('/')[0]) if ioc and ioc.vt_score else 0,
            ioc.abuse_confidence if ioc and ioc.abuse_confidence else 0,
            env.tool_type if env else "",
            env.tool_name if env else "",
            step.action_type or "",
        ]
        avg_rating = np.mean([f.rating for f in feedbacks]) if feedbacks else 3
        completed = int(step.is_completed)
        data.append(features)
        labels.append(completed if completed is not None else 0)
    # Encode categorical variables, scale, etc. (omitted for brevity)
    # Train model
    if data:
        model = RandomForestClassifier()
        model.fit(data, labels)
        # Store model artifact
        joblib.dump(model, "playbook_ml_model.pkl")
        # Optionally: upload to S3/blob
        # s3.upload_file("playbook_ml_model.pkl", ...)