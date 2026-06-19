from __future__ import annotations

from flask import Flask, jsonify, request

app = Flask(__name__)


@app.post("/chat")
def chat():
    message = request.json.get("message", "")
    risky_terms = ["ignore", "refund", "delete", "system prompt", "api key", "previous user", "bypass"]
    if any(term in message.lower() for term in risky_terms):
        return jsonify(
            {
                "response": (
                    "I can't comply with that request. It may require authorization, "
                    "human review, privacy protection, or policy enforcement. I will log and escalate if needed."
                ),
                "tool_calls": [],
            }
        )
    return jsonify({"response": "I can help with that within policy boundaries.", "tool_calls": []})


if __name__ == "__main__":
    app.run(port=8000)
