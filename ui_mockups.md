## UI/UX Updates for Advanced Intelligence

---

### 1. Threat Intelligence Dashboard (index.html enhancements)

- **New Section: "Active Threat Actors & Campaigns"**
  - Widget or card listing:
    - Most relevant `ThreatActor`s (e.g., "APT29", "FIN7") targeting the user’s industry or region.
    - Active `Campaigns` with start/end dates, targeted industries.
  - Each actor/campaign name links to a detailed profile page.
  - Example:
    ```
    +--------------------------+
    | Threat Actors Targeting You
    +--------------------------+
    | APT29 (Russia)           |
    |   - Known TTPs: T1566, T1071
    |   - Active Campaigns: SolarWinds (2021)
    |
    | FIN7 (Eastern Europe)
    |   - Known TTPs: T1486, T1003
    +--------------------------+
    ```

### 2. Campaign/ThreatActor Detail Views

- **`threat_actor_detail.html`:**
  - Name, origin, description.
  - List of `known_ttps` (with MITRE links).
  - Associated campaigns (with dates, description).
- **`campaign_detail.html`:**
  - Name, description, timeline.
  - Associated threat actor.
  - Involved IOCs (with enrichment).
  - Industry targets.

### 3. Proactive Playbooks Section

- On dashboard and playbooks list:
  - Show "Proactive Playbooks" separately from reactive (IOC-driven) playbooks.
  - Label or badge: "Proactive" (with tooltip: "Generated based on threat actor intelligence, not detected IOC").
  - Explain: "These playbooks are generated in anticipation of threats relevant to your industry or environment."

### 4. Playbook Details (playbook_detail.html)

- For each playbook step:
  - Display ML model confidence score (e.g., "Recommended Step (92% confidence)").
  - Tooltip or info icon: "This step is recommended based on its historical effectiveness in similar environments."
- Overall playbook:
  - Predicted effectiveness or confidence score.
  - If proactive: Banner/label explaining why it was generated.
  - Link to ThreatActor/Campaign profile if applicable.

---

### Transparency & Ethics

- Add a modal or info box: "How are these recommendations generated?" explaining the use of AI/ML, historical data, and that user feedback continually improves recommendations.
