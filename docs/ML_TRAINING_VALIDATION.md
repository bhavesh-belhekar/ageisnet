# Flow model training and validation

The flow model is an unsupervised Isolation Forest. Fit it only on clean,
representative external traffic. Keep a later chronological slice of that
normal traffic for false-positive validation. Attack recall is a separate
measurement and must use labeled held-out traffic; the normal validation CSV
alone cannot establish that the model detects attacks.

## Collect and train

With the backend database running and collecting representative benign
north-south traffic, run:

```sh
python scripts/collect_baseline.py --since <start-of-clean-traffic-ISO-8601>
python -m backend.app.ml_engine.flow_model.train
```

Collection exports chronologically separated train and validation CSVs under
`data/training_baselines/`. Training rejects empty, non-finite, negative, or
undersized data and requires a held-out normal validation file. Review the
reported normal false-positive rate before using the generated artifact in a
demo or deployment. These CSVs and the pickle artifact are intentionally
gitignored because they contain environment-specific traffic and are not
reproducible source files.

## Evaluate on held-out attacks

Create a separate CSV from captured application traffic and attack simulations
with the six feature columns below plus `label` (`0` for benign, `1` for an
attack window):

```text
total_bytes_sent,total_bytes_received,connection_count,unique_dst_ports,unique_dst_ips,window_seconds,label
```

Do not use training windows in this file. Include both classes and the attack
types the product is expected to detect. Then run:

```sh
python scripts/evaluate_flow_model.py --csv <path-to-labeled-held-out.csv>
```

The evaluator uses the configured production alert threshold and reports the
confusion matrix, precision, recall, F1, normal false-positive rate, and SHAP
coverage for predicted anomalies. Compare those metrics across attack types;
an aggregate score can conceal a missed scenario. Retain the labeled CSV and
JSON output alongside experiment notes outside Git so results are auditable.

## SHAP interpretation

The evaluator checks finite SHAP values for every feature on a balanced sample
from the confusion-matrix groups (four rows by default) and verifies that the
contributions reconstruct the decision score. Metrics still use the entire
holdout.
Contribution magnitude ranks which features most affected the score for that
sample. It does not by itself establish
causality or validate detection quality; the held-out labels and metrics do
that. Review SHAP payloads on representative true positives and false
positives before treating the explanations as useful to analysts.
