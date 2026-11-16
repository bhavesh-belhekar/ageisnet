# Synthetic flow model smoke test

`data/model_artifacts/flow_model_v2_synthetic.pkl` was trained only to smoke
test the training, inference, and explanation paths. The CSVs are generated
deterministically by `scripts/generate_synthetic_flow_data.py`; they do not
represent captured network traffic.

See [SYNTHETIC_MODEL_PERFORMANCE.md](SYNTHETIC_MODEL_PERFORMANCE.md) for full
metric definitions, confusion matrices, threshold details, SHAP values, and
reproduction steps.

## Data and fit

- Training: 1,000 synthetic normal feature windows.
- Normal validation: 250 windows; Isolation Forest validation false-positive
  rate was 5.2%.
- Labeled holdout: 400 windows (250 synthetic normal, 150 synthetic attacks
  spanning exfiltration, port scans, and destination spread).
- Runtime score threshold remains `0.52` from `risk_policy.yaml`.
- Pickle was produced with scikit-learn 1.6.1 and SHAP 0.47.2.

At the configured `0.52` threshold, holdout results were 3 true positives, 1
false positive, 147 false negatives, and 249 true negatives (2.0% attack
recall; 0.4% normal false-positive rate). This shows that the current fixed
threshold is too conservative for these synthetic score distributions.

Using only the separate normal validation scores to choose a candidate
threshold for the configured 10% normal false-positive target yielded
`0.492817`. On the synthetic labeled holdout this gave 150 true positives, 18
false positives, 0 false negatives, and 232 true negatives (100% recall; 7.2%
false-positive rate). This is a synthetic-only calibration result and does not
justify changing the production threshold.

## SHAP check

For one held-out synthetic normal row, exact SHAP contributions over the
`decision_function` covered all six features and reconstructed the model score
with absolute additivity error `1.39e-17`.

## Use

The artifact is named with `_synthetic` and is not selected by the backend's
default artifact path. Do not use it for security decisions or as a substitute
for retraining on representative clean traffic and validating against captured
attack simulations.
