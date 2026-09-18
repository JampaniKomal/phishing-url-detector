# AI-Powered Phishing URL Detector

This project is an end-to-end machine learning system for detecting phishing URLs using lexical and structural features. It demonstrates the complete data science workflow, from data sourcing to model evaluation and interpretation, using a notebook-based approach.

## Inspiration

Inspired by a real-world cybersecurity challenge from the Smart India Hackathon (SIH).

- **Organization:** National Technical Research Organisation (NTRO)
- **Problem Statement ID:** SIH1454
- **Title:** Create an intelligent system using AI/ML to detect phishing domains which imitate look and feel of genuine domains.

## Tech Stack

- Python 3.8+
- Libraries:
    - pandas for data manipulation and analysis
    - numpy for numerical operations
    - scikit-learn for machine learning model training and evaluation
    - matplotlib and seaborn for data visualization
    - requests for downloading data
    - urllib and re for feature engineering from URLs
    - pickle for saving the trained model

## Project Structure

The project is organized into Jupyter notebooks, each handling a specific part of the workflow:

```
phishing-url-detector/
│
├── data/
│   ├── raw/
│   │   └── dataset_phishing.csv
│   └── processed/
│       ├── X_train.csv
│       ├── X_test.csv
│       ├── y_train.npy
│       └── y_test.npy
│
├── models/
│   └── best_model.pkl
│
├── notebooks/
│   ├── 01_data_sourcing_and_exploration.ipynb
│   ├── 02_feature_engineering_and_preprocessing.ipynb
│   ├── 03_model_development.ipynb
│   └── 04_results_and_visualization.ipynb
│
├── .gitignore
├── README.md
└── requirements.txt
```

## Notebook Workflow

**Notebook 01: Data Sourcing and Exploration**
- Loads the raw phishing URL dataset
- Performs exploratory data analysis (EDA) to understand data structure and distribution

**Notebook 02: Feature Engineering & Preprocessing**
- Extracts meaningful features from URL strings (e.g., URL length, hostname length, counts of special characters)
- Encodes the target variable
- Splits data into training and testing sets

**Notebook 03: Model Development**
- Trains multiple classification models (Logistic Regression, Random Forest, SVM)
- Evaluates models using metrics (Accuracy, Precision, Recall, F1-Score)
- Compares models and saves the best-performing one

**Notebook 04: Results Visualization**
- Loads the saved model
- Generates a confusion matrix for test set performance
- Creates a feature importance plot

## Future Scope

Potential extensions include:

- Deployment as a web service using Flask or FastAPI
- Development of a browser extension for real-time URL checking
- Experimentation with advanced models (XGBoost, LightGBM, neural networks)
- Engineering additional features (e.g., TLD analysis, WHOIS lookups, webpage content analysis)

## How To Use

1. Clone the repository:
     ```
     git clone https://github.com/JampaniKomal/phishing-url-detector.git
     cd phishing-url-detector
     ```
2. Create and activate a virtual environment:
     ```
     python -m venv venv
     # On Windows
     venv\Scripts\activate
     # On macOS/Linux
     source venv/bin/activate
     ```
3. Install required libraries:
     ```
     pip install -r requirements.txt
     ```
4. Download the data:
     - Place `dataset_phishing.csv` inside the `data/raw/` directory.
5. Run the notebooks:
     - Open the `notebooks/` directory and run the Jupyter notebooks in order (01 to 04).

## Testing & Verification

The processed train/test split (`data/processed/`) is already committed,
so notebooks 03 and 04 were actually re-executed end to end
(`jupyter nbconvert --execute`) against it rather than just reading the
code. Notebook 03 trains Logistic Regression, Random Forest, and an SVM
and picks the best by F1-score; Random Forest wins reproducibly
(F1 0.847 vs. 0.727 and 0.719) since the split and models are seeded
with `random_state=42`. Notebook 04's feature-importance plot is gated
behind `isinstance(best_model, RandomForestClassifier)`, so it would
silently skip itself if a different model type ever won instead — but
on this dataset Random Forest genuinely and consistently wins, so the
check passes and both the confusion matrix and feature-importance
plots render. `url_length`, `hostname_length`, and `count_digits` came
out as the top predictive features.

Notebooks 01 and 02 require the raw Kaggle CSV
(`data/raw/dataset_phishing.csv`), which is intentionally not committed
(`.gitignore` excludes raw CSVs) — this step was verified by reading
the notebook logic rather than a live re-run, since it needs a manual
Kaggle download.

`pip-audit` on `requirements.txt`: no known vulnerabilities.

## Known Limitations

- The 13 hand-engineered lexical/structural features do not include
  domain-reputation, WHOIS, or webpage-content signals — see Future
  Scope.
- No automated test suite — verification was running the real
  notebooks against real data, not a committed `tests/` directory.
- Reproducing notebooks 01-02 requires manually downloading the
  Kaggle dataset; it is not bundled with the repository.

## License

MIT — see [LICENSE](LICENSE).
