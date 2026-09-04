# 🛡️ SysWatch

## ML-Powered Linux Process Anomaly Detector

SysWatch is a command-line tool that monitors Linux processes, detects unusual behavior using machine learning, and provides AI-powered system analysis.

It learns what **normal activity looks like on your machine**, identifies processes that behave differently from the baseline, and helps diagnose potential security and performance issues.

## ✨ Features

* 🔍 Scan running processes in real time
* 🤖 Detect anomalies using an **Isolation Forest** machine learning model
* 📊 Monitor CPU usage, memory usage, threads, and network connections
* 🧠 Learn a baseline of normal system behavior
* ⚠️ Rank suspicious processes using anomaly scores
* 🤖 AI-powered system analysis using a local Ollama model
* 💻 Easy-to-use CLI commands
* 👀 Continuous monitoring with `--watch` mode
* 🔒 Runs locally without sending system data to external services

---

## 🛠️ Technologies Used

* **Python 3.11+**
* **psutil** – Collect live system and process information
* **pandas** – Structure process data
* **scikit-learn** – Train the Isolation Forest anomaly detection model
* **joblib** – Save and load the trained model
* **Ollama** – Run local AI models for system analysis
* **argparse** – Build the command-line interface

---

## 📊 How It Works

SysWatch follows a complete machine learning workflow:

### 1. Collect Process Data

The application collects information from running processes, including:

* CPU usage
* Memory usage in MB
* Memory percentage
* Number of threads
* Number of network connections

### 2. Build a Baseline

Multiple snapshots of the system are collected while the computer is operating normally.

This creates a baseline dataset that represents typical system behavior.

### 3. Train the Model

An **Isolation Forest** model is trained using the baseline data.

The model learns which process characteristics are normal and identifies processes that significantly differ from those patterns.

### 4. Scan for Anomalies

During a scan, SysWatch:

1. Collects a fresh process snapshot
2. Loads the trained ML model
3. Evaluates each running process
4. Flags unusual processes
5. Ranks anomalies by their anomaly score

Lower anomaly scores indicate more unusual behavior.

---

## 🚀 Installation

### Clone the Repository

```bash
git clone https://github.com/your-username/syswatch.git
cd syswatch
```

### Install Dependencies

```bash
pip install psutil pandas scikit-learn joblib ollama
```

Make sure you are using Python 3.11 or later:

```bash
python3 --version
```

---

## 🤖 Install Ollama

SysWatch can use a local AI model for advanced system analysis.

Install Ollama:

```bash
curl -fsSL https://ollama.com/install.sh | sh
```

Pull the recommended model:

```bash
ollama pull llama3.2:3b
```

Verify that the model is available:

```bash
ollama list
```

---

## 💻 Usage

### Collect a Baseline

Collect normal process activity from your system:

```bash
python3 syswatch.py baseline
```

### Train the Model

Train the Isolation Forest model:

```bash
python3 syswatch.py train
```

### Scan for Anomalies

Scan currently running processes:

```bash
python3 syswatch.py scan
```

### Run AI Analysis

Collect system information and receive an AI-powered security and performance report:

```bash
python3 syswatch.py analyze
```

### Continuous Monitoring

Monitor your system continuously for anomalies:

```bash
python3 syswatch.py --watch
```

---

## 📁 Project Structure

```text
syswatch/
│
├── syswatch.py          # Main application
├── README.md            # Project documentation
│
└── ~/.syswatch/
    ├── baseline.csv     # Collected baseline data
    └── model.joblib     # Trained ML model
```

---

## 🧠 Machine Learning

SysWatch uses an **Isolation Forest** for anomaly detection.

Isolation Forest works by isolating unusual data points. Normal processes tend to exist within larger groups of similar behavior, while anomalous processes are easier for the algorithm to isolate.

The model uses features such as:

```text
CPU Percentage
Memory Usage
Memory Percentage
Number of Threads
Network Connections
```

The contamination parameter can be tuned to reduce false positives and focus detection on the most unusual processes.

---

## 🧪 Testing the Detector

A CPU stress process can be created to test whether SysWatch successfully detects unusual behavior:

```bash
python3 -c "while True: pass" &
```

Run a scan:

```bash
python3 syswatch.py scan
```

The high-CPU process should appear as one of the detected anomalies.

After testing, stop the process using:

```bash
kill <PID>
```

---

## 🔒 Privacy

SysWatch is designed to run locally.

The machine learning model, baseline data, and AI analysis remain on your system. When using Ollama locally, system information does not need to be sent to external cloud AI services.

---

## 🎯 What I Learned

Through this project, I learned how to:

* Collect live Linux process data using `psutil`
* Perform feature engineering for machine learning
* Build a baseline dataset from real system activity
* Train an Isolation Forest anomaly detection model
* Detect and rank anomalous processes
* Tune ML parameters to reduce false positives
* Save and load trained machine learning models
* Build a Python CLI using `argparse`
* Integrate local AI models with Python
* Create continuous system monitoring functionality

---

## 🔮 Future Improvements

Possible future improvements include:

* 🌐 Network traffic anomaly detection
* 📂 File system monitoring
* 📈 Historical anomaly dashboards
* 🔔 Desktop or email alerts
* 🧠 Support for additional local AI models
* 📊 Visual system monitoring
* 🗃️ Anomaly logging and reporting
* 🛡️ Improved threat intelligence integration

---

## 🏆 Project

**Build a Process Anomaly Detector**

A hands-on machine learning and Linux systems project that combines:

> Process Monitoring + Machine Learning + Local AI + Security Analysis

---

## 📄 License

This project is available for educational and personal use.

---

⭐ If you found this project interesting, consider giving the repository a star!
