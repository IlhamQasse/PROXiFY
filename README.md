PROXiFY: Smart Contract Proxy Detector and Classifier
PROXiFY is a tool designed to detect and classify Ethereum smart contract proxies using bytecode analysis. It distinguishes between forward proxies (with fixed implementation addresses) and upgradeable proxies (which allow updates). PROXiFY is ideal for researchers, developers, and auditors working on Ethereum-based decentralized applications (DApps).

This project is based on the paper:

"PROXiFY: Detecting and Classifying Upgradeable Proxy Contracts in Ethereum Bytecode"
Submitted to ICSE 2025

Features
Bytecode Decompilation: Uses SEVM to decompile Ethereum bytecode.
Proxy Detection: Identifies proxy contracts using delegatecall and classifies them as forward or upgradeable.
Report Generation: Generates downloadable reports with classification results and decompiled bytecode.
Requirements
To run PROXiFY, you will need:

1. Install Python and Streamlit
Python 3.7 or later
Streamlit: For running the web interface.
Install Streamlit using pip:

bash
Copy code
pip install streamlit
2. Install SEVM CLI Tools
PROXiFY uses SEVM for decompiling Ethereum bytecode. Install SEVM globally via npm:

bash
Copy code
npm install --global sevm
Note: We are using SEVM from GitHub, an EVM decompiler that is lightweight and reliable.

3. Run the Application
Clone this repository:

bash
Copy code
git clone https://github.com/<your-github-username>/proxify.git
cd proxify
Install the necessary Python dependencies (just Streamlit):

bash
Copy code
pip install -r requirements.txt
Run the application using Streamlit:

bash
Copy code
streamlit run app.py
The application will open in your browser at http://localhost:8501.

Usage
Upload or Paste Bytecode
Upload Bytecode: Users can upload .txt files containing the bytecode of a deployed contract.
Paste Bytecode: Users can paste the bytecode directly into the provided text area.
Analyze and Download Results
Analyze Bytecode: After uploading or pasting bytecode, click "Analyze" to classify the contract.
View Results: The tool will display the classification and explanation.
Download Report: A detailed report can be downloaded, which includes the decompiled bytecode and classification result.
Project Structure
bash
Copy code
|-- app.py                 # Main Streamlit app file
|-- requirements.txt        # Python dependencies (Streamlit)
|-- proxify_logo.png        # Project logo
|-- README.md               # This file
Citation
If you use PROXiFY in your research, please cite the paper submitted to ICSE 2025:

PROXiFY: Detecting and Classifying Upgradeable Proxy Contracts in Ethereum Bytecode

License
This project is licensed under the MIT License. See the LICENSE file for more details.

Notes for Developers:
Make sure SEVM is installed globally and accessible in your PATH.
Ensure that streamlit is installed as per the requirements.
For updates or issues with SEVM, please refer to SEVM's GitHub repository.
