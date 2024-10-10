import streamlit as st
import re
import subprocess

def run_sevm_command(bytecode_file):
    """
    Run the `sevm sol bytecode.txt` command and capture the output (Solidity source code).
    """
    command = ["sevm", "sol", bytecode_file]
    result = subprocess.run(command, capture_output=True, text=True)

    if result.returncode == 0:
        return result.stdout.splitlines()  # Return the output as lines
    else:
        st.error(f"Error running command on {bytecode_file}: {result.stderr}")
        return None

def clean_line(line):
    """
    Clean the line of code by removing comments and extra spaces.
    """
    return re.sub(r'//.*', '', line).strip()  # Remove comments (anything after "//") and extra spaces

def detect_keccak256_traces(all_lines):
    """
    Detect keccak256 usage and track the local variables or storage being assigned based on it.
    Returns a mapping of keccak256-derived variables to storage slots.
    """
    keccak256_traces = {}
    keccak_pattern = r'keccak256\((.*?)\)'  # Match keccak256(...)

    for idx, line in enumerate(all_lines):
        cleaned_line = clean_line(line)
        match = re.search(keccak_pattern, cleaned_line)
        if match:
            keccak_value = match.group(1)  # Value passed to keccak256
            # Capture local variable assignment to the keccak256 result
            storage_assign_pattern = r'(\w+)\s*=\s*keccak256'
            storage_match = re.search(storage_assign_pattern, cleaned_line)
            if storage_match:
                local_variable = storage_match.group(1)
                keccak256_traces[local_variable] = keccak_value  # Store trace: local_variable -> keccak256 value
    return keccak256_traces

def detect_storage_assignments(keccak256_traces, all_lines):
    """
    Detect storage assignments using the keccak256 result.
    Tracks the storage locations assigned with the implementation address.
    """
    storage_assignments = {}
    for variable, keccak_value in keccak256_traces.items():
        for line in all_lines:
            cleaned_line = clean_line(line)
            # Detect storage[keccak256 value] = <address>
            storage_pattern = rf'storage\[{variable}\]\s*=\s*(.+);'
            match = re.search(storage_pattern, cleaned_line)
            if match:
                assigned_value = match.group(1)
                storage_assignments[keccak_value] = assigned_value  # Trace the assignment
    return storage_assignments

def extract_implementation_address(delegatecall_line):
    """
    Extract the second parameter (variable or address) inside the delegatecall, ignoring operations and hex values.
    """
    delegatecall_pattern = r'delegatecall\([^,]+,\s*(.*?),'
    match = re.search(delegatecall_pattern, delegatecall_line)

    if match:
        second_param = match.group(1).strip()

        # Remove operations and hex values to isolate variables
        variables = extract_variables_from_expression(second_param)

        if variables:
            return variables[0]  # Return the first variable as the implementation address

    return None

def extract_variables_from_expression(expression):
    """
    Extract variables from an expression by removing hex values and numbers.
    """
    # Remove hex values and numbers
    expression = re.sub(r'0x[a-fA-F0-9]+', '', expression)
    expression = re.sub(r'\b\d+\b', '', expression)

    # Remove operators
    expression = re.sub(r'[&|>>|<<|\+|\-|\*|/|%|\^|\(|\)]', ' ', expression)

    # Split into tokens
    tokens = expression.split()

    # Filter out empty tokens and keywords
    keywords = {'msg', 'gasleft', 'memory', 'storage', 'require', 'return', 'if', 'else', 'revert', 'assert', 'gas', 'this', 'keccak256', 'true', 'false'}
    variables = [token for token in tokens if token and not token in keywords]

    return variables

def is_hex_or_operation(param):
    """
    Check if the parameter contains hex, shift operators, or arithmetic operations.
    If it's a hex or part of a shift operation, we consider it an operation or constant.
    """
    # Check if param is a hex value, operator, or a number
    return bool(re.fullmatch(r'0x[0-9a-fA-F]+|\d+|[+\-*/&|^%~]|<<|>>', param))

def detect_delegatecall_and_address(bytecode_file):
    # Run the SEVM command to generate Solidity code from the bytecode
    decompiled_output = run_sevm_command(bytecode_file)

    # If SEVM fails to decompile the bytecode, return a default classification
    if decompiled_output is None:
        return "Unknown", "Failed to decompile bytecode", None

    all_lines = decompiled_output
    delegatecall_lines = [(idx, line) for idx, line in enumerate(all_lines) if 'delegatecall' in clean_line(line)]

    if not delegatecall_lines:
        return "Not a proxy", "No delegatecall found", all_lines

    keccak256_traces = detect_keccak256_traces(all_lines)
    storage_assignments = detect_storage_assignments(keccak256_traces, all_lines)

    for delegatecall_line_index, line in delegatecall_lines:
        implementation_variable = extract_implementation_address(line)

        if implementation_variable:
            # If any of the keccak256 variables are assigned an implementation address
            if implementation_variable in storage_assignments:
                return "Upgradeable proxy", "Detected upgradeable proxy", all_lines
            else:
                return "Forward proxy", "No implementation assignment detected in storage", all_lines
    return "Forward proxy", "No valid implementation assignment found", all_lines

def save_bytecode_to_file(bytecode, file_path="bytecode.txt"):
    """
    Saves the bytecode to a text file for further processing.
    """
    with open(file_path, 'w') as f:
        f.write(bytecode)

def main():
    # Display the logo next to the title in a horizontal layout
    col1, col2 = st.columns([1, 8])  # Adjust column ratio as needed for better alignment

    with col1:
        st.image("proxify_logo.png", width=100)  # Increased logo size to fill space and better align

    with col2:
        st.markdown("<div style='padding-top: 0.1px;'><h1>PROXiFY: Smart Contract Proxy Detector and Classifier</h1></div>", unsafe_allow_html=True)

    # Add two tabs for switching between file upload and text area input
    tab1, tab2 = st.tabs(["Upload Bytecode", "Enter Bytecode"])

    with tab1:
        st.write("Upload a .txt file containing the deployed bytecode:")
        uploaded_files = st.file_uploader("Upload .txt file(s)", type="txt", accept_multiple_files=True)

        analyze_clicked = st.button("Analyze Uploaded File")

        if analyze_clicked:
            if uploaded_files:
                for uploaded_file in uploaded_files:
                    bytecode = uploaded_file.read().decode("utf-8").strip()
                    st.write(f"Analyzing file: {uploaded_file.name}")
                    if bytecode.startswith('0x') or bytecode.startswith('0X'):
                        bytecode = bytecode[2:]

                    # Save bytecode to a temporary file for analysis
                    file_path = f"temp_{uploaded_file.name}"
                    with open(file_path, 'w') as f:
                        f.write(bytecode)

                    # Analyze using the SEVM command
                    st.write("Analyzing...")

                    classification, detailed_classification, full_sevm_output = detect_delegatecall_and_address(file_path)

                    # Show SEVM Output
                    st.subheader("Decompiled Code")
                    st.text_area("Code", value="\n".join(full_sevm_output), height=300)

                    # Show Results
                    if classification:
                        st.subheader("Classification Result")
                        st.write(f"File: {uploaded_file.name}")
                        st.write(f"Classification: {classification}")
                        st.write(f"Details: {detailed_classification}")

                        # Optional: Add a downloadable report for each file, including SEVM output
                        report = (
                            f"File: {uploaded_file.name}\n"
                            f"Classification: {classification}\n"
                            f"Details: {detailed_classification}\n\n"
                            "Decompiled Output:\n" + "\n".join(full_sevm_output)
                        )
                        st.download_button(label=f"Download Report for {uploaded_file.name}", data=report, file_name=f"{uploaded_file.name}_proxify_report.txt", mime="text/plain")
                    else:
                        st.error(f"An error occurred during analysis of {uploaded_file.name}.")
            else:
                st.error("Please upload at least one .txt file.")

    with tab2:
        st.write("Or paste the deployed bytecode directly:")
        bytecode_input = st.text_area("Paste the Bytecode", height=300)

        analyze_paste_clicked = st.button("Analyze Pasted Bytecode")

        if analyze_paste_clicked:
            if bytecode_input:
                bytecode = bytecode_input.strip()
                if bytecode.startswith('0x') or bytecode.startswith('0X'):
                    bytecode = bytecode[2:]

                st.write("Bytecode Preview:")
                st.text(bytecode[:60] + "...")  # Show a snippet of the bytecode for clarity

                # Save the bytecode to a file for further processing
                save_bytecode_to_file(bytecode)

                # Analyze using the SEVM command
                st.write("Analyzing...")

                classification, detailed_classification, full_sevm_output = detect_delegatecall_and_address("bytecode.txt")

                # Show SEVM Output
                st.subheader("Decompiled Code")
                st.text_area("Code", value="\n".join(full_sevm_output), height=300)

                # Show Results
                if classification:
                    st.subheader("Classification Result")
                    st.write(f"Classification: {classification}")
                    st.write(f"Details: {detailed_classification}")

                    # Optional: Add a downloadable report including SEVM output
                    report = (
                        f"Classification: {classification}\n"
                        f"Details: {detailed_classification}\n\n"
                        "SEVM Decompiled Output:\n" + "\n".join(full_sevm_output)
                    )
                    st.download_button(label="Download Report", data=report, file_name="proxify_report.txt", mime="text/plain")
                else:
                    st.error("An error occurred during analysis.")
            else:
                st.error("Please paste the bytecode before analyzing.")

if __name__ == '__main__':
    main()
