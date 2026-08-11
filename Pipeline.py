# M-Cloud Pipeline
import streamlit as st
import pandas as pd
import json
import plotly.express as px
from Python_Parser import parse_uploaded_json
from LLM_Threat_Detection import detect_threats
import plotly.graph_objects as go

# Title
st.set_page_config(
    page_title="M-Cloud Threat Detection Framework",
    layout="wide"
)
st.title("M-Cloud Threat Detection Framework Dashboard")

# Add side bar
st.sidebar.subheader("JSON Upload")

# Setup file upload
upload_file = st.sidebar.file_uploader(
    label="Upload JSON file",
    type=["JSON"]
)


def sliding_window(parsed_results, window_size=20, overlap=5):
    # gets the number of entries in the parsed logs
    length = len(parsed_results)

    # sees how far the window should move each time
    step = window_size - overlap

    # loops through the parsed logs
    for start in range(0, length, step):
        # calculates the end of the window
        end = start + window_size
        # Returns the current window
        yield parsed_results[start:end]
        # stops when the end has been reached
        if end >= length:
            break


if upload_file is None:
    st.write("Please upload a JSON file.")

else:
    st.success(f"Uploaded: {upload_file.name}")

    try:
        progress_bar = st.progress(0, text="Preparing logs")

        progress_bar.progress(25, text="Parsing uploaded JSON file")

        # Send the uploaded Streamlit file directly to the parser
        parsed_results = parse_uploaded_json(upload_file)

        # Convert parsed results to a DataFrame
        df = pd.DataFrame(parsed_results)

        progress_bar.progress(40, text="Ordering logs by timestamp")

        # Convert the time column to datetime 
        df["time"] = pd.to_datetime(df["time"], format="mixed", utc=True)

        # Sort logs by earliest 
        df = df.sort_values(by="time", ascending=False).reset_index(drop=True)

        # Convert the time column to text
        df["time"] = df["time"].dt.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Convert the sorted logs to a dictionary
        ordered_logs = df.to_dict(orient="records")

        progress_bar.progress(50, text="Sending to LLM Threat Detection")

        # Create the sliding windows from the ordered logs
        windows = list(sliding_window(ordered_logs, window_size=20, overlap=5))
        total_windows = len(windows)

        threat_results = []

        # Send each window to the LLM
        for index, window in enumerate(windows, start=1):
            progress_bar.progress(
                60,
                text=f"Sending window {index} of {total_windows} to LLM"
            )

            run_1 = detect_threats(window)
            run_2 = detect_threats(window)
            run_3 = detect_threats(window)

            runs = [run_1, run_2, run_3]

            # Selects the best result of the run that has the most threats
            best_result = max(
                runs,
                key=lambda result: str(result).lower().count("'threat': true")
            )

            threat_results.append({
                "window_number": index,
                "window_size": len(window),
                "llm_result": best_result,
                "run_1": run_1,
                "run_2": run_2,
                "run_3": run_3
            })

        progress_bar.progress(100, text="LLM Threat Detection Complete")
        progress_bar.empty()
        
        total_threats = 0
        for item in threat_results:
            total_threats += str(item["llm_result"]).lower().count("'threat': true")
        
        if total_threats == 0:
            critical_level = "Low"
        elif total_threats <= 2:
            critical_level = "Medium"
        else:
            critical_level = "High"
            
        # Summary cards
        st.subheader("Detection Summary")
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Logs", len(parsed_results))
        col2.metric("Windows Analysed", total_windows)
        col3.metric("Threats Detected", total_threats)
        col4.metric("Critical Level", critical_level)

        attack_type = []
        cloud_platform = []

        for item in threat_results:
            result = item["llm_result"]
            if isinstance(result, dict):
                result = [result]

            for threat in result:
                if threat.get("threat") == True:
                    attack_type.append(threat.get("attack_type", "Unknown"))
                    cloud_platform.append(threat.get("cloud_provider", "Unknown"))

        if attack_type or cloud_platform:
            col1, col2 = st.columns(2)

            if attack_type:
                attack = px.bar(
                    x=attack_type,
                    title="Threats by Attack Type",
                    labels={"x": "Attack Type", "y": "Count"},
                    color_discrete_sequence=px.colors.qualitative.Set1
                )

                col1.plotly_chart(attack, use_container_width=True)

            if cloud_platform:
                cloud = px.pie(
                    names=cloud_platform,
                    title="Threats by Cloud Platform",
                    color_discrete_sequence=px.colors.qualitative.Set2
                )
                col2.plotly_chart(cloud, use_container_width=True)



        st.subheader("Threat Detection Overview")
        for item in threat_results:
            result = item["llm_result"]

            if isinstance(result, dict):
                result = [result]

            for threat in result:
                if threat.get("threat") == True:
                    attack_type = threat.get("attack_type", "Unknown threat").title()
                    cloud_provider = threat.get("cloud_provider", "Unknown")
                    mitre_id = threat.get("mitre_id", "Unknown")
                    user = threat.get("user", "Unknown")
                    source_ip = threat.get("source_ip") or f"{threat.get('first_source_ip', 'Unknown')} to {threat.get('second_source_ip', 'Unknown')}"
                    confidence = threat.get("confidence", "Unknown")
                    evidence = threat.get("evidence", "No evidence given")

                    with st.container(border=True):
                        st.markdown(f"#### :red[{attack_type}]")

                        threat_col1, threat_col2, threat_col3 = st.columns(3)

                        threat_col1.write("**Cloud Platform:**")
                        threat_col1.write(cloud_provider)

                        threat_col1.write("**MITRE ID:**")
                        threat_col1.write(mitre_id)

                        threat_col2.write("**User:**")
                        threat_col2.write(user)

                        threat_col2.write("**Source IP:**")
                        threat_col2.write(source_ip)

                        threat_col3.write("**Confidence:**")
                        threat_col3.write(confidence)

                        st.write("**Evidence:**")
                        st.info(evidence)

        sankey_labels = [
            f"JSON Upload<br>{len(parsed_results)} logs",
            f"Parse Uploaded JSON<br>{len(parsed_results)} logs",
            f"Order Logs by Timestamp<br>{len(parsed_results)} logs",
            f"Sliding Window Group of 20<br>{total_windows} windows",
            f"LLM Threat Detection<br>{total_windows} windows",
            f"Threat Results<br>{total_threats} threats"
        ]

        sankey_fig = go.Figure(
            go.Sankey(
                node=dict(
                    pad=20,
                    thickness=20,
                    line=dict(width=0.5),
                    label=sankey_labels
                ),
                link=dict(
                    source=[0, 1, 2, 3, 4],
                    target=[1, 2, 3, 4, 5],
                    value=[
                        len(parsed_results),
                        len(parsed_results),
                        len(parsed_results),
                        total_windows,
                        total_windows
                    ]
                )
            )
        )

        sankey_fig.update_layout(
            title_text="M-Cloud LLM Threat Detection Pipeline",
            font_size=12,
            height=500
        )

        st.plotly_chart(sankey_fig, use_container_width=True)

        # Display the LLM result as JSON
        with st.expander("View Threat Detection Results"):
            st.json(threat_results)

        # Display parsed logs in a dropdown
        with st.expander("View Parsed Cloud Logs"):
            st.dataframe(df, use_container_width=True)
        
        # Display the original uploaded JSON file 
        with st.expander("View Original Uploaded File"): 
            upload_file.seek(0) 
            original_json = json.load(upload_file) 
            st.json(original_json)
        
    except Exception as e:
        st.error(f"Could not process uploaded JSON file: {e}")