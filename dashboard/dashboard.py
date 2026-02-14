import streamlit as st
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

DB = "netsentry.db"

st.set_page_config(page_title="NetSentry Dashboard", layout="wide")

# ---------------- CYBER DARK THEME ---------------- #
st.markdown("""
<style>
body { background-color: #0E1117; }
.main { background-color: #0E1117; }

div[data-testid="metric-container"] {
    background-color: #161B22;
    border: 1px solid #30363D;
    padding: 15px;
    border-radius: 10px;
}

h1,h2,h3,h4 { color: #58A6FF; }

</style>
""", unsafe_allow_html=True)

# ---------------- HEADER ---------------- #
st.markdown("""
<h1 style='text-align:center;color:#58A6FF'>
🛡 NetSentry Security Operations Dashboard
</h1>
<p style='text-align:center;color:gray'>
Real-Time Network Monitoring & Intrusion Detection System
</p>
""", unsafe_allow_html=True)

# ---------------- DATABASE ---------------- #
def get_packets():
    try:
        conn = sqlite3.connect(DB)
        query = """
        SELECT timestamp, src_ip, dst_ip, protocol, src_port, dst_port, size
        FROM packets
        ORDER BY id DESC LIMIT 500
        """
        df = pd.read_sql_query(query, conn)
        conn.close()

        if df.empty:
            return pd.DataFrame()

        df = df.rename(columns={
            "timestamp": "Timestamp",
            "src_ip": "Source IP",
            "dst_ip": "Destination IP",
            "protocol": "Protocol",
            "src_port": "Source Port",
            "dst_port": "Destination Port",
            "size": "Packet Size"
        })

        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")
        df = df.sort_values(by="Timestamp", ascending=False)
        df["Timestamp"] = df["Timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

        df = df.reset_index(drop=True)
        df.index += 1
        return df

    except:
        return pd.DataFrame()

def get_alerts():
    try:
        conn = sqlite3.connect(DB)
        df = pd.read_sql_query("SELECT * FROM alerts", conn)
        conn.close()
        return df
    except:
        return pd.DataFrame()

# ---------------- SIDEBAR ---------------- #
menu = st.sidebar.selectbox("Navigation", ["Live Traffic", "Statistics", "Alerts"])
st.sidebar.markdown("---")
st.sidebar.markdown("NetSentry v1.0")

# ---------------- LIVE TRAFFIC ---------------- #
if menu == "Live Traffic":

    st.subheader("📡 Live Network Traffic")

    df = get_packets()

    if df.empty:
        st.warning("No traffic detected.")
    else:
        st.success("🟢 System Active — Monitoring Network")

        col1, col2, col3 = st.columns(3)

        col1.metric("📦 Total Packets", len(df))
        col2.metric("🌐 Unique Source IPs", df["Source IP"].nunique())
        col3.metric("🎯 Unique Destination IPs", df["Destination IP"].nunique())

        st.markdown("---")

        st.dataframe(df, use_container_width=True)

# ---------------- STATISTICS ---------------- #
elif menu == "Statistics":

    st.subheader("📊 Network Statistics")

    df = get_packets()

    if df.empty:
        st.warning("No data available.")
    else:

        # Convert back for grouping
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")

        col1, col2 = st.columns(2)

        # -------- PROTOCOL DONUT -------- #
        with col1:
            st.markdown("### 🧬 Protocol Distribution")
            proto_counts = df["Protocol"].value_counts()

            fig1, ax1 = plt.subplots()
            ax1.pie(
                proto_counts,
                labels=proto_counts.index,
                autopct="%1.1f%%",
                wedgeprops=dict(width=0.4)
            )
            st.pyplot(fig1)

        # -------- TOP SOURCE IPS -------- #
        with col2:
            st.markdown("### 🌍 Top Source IPs")
            top_ips = df["Source IP"].value_counts().head(5)

            fig2, ax2 = plt.subplots()
            ax2.bar(top_ips.index, top_ips.values)
            plt.xticks(rotation=45)
            st.pyplot(fig2)

        st.markdown("---")

        # -------- TRAFFIC TREND -------- #
        st.markdown("### 📈 Traffic Over Time")

        traffic_time = df.groupby(
            df["Timestamp"].dt.floor("min")
        ).size()

        fig3, ax3 = plt.subplots()
        ax3.plot(traffic_time.index, traffic_time.values)
        plt.xticks(rotation=45)
        st.pyplot(fig3)

# ---------------- ALERTS ---------------- #
elif menu == "Alerts":

    st.subheader("🚨 Security Alerts")

    alerts = get_alerts()

    if alerts.empty:
        st.info("No alerts detected.")
    else:
        for _, row in alerts.iterrows():
            st.markdown(f"""
            <div style='
                background-color:#3b0d0c;
                padding:15px;
                border-radius:10px;
                margin-bottom:10px;
                border-left:6px solid red;
                color:white;
            '>
                <strong>⚠ {row['timestamp']}</strong><br>
                {row['message']}
            </div>
            """, unsafe_allow_html=True)
