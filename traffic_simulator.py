import streamlit as st
import socket
import threading
import time
from urllib.parse import urlparse

# Function to establish a TCP connection
def establish_tcp_connection(host, port, duration):
    try:
        with socket.create_connection((host, port), timeout=5) as s:
            st.write(f"Connection established with {host}:{port}")
            time.sleep(duration)
    except Exception as e:
        st.write(f"Failed to connect to {host}:{port} - {e}")

# Function to manage TCP sessions
def start_tcp_sessions(host, port, num_sessions, session_duration, total_duration, interval):
    threads = []
    start_time = time.time()
    session_count = 0

    while session_count < num_sessions and (time.time() - start_time) < total_duration:
        t = threading.Thread(target=establish_tcp_connection, args=(host, port, session_duration))
        t.start()
        threads.append(t)
        session_count += 1
        time.sleep(interval)

    # Wait for all threads to finish
    for t in threads:
        t.join()

# Streamlit app
def main():
    st.title("TCP Traffic Simulator")

    # Input fields
    destination = st.text_input("Enter IP address or URL:", "example.com")
    port = st.number_input("Enter port number:", min_value=1, max_value=65535, value=80)
    num_sessions = st.slider("Number of TCP sessions to open:", min_value=1, max_value=20, value=5)
    session_duration = st.number_input("Duration each TCP session stays open (seconds):", min_value=1, max_value=3600, value=10)
    total_duration = st.number_input("Total execution time (seconds):", min_value=1, max_value=86400, value=60)
    interval = st.number_input("Interval between starting sessions (seconds):", min_value=0.1, max_value=10.0, value=1.0)

    # Start simulation button
    if st.button("Start Simulation"):
        # Parse the destination to get the host
        parsed_url = urlparse(destination)
        host = parsed_url.netloc or parsed_url.path  # Handles both 'example.com' and 'http://example.com'

        st.write(f"Starting TCP traffic simulation to {host}:{port}...")
        start_tcp_sessions(host, port, num_sessions, session_duration, total_duration, interval)
        st.write("Simulation completed.")

if __name__ == "__main__":
    main()
