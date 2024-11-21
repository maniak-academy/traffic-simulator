import streamlit as st
import asyncio
import aiohttp
import time
from urllib.parse import urlparse
import pandas as pd
import ssl

# Function to simulate and display TCP/TLS handshake and HTTP GET
async def simulate_tcp_tls_http(session_id, animation_placeholder, use_https, cipher_suite):
    steps = []

    if use_https:
        # TLS Handshake steps
        steps.extend([
            f"Session {session_id}: [ ] -> [ ] Initiating TCP Connection...",
            f"Session {session_id}: [ ] -> [ ] Starting TLS Handshake...",
            f"Session {session_id}: [ClientHello] -> [ ] Sending ClientHello...",
            f"Session {session_id}: [ ] <- [ServerHello] Receiving ServerHello...",
            f"Session {session_id}: [ ] <- [Certificate] Receiving Server Certificate...",
            f"Session {session_id}: [ ] -> [ ] Verifying Server Certificate...",
            f"Session {session_id}: [ ] -> [ ] TLS Handshake Completed.",
            f"Session {session_id}: [ ] -> [ ] Secure Connection Established using {cipher_suite}.",
        ])
    else:
        # TCP Handshake steps
        steps.extend([
            f"Session {session_id}: [ ] -> [ ] Initiating TCP Connection...",
            f"Session {session_id}: [SYN] -> [ ] Sending SYN...",
            f"Session {session_id}: [SYN] -> [SYN-ACK] Waiting for SYN-ACK...",
            f"Session {session_id}: [SYN] <- [SYN-ACK] Received SYN-ACK.",
            f"Session {session_id}: [ACK] -> [ ] Sending ACK...",
            f"Session {session_id}: [ ] -> [ ] TCP Connection Established.",
        ])

    # Common steps for HTTP GET
    steps.extend([
        f"Session {session_id}: [GET] -> [ ] Sending HTTP GET Request...",
        f"Session {session_id}: [ ] <- [200 OK] Receiving HTTP Response...",
        f"Session {session_id}: [ ] -> [FIN] Closing Connection.",
    ])

    for step in steps:
        # Update the placeholder with the current step
        animation_placeholder.text(step)
        await asyncio.sleep(0.5)  # Simulate time between steps

# Function to make an HTTP/HTTPS GET request
async def make_http_request(session, url, session_duration, active_conn, closed_conn, session_id, animation_placeholder, use_https, ssl_context):
    try:
        # Simulate TCP/TLS handshake and HTTP GET
        cipher_suite = 'TLS_AES_256_GCM_SHA384' if use_https else 'N/A'
        await simulate_tcp_tls_http(session_id, animation_placeholder, use_https, cipher_suite)

        async with session.get(url, ssl=ssl_context, timeout=5) as response:
            status = response.status
            # Keep the connection open for the specified duration
            await asyncio.sleep(session_duration)
    except Exception as e:
        # Handle exceptions (e.g., SSL errors, connection errors)
        animation_placeholder.text(f"Session {session_id}: Error - {e}")
    finally:
        # Update connection counts
        active_conn['count'] -= 1
        closed_conn['count'] += 1
        # Optionally, keep the final animation displayed
        # animation_placeholder.empty()  # Commented out to keep animations visible

# Function to manage HTTP/HTTPS sessions
async def start_http_sessions(url, num_sessions, session_duration, total_duration, interval, chart_placeholder, animations_container, use_https, ignore_ssl_errors):
    tasks = []
    start_time = time.time()
    active_conn = {'count': 0}
    closed_conn = {'count': 0}
    session_counter = 0

    # List to store the connection data over time
    conn_data_list = []

    # Create a semaphore to limit the number of concurrent sessions
    semaphore = asyncio.Semaphore(num_sessions)

    # Create SSL context based on user preference
    if use_https:
        ssl_context = ssl.create_default_context()
        if ignore_ssl_errors:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
    else:
        ssl_context = None  # Not needed for HTTP

    async with aiohttp.ClientSession() as session:
        while (time.time() - start_time) < total_duration:
            if active_conn['count'] >= num_sessions:
                await asyncio.sleep(interval)
                continue

            async with semaphore:
                session_counter += 1
                session_id = session_counter

                # Update connection counts
                active_conn['count'] += 1

                # Record the current time and connection counts
                current_time = time.time() - start_time
                conn_data_list.append({
                    'Time': current_time,
                    'Active Connections': active_conn['count'],
                    'Closed Connections': closed_conn['count']
                })

                # Convert list to DataFrame
                conn_data = pd.DataFrame(conn_data_list)

                # Update the chart
                chart_placeholder.line_chart(conn_data.set_index('Time'))

                # Create a unique placeholder for each session animation
                animation_placeholder = animations_container.container()

                # Start the HTTP/HTTPS request task
                task = asyncio.create_task(make_http_request(
                    session, url, session_duration, active_conn, closed_conn,
                    session_id, animation_placeholder, use_https, ssl_context))
                tasks.append(task)

                await asyncio.sleep(interval)

        # Wait for all tasks to complete
        await asyncio.gather(*tasks)

        # Final chart update after all tasks are completed
        current_time = time.time() - start_time
        conn_data_list.append({
            'Time': current_time,
            'Active Connections': active_conn['count'],
            'Closed Connections': closed_conn['count']
        })
        conn_data = pd.DataFrame(conn_data_list)
        chart_placeholder.line_chart(conn_data.set_index('Time'))

# Streamlit app
def main():
    st.title("HTTP/HTTPS Traffic Simulator with TLS Handshake Animation")

    # Input fields
    destination = st.text_input("Enter URL:", "example.com")

    # Protocol selection
    protocol = st.radio("Select Protocol:", ["HTTP", "HTTPS"])
    use_https = protocol == "HTTPS"

    # Option to ignore SSL certificate verification
    ignore_ssl_errors = False
    if use_https:
        ignore_ssl_errors = st.checkbox("Ignore SSL Certificate Verification (Use with caution for self-signed certificates)")

    num_sessions = st.slider("Maximum concurrent sessions:", min_value=1, max_value=10, value=5)
    session_duration = st.number_input("Duration each session stays open (seconds):", min_value=1, max_value=3600, value=5)
    total_duration = st.number_input("Total execution time (seconds):", min_value=1, max_value=86400, value=30)
    interval = st.number_input("Interval between starting sessions (seconds):", min_value=0.1, max_value=10.0, value=1.0)

    # Start simulation button
    if st.button("Start Simulation"):
        # Parse the destination to get the URL
        parsed_url = urlparse(destination)
        if parsed_url.scheme:
            url = parsed_url.geturl()
        else:
            url = f"{protocol.lower()}://{parsed_url.geturl()}"

        st.write(f"Starting {protocol} traffic simulation to {url}...")

        # Placeholder for the chart
        chart_placeholder = st.empty()

        # Container for animations
        st.subheader("Session Animations")
        animations_container = st.container()

        # Run the async function
        asyncio.run(start_http_sessions(
            url, num_sessions, session_duration, total_duration, interval,
            chart_placeholder, animations_container, use_https, ignore_ssl_errors))

        st.write("Simulation completed.")

if __name__ == "__main__":
    main()
