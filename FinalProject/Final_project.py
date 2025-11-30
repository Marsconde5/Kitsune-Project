import numpy as np
import sys
import os
from datetime import datetime
# Note: You need to ensure scapy is installed (pip install scapy)
from scapy.all import IP, TCP, UDP, ARP, ICMP, IPv6 

# --- STEP 1: IMPORTING THE KITSUNE CLASS ---
# Path to the Kitsune-py repository folder (where Kitsune.py lives)
KITSUNE_REPO_PATH = 'Kitsune-py-master' 

# Add the repository path to Python's system path to enable imports
sys.path.append(os.path.abspath('.'))
sys.path.append(os.path.abspath(KITSUNE_REPO_PATH))

try:
    from Kitsune import Kitsune
    print("Importing Kitsune Library (Success)")
except ImportError as e:
    print(f"Error: Could not import Kitsune. Please check the KITSUNE_REPO_PATH variable.")
    print(f"Original ImportError: {e}")
    sys.exit(1)

# ====================================================================
# CUSTOM REPORTING MODULES
# ====================================================================

def get_packet_metadata(kitsune_instance):
    """
    Retrieves the last processed packet's metadata using the exposed 'fe.packet' attribute.
    This relies on the manual modification made to FeatureExtractor.py.
    """
    fe = kitsune_instance.FE
    
    # Accesses the Scapy packet object, which was exposed as 'fe.packet' 
    packet = fe.packet if hasattr(fe, 'packet') else None 
    
    # Default metadata if packet is None or raw access fails
    default_metadata = {'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3], 
                        'src_ip': 'N/A', 'dst_port': 'N/A', 'protocol': 'N/A'}

    if packet:
        # FIX: Explicitly convert packet.time to float to avoid DeprecationWarning
        metadata = {'timestamp': datetime.fromtimestamp(float(packet.time)).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]}
        
        # Source IP and Protocol
        if packet.haslayer(IP):
            metadata['src_ip'] = packet[IP].src
            # Use 'packet[IP].proto' for IP protocol number, or check for common transport layer protocols
            metadata['protocol'] = packet[IP].proto 
        else:
            metadata['src_ip'] = packet.src if packet.src else 'No_IP'
            metadata['protocol'] = 'ARP/Other'

        # Destination Port
        if packet.haslayer(TCP):
            metadata['dst_port'] = packet[TCP].dport
        elif packet.haslayer(UDP):
            metadata['dst_port'] = packet[UDP].dport
        else:
            metadata['dst_port'] = 'N/A'
            
        return metadata
        
    return default_metadata


def generate_anomaly_report(score, threshold, metadata, feature_vector):
    """Logs a detailed report entry for any score exceeding the threshold."""
    
    if threshold > 0.0 and score >= threshold:
        # Check if the feature vector array is empty and create a note
        if feature_vector.size == 0:
            feature_summary = 'Feature vector data not fully exposed by AD component.'
        else:
            # Extract the first five features for the report
            feature_summary = ', '.join(f'{f:.4f}' for f in feature_vector[:5]) + ', ...'
        
        report_entry = (
            f"ALERT [{metadata['timestamp']}] | "
            f"Score: **{score:.5f}** (Threshold: {threshold:.5f}) | "
            f"VERDICT: **ANOMALY DETECTED**\n"
            f"\tSource/Target: {metadata['src_ip']} -> Port {metadata['dst_port']} ({metadata['protocol']})\n"
            f"\tTriggering Features (Partial): {feature_summary}\n"
        )
        print(report_entry)
        
        # Save to a log file for the final deliverable
        with open("anomaly_report.txt", "a") as f:
            f.write(report_entry + "\n")

# ====================================================================
# MAIN EXECUTION LOOP
# ====================================================================

if __name__ == "__main__":
    # --- Configuration ---
    # PCAP_FILE_PATH must point to your unzipped mirai.pcap file
    PCAP_FILE_PATH = "Kitsune-py-master/mirai.pcap" 
    
    MAX_AE_SIZE = 10         
    FM_GRACE_PACKETS = 5000  
    AD_GRACE_PACKETS = 50000 
    BETA = 1.10             

    # 1. Initialize Kitsune object
    print("--- Initializing Kitsune and starting TShark/Scapy Packet Parsing ---")
    
    # FIX: Using the required positional argument 'None' for 'limit'
    K = Kitsune(PCAP_FILE_PATH, None, max_autoencoder_size=MAX_AE_SIZE, 
                FM_grace_period=FM_GRACE_PACKETS, AD_grace_period=AD_GRACE_PACKETS)
    
    learned_threshold = 0.0
    max_training_score = 0.0
    
    print(f"Kitsune Initialized: FM Grace={FM_GRACE_PACKETS}, AD Grace={AD_GRACE_PACKETS}")
    print("\n--- Starting Kitsune Online Processing Loop ---\n")
    
    # 2. Start Online Processing
    while True:
        anomaly_score = K.proc_next_packet()
        
        if anomaly_score == -1:
            break 
            
        # FIX: Using the correct attribute 'curPacketIndx'
        total_processed = K.FE.curPacketIndx 
        is_training = total_processed <= (FM_GRACE_PACKETS + AD_GRACE_PACKETS)
        
        # 3. Determine Threshold (Learned during AD grace period)
        if is_training and anomaly_score > 0.0:
            max_training_score = max(max_training_score, anomaly_score)
        
        # --- FINAL FIX: Stop Repetitive Threshold Setting ---
        if total_processed > (FM_GRACE_PACKETS + AD_GRACE_PACKETS) and learned_threshold == 0.0:
            
            # 1. Calculate the score, forcing a minimal non-zero value (0.0001) if max_training_score is zero.
            final_max_score = max(max_training_score, 0.0001) 
            learned_threshold = final_max_score * BETA
            
            # 2. Print the completion message ONLY ONCE
            print(f"\n*** AD GRACE COMPLETE *** Learned Max Training Score: {max_training_score:.5f}")
            print(f"*** THRESHOLD SET *** Detection Threshold ({BETA}X): {learned_threshold:.5f}\n")
            
        # 4. Custom Reporting Logic (Only executed after the full grace period)
        if learned_threshold > 0.0:
            packet_metadata = get_packet_metadata(K)
            
            # FIX: Use the correct internal attribute 'AnomDetector'
            last_feature_vector = K.AnomDetector.last_feature_vector if hasattr(K.AnomDetector, 'last_feature_vector') else np.array([])
            
            generate_anomaly_report(anomaly_score, learned_threshold, packet_metadata, last_feature_vector)

        # Progress indicator
        if total_processed % 5000 == 0:
            mode = "TRAINING" if is_training else "EXECUTION"
            print(f"[{total_processed:06d}] Mode: {mode} | Last Score: {anomaly_score:.5f}")

    print(f"\n--- Processing Complete. Total Packets: {total_processed} ---")
    print("Check 'anomaly_report.txt' for detailed anomaly alerts.")