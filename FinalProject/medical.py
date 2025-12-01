import numpy as np
import sys
import os
from datetime import datetime

# --- SETUP: IMPORT CORE KITNET CLASS ---

# 1. Define the repository path (same as your other project files)
KITSUNE_REPO_PATH = 'Kitsune-py-master' 

# 2. Add the repository path to Python's system path
sys.path.append(os.path.abspath('.'))
sys.path.append(os.path.abspath(KITSUNE_REPO_PATH))

try:
    # 3. Import the core KitNET class using its path within the repository
    # This works because we just added 'Kitsune-py-master' to the path.
    from KitNET.KitNET import KitNET 
    print("KitNET Import Successful")
except ImportError:
    print("Error: Could not import KitNET. Ensure the Kitsune-py-master folder structure is correct.")
    # Exit if the import fails to prevent further errors
    sys.exit(1)

# --- SIMULATED MEDICAL IOT DATA ---
# Features: [Heart Rate (BPM), Data Rate (kbps), Encryption Status (0=False, 1=True)]
# Status: Anomaly Score (RMSE) is set to be HIGH for anomalies and LOW for normal traffic.
MEDICAL_IOT_DATA = [
    # Normal Traffic (Used for Training) - Events 1-6
    (1700000001.0, np.array([ 85.0,  1.2, 1.0]), "Normal"),
    (1700000002.0, np.array([ 78.0,  0.8, 1.0]), "Normal"),
    (1700000003.0, np.array([ 92.0,  1.1, 1.0]), "Normal"),
    (1700000004.0, np.array([ 75.0,  1.0, 1.0]), "Normal"),
    (1700000005.0, np.array([ 83.0,  1.3, 1.0]), "Normal"),
    (1700000006.0, np.array([ 88.0,  0.9, 1.0]), "Normal"),
    
    # Anomalous Traffic - Events 7-13 (7 Anomalies)
    (1700000007.0, np.array([ 180.0, 2.5, 0.0]), "ANOMALY"), # High HR, Unencrypted
    (1700000008.0, np.array([ 75.0,  0.1, 1.0]), "ANOMALY"), # Rate Drop
    (1700000009.0, np.array([ 80.0, 15.5, 1.0]), "ANOMALY"), # Extreme Rate Spike
    (1700000010.0, np.array([ 85.0,  1.2, 0.0]), "ANOMALY"), # Encryption Loss
    (1700000011.0, np.array([ 80.0,  1.0, 0.0]), "ANOMALY"), # Rogue Device/Protocol
    (1700000012.0, np.array([ 110.0, 0.8, 1.0]), "ANOMALY"), # Internal HR Spike
    (1700000013.0, np.array([ 82.0, 25.0, 0.0]), "ANOMALY"), # Max Rate Spike + Encryption Loss
    
    # Final Normal Traffic - Events 14-15 (2 More Normal = 8 Total Normal)
    (1700000014.0, np.array([ 76.0,  1.1, 1.0]), "Normal"),
    (1700000015.0, np.array([ 84.0,  1.2, 1.0]), "Normal"),
]

# --- KITNET PARAMETERS FOR SMALL DATASET ---
n = 3 # number of features in the data vector
maxAE = 10 
FMgrace = 3 # Train feature mapping on the first 3 events
ADgrace = 3 # Train detector on the next 3 events (Total training = 6 events)
BETA = 1.10

# --- CUSTOM REPORTING MODULE ---
def generate_anomaly_report(i, score, threshold, data_vector, ground_truth):
    """Generates a structured report based on the anomaly score."""
    
    timestamp = datetime.fromtimestamp(data_vector[0]).strftime("%H:%M:%S")
    status = "ANOMALY DETECTED" if score >= threshold else "NORMAL TRAFFIC"
    
    print("-" * 50)
    print(f"[{i:02d} @ {timestamp}] {status} (GT: {ground_truth})")
    print(f"  Score: {score:.5f} (Threshold: {threshold:.5f})")
    print(f"  Features: [HR: {data_vector[1][0]:.1f}, Rate: {data_vector[1][1]:.1f}kbps, Encrypt: {int(data_vector[1][2])}]")
    print("-" * 50)
    
# ====================================================================
# MAIN EXECUTION LOOP
# ====================================================================

if __name__ == "__main__":
    
    # 1. Initialize KitNET (The Anomaly Detector)
    K = KitNET(n, max_autoencoder_size=maxAE, FM_grace_period=FMgrace, AD_grace_period=ADgrace)
    
    learned_threshold = 0.0
    max_training_score = 0.0
    total_processed = 0
    
    print("\n--- Starting Medical IoT Anomaly Simulation ---\n")

    # 2. Process (Train/Execute) each simulated event
    for timestamp, feature_vector, ground_truth in MEDICAL_IOT_DATA:
        total_processed += 1
        
        # K.process(x) automatically handles training during the grace period
        anomaly_score = K.process(feature_vector) 
        
        is_training = total_processed <= (FMgrace + ADgrace)
        
        # 3. Determine Threshold (Runs only during ADgrace period)
        if is_training and anomaly_score > 0.0:
            max_training_score = max(max_training_score, anomaly_score)
        
        # --- EXECUTION/REPORTING PHASE ---
        if total_processed > (FMgrace + ADgrace):
            
            # Set threshold only once when execution starts
            if learned_threshold == 0.0:
                final_max_score = max(max_training_score, 0.0001) 
                learned_threshold = final_max_score * BETA
                
                print("\n*** GRACE PERIOD COMPLETE ***")
                print(f"*** THRESHOLD SET *** Detection Threshold ({BETA}X): {learned_threshold:.5f}\n")

            # Generate Report for every event after training
            data_to_report = (timestamp, feature_vector, ground_truth)
            generate_anomaly_report(total_processed, anomaly_score, learned_threshold, data_to_report, ground_truth)

    print(f"\n--- Simulation Complete. Total Events: {total_processed} ---")