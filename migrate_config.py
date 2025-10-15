#!/usr/bin/env python3
"""
Migration script to convert config.ini to .env.local format
"""

import configparser
import os
from pathlib import Path

def migrate_config_ini():
    """Migrate config.ini to .env.local format"""
    script_dir = Path(__file__).parent
    config_ini = script_dir / 'config.ini'
    env_local = script_dir / '.env.local'
    
    if not config_ini.exists():
        print("No config.ini found, nothing to migrate")
        return
    
    if env_local.exists():
        try:
            response = input(f".env.local already exists. Overwrite? [y/N]: ")
            if response.lower() != 'y':
                print("Migration cancelled")
                return
        except EOFError:
            # Non-interactive mode, create backup
            backup_name = f".env.local.backup-{int(__import__('time').time())}"
            print(f"Non-interactive mode: backing up existing .env.local to {backup_name}")
            env_local.rename(backup_name)
    
    print("Migrating config.ini to .env.local...")
    
    # Parse config.ini
    config = configparser.ConfigParser()
    config.read(config_ini)
    
    # Create .env.local content
    env_content = []
    env_content.append("# MeshCore Packet Capture - Local Configuration")
    env_content.append("# Migrated from config.ini")
    env_content.append("")
    
    # Connection settings
    env_content.append("# ============================================================================")
    env_content.append("# CONNECTION SETTINGS")
    env_content.append("# ============================================================================")
    
    if config.has_section('connection'):
        connection_type = config.get('connection', 'connection_type', fallback='ble')
        env_content.append(f"PACKETCAPTURE_CONNECTION_TYPE={connection_type}")
        
        if connection_type == 'serial':
            serial_port = config.get('connection', 'serial_port', fallback='')
            if serial_port:
                env_content.append(f"PACKETCAPTURE_SERIAL_PORTS={serial_port}")
        else:
            ble_address = config.get('connection', 'ble_address', fallback='')
            ble_device_name = config.get('connection', 'ble_device_name', fallback='')
            if ble_address:
                env_content.append(f"PACKETCAPTURE_BLE_ADDRESS={ble_address}")
            if ble_device_name:
                env_content.append(f"PACKETCAPTURE_BLE_DEVICE_NAME={ble_device_name}")
        
        timeout = config.get('connection', 'timeout', fallback='')
        if timeout:
            env_content.append(f"PACKETCAPTURE_TIMEOUT={timeout}")
        
        max_retries = config.get('connection', 'max_connection_retries', fallback='')
        if max_retries:
            env_content.append(f"PACKETCAPTURE_MAX_CONNECTION_RETRIES={max_retries}")
        
        retry_delay = config.get('connection', 'connection_retry_delay', fallback='')
        if retry_delay:
            env_content.append(f"PACKETCAPTURE_CONNECTION_RETRY_DELAY={retry_delay}")
        
        health_check = config.get('connection', 'health_check_interval', fallback='')
        if health_check:
            env_content.append(f"PACKETCAPTURE_HEALTH_CHECK_INTERVAL={health_check}")
    
    env_content.append("")
    
    # IATA code
    env_content.append("# ============================================================================")
    env_content.append("# LOCATION CODE")
    env_content.append("# ============================================================================")
    env_content.append("PACKETCAPTURE_IATA=sea  # Change this to your IATA code")
    env_content.append("")
    
    # MQTT settings
    env_content.append("# ============================================================================")
    env_content.append("# MQTT BROKER 1 (Primary)")
    env_content.append("# ============================================================================")
    
    if config.has_section('mqtt'):
        server = config.get('mqtt', 'server', fallback='')
        if server:
            env_content.append("PACKETCAPTURE_MQTT1_ENABLED=true")
            env_content.append(f"PACKETCAPTURE_MQTT1_SERVER={server}")
            
            port = config.get('mqtt', 'port', fallback='1883')
            env_content.append(f"PACKETCAPTURE_MQTT1_PORT={port}")
            
            username = config.get('mqtt', 'username', fallback='')
            password = config.get('mqtt', 'password', fallback='')
            if username:
                env_content.append(f"PACKETCAPTURE_MQTT1_USERNAME={username}")
                env_content.append(f"PACKETCAPTURE_MQTT1_PASSWORD={password}")
            
            qos = config.get('mqtt', 'qos', fallback='0')
            env_content.append(f"PACKETCAPTURE_MQTT1_QOS={qos}")
            
            retain = config.get('mqtt', 'retain', fallback='true')
            env_content.append(f"PACKETCAPTURE_MQTT1_RETAIN={retain}")
            
            # MQTT reconnection settings
            max_mqtt_retries = config.get('mqtt', 'max_mqtt_retries', fallback='')
            if max_mqtt_retries:
                env_content.append(f"PACKETCAPTURE_MAX_MQTT_RETRIES={max_mqtt_retries}")
            
            mqtt_retry_delay = config.get('mqtt', 'mqtt_retry_delay', fallback='')
            if mqtt_retry_delay:
                env_content.append(f"PACKETCAPTURE_MQTT_RETRY_DELAY={mqtt_retry_delay}")
        else:
            env_content.append("PACKETCAPTURE_MQTT1_ENABLED=false")
    else:
        env_content.append("PACKETCAPTURE_MQTT1_ENABLED=false")
    
    env_content.append("")
    
    # Topics
    env_content.append("# ============================================================================")
    env_content.append("# GLOBAL MQTT TOPICS")
    env_content.append("# ============================================================================")
    
    if config.has_section('topics'):
        status_topic = config.get('topics', 'status', fallback='')
        if status_topic:
            env_content.append(f"PACKETCAPTURE_TOPIC_STATUS={status_topic}")
        
        raw_topic = config.get('topics', 'raw', fallback='')
        if raw_topic:
            env_content.append(f"PACKETCAPTURE_TOPIC_RAW={raw_topic}")
        
        decoded_topic = config.get('topics', 'decoded', fallback='')
        if decoded_topic:
            env_content.append(f"PACKETCAPTURE_TOPIC_DECODED={decoded_topic}")
        
        packets_topic = config.get('topics', 'packets', fallback='')
        if packets_topic:
            env_content.append(f"PACKETCAPTURE_TOPIC_PACKETS={packets_topic}")
        
        debug_topic = config.get('topics', 'debug', fallback='')
        if debug_topic:
            env_content.append(f"PACKETCAPTURE_TOPIC_DEBUG={debug_topic}")
    
    env_content.append("")
    
    # Packet capture settings
    env_content.append("# ============================================================================")
    env_content.append("# PACKET CAPTURE SETTINGS")
    env_content.append("# ============================================================================")
    
    if config.has_section('packetcapture'):
        origin = config.get('packetcapture', 'origin', fallback='')
        if origin:
            env_content.append(f"PACKETCAPTURE_ORIGIN={origin}")
        
        advert_interval = config.get('packetcapture', 'advert_interval_hours', fallback='')
        if advert_interval:
            env_content.append(f"PACKETCAPTURE_ADVERT_INTERVAL_HOURS={advert_interval}")
        
        rf_data_timeout = config.get('packetcapture', 'rf_data_timeout', fallback='')
        if rf_data_timeout:
            env_content.append(f"PACKETCAPTURE_RF_DATA_TIMEOUT={rf_data_timeout}")
    
    # Write .env.local
    with open(env_local, 'w') as f:
        f.write('\n'.join(env_content))
    
    print(f"Migration complete! Created {env_local}")
    print("")
    print("Next steps:")
    print("1. Review the generated .env.local file")
    print("2. Update PACKETCAPTURE_IATA to your actual IATA code")
    print("3. Test the script with: python3 packet_capture.py")
    print("4. Once working, you can remove config.ini")

if __name__ == "__main__":
    migrate_config_ini()
