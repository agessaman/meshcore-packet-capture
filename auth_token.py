#!/usr/bin/env python3
"""
MeshCore Auth Token Generator
Generates JWT-style authentication tokens for MQTT authentication

This implementation uses on-device signing by default (via meshcore_py),
with fallback options to Python signing or meshcore-decoder CLI.

Environment variables:
    AUTH_TOKEN_METHOD: Signing method preference
        - "device" (default): Use on-device signing via meshcore instance
        - "python": Use pure Python implementation with PyNaCl
        - "meshcore-decoder": Use meshcore-decoder CLI tool
"""
import json
import base64
import hashlib
import time
import sys
import os
import asyncio
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

try:
    import nacl.bindings
    import nacl.signing
    import nacl.exceptions
except ImportError:
    raise ImportError(
        "PyNaCl is required for JWT token generation. "
        "Please install it with: pip install pynacl"
    )


class AuthTokenPayload:
    """JWT-style token payload for MeshCore authentication"""
    def __init__(self, 
                 public_key: str,
                 iat: Optional[int] = None,
                 exp: Optional[int] = None,
                 aud: Optional[str] = None,
                 **kwargs):
        self.public_key = public_key.upper()
        self.iat = iat if iat is not None else int(time.time())
        self.exp = exp
        self.aud = aud
        self.custom_claims = kwargs
    
    def to_dict(self) -> Dict[str, Any]:
        payload = {
            'publicKey': self.public_key,
            'iat': self.iat
        }
        if self.exp is not None:
            payload['exp'] = self.exp
        if self.aud is not None:
            payload['aud'] = self.aud
        payload.update(self.custom_claims)
        return payload


def base64url_encode(data: bytes) -> str:
    """Base64url encode (URL-safe base64 without padding)"""
    b64 = base64.b64encode(data).decode('ascii')
    return b64.replace('+', '-').replace('/', '_').replace('=', '')


def base64url_decode(data: str) -> bytes:
    """Base64url decode"""
    b64 = data.replace('-', '+').replace('_', '/')
    padding = 4 - (len(b64) % 4)
    if padding != 4:
        b64 += '=' * padding
    return base64.b64decode(b64)


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_str.replace('0x', '').replace(' ', ''))


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string (lowercase)"""
    return data.hex()


def int_to_bytes_le(value: int, length: int) -> bytes:
    """Convert integer to little-endian bytes"""
    return value.to_bytes(length, byteorder='little')


def bytes_to_int_le(data: bytes) -> int:
    """Convert little-endian bytes to integer"""
    return int.from_bytes(data, byteorder='little')


# Ed25519 group order
L = 2**252 + 27742317777372353535851937790883648493


def ed25519_sign_with_expanded_key(message: bytes, scalar: bytes, prefix: bytes, public_key: bytes) -> bytes:
    """
    Sign a message using Ed25519 with pre-expanded key (orlp format)
    
    This implements RFC 8032 Ed25519 signing with an already-expanded key.
    This matches exactly how orlp/ed25519's ed25519_sign() works.
    
    Args:
        message: Message to sign
        scalar: First 32 bytes of orlp private key (clamped scalar)
        prefix: Last 32 bytes of orlp private key (prefix for nonce)
        public_key: 32-byte public key
        
    Returns:
        64-byte signature (R || s)
    """
    # Step 1: Compute nonce r = H(prefix || message) mod L
    h_r = hashlib.sha512(prefix + message).digest()
    r = bytes_to_int_le(h_r) % L
    
    # Step 2: Compute R = r * B (base point multiplication)
    r_bytes = int_to_bytes_le(r, 32)
    R = nacl.bindings.crypto_scalarmult_ed25519_base_noclamp(r_bytes)
    
    # Step 3: Compute challenge k = H(R || public_key || message) mod L
    h_k = hashlib.sha512(R + public_key + message).digest()
    k = bytes_to_int_le(h_k) % L
    
    # Step 4: Compute s = (r + k * scalar) mod L
    scalar_int = bytes_to_int_le(scalar)
    s = (r + k * scalar_int) % L
    s_bytes = int_to_bytes_le(s, 32)
    
    # Step 5: Signature is R || s
    return R + s_bytes


def _create_auth_token_internal(
    payload: AuthTokenPayload,
    private_key_hex: str,
    public_key_hex: str
) -> str:
    """
    Internal function to create a signed authentication token
    
    This signs DIRECTLY with the 64-byte orlp private key.
    NO SEED REQUIRED! This matches exactly how meshcore-decoder works.
    
    Args:
        payload: Token payload containing claims
        private_key_hex: 64-byte private key in hex (orlp format: scalar || prefix)
        public_key_hex: 32-byte public key in hex
        
    Returns:
        JWT-style token string in format: header.payload.signature
    """
    # Create header
    header = {
        'alg': 'Ed25519',
        'typ': 'JWT'
    }
    
    # Ensure publicKey is in the payload (normalize to uppercase)
    payload.public_key = public_key_hex.upper()
    
    # Encode header and payload as JSON (compact format)
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload.to_dict(), separators=(',', ':'))
    
    # Encode to UTF-8 bytes
    header_bytes = header_json.encode('utf-8')
    payload_bytes = payload_json.encode('utf-8')
    
    # Base64url encode
    header_encoded = base64url_encode(header_bytes)
    payload_encoded = base64url_encode(payload_bytes)
    
    # Create signing input
    signing_input = f"{header_encoded}.{payload_encoded}"
    signing_input_bytes = signing_input.encode('utf-8')
    
    # Parse keys
    private_bytes = hex_to_bytes(private_key_hex)
    public_bytes = hex_to_bytes(public_key_hex)
    
    if len(private_bytes) != 64:
        raise ValueError(f"Private key must be 64 bytes, got {len(private_bytes)}")
    
    if len(public_bytes) != 32:
        raise ValueError(f"Public key must be 32 bytes, got {len(public_bytes)}")
    
    # Extract scalar and prefix from orlp private key
    scalar = private_bytes[:32]
    prefix = private_bytes[32:64]
    
    # Sign using Ed25519 with expanded key (no seed required!)
    signature_bytes = ed25519_sign_with_expanded_key(
        signing_input_bytes,
        scalar,
        prefix,
        public_bytes
    )
    
    # Convert signature to hex (lowercase)
    signature_hex = bytes_to_hex(signature_bytes)
    
    # Return JWT format with hex signature
    return f"{header_encoded}.{payload_encoded}.{signature_hex}"


async def _retryable_device_sign(
    sign_func,
    command_name: str = "sign",
    timeout: float = 20.0,
    max_retries: int = 3,
    retry_delay: float = 0.3,
    backoff_multiplier: float = 1.5
):
    """
    Execute a device signing command with timeout and retry logic.
    
    Args:
        sign_func: Async function that returns a meshcore Event
        command_name: Name of the command for logging
        timeout: Timeout in seconds for each attempt
        max_retries: Maximum number of retry attempts (including initial attempt)
        retry_delay: Initial delay between retries in seconds
        backoff_multiplier: Multiplier for exponential backoff
    
    Returns:
        Event object from the command
    
    Raises:
        Exception: If all retries fail
    """
    from meshcore import EventType
    
    last_error = None
    current_delay = retry_delay
    
    for attempt in range(max_retries):
        try:
            # Add small delay between retries (except first attempt)
            if attempt > 0:
                await asyncio.sleep(current_delay)
                current_delay *= backoff_multiplier  # Exponential backoff
            
            # Execute command with timeout
            result = await asyncio.wait_for(
                sign_func(),
                timeout=timeout
            )
            
            # Check if result is an error
            if result and hasattr(result, 'type'):
                if result.type == EventType.ERROR:
                    error_payload = result.payload if hasattr(result, 'payload') else {}
                    error_reason = error_payload.get('reason', 'unknown')
                    
                    # Check if it's a transient error that we should retry
                    if error_reason == 'no_event_received' and attempt < max_retries - 1:
                        last_error = f"{command_name} failed: {error_reason}"
                        logger.debug(f"{last_error} (attempt {attempt + 1}/{max_retries})")
                        continue
                    else:
                        # Permanent error or last attempt
                        raise Exception(f"{command_name} failed: {error_payload}")
                else:
                    # Success - return the result
                    if attempt > 0:
                        logger.debug(f"{command_name} succeeded on attempt {attempt + 1}")
                    return result
            else:
                # Unexpected result format
                raise Exception(f"{command_name} returned unexpected result format")
                
        except asyncio.TimeoutError:
            last_error = f"{command_name} timed out after {timeout}s"
            if attempt < max_retries - 1:
                logger.debug(f"{last_error} (attempt {attempt + 1}/{max_retries})")
                continue
            else:
                raise Exception(f"{last_error} (all {max_retries} attempts exhausted)")
        except Exception as e:
            # Re-raise if it's not a retryable error
            if "failed:" in str(e) and attempt < max_retries - 1:
                last_error = str(e)
                logger.debug(f"{last_error} (attempt {attempt + 1}/{max_retries})")
                continue
            raise
    
    # All retries failed
    raise Exception(f"{command_name} failed after {max_retries} attempts: {last_error}")


async def _create_auth_token_with_device(
    payload: AuthTokenPayload,
    public_key_hex: str,
    meshcore_instance,
    chunk_size: int = None
) -> str:
    """
    Create JWT token using on-device signing via meshcore_py
    
    Args:
        payload: Token payload containing claims
        public_key_hex: 32-byte public key in hex
        meshcore_instance: Connected MeshCore instance
        
    Returns:
        JWT-style token string
    """
    # Import meshcore here to avoid circular imports
    try:
        from meshcore import EventType
    except ImportError:
        raise ImportError("meshcore package required for on-device signing")
    
    if not meshcore_instance:
        raise Exception("MeshCore instance not provided")
    
    if not meshcore_instance.is_connected:
        raise Exception("MeshCore instance not connected")
    
    if not hasattr(meshcore_instance, 'commands'):
        raise Exception("MeshCore instance does not support commands")
    
    # Ensure device is ready - wait a brief moment if needed
    # (Some operations like private key export might need the device to be ready)
    # Also ensure connection is still active
    if not meshcore_instance.is_connected:
        raise Exception("MeshCore instance disconnected before signing")
    await asyncio.sleep(0.2)
    
    # IMPORTANT: The device signs with self_id.sign(), which uses the device's LocalIdentity
    # The LocalIdentity has its own pub_key and prv_key that may differ from the exported key.
    # We MUST use the device's actual signing public key (from self_id) in the JWT payload
    # so the signature will verify correctly.
    # 
    # According to the firmware: self_id.sign() calls ed25519_sign() with:
    #   - pub_key from LocalIdentity (self_id)
    #   - prv_key from LocalIdentity (self_id)
    # This is standard Ed25519 (RFC 8032), so the signature will verify with the matching public key.
    device_signing_public_key = public_key_hex  # Default to provided key
    if hasattr(meshcore_instance, 'self_info') and meshcore_instance.self_info:
        device_info_public_key = meshcore_instance.self_info.get('public_key', '')
        if device_info_public_key:
            # Normalize to hex string if it's bytes
            if isinstance(device_info_public_key, bytes):
                device_info_public_key = device_info_public_key.hex()
            device_signing_public_key = device_info_public_key.upper()
            if device_signing_public_key != public_key_hex.upper():
                logger.debug("⚠️  Device's self_id public key differs from exported key")
                logger.debug("  Using device's self_id public key for JWT payload (required for verification)")
                logger.debug(f"  Device signing key (self_id): {device_signing_public_key[:32]}...")
                logger.debug(f"  Exported key: {public_key_hex[:32]}...")
            else:
                logger.debug("✓ Device's self_id public key matches exported key")
    else:
        logger.debug("⚠️  Could not get device's self_info, using provided public key")
        logger.debug("  If signature doesn't verify, device may be using different key")
    
    # Update payload with the device's actual signing public key (from self_id)
    # This is critical: the signature was created with self_id's private key,
    # so it will only verify with self_id's public key
    payload.public_key = device_signing_public_key
    
    # Create header and payload
    header = {
        'alg': 'Ed25519',
        'typ': 'JWT'
    }
    
    # Encode header and payload as JSON (compact format)
    header_json = json.dumps(header, separators=(',', ':'))
    payload_json = json.dumps(payload.to_dict(), separators=(',', ':'))
    
    # Base64url encode
    header_encoded = base64url_encode(header_json.encode('utf-8'))
    payload_encoded = base64url_encode(payload_json.encode('utf-8'))
    
    # Create signing input
    signing_input = f"{header_encoded}.{payload_encoded}"
    signing_input_bytes = signing_input.encode('utf-8')
    
    # Debug: Output the signing input for troubleshooting
    logger.debug("Signing input (message to be signed):")
    logger.debug(f"  Full string: {signing_input}")
    logger.debug(f"  Length: {len(signing_input)} characters ({len(signing_input_bytes)} bytes)")
    logger.debug(f"  Hex representation: {signing_input_bytes.hex()}")
    logger.debug(f"  Header part: {header_encoded}")
    logger.debug(f"  Payload part: {payload_encoded}")
    
    # Use meshcore_py signing API
    # The sign() method handles chunking internally via sign_start/sign_data/sign_finish
    # Based on meshcore_py implementation and example: https://github.com/agessaman/meshcore_py/blob/dev/examples/ble_sign_example.py
    if not hasattr(meshcore_instance.commands, 'sign'):
        raise Exception("Device signing method 'sign()' not available")
    
    # Debug: Log what we're about to sign
    logger.debug("About to sign with device:")
    logger.debug(f"  Data length: {len(signing_input_bytes)} bytes")
    logger.debug(f"  Data (first 100 bytes hex): {signing_input_bytes[:100].hex()}")
    logger.debug(f"  Data (last 100 bytes hex): {signing_input_bytes[-100:].hex() if len(signing_input_bytes) > 100 else signing_input_bytes.hex()}")
    
    # For debugging: manually implement the signing flow to see what's happening
    # This will help us verify if sign() is working correctly
    if os.getenv('DEBUG_DEVICE_SIGNING', '').lower() == 'true':
        logger.debug("Using manual signing flow for debugging")
        try:
            from meshcore import EventType
            
            # Verify device's public key matches what we expect
            # The device signs with self_id, which might be different from exported key
            try:
                device_id_result = await meshcore_instance.commands.get_id()
                if device_id_result and device_id_result.type != EventType.ERROR:
                    device_id = device_id_result.payload.get("id", {})
                    device_public_key = device_id.get("public_key", "")
                    if device_public_key:
                        device_public_key_hex = device_public_key.hex() if isinstance(device_public_key, bytes) else device_public_key
                        expected_public_key_hex = public_key_hex.upper()
                        logger.debug(f"Device public key from get_id: {device_public_key_hex[:32]}...")
                        logger.debug(f"Expected public key: {expected_public_key_hex[:32]}...")
                        if device_public_key_hex.upper() != expected_public_key_hex:
                            logger.debug("⚠️  WARNING: Device public key does NOT match exported key!")
                            logger.debug("  Device will sign with different key than expected")
                        else:
                            logger.debug("✓ Device public key matches exported key")
            except Exception as e:
                logger.debug(f"Could not verify device public key: {e}")
            
            # Manual sign_start
            start_evt = await meshcore_instance.commands.sign_start()
            if start_evt.type == EventType.ERROR:
                raise Exception(f"sign_start failed: {start_evt.payload}")
            max_len = start_evt.payload.get("max_length", 0)
            logger.debug(f"sign_start: max_length={max_len}")
            
            # Manual sign_data chunks - use provided chunk_size or library's default
            # Get default chunk_size from sign() method if available, otherwise use 120
            default_chunk_size = chunk_size if chunk_size is not None else 120
            if default_chunk_size is None or default_chunk_size <= 0:
                # Try to get default from function signature
                if hasattr(meshcore_instance.commands.sign, '__defaults__'):
                    import inspect
                    sig = inspect.signature(meshcore_instance.commands.sign)
                    if 'chunk_size' in sig.parameters:
                        default_chunk_size = sig.parameters['chunk_size'].default if sig.parameters['chunk_size'].default != inspect.Parameter.empty else 120
                if default_chunk_size is None or default_chunk_size <= 0:
                    default_chunk_size = 120
            
            total_sent = 0
            for idx in range(0, len(signing_input_bytes), default_chunk_size):
                chunk = signing_input_bytes[idx:idx + default_chunk_size]
                logger.debug(f"Sending chunk {idx//default_chunk_size + 1}: {len(chunk)} bytes (offset {idx})")
                logger.debug(f"  Chunk hex (first 32): {chunk[:32].hex()}")
                logger.debug(f"  Chunk hex (last 32): {chunk[-32:].hex() if len(chunk) >= 32 else chunk.hex()}")
                data_evt = await meshcore_instance.commands.sign_data(chunk)
                if data_evt.type == EventType.ERROR:
                    raise Exception(f"sign_data failed: {data_evt.payload}")
                total_sent += len(chunk)
                # Small delay between chunks to ensure device processes them
                await asyncio.sleep(0.01)
            
            logger.debug(f"Total bytes sent: {total_sent} (expected: {len(signing_input_bytes)})")
            
            # Manual sign_finish with retry logic
            logger.debug("Calling sign_finish...")
            sig_evt = await _retryable_device_sign(
                lambda: meshcore_instance.commands.sign_finish(timeout=None, data_size=len(signing_input_bytes)),
                "sign_finish",
                timeout=20.0,
                max_retries=3,
                retry_delay=0.3
            )
        except Exception as e:
            logger.debug(f"Manual signing flow failed: {e}")
            raise
    else:
        # Use the high-level sign() method with library defaults and retry logic
        # Call sign() - it internally:
        # 1. Calls sign_start() to initialize
        # 2. Calls sign_data() for each chunk (using library's default chunk_size)
        # 3. Calls sign_finish() with calculated timeout based on data_size
        # The timeout parameter lets sign_finish() calculate timeout based on data_size
        # For JWT tokens (~372 bytes), it will use at least 15 seconds
        # Wrap in retry logic to handle transient BLE communication issues
        async def sign_with_retry():
            # Try with timeout first (newer dev branch), fall back if not supported
            try:
                return await meshcore_instance.commands.sign(
                    signing_input_bytes,
                    timeout=None  # Let sign_finish() calculate timeout based on data_size (15s minimum)
                )
            except TypeError:
                # Older version doesn't support timeout parameter
                return await meshcore_instance.commands.sign(
                    signing_input_bytes
                )
        
        # Use retry helper with longer timeout for signing operations
        sig_evt = await _retryable_device_sign(
            sign_with_retry,
            "sign",
            timeout=20.0,  # Longer timeout for signing (device needs time to process)
            max_retries=3,
            retry_delay=0.3
        )
    
    # Check for error first (as shown in example)
    if sig_evt.type == EventType.ERROR:
        raise Exception(f"Signing failed: {sig_evt.payload}")
    
    # Get signature (as shown in example)
    signature_bytes = sig_evt.payload.get("signature", b"")
    if not signature_bytes:
        raise Exception("No signature in response")
    
    # Debug: Check signature format
    logger.debug("Signature from device:")
    logger.debug(f"  Type: {type(signature_bytes)}")
    if isinstance(signature_bytes, bytes):
        logger.debug(f"  Length: {len(signature_bytes)} bytes")
        logger.debug(f"  Hex (first 32): {signature_bytes[:32].hex()}")
        logger.debug(f"  Hex (last 32): {signature_bytes[-32:].hex()}")
    else:
        logger.debug(f"  Value: {signature_bytes}")
    
    # Convert signature to hex
    if isinstance(signature_bytes, bytes):
        signature_hex = signature_bytes.hex()
    else:
        signature_hex = signature_bytes
    
    # Return JWT format with hex signature
    return f"{header_encoded}.{payload_encoded}.{signature_hex}"


def _create_auth_token_with_meshcore_decoder(
    payload: AuthTokenPayload,
    public_key_hex: str,
    private_key_hex: str
) -> str:
    """
    Create JWT token using meshcore-decoder CLI tool
    
    Args:
        payload: Token payload containing claims
        public_key_hex: 32-byte public key in hex
        private_key_hex: 64-byte private key in hex
        
    Returns:
        JWT-style token string
    """
    import subprocess
    import shutil
    import tempfile
    import json
    
    # Try to use meshcore-decoder CLI directly first (it's a wrapper around npx)
    decoder_cmd = shutil.which('meshcore-decoder')
    if decoder_cmd:
        # Use the CLI command directly - it handles npx internally
        payload_dict = payload.to_dict()
        
        # Extract claims (excluding iat/exp which are handled by the CLI)
        claims = {k: v for k, v in payload_dict.items() if k not in ('iat', 'exp', 'publicKey')}
        
        # Build the claims JSON
        claims_json = json.dumps(claims) if claims else '{}'
        
        # Calculate expiry (CLI uses seconds from now)
        current_time = int(time.time())
        expiry_seconds = payload_dict.get('exp', current_time + 86400) - current_time
        
        # Use meshcore-decoder auth-token command
        # Format: meshcore-decoder auth-token <public-key> <private-key> --claims <json> --exp <seconds>
        try:
            result = subprocess.run(
                [decoder_cmd, 'auth-token', public_key_hex, private_key_hex, 
                 '--claims', claims_json, '--exp', str(expiry_seconds)],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                token = result.stdout.strip()
                if token and token.count('.') == 2:
                    return token
        except Exception as e:
            # CLI not available or failed, fall back to script method
            pass
    
    # Fallback: Use Node.js script with require (for compatibility)
    # Create Node.js script to generate token
    payload_dict = payload.to_dict()
    node_script = f"""
const {{ Utils }} = require('@michaelhart/meshcore-decoder');

async function createToken() {{
    const payload = {json.dumps(payload_dict)};
    const privateKey = '{private_key_hex}';
    const publicKey = '{public_key_hex}';
    
    try {{
        const token = await Utils.createAuthToken(payload, privateKey, publicKey);
        console.log(token);
    }} catch (error) {{
        console.error(JSON.stringify({{ error: error.message }}));
        process.exit(1);
    }}
}}

createToken();
"""
    
    # Write script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as f:
        f.write(node_script)
        script_path = f.name
    
    try:
        # First try running with node directly (module might be installed globally)
        result = subprocess.run(
            ['node', script_path],
            capture_output=True,
            text=True,
            timeout=10
        )
        
        # If that fails with module not found, use npx to run it
        # (meshcore-decoder is typically a wrapper around npx)
        if result.returncode != 0 and ('Cannot find module' in result.stderr or 'MODULE_NOT_FOUND' in result.stderr):
            npx_cmd = shutil.which('npx')
            if npx_cmd:
                # Use npx to run the script file directly
                # npx will automatically download and make the module available
                # when running node with a script file
                result = subprocess.run(
                    ['npx', '-y', '--', 'node', script_path],
                    capture_output=True,
                    text=True,
                    timeout=30,  # Longer timeout for npx to download if needed
                    env={**os.environ, 'NODE_PATH': ''}  # Clear NODE_PATH to let npx handle module resolution
                )
                
                # If that still fails, try using npx with the package explicitly
                if result.returncode != 0 and ('Cannot find module' in result.stderr or 'MODULE_NOT_FOUND' in result.stderr):
                    # Create a wrapper script that npx can use
                    wrapper_script = f"""
const {{ Utils }} = require('@michaelhart/meshcore-decoder');
const payload = {json.dumps(payload_dict)};
const privateKey = '{private_key_hex}';
const publicKey = '{public_key_hex}';
Utils.createAuthToken(payload, privateKey, publicKey).then(token => {{
    console.log(token);
}}).catch(error => {{
    console.error(JSON.stringify({{ error: error.message }}));
    process.exit(1);
}});
"""
                    # Write wrapper to temp file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.js', delete=False) as wrapper_file:
                        wrapper_file.write(wrapper_script)
                        wrapper_path = wrapper_file.name
                    
                    try:
                        # Use npx to run node with the package available
                        # The trick is to use npx's package resolution by running from a temp directory
                        import tempfile as tf
                        with tf.TemporaryDirectory() as tmpdir:
                            # Copy script to temp dir
                            import shutil as sh
                            tmp_script = os.path.join(tmpdir, 'script.js')
                            sh.copy2(script_path, tmp_script)
                            
                            # Run npx from temp dir - it will create node_modules there
                            result = subprocess.run(
                                ['npx', '-y', '--package=@michaelhart/meshcore-decoder', '--', 'node', tmp_script],
                                capture_output=True,
                                text=True,
                                timeout=30,
                                cwd=tmpdir
                            )
                    finally:
                        # Clean up wrapper if it was created
                        if 'wrapper_path' in locals():
                            try:
                                os.unlink(wrapper_path)
                            except:
                                pass
            else:
                # No npx available, raise the original error
                error_msg = result.stderr.strip() or result.stdout.strip()
                raise ModuleNotFoundError(
                    f"meshcore-decoder module not installed and npx is not available. "
                    f"Install with: npm install -g @michaelhart/meshcore-decoder\n"
                    f"Error: {error_msg}"
                )
        
        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip()
            # Check if it's a module not found error
            if 'Cannot find module' in error_msg or 'MODULE_NOT_FOUND' in error_msg:
                raise ModuleNotFoundError(
                    f"meshcore-decoder module not installed. "
                    f"Install with: npm install -g @michaelhart/meshcore-decoder\n"
                    f"Error: {error_msg}"
                )
            raise Exception(f"meshcore-decoder error: {error_msg}")
        
        token = result.stdout.strip()
        if not token or token.count('.') != 2:
            raise Exception(f"Invalid token format from meshcore-decoder: {token[:80]}...")
        
        return token
    finally:
        os.unlink(script_path)


def create_auth_token(
    public_key_hex: str,
    private_key_hex: str = None,
    expiry_seconds: int = 86400,
    meshcore_instance = None,
    **claims
) -> str:
    """
    Create a JWT-style auth token for MeshCore MQTT authentication
    
    This function supports multiple signing methods:
    1. On-device signing (default if meshcore_instance provided)
    2. Python implementation with PyNaCl
    3. meshcore-decoder CLI tool
    
    The method is determined by:
    - If meshcore_instance is provided and AUTH_TOKEN_METHOD != "python" or "meshcore-decoder": use device
    - If AUTH_TOKEN_METHOD == "meshcore-decoder": use meshcore-decoder CLI
    - Otherwise: use Python implementation
    
    Args:
        public_key_hex: 32-byte public key in hex format
        private_key_hex: 64-byte private key in hex format (MeshCore format)
                       Required unless using on-device signing
        expiry_seconds: Token expiry time in seconds (default 24 hours)
        meshcore_instance: Optional connected MeshCore instance for on-device signing
        **claims: Additional JWT claims (e.g., audience="mqtt.example.com", sub="device-123")
    
    Returns:
        JWT-style token string
    
    Raises:
        ValueError: If keys are invalid format or length
        Exception: If token generation fails
    """
    try:
        # Calculate expiration time
        current_time = int(time.time())
        exp_time = current_time + expiry_seconds
        
        # Extract 'aud' and 'exp' from claims if present (these are handled separately)
        aud = claims.pop('aud', None)
        # Remove 'exp' from claims if present - we use expiry_seconds parameter instead
        claims.pop('exp', None)
        
        # Create payload with expiration and claims
        payload = AuthTokenPayload(
            public_key=public_key_hex,
            iat=current_time,
            exp=exp_time,
            aud=aud,
            **claims
        )
        
        # Determine signing method from environment variable
        auth_method = os.getenv('AUTH_TOKEN_METHOD', '').lower().strip()
        
        # Use on-device signing if:
        # 1. meshcore_instance is provided AND
        # 2. AUTH_TOKEN_METHOD is not explicitly set to "python" or "meshcore-decoder"
        use_device = (
            meshcore_instance is not None and
            auth_method not in ('python', 'meshcore-decoder')
        )
        
        # Use meshcore-decoder if explicitly requested
        use_decoder = auth_method == 'meshcore-decoder'
        
        if use_device:
            # On-device signing (async)
            # Check if we're in an async context
            try:
                loop = asyncio.get_running_loop()
                # We're in an async context, but this function is sync
                # Raise an error suggesting to use async version
                raise RuntimeError(
                    "Cannot use on-device signing in sync context. "
                    "Use create_auth_token_async() instead, or set AUTH_TOKEN_METHOD=python"
                )
            except RuntimeError:
                # No running loop, create one
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    token = loop.run_until_complete(
                        _create_auth_token_with_device(payload, public_key_hex, meshcore_instance)
                    )
                finally:
                    loop.close()
            
        elif use_decoder:
            # meshcore-decoder CLI
            if not private_key_hex:
                raise ValueError("private_key_hex required for meshcore-decoder method")
            token = _create_auth_token_with_meshcore_decoder(payload, public_key_hex, private_key_hex)
        
        else:
            # Python implementation (default fallback)
            if not private_key_hex:
                raise ValueError("private_key_hex required for Python signing method")
            token = _create_auth_token_internal(payload, private_key_hex, public_key_hex)
        
        # Validate token format
        if not token or token.count('.') != 2:
            raise Exception(f"Invalid token format generated: {token[:80]}...")
        
        return token
        
    except ValueError as e:
        raise ValueError(f"Invalid key format: {str(e)}")
    except Exception as e:
        raise Exception(f"Failed to generate auth token: {str(e)}")


async def create_auth_token_async(
    public_key_hex: str,
    private_key_hex: str = None,
    expiry_seconds: int = 86400,
    meshcore_instance = None,
    chunk_size: int = None,
    **claims
) -> str:
    """
    Async version of create_auth_token for use in async contexts
    
    This version supports on-device signing without requiring event loop management.
    Use this when calling from async functions.
    
    Args:
        public_key_hex: 32-byte public key in hex format
        private_key_hex: 64-byte private key in hex format (MeshCore format)
                       Required unless using on-device signing
        expiry_seconds: Token expiry time in seconds (default 24 hours)
        meshcore_instance: Optional connected MeshCore instance for on-device signing
        **claims: Additional JWT claims (e.g., audience="mqtt.example.com", sub="device-123")
    
    Returns:
        JWT-style token string
    
    Raises:
        ValueError: If keys are invalid format or length
        Exception: If token generation fails
    """
    # Calculate expiration time
    current_time = int(time.time())
    exp_time = current_time + expiry_seconds
    
    # Extract 'aud' and 'exp' from claims if present
    aud = claims.pop('aud', None)
    claims.pop('exp', None)
    
    # Create payload with expiration and claims
    payload = AuthTokenPayload(
        public_key=public_key_hex,
        iat=current_time,
        exp=exp_time,
        aud=aud,
        **claims
    )
    
    # Determine signing method from environment variable
    auth_method = os.getenv('AUTH_TOKEN_METHOD', '').lower().strip()
    
    # Use on-device signing if:
    # 1. meshcore_instance is provided AND
    # 2. AUTH_TOKEN_METHOD is not explicitly set to "python" or "meshcore-decoder"
    use_device = (
        meshcore_instance is not None and
        auth_method not in ('python', 'meshcore-decoder')
    )
    
    # Use meshcore-decoder if explicitly requested
    use_decoder = auth_method == 'meshcore-decoder'
    
    if use_device:
        # On-device signing (async)
        # Try device signing, but fall back to Python if it fails
        try:
            token = await _create_auth_token_with_device(payload, public_key_hex, meshcore_instance, chunk_size=chunk_size)
        except Exception as device_error:
            # Device signing failed, try to fetch private key for fallback
            fallback_private_key = private_key_hex
            
            # If no private key was provided, try to fetch it from device or config
            if not fallback_private_key:
                logger.debug("Device signing failed, attempting to fetch private key for fallback...")
                fallback_private_key = await _fetch_private_key_for_fallback(
                    meshcore_instance=meshcore_instance,
                    public_key_hex=public_key_hex
                )
            
            # If we still don't have a private key, raise an error
            if not fallback_private_key:
                raise Exception(
                    f"Device signing failed ({str(device_error)}) and no private key available for fallback. "
                    "Please provide private_key_hex, ensure device supports private key export, "
                    "or set PACKETCAPTURE_PRIVATE_KEY environment variable."
                )
            
            # Log the fallback
            logger.warning(
                f"Device signing failed ({str(device_error)}), falling back to Python signing "
                f"with {'provided' if private_key_hex else 'fetched'} private key"
            )
            
            # Fall back to Python implementation
            token = _create_auth_token_internal(payload, fallback_private_key, public_key_hex)
    elif use_decoder:
        # meshcore-decoder CLI (sync, but we're in async context)
        if not private_key_hex:
            raise ValueError("private_key_hex required for meshcore-decoder method")
        token = _create_auth_token_with_meshcore_decoder(payload, public_key_hex, private_key_hex)
    else:
        # Python implementation (sync, but we're in async context)
        if not private_key_hex:
            raise ValueError("private_key_hex required for Python signing method")
        token = _create_auth_token_internal(payload, private_key_hex, public_key_hex)
    
    # Validate token format
    if not token or token.count('.') != 2:
        raise Exception(f"Invalid token format generated: {token[:80]}...")
    
    return token


def read_private_key_file(filepath: str) -> str:
    """Read private key from file (64-byte hex format)"""
    try:
        with open(filepath, 'r') as f:
            key = f.read().strip()
            key = ''.join(key.split())
            if len(key) != 128:  # 64 bytes = 128 hex chars
                raise ValueError(f"Invalid private key length: {len(key)} (expected 128)")
            int(key, 16)
            return key
    except FileNotFoundError:
        raise Exception(f"Private key file not found: {filepath}")
    except ValueError as e:
        raise Exception(f"Invalid private key format: {str(e)}")


async def _fetch_private_key_for_fallback(
    meshcore_instance = None,
    public_key_hex: str = None
) -> Optional[str]:
    """
    Attempt to fetch private key from device or config for fallback signing
    
    Tries in order:
    1. Export from device (if meshcore_instance is available and connected)
    2. Environment variable (PACKETCAPTURE_PRIVATE_KEY or PRIVATE_KEY)
    3. File (PACKETCAPTURE_PRIVATE_KEY_FILE or PRIVATE_KEY_FILE)
    
    Args:
        meshcore_instance: Optional connected MeshCore instance
        public_key_hex: Optional public key to verify the fetched private key matches
        
    Returns:
        Private key as hex string (64 bytes = 128 hex chars), or None if not found
    """
    # Try 1: Export from device
    if meshcore_instance and meshcore_instance.is_connected:
        try:
            from meshcore import EventType
            
            if hasattr(meshcore_instance, 'commands') and hasattr(meshcore_instance.commands, 'export_private_key'):
                logger.debug("Attempting to export private key from device for fallback...")
                result = await meshcore_instance.commands.export_private_key()
                
                if result.type == EventType.PRIVATE_KEY:
                    device_private_key = result.payload.get("private_key")
                    if device_private_key:
                        # Convert to hex string if it's bytes
                        if isinstance(device_private_key, bytes):
                            device_private_key = device_private_key.hex()
                        elif isinstance(device_private_key, bytearray):
                            device_private_key = bytes(device_private_key).hex()
                        
                        # Validate length
                        if len(device_private_key) == 128:  # 64 bytes = 128 hex chars
                            logger.debug("✓ Successfully exported private key from device for fallback")
                            return device_private_key
                        else:
                            logger.debug(f"Exported private key has wrong length: {len(device_private_key)} (expected 128)")
                    else:
                        logger.debug("Device returned empty private key")
                elif result.type == EventType.DISABLED:
                    logger.debug("Private key export is disabled on device")
                elif result.type == EventType.ERROR:
                    logger.debug(f"Device returned error when exporting private key: {result.payload}")
                else:
                    logger.debug(f"Unexpected response type when exporting private key: {result.type}")
        except Exception as e:
            logger.debug(f"Failed to export private key from device: {e}")
    
    # Try 2: Environment variable
    env_keys = ['PACKETCAPTURE_PRIVATE_KEY', 'PRIVATE_KEY']
    for env_key in env_keys:
        env_private_key = os.getenv(env_key, '').strip()
        if env_private_key:
            # Remove whitespace
            env_private_key = ''.join(env_private_key.split())
            if len(env_private_key) == 128:
                try:
                    # Validate it's valid hex
                    int(env_private_key, 16)
                    logger.debug(f"✓ Found private key in environment variable: {env_key}")
                    return env_private_key
                except ValueError:
                    logger.debug(f"Private key in {env_key} is not valid hex")
            else:
                logger.debug(f"Private key in {env_key} has wrong length: {len(env_private_key)} (expected 128)")
    
    # Try 3: File
    file_keys = ['PACKETCAPTURE_PRIVATE_KEY_FILE', 'PRIVATE_KEY_FILE']
    for file_key in file_keys:
        private_key_file = os.getenv(file_key, '').strip()
        if private_key_file:
            try:
                from pathlib import Path
                if Path(private_key_file).exists():
                    private_key = read_private_key_file(private_key_file)
                    logger.debug(f"✓ Successfully read private key from file: {private_key_file}")
                    return private_key
                else:
                    logger.debug(f"Private key file not found: {private_key_file}")
            except Exception as e:
                logger.debug(f"Failed to read private key from file {private_key_file}: {e}")
    
    logger.debug("No private key found in device, environment, or file")
    return None


if __name__ == "__main__":
    # Test/CLI usage
    if len(sys.argv) < 3:
        print("Usage: python auth_token.py <public_key_hex> <private_key_hex_or_file>")
        sys.exit(1)
    
    public_key = sys.argv[1]
    private_key_input = sys.argv[2]
    
    if len(private_key_input) < 128:
        try:
            private_key = read_private_key_file(private_key_input)
            print(f"Loaded private key from: {private_key_input}")
        except Exception as e:
            print(f"Error: {e}")
            sys.exit(1)
    else:
        private_key = private_key_input
    
    try:
        token = create_auth_token(public_key, private_key)
        print(f"Generated token: {token}")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
