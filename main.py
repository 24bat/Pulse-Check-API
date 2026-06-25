# flask is the web framework — it creates the web server and handles HTTP requests

from flask import Flask, request, jsonify

# datetime = lets us work with dates and times (e.g. "right now")
# timedelta = lets us add/subtract time (e.g. "now + 60 seconds")
from datetime import datetime, timedelta

# threading = lets us run code in the background without blocking the API

import threading

# logging = Python's built-in way to write structured log messages to the terminal
# Better than print() because it includes timestamps and severity levels
import logging

# re = regular expressions — used to detect dangerous characters in user input
import re

# os = lets us read environment variables from the system
# Used to load the API key securely instead of hardcoding it
import os

# defaultdict = a special dictionary that auto-creates a default value for missing keys
# We use it for the rate tracker so we don't have to manually create entries per IP
from collections import defaultdict



# basicConfig sets the global logging format and minimum level for the whole app
logging.basicConfig(
    level=logging.INFO,                               # show INFO and above (INFO, WARNING, ERROR, CRITICAL)
    format="%(asctime)s [%(levelname)s] %(message)s"  # format: "2025-06-19 10:00:00 [INFO] message"
)

# Create a named logger for this app so log messages are clearly tagged
logger = logging.getLogger("pulse-check-api")



# API key loaded from environment variable, NOT hardcoded
# To set it: export API_KEY=supersecretkey123 (in terminal before running)
# This means the secret never appears in source code. A security best practice
API_KEY = os.environ.get("API_KEY")

# If no API_KEY environment variable is set, refuse to start the server at all
# This forces the developer to set it properly before running
if not API_KEY:
    raise RuntimeError("API_KEY environment variable is required. Set it with: export API_KEY=your_secret_key")

# Maximum number of requests any single IP address can make per RATE_WINDOW seconds
RATE_LIMIT = 30  # 30 requests allowed per window

# The time window in seconds for rate limiting — resets after this many seconds pass
RATE_WINDOW = 60  # 60 second window (1 minute)

# Minimum and maximum allowed timeout values in seconds
# FIX #6: Prevents absurdly small timeouts (e.g. 0.001s) that expire before the response returns
# and absurdly large timeouts that would never practically fire
MIN_TIMEOUT = 5      # minimum 5 seconds
MAX_TIMEOUT = 86400  # maximum 24 hours (86400 seconds)

# Dictionary tracking request counts per IP address
# defaultdict auto-creates {"count": 0, "window_start": now} for any new IP
rate_tracker = defaultdict(lambda: {"count": 0, "window_start": datetime.utcnow()})

# Lock to safely read/write rate_tracker across multiple threads simultaneously
rate_lock = threading.Lock()


def check_api_key():
    # Extract the X-API-Key header value from the incoming request
    # Returns None if the header is not present
    key = request.headers.get("X-API-Key")

    # If no API key header was included at all, reject with 401 Unauthorized
    if not key:
        # Use %s style logging — avoids building the string when log level suppresses it (FIX #9)
        logger.warning("Rejected request — no API key from %s", request.remote_addr)
        return jsonify({"error": "Missing API key. Include X-API-Key header."}), 401

    # If a key was provided but it doesn't match our expected key, reject with 403 Forbidden
    if key != API_KEY:
        logger.warning("Rejected request — wrong API key from %s", request.remote_addr)
        return jsonify({"error": "Invalid API key."}), 403

    # Key is valid — return None to signal "all good, continue"
    return None


def check_rate_limit():
    # Get the IP address of whoever sent this request
    ip = request.remote_addr

    # Acquire the lock before reading/writing rate_tracker
    with rate_lock:
        # Get or auto-create the rate tracking record for this IP
        tracker = rate_tracker[ip]

        # Get the current time to compare against the window start
        now = datetime.utcnow()

        # Calculate how many seconds have passed since this IP's window started
        window_age = (now - tracker["window_start"]).total_seconds()

        # If the window has expired, reset the counter and start a new window
        if window_age > RATE_WINDOW:
            tracker["count"] = 0           # reset request count to zero
            tracker["window_start"] = now  # start fresh window from now

        # Increment the request count for this IP
        tracker["count"] += 1

        # If this IP has exceeded the allowed number of requests, block them
        if tracker["count"] > RATE_LIMIT:
            logger.warning("Rate limit exceeded by %s (%d requests)", ip, tracker["count"])
            return jsonify({
                "error": "Rate limit exceeded. Max %d requests per %ds." % (RATE_LIMIT, RATE_WINDOW)
            }), 429

    # Under the limit, return None to signal success
    return None


def sanitize_string(value: str, field_name: str):
    # Regex pattern that matches any character NOT in the allowed set
    # Allowed: letters, numbers, hyphens, underscores, dots, @ signs, spaces
    # Blocked: angle brackets, quotes, semicolons, and anything else
    pattern = r"[^a-zA-Z0-9\-_\.@\s]"

    # Search the string for any character matching the blocked pattern
    if re.search(pattern, str(value)):
        logger.warning("Suspicious input in field '%s': %s", field_name, value)
        return jsonify({
            "error": "Invalid characters in field '%s'. Only letters, numbers, hyphens, underscores, dots and @ are allowed." % field_name
        }), 400

    # If the input is clean,return None to signal success
    return None


def run_security_checks(sanitize_fields=None):
    # Run check 1: API Key — stop immediately if it fails
    err = check_api_key()
    if err:
        return err

    # Run check 2: Rate Limiting, stop immediately if it fails
    err = check_rate_limit()
    if err:
        return err

    # Run check 3: Input Sanitization. Only if fields were passed in
    if sanitize_fields:
        for field_name, value in sanitize_fields.items():
            err = sanitize_string(value, field_name)
            if err:
                return err

    # All checks passed, return None to signal safe to proceed
    return None



# monitors is the main dictionary storing all registered devices
# Key = device ID string (e.g. "device-123")
# Value = dict with: timeout, alert_email, status, deadline, created_at, history
monitors = {}

# Lock to safely read/write monitors across the API thread and watchdog thread
# IMPORTANT: add_history() must only be called while this lock is already held
store_lock = threading.Lock()


def add_history(device_id: str, event: str):
    # NOTE: This function must only be called while store_lock is already held by the caller
    # It does not acquire the lock itself — the caller is responsible for that
    # This avoids a deadlock where we'd try to acquire a lock we already own

    # Only log if the device exists (it always should when called correctly)
    if device_id in monitors:
        # Append a new event dict to the device's history list
        monitors[device_id]["history"].append({
            "event": event,                                    # description of what happened
            "timestamp": datetime.utcnow().isoformat() + "Z"  # UTC timestamp in ISO 8601 format
        })



# WATCHDOG SCHEDULER

def check_monitors():
    # Get the current UTC time once, used for all comparisons in this iteration
    now = datetime.utcnow()

    # Acquire the store lock before reading or writing any monitor data
    with store_lock:

        # Loop through every registered device
        for device_id, monitor in monitors.items():

            # Skip devices that are already down or paused — nothing to check
            if monitor["status"] != "active":
                continue

            # If the current time has passed this device's deadline, it missed its heartbeat
            if now >= monitor["deadline"]:

                # Mark as down immediately so the alert doesn't fire again next second
                monitor["status"] = "down"

                # Build the alert object as specified in the project brief
                alert = {
                    "ALERT": "Device %s is down!" % device_id,  # the alert message
                    "time": now.isoformat() + "Z",               # exact time of the alert
                    "alert_email": monitor.get("alert_email", "N/A")  # who to notify
                }

                # Log at CRITICAL level — in production this would send email/SMS/webhook
                logger.critical(alert)

                # Print clearly to terminal so it is impossible to miss
                print("\n ALERT FIRED: %s\n" % alert)

                # Record the alert in the device's history log
                # Safe to call here because we are holding store_lock
                add_history(device_id, "ALERT_FIRED — device went down")


def start_scheduler():
    # Inner loop function — calls itself every 1 second via threading.Timer
    def loop():
        check_monitors()  # run the timer check

        # Schedule this same function to run again in 1.0 seconds
        t = threading.Timer(1.0, loop)

        # daemon=True means this thread dies when the main Flask process exits
        # Without this, the background thread would keep running after Ctrl+C
        t.daemon = True

        # Start the timer countdown
        t.start()

    # Kick off the very first iteration to start the loop
    loop()

    logger.info("Watchdog scheduler started — checking every 1 second")



# FLASK APP


# Create the Flask application instance
app = Flask(__name__)


# Root endpoint — simple health check to confirm the server is running
@app.route("/")
def index():
    return jsonify({
        "service": "Pulse Check API — Dead Man's Switch",
        "status": "running",
        "security": ["API Key Auth", "Rate Limiting", "Input Sanitization"],
        "endpoints": [
            "POST   /monitors",
            "POST   /monitors/<id>/heartbeat",
            "POST   /monitors/<id>/pause",
            "GET    /monitors/<id>",
            "GET    /monitors",
            "DELETE /monitors/<id>"
        ]
    }), 200


# ENDPOINT 1: POST /monitors 
@app.route("/monitors", methods=["POST"])
def register_monitor():

    # Parse the JSON body from the request
    data = request.get_json()

    # Reject if no JSON body was provided
    if not data:
        return jsonify({"error": "Request body must be JSON"}), 400

    # Extract the three required fields
    device_id   = data.get("id")
    timeout     = data.get("timeout")
    alert_email = data.get("alert_email")

    # Validate all three fields are present
    if not device_id or timeout is None or not alert_email:
        return jsonify({"error": "Missing required fields: id, timeout, alert_email"}), 400

    # Validate timeout is within the allowed range (not just > 0)
    # Prevents absurdly small values like 0.001 that expire before the response even returns
    if not isinstance(timeout, (int, float)) or timeout < MIN_TIMEOUT or timeout > MAX_TIMEOUT:
        return jsonify({
            "error": "timeout must be between %d and %d seconds" % (MIN_TIMEOUT, MAX_TIMEOUT)
        }), 400

    # Run all security checks including sanitizing the id and email fields
    err = run_security_checks(sanitize_fields={"id": device_id, "alert_email": alert_email})
    if err:
        return err

    # Acquire the lock before writing to the monitors dictionary
    with store_lock:

        # Check if this device ID already exists you know to prevent silent overwrite
        # Without this check, re-registering an existing device would silently reset it
        if device_id in monitors:
            return jsonify({
                "error": "Monitor '%s' already exists. Delete it first to re-register." % device_id
            }), 409  # 409 Conflict — the resource already exists

        # Calculate the exact moment the timer will expire
        deadline = datetime.utcnow() + timedelta(seconds=timeout)

        # Store all monitor data in the dictionary
        monitors[device_id] = {
            "timeout":     timeout,                              # original timeout for resets
            "alert_email": alert_email,                         # alert recipient
            "status":      "active",                            # starts counting down immediately
            "deadline":    deadline,                            # when the timer expires
            "created_at":  datetime.utcnow().isoformat() + "Z", # creation timestamp
            "history":     []                                   # empty event log
        }

        # Record the registration event — safe because we hold store_lock
        add_history(device_id, "Monitor registered with timeout=%ds" % timeout)

    # Return 201 Created with confirmation details
    return jsonify({
        "message":     "Monitor for '%s' registered successfully." % device_id,
        "id":          device_id,
        "timeout":     timeout,
        "alert_email": alert_email,
        "status":      "active",
        "deadline":    deadline.isoformat() + "Z"
    }), 201


# ENDPOINT 2: POST /monitors/<device_id>/heartbeat 
@app.route("/monitors/<device_id>/heartbeat", methods=["POST"])
def heartbeat(device_id):

    # Sanitize the device_id from the URL path
    # Previously only POST body fields were sanitized — URL params were missed
    err = run_security_checks(sanitize_fields={"id": device_id})
    if err:
        return err

    # Acquire the lock before reading/writing monitor data
    with store_lock:

        # Return 404 if the device hasn't been registered
        if device_id not in monitors:
            return jsonify({"error": "Monitor '%s' not found" % device_id}), 404

        monitor = monitors[device_id]

        # If paused: heartbeat resumes the monitor and resets the timer
        if monitor["status"] == "paused":
            monitor["status"]   = "active"
            monitor["deadline"] = datetime.utcnow() + timedelta(seconds=monitor["timeout"])
            add_history(device_id, "Monitor resumed via heartbeat")
            return jsonify({
                "message":      "Monitor '%s' resumed and timer reset." % device_id,
                "status":       "active",
                "new_deadline": monitor["deadline"].isoformat() + "Z"
            }), 200

        # If already down: can't be revived by heartbeat — must re-register
        if monitor["status"] == "down":
            return jsonify({
                "error": "Monitor '%s' is already DOWN. Delete and re-register to restart." % device_id
            }), 409

        # Active: reset the deadline from right now
        monitor["deadline"] = datetime.utcnow() + timedelta(seconds=monitor["timeout"])
        add_history(device_id, "Heartbeat received — timer reset")

        # Capture the new deadline inside the lock for use in the response
        new_deadline = monitor["deadline"].isoformat() + "Z"

    # Return 200 OK with the updated deadline
    return jsonify({
        "message":      "Heartbeat received for '%s'. Timer reset." % device_id,
        "id":           device_id,
        "status":       "active",
        "new_deadline": new_deadline  # built inside the lock — safe and consistent
    }), 200


# ENDPOINT 3: POST /monitors/<device_id>/pause 
@app.route("/monitors/<device_id>/pause", methods=["POST"])
def pause_monitor(device_id):

    # FIX #5: Sanitize the device_id from the URL path
    err = run_security_checks(sanitize_fields={"id": device_id})
    if err:
        return err

    with store_lock:

        if device_id not in monitors:
            return jsonify({"error": "Monitor '%s' not found" % device_id}), 404

        monitor = monitors[device_id]

        # Can't pause a device that is already down
        if monitor["status"] == "down":
            return jsonify({"error": "Monitor '%s' is already DOWN." % device_id}), 409

        # Already paused — nothing to change
        if monitor["status"] == "paused":
            return jsonify({"message": "Monitor '%s' is already paused." % device_id}), 200

        # Set status to paused — watchdog will skip this device from now on
        monitor["status"] = "paused"
        add_history(device_id, "Monitor paused — no alerts will fire")

    return jsonify({
        "message": "Monitor '%s' is now paused. No alerts will fire." % device_id,
        "id":      device_id,
        "status":  "paused"
    }), 200


#  ENDPOINT 4: GET /monitors/<device_id> 
# Developer's Choice: full status + event history for one device
@app.route("/monitors/<device_id>", methods=["GET"])
def get_monitor(device_id):

    # Sanitize the device_id from the URL path
    err = run_security_checks(sanitize_fields={"id": device_id})
    if err:
        return err

    #  Build the ENTIRE response dict inside the lock
    # Previously, monitor["status"] was checked again OUTSIDE the lock for the deadline field
    # The watchdog could flip status to "down" between the lock release and the jsonify() call
    # producing an inconsistent response. Now everything is captured atomically inside the lock.
    with store_lock:

        if device_id not in monitors:
            return jsonify({"error": "Monitor '%s' not found" % device_id}), 404

        monitor = monitors[device_id]

        # Calculate remaining seconds only if actively counting down
        if monitor["status"] == "active":
            remaining = max(0, round(
                (monitor["deadline"] - datetime.utcnow()).total_seconds(), 2
            ))
            # Capture deadline as a string inside the lock — status won't change under us
            deadline_str = monitor["deadline"].isoformat() + "Z"
        else:
            # Paused or down — no meaningful countdown or deadline to show
            remaining    = None
            deadline_str = None

        # Build the full response dict while still holding the lock
        # This guarantees status, deadline, and remaining are all consistent
        response_data = {
            "id":                device_id,
            "status":            monitor["status"],
            "timeout":           monitor["timeout"],
            "alert_email":       monitor["alert_email"],
            "created_at":        monitor["created_at"],
            "deadline":          deadline_str,   # None if not active
            "seconds_remaining": remaining,      # None if not active
            "history":           list(monitor["history"])  # copy the list so it's safe to return outside the lock
        }

    # Now safe to return — all data was captured atomically inside the lock
    return jsonify(response_data), 200


#  ENDPOINT 5: GET /monitors
@app.route("/monitors", methods=["GET"])
def list_monitors():

    err = run_security_checks()
    if err:
        return err

    with store_lock:
        result = []
        for device_id, monitor in monitors.items():

            if monitor["status"] == "active":
                remaining = max(0, round(
                    (monitor["deadline"] - datetime.utcnow()).total_seconds(), 2
                ))
            else:
                remaining = None

            result.append({
                "id":                device_id,
                "status":            monitor["status"],
                "timeout":           monitor["timeout"],
                "seconds_remaining": remaining,
                "alert_email":       monitor["alert_email"]
            })

    return jsonify({"total": len(result), "monitors": result}), 200


#  ENDPOINT 6: DELETE /monitors/<device_id> 
@app.route("/monitors/<device_id>", methods=["DELETE"])
def delete_monitor(device_id):

    #  Sanitize the device_id from the URL path
    err = run_security_checks(sanitize_fields={"id": device_id})
    if err:
        return err

    with store_lock:

        if device_id not in monitors:
            return jsonify({"error": "Monitor '%s' not found" % device_id}), 404

        # Permanently remove this device from the store
        del monitors[device_id]

    #  Use 204 No Content for DELETE — REST convention for successful deletion with no body
    # 204 means "success, nothing to return"
    return "", 204



# ENTRY POINT


if __name__ == "__main__":

    # Start the background watchdog before the web server
    start_scheduler()

    # FIX #4: debug=False in all cases
    # debug=True enables Werkzeug's interactive debugger which allows arbitrary
    # Python code execution in the browser on unhandled exceptions — a critical security risk
    # Use an environment variable to optionally enable debug mode during local development only
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # Start the Flask web server
    # host="0.0.0.0" = listen on all network interfaces
    # port=5000       = accessible at http://localhost:5000
    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
