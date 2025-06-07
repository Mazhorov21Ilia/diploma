import threading
from flask import Flask, jsonify
from agent.collector import start_background_sniffer, collect_network_metrics
from config.config_m import load_config

config = load_config()

app = Flask(__name__)

sniffer_thread = threading.Thread(target=start_background_sniffer, daemon=True)
sniffer_thread.start()


@app.route("/metrics", methods=["GET"])
def metrics():
    try:
        metrics_data = collect_network_metrics(config)

        return jsonify(metrics_data), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def run_agent():
    host_ip = "0.0.0.0"
    port = config.get("server_polling_port", 8080)

    app.run(host=host_ip, port=port)


if __name__ == "__main__":
    run_agent()