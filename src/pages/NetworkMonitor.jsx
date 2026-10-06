import { useEffect, useState } from "react";
import {
  Activity,
  Server,
  Wifi,
  ArrowUp,
  ArrowDown,
} from "lucide-react";

import PageLayout from "../components/PageLayout";

const API = "http://127.0.0.1:8000";

function NetworkMonitor() {
  const [devices, setDevices] = useState([]);

  const loadDevices = async () => {
    try {
      const response = await fetch(`${API}/api/devices`);
      const data = await response.json();
      setDevices(data);
    } catch (error) {
      console.error(error);
    }
  };

  useEffect(() => {
    loadDevices();
  }, []);

  return (
    <PageLayout
      title="Network Monitor"
      subtitle="Real-time network traffic and device monitoring"
    >
      <div className="monitor-page">

        <div className="monitor-stats">

          <div className="monitor-stat">
            <div className="monitor-icon blue">
              <Activity size={21} />
            </div>
            <div>
              <strong>98.4%</strong>
              <span>Network Health</span>
            </div>
          </div>

          <div className="monitor-stat">
            <div className="monitor-icon green">
              <Wifi size={21} />
            </div>
            <div>
              <strong>{devices.length}</strong>
              <span>Connected Devices</span>
            </div>
          </div>

          <div className="monitor-stat">
            <div className="monitor-icon purple">
              <ArrowUp size={21} />
            </div>
            <div>
              <strong>842 MB/s</strong>
              <span>Inbound Traffic</span>
            </div>
          </div>

          <div className="monitor-stat">
            <div className="monitor-icon orange">
              <ArrowDown size={21} />
            </div>
            <div>
              <strong>516 MB/s</strong>
              <span>Outbound Traffic</span>
            </div>
          </div>

        </div>

        <div className="monitor-grid">

          <section className="monitor-card traffic-panel">

            <div className="monitor-card-header">
              <div>
                <h2>Live Traffic</h2>
                <p>Network activity over the last 24 hours</p>
              </div>

              <span className="live-pill">
                <i></i> LIVE
              </span>
            </div>

            <div className="traffic-visual">

              <div className="traffic-bars">
                {[35, 48, 42, 65, 52, 76, 60, 84, 70, 91, 68, 78].map(
                  (height, index) => (
                    <div
                      key={index}
                      className="traffic-bar"
                      style={{ height: `${height}%` }}
                    />
                  )
                )}
              </div>

              <div className="traffic-axis">
                <span>00:00</span>
                <span>04:00</span>
                <span>08:00</span>
                <span>12:00</span>
                <span>16:00</span>
                <span>20:00</span>
                <span>24:00</span>
              </div>

            </div>

          </section>

          <section className="monitor-card">

            <div className="monitor-card-header">
              <div>
                <h2>Protocol Distribution</h2>
                <p>Current traffic breakdown</p>
              </div>
            </div>

            <div className="protocol-list">

              <div>
                <span>TCP</span>
                <strong>62%</strong>
              </div>

              <div className="protocol-line">
                <i style={{ width: "62%" }}></i>
              </div>

              <div>
                <span>UDP</span>
                <strong>24%</strong>
              </div>

              <div className="protocol-line">
                <i style={{ width: "24%" }}></i>
              </div>

              <div>
                <span>HTTP/HTTPS</span>
                <strong>11%</strong>
              </div>

              <div className="protocol-line">
                <i style={{ width: "11%" }}></i>
              </div>

              <div>
                <span>Other</span>
                <strong>3%</strong>
              </div>

              <div className="protocol-line">
                <i style={{ width: "3%" }}></i>
              </div>

            </div>

          </section>

        </div>

        <section className="monitor-card devices-card">

          <div className="monitor-card-header">
            <div>
              <h2>Connected Devices</h2>
              <p>Devices currently visible on the network</p>
            </div>

            <span className="device-count">
              {devices.length} devices
            </span>
          </div>

          {devices.length === 0 ? (
            <div className="monitor-empty">
              No devices found. Use the API device seed endpoint first.
            </div>
          ) : (
            <div className="device-grid">

              {devices.map((device) => (
                <div className="device-card" key={device.id}>

                  <div className="device-card-top">

                    <div className="device-icon">
                      <Server size={20} />
                    </div>

                    <span className="online-status">
                      <i></i>
                      {device.status}
                    </span>

                  </div>

                  <h3>{device.name}</h3>

                  <p>{device.device_type}</p>

                  <div className="device-ip">
                    {device.ip_address}
                  </div>

                  <div className="trust-row">
                    <span>Trust Score</span>
                    <strong>{device.trust_score}%</strong>
                  </div>

                  <div className="trust-bar">
                    <i style={{ width: `${device.trust_score}%` }}></i>
                  </div>

                </div>
              ))}

            </div>
          )}

        </section>

      </div>
    </PageLayout>
  );
}

export default NetworkMonitor;
