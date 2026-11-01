import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { API_BASE as API } from "../../api";
import {
  Activity,
  RefreshCw,
  Server,
  ShieldAlert,
  Wifi,
  AlertTriangle,
  Network,
} from "lucide-react";

function TopologyNode({ data }) {
  const Icon = data.kind === "interface"
    ? Wifi
    : data.threatCount > 0
      ? ShieldAlert
      : Server;

  return (
    <div className={`topology-node ${data.threatCount > 0 ? "has-threat" : ""}`}>
      <Handle type="target" position={Position.Left} />
      <div className="topology-node-icon">
        <Icon size={18} />
      </div>
      <div className="topology-node-content">
        <strong>{data.label}</strong>
        <span>{data.ip || data.subtitle || "Network interface"}</span>
        {data.threatCount > 0 && (
          <small>{data.threatCount} threat event(s)</small>
        )}
      </div>
      <Handle type="source" position={Position.Right} />
    </div>
  );
}

const nodeTypes = { topology: TopologyNode };

function NetworkTopology() {
  const [topology, setTopology] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedNode, setSelectedNode] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);

  const loadTopology = useCallback(async () => {
    try {
      setError("");
      const response = await fetch(`${API}/api/network/topology`);

      if (!response.ok) {
        throw new Error(`Topology API returned HTTP ${response.status}`);
      }

      const data = await response.json();
      setTopology(data);
      setLastUpdated(new Date());
    } catch (err) {
      setError(err.message || "Unable to load network topology.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTopology();
    const timer = setInterval(loadTopology, 30000);
    return () => clearInterval(timer);
  }, [loadTopology]);

  const graph = useMemo(() => {
    if (!topology) return { nodes: [], edges: [] };

    const sourceNodes = Array.isArray(topology.nodes) ? topology.nodes : [];
    const sourceEdges = Array.isArray(topology.edges) ? topology.edges : [];
    const interfaces = Array.isArray(topology.interfaces)
      ? topology.interfaces
      : [];

    const interfaceNodes = interfaces.flatMap((item) => {
      const addresses = Array.isArray(item.addresses) ? item.addresses : [];

      return addresses.map((address, index) => ({
        id: `interface-${item.name}-${index}`,
        label: item.name || "Interface",
        ip: address.address || address.ip || "",
        kind: "interface",
        threatCount: 0,
        subtitle: item.is_up ? "Interface active" : "Interface inactive",
      }));
    });

    const allNodes = [...interfaceNodes, ...sourceNodes];
    const uniqueNodes = Array.from(
      new Map(
        allNodes.map((node, index) => [
          String(node.id ?? node.ip ?? node.ip_address ?? `node-${index}`),
          node,
        ])
      ).values()
    );

    const positions = uniqueNodes.map((node, index) => {
      const column = index % 3;
      const row = Math.floor(index / 3);

      return {
        id: String(node.id ?? node.ip ?? node.ip_address ?? `node-${index}`),
        type: "topology",
        position: {
          x: column * 290,
          y: row * 145,
        },
        data: {
          label: node.name || node.hostname || node.ip || node.ip_address || "Network node",
          ip: node.ip || node.ip_address || "",
          kind: node.kind || node.type || (node.sources?.includes("interface") ? "interface" : "device"),
          threatCount: Number(node.threat_count || node.threatCount || 0),
          subtitle: node.address_type || node.device_type || node.status || "",
          original: node,
        },
      };
    });

    const validIds = new Set(positions.map((node) => node.id));

    const edges = sourceEdges
      .map((edge, index) => {
        const source = String(edge.source ?? edge.source_id ?? "");
        const target = String(edge.target ?? edge.target_id ?? "");

        if (!validIds.has(source) || !validIds.has(target)) return null;

        return {
          id: String(edge.id || `connection-${index}`),
          source,
          target,
          label: edge.protocol || "",
          animated: true,
          markerEnd: { type: MarkerType.ArrowClosed },
          style: { stroke: "#38bdf8", strokeWidth: 1.8 },
        };
      })
      .filter(Boolean);

    return { nodes: positions, edges };
  }, [topology]);

  const statistics = topology?.statistics || {};

  return (
    <section className="monitor-card topology-panel">
      <div className="topology-header">
        <div>
          <div className="topology-title">
            <Network size={19} />
            <h2>Live Network Topology</h2>
          </div>
          <p>Network interfaces, known devices and observed connections</p>
        </div>

        <button
          className="topology-refresh"
          onClick={loadTopology}
          disabled={loading}
          type="button"
        >
          <RefreshCw size={15} className={loading ? "topology-spinning" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="topology-error">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}

      <div className="topology-stats">
        <div>
          <span>Interfaces</span>
          <strong>{statistics.interface_count ?? interfacesCount(topology)}</strong>
        </div>
        <div>
          <span>Network nodes</span>
          <strong>{statistics.node_count ?? graph.nodes.length}</strong>
        </div>
        <div>
          <span>Observed connections</span>
          <strong>{statistics.connection_count ?? graph.edges.length}</strong>
        </div>
        <div>
          <span>Threat events</span>
          <strong>{statistics.threat_event_count ?? 0}</strong>
        </div>
      </div>

      <div className="topology-legend">
        <span><i className="legend-interface" /> Interface</span>
        <span><i className="legend-device" /> Device</span>
        <span><i className="legend-threat" /> Threat-associated</span>
        <span><i className="legend-edge" /> Observed connection</span>
      </div>

      <div className="topology-canvas">
        {loading && !topology ? (
          <div className="topology-message">
            <Activity size={22} />
            Discovering network topology...
          </div>
        ) : graph.nodes.length === 0 ? (
          <div className="topology-message">
            <Network size={24} />
            No topology nodes were returned by the backend.
          </div>
        ) : (
          <ReactFlow
            nodes={graph.nodes}
            edges={graph.edges}
            nodeTypes={nodeTypes}
            onNodeClick={(_, node) => setSelectedNode(node)}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            nodesDraggable
            nodesConnectable={false}
            elementsSelectable
            proOptions={{ hideAttribution: true }}
          >
            <Background color="#29445e" gap={22} size={1} />
            <Controls />
            <MiniMap
              nodeColor={(node) =>
                node.data?.threatCount > 0 ? "#f87171" : "#38bdf8"
              }
              maskColor="rgba(4, 14, 26, 0.75)"
            />
          </ReactFlow>
        )}
      </div>

      {selectedNode && (
        <div className="topology-details">
          <div>
            <strong>{selectedNode.data.label}</strong>
            <span>{selectedNode.data.ip || "No IP address reported"}</span>
          </div>
          <div>
            <span>Threat events</span>
            <strong>{selectedNode.data.threatCount}</strong>
          </div>
          <button type="button" onClick={() => setSelectedNode(null)}>
            Close
          </button>
        </div>
      )}

      {Array.isArray(topology?.warnings) && topology.warnings.length > 0 && (
        <div className="topology-warning">
          <AlertTriangle size={16} />
          <div>
            {topology.warnings.map((warning, index) => (
              <p key={index}>{warning}</p>
            ))}
          </div>
        </div>
      )}

      <div className="topology-footer">
        <span>
          <Activity size={13} />
          {lastUpdated
            ? `Last updated: ${lastUpdated.toLocaleTimeString()}`
            : "Waiting for data"}
        </span>
        <span>Automatic refresh: 30 seconds</span>
      </div>

      <p className="topology-disclaimer">
        Threat events may include historical database records. They do not
        confirm that a device is currently online. Connections are displayed
        only when reported by the backend.
      </p>
    </section>
  );
}

function interfacesCount(topology) {
  return Array.isArray(topology?.interfaces)
    ? topology.interfaces.length
    : 0;
}

export default NetworkTopology;
