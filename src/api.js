const API_BASE = import.meta.env.DEV
  ? ""
  : (import.meta.env.VITE_API_URL || "https" + "://sentinelai-api-2pqw.onrender.com").replace(/\/+$/, "");

export { API_BASE };
