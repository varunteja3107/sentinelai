import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./index.css";

if ("serviceWorker" in navigator) {
  navigator.serviceWorker.getRegistrations().then(async (registrations) => {
    if (registrations.length > 0) {
      await Promise.all(
        registrations.map((registration) => registration.unregister())
      );

      await caches.delete("securex-ai-v1");
      window.location.reload();
    }
  }).catch((error) => {
    console.error("Service worker cleanup failed:", error);
  });
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
