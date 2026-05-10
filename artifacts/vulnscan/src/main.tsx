import { createRoot } from "react-dom/client";
import App from "./App";
import "./index.css";

const KEEP_ALIVE_URL = "/scanner-api/api/health";
const KEEP_ALIVE_INTERVAL = 10 * 60 * 1000;

function startKeepAlive() {
  fetch(KEEP_ALIVE_URL).catch(() => {});
  setInterval(() => {
    fetch(KEEP_ALIVE_URL).catch(() => {});
  }, KEEP_ALIVE_INTERVAL);
}

startKeepAlive();

createRoot(document.getElementById("root")!).render(<App />);
