import axios from "axios";
import { API_BASE_URL } from "../config/env";
import toast from "react-hot-toast";

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: { "Content-Type": "application/json" },
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    // Skip toast for silent requests (e.g. cache-miss checks)
    if (!error.config?._silent) {
      const msg = error.response?.data?.detail || error.message || "API error";
      toast.error(msg);
    }
    return Promise.reject(error);
  }
);

export default api;
