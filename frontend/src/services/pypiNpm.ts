import api from "./api";

export const installPackage = async (
  packageManager: "pypi" | "npm",
  packageName: string,
  packageVersion: string
) => {
  const res = await api.post("/pypi-npm/install_package", {
    package_manager: packageManager,
    package_name: packageName,
    package_version: packageVersion,
  });
  return res.data;
};

export const storeAnalysis = async (
  packageManager: "pypi" | "npm",
  packageName: string,
  packageVersion: string
) => {
  const res = await api.post("/pypi-npm/store_analysis", {
    package_manager: packageManager,
    package_name: packageName,
    package_version: packageVersion,
  });
  return res.data;
};

export const checkInstallStatus = async (taskId: string) => {
  const res = await api.get(`/pypi-npm/install-status/${taskId}`);
  return res.data;
};

export const getStoreStatus = async (taskId: string) => {
  const res = await api.get(`/pypi-npm/store-status/${taskId}`);
  return res.data;
};

export const getDashboard = async (packageName: string) => {
  const res = await api.get(`/pypi-npm/dashboard/${packageName}`);
  return res.data;
};

export const preCheckPackage = async (
  packageManager: "pypi" | "npm",
  packageName: string
) => {
  const res = await api.post("/pypi-npm/pre-check", {
    package_manager: packageManager,
    package_name: packageName,
    package_version: "",
  });
  return res.data;
};
