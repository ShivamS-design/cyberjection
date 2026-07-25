import { Route, Routes } from "react-router-dom";
import Layout from "./components/Layout";
import CampaignDetailPage from "./pages/CampaignDetailPage";
import CampaignsPage from "./pages/CampaignsPage";
import PluginsPage from "./pages/PluginsPage";
import TestDetailPage from "./pages/TestDetailPage";

export default function App() {
  return (
    <Routes>
      <Route element={<Layout />}>
        <Route path="/" element={<CampaignsPage />} />
        <Route path="/campaigns/:campaignId" element={<CampaignDetailPage />} />
        <Route path="/campaigns/:campaignId/tests/:testId" element={<TestDetailPage />} />
        <Route path="/plugins" element={<PluginsPage />} />
      </Route>
    </Routes>
  );
}
