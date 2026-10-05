import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AnalysisProvider } from './context/AnalysisContext';
import Layout from './components/Layout';
import OverviewPage from './pages/OverviewPage';
import CaptureLibraryPage from './pages/CaptureLibraryPage';
import SessionExplorerPage from './pages/SessionExplorerPage';
import SessionDetailPage from './pages/SessionDetailPage';
import CryptographyPage from './pages/CryptographyPage';
import AIAnomaliesPage from './pages/AIAnomaliesPage';
import PrioritizedFindingsPage from './pages/PrioritizedFindingsPage';
import ForensicReportsPage from './pages/ForensicReportsPage';

export default function App() {
  return (
    <AnalysisProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="overview" element={<OverviewPage />} />
            <Route path="captures" element={<CaptureLibraryPage />} />
            <Route path="sessions" element={<SessionExplorerPage />} />
            <Route path="sessions/:id" element={<SessionDetailPage />} />
            <Route path="crypto" element={<CryptographyPage />} />
            <Route path="anomalies" element={<AIAnomaliesPage />} />
            <Route path="findings" element={<PrioritizedFindingsPage />} />
            <Route path="reports" element={<ForensicReportsPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AnalysisProvider>
  );
}
