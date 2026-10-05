import React, { useState } from 'react';
import { Outlet } from 'react-router-dom';
import Sidebar from './Sidebar';
import Topbar from './Topbar';
import NewAnalysisModal from './NewAnalysisModal';
import { useAnalysis } from '../context/AnalysisContext';

export default function Layout() {
  const [modalOpen, setModalOpen] = useState(false);
  const {
    selectedCapture,
    activeAnalysis,
    pcaps,
    analyses,
    selectCapture,
    loadAnalysisById,
    isLoading,
    isBackendLive,
    error,
    refreshAnalyses,
    runAllScenarios,
  } = useAnalysis();

  return (
    <div className="app-shell">
      <Sidebar
        selectedCapture={selectedCapture}
        isBackendLive={isBackendLive}
        activeAnalysis={activeAnalysis}
      />
      <div className="main-wrapper">
        <Topbar
          selectedCapture={selectedCapture}
          pcaps={pcaps}
          onSelectCapture={selectCapture}
          onOpenNewAnalysis={() => setModalOpen(true)}
          isBackendLive={isBackendLive}
          isLoading={isLoading}
        />
        <main className="content-scrollable">
          {isLoading && (
            <div style={{
              background: 'linear-gradient(90deg, #163A34 0%, #59D9BC 50%, #163A34 100%)',
              height: '2px',
              width: '100%',
              animation: 'pulse 1.5s infinite',
            }} />
          )}
          <Outlet
            context={{
              selectedCapture,
              activeAnalysis,
              pcaps,
              analyses,
              selectCapture,
              loadAnalysisById,
              isLoading,
              isBackendLive,
              error,
              refreshAnalyses,
              runAllScenarios,
              onOpenNewAnalysis: () => setModalOpen(true),
            }}
          />
        </main>
      </div>

      <NewAnalysisModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        onAnalysisComplete={(res) => {
          if (res?.analysis_id) {
            loadAnalysisById(res.analysis_id);
          } else if (res?.filename) {
            selectCapture(res.filename);
          }
        }}
      />
    </div>
  );
}
