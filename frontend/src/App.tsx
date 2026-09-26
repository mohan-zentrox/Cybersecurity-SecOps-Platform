import { Navigate, Route, Routes } from "react-router-dom";

import { Navbar } from "@/components/Navbar";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { ToastProvider } from "@/components/Toast";
import Account from "@/pages/Account/Account";
import AlertQueue from "@/pages/AlertQueue/AlertQueue";
import Audit from "@/pages/Audit/Audit";
import CaseDetail from "@/pages/CaseDetail/CaseDetail";
import CaseList from "@/pages/Cases/CaseList";
import Compliance from "@/pages/Compliance/Compliance";
import Dashboard from "@/pages/Dashboard/Dashboard";
import Events from "@/pages/Events/Events";
import Login from "@/pages/Login/Login";
import RuleEditor from "@/pages/Rules/RuleEditor";
import Rules from "@/pages/Rules/Rules";
import Settings from "@/pages/Settings/Settings";
import ThreatIntel from "@/pages/ThreatIntel/ThreatIntel";
import Vulnerabilities from "@/pages/Vulnerabilities/Vulnerabilities";
import { ADMIN_ONLY, ANALYST_PLUS, AUDIT_READERS, RULE_AUTHORS } from "@/store/authStore";

export default function App() {
  return (
    <ToastProvider>
      <Navbar />
      <Routes>
        <Route path="/login" element={<Login />} />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts"
          element={
            <ProtectedRoute roles={ANALYST_PLUS}>
              <AlertQueue />
            </ProtectedRoute>
          }
        />
        <Route
          path="/cases"
          element={
            <ProtectedRoute roles={ANALYST_PLUS}>
              <CaseList />
            </ProtectedRoute>
          }
        />
        <Route
          path="/cases/:caseId"
          element={
            <ProtectedRoute roles={ANALYST_PLUS}>
              <CaseDetail />
            </ProtectedRoute>
          }
        />
        <Route
          path="/rules"
          element={
            <ProtectedRoute roles={[...RULE_AUTHORS, "analyst"]}>
              <Rules />
            </ProtectedRoute>
          }
        />
        <Route
          path="/rules/new"
          element={
            <ProtectedRoute roles={RULE_AUTHORS}>
              <RuleEditor />
            </ProtectedRoute>
          }
        />
        <Route
          path="/rules/:ruleId"
          element={
            <ProtectedRoute roles={[...RULE_AUTHORS, "analyst"]}>
              <RuleEditor />
            </ProtectedRoute>
          }
        />
        <Route
          path="/events"
          element={
            <ProtectedRoute>
              <Events />
            </ProtectedRoute>
          }
        />
        <Route
          path="/threat-intel"
          element={
            <ProtectedRoute>
              <ThreatIntel />
            </ProtectedRoute>
          }
        />
        <Route
          path="/vulnerabilities"
          element={
            <ProtectedRoute>
              <Vulnerabilities />
            </ProtectedRoute>
          }
        />
        <Route
          path="/compliance"
          element={
            <ProtectedRoute roles={AUDIT_READERS}>
              <Compliance />
            </ProtectedRoute>
          }
        />
        <Route
          path="/audit"
          element={
            <ProtectedRoute roles={AUDIT_READERS}>
              <Audit />
            </ProtectedRoute>
          }
        />
        <Route
          path="/settings"
          element={
            <ProtectedRoute roles={ADMIN_ONLY}>
              <Settings />
            </ProtectedRoute>
          }
        />
        <Route
          path="/account"
          element={
            <ProtectedRoute>
              <Account />
            </ProtectedRoute>
          }
        />

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </ToastProvider>
  );
}
