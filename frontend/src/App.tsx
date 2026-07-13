import { Navigate, Route, Routes } from "react-router-dom";

import { Navbar } from "@/components/Navbar";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import AlertQueue from "@/pages/AlertQueue/AlertQueue";
import CaseDetail from "@/pages/CaseDetail/CaseDetail";
import Login from "@/pages/Login/Login";
import Rules from "@/pages/Rules/Rules";

export default function App() {
  return (
    <div>
      <Navbar />
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route
          path="/alerts"
          element={
            <ProtectedRoute>
              <AlertQueue />
            </ProtectedRoute>
          }
        />
        <Route
          path="/cases/:caseId"
          element={
            <ProtectedRoute>
              <CaseDetail />
            </ProtectedRoute>
          }
        />
        <Route
          path="/rules"
          element={
            <ProtectedRoute>
              <Rules />
            </ProtectedRoute>
          }
        />
        <Route path="/" element={<Navigate to="/alerts" replace />} />
      </Routes>
    </div>
  );
}
