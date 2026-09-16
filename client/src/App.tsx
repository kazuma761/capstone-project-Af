import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { useAuthStore } from "./store/authStore";
import Login from "./pages/Login";
import Signup from "./pages/Signup";
import Dashboard from "./pages/Dashboard";
import Scanner from "./pages/Scanner";
import Downloads from "./pages/Downloads";
import BehavioralMonitor from "./pages/BehavioralMonitor";
import Chatbot from "./components/Chatbot";

function App() {
  const { token } = useAuthStore();

  return (
    <BrowserRouter>
      <Routes>
        <Route
          path="/login"
          element={!token ? <Login /> : <Navigate to="/dashboard" />}
        />
        <Route
          path="/signup"
          element={!token ? <Signup /> : <Navigate to="/dashboard" />}
        />
        <Route
          path="/dashboard"
          element={token ? <Dashboard /> : <Navigate to="/login" />}
        />
        <Route
          path="/scanner"
          element={token ? <Scanner /> : <Navigate to="/login" />}
        />
        <Route
          path="/downloads"
          element={token ? <Downloads /> : <Navigate to="/login" />}
        />
        <Route
          path="/behavioral"
          element={token ? <BehavioralMonitor /> : <Navigate to="/login" />}
        />
        <Route
          path="/"
          element={<Navigate to={token ? "/dashboard" : "/login"} />}
        />
      </Routes>
      {token && <Chatbot />}
    </BrowserRouter>
  );
}

export default App;
