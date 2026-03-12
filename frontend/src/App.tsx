import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import './App.css'
import MainLayout from './components/MainLayout'
import ContractData from './pages/ContractData'
import Detection from './pages/Detection'
import PromptConfig from './pages/PromptConfig'
import Training from './pages/Training'
import Robustness from './pages/Robustness'
import Report from './pages/Report'

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<MainLayout />}>
          <Route index element={<Navigate to="/contracts" replace />} />
          <Route path="contracts" element={<ContractData />} />
          <Route path="detection" element={<Detection />} />
          <Route path="prompts" element={<PromptConfig />} />
          <Route path="training" element={<Training />} />
          <Route path="robustness" element={<Robustness />} />
          <Route path="report" element={<Report />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default App
