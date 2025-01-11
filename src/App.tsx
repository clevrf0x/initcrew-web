import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import NotFound from './pages/404';
import Unauthorized from './pages/401';
import HomePage from './pages/home';
import Projects from './pages/projects';

function App() {
  return (
    <React.Fragment>
      <Router>
        <div>
          <Routes>
            {/* Public Routes */}
            <Route path='/' element={<HomePage />} />
            <Route path='/projects' element={<Projects />} />
            <Route path='/unauthorized' element={<Unauthorized />} />

            {/* 404 Route */}
            <Route path='*' element={<NotFound />} />
          </Routes>
        </div>
      </Router>
    </React.Fragment>
  );
}

export default App;
