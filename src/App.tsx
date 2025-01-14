import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import { Analytics } from '@vercel/analytics/react';
import { SpeedInsights } from '@vercel/speed-insights/react';
import NotFound from './pages/404';
import Unauthorized from './pages/401';
import HomePage from './pages/home';
import Projects from './pages/projects';
import Events from './pages/events';
import WorkInProgress from './pages/work-in-progress';
import AboutUs from './pages/about';
import BlogList from './pages/blog-list';
import JuicyBarBruteforceBlog from './pages/blogs/juicy-bar-bruteforce';
import KeralaPoliceYoutubeHackBlog from './pages/blogs/kerala-police-youtube-takeover';

function App() {
  return (
    <React.Fragment>
      <Router>
        <div>
          <Routes>
            {/* Public Routes */}
            <Route path='/' element={<HomePage />} />
            <Route path='/projects' element={<Projects />} />
            <Route path='/events' element={<Events />} />
            <Route path='/about' element={<AboutUs />} />
            <Route path='/blogs' element={<BlogList />} />
            <Route path='/initcon' element={<WorkInProgress />} />
            <Route path='/shop' element={<WorkInProgress />} />
            <Route path='/contact' element={<WorkInProgress />} />
            <Route path='/unauthorized' element={<Unauthorized />} />

            {/* Blogs Routes */}
            <Route path='/blogs/juicy-bar-bruteforce' element={<JuicyBarBruteforceBlog />} />
            <Route
              path='/blogs/kerala-police-youtube-takeover'
              element={<KeralaPoliceYoutubeHackBlog />}
            />

            {/* 404 Route */}
            <Route path='*' element={<NotFound />} />
          </Routes>
        </div>
      </Router>
      <Analytics />
      <SpeedInsights />
    </React.Fragment>
  );
}

export default App;
