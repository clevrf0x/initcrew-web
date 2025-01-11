import Landing from '@/components/custom/landing';
import NavMenu from '@/components/custom/nav-menu';
import React from 'react';

function HomePage() {
  return (
    <React.Fragment>
      <div className='px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
        <NavMenu />
        <Landing />
      </div>
    </React.Fragment>
  );
}

export default HomePage;
