import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';
import { Button } from '@/components/ui/button';
import { Link } from 'react-router-dom';

function HomePage() {
  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5 '>
      <div className='flex-grow'>
        <NavMenu />
        <div className='h-[60vh] w-full flex flex-row justify-between items-center'>
          <div className='flex flex-col justify-center'>
            <h1 className='text-5xl font-bold py-4'>Code. Defend. Conquer. Evolve</h1>
            <p className='text-xl font-medium'>
              Unlock your potential with hands-on learning and a community of experts.
            </p>
            <p className='text-xl font-medium'>
              Build your skills, secure the future, and join a thriving cybersecurity network.
            </p>
            <div className='mt-6 flex flex-row'>
              <Button className='me-4 px-8 py-5 font-semibold' variant='destructive'>
                <Link to='/team'>Meet Team</Link>
              </Button>
              <Button className='px-8 py-5 font-semibold' variant='outline'>
                <Link to='/blogs'>Blogs</Link>
              </Button>
            </div>
          </div>
          <div className='hidden lg:block'>
            <img src='/images/server-dark.webp' alt='guy working on a server' className='h-96' />
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}

export default HomePage;
