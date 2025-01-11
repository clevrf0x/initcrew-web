import { Link } from 'react-router-dom';
import { Button } from '../ui/button';

function Landing() {
  return (
    <div className='h-[60vh] flex flex-row justify-between items-center'>
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
            <Link to='/#about'>About Us</Link>
          </Button>
          <Button className='px-8 py-5 font-semibold' variant='outline'>
            <Link to='/blogs'>Our Blogs</Link>
          </Button>
        </div>
      </div>
      <div>
        <img src='/images/server-dark.webp' alt='guy working on a server' className='h-96' />
      </div>
    </div>
  );
}

export default Landing;
