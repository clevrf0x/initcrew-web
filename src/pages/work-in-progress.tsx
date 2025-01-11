import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';

function WorkInProgress() {
  const navigate = useNavigate();

  return (
    <div className='flex flex-col items-center justify-center min-h-screen text-center'>
      <h1 className='text-6xl font-extrabold'>418</h1>
      <h2 className='mt-4 text-2xl font-bold'>I'm a Teapot!</h2>
      <p className='mt-2'>
        Oops, this page is brewing... but it’s not ready yet. Check back later for the perfect
        blend!
      </p>
      <Button className='mt-6' onClick={() => navigate('/')} variant='ghost'>
        Go Back Home
      </Button>
    </div>
  );
}

export default WorkInProgress;
