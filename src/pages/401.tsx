import { Button } from '@/components/ui/button';
import { useNavigate } from 'react-router-dom';

function Unauthorized() {
  const navigate = useNavigate();

  return (
    <div className='flex flex-col items-center justify-center min-h-screen text-center'>
      <h1 className='text-6xl font-extrabold'>401</h1>
      <h2 className='mt-4 text-2xl font-bold'>Unauthorized Access</h2>
      <p className='mt-2'>Sorry, you don't have permission to access this page.</p>
      <Button className='mt-6' onClick={() => navigate('/')} variant='ghost'>
        Go Back Home
      </Button>
    </div>
  );
}

export default Unauthorized;
