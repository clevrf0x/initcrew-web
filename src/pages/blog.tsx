import BlogCard from '@/components/custom/blog-card';
import NavMenu from '@/components/custom/nav-menu';
import { Separator } from '@/components/ui/separator';
import { useNavigate } from 'react-router-dom';

function BlogList() {
  const navigate = useNavigate();
  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
      <div className='flex-grow'>
        <NavMenu />
        <div className='mt-12 flex flex-col justify-center items-center '>
          <h1 className='text-3xl text-center font-bold uppercase'>Blogs</h1>
          <Separator className='my-2 mb-10 w-[50px] bg-gray-500' />
          <div />
          <div className='mb-10 grid grid-cols-1 gap-6 lg:grid-cols-2'>
            {/* <BlogCard
              title='Android CTF Juicy Bar::Bruteforce'
              authors={[{ name: 'Jane Doe', avatar: '/jane-avatar.jpg' }, { name: 'John Smith' }]}
              publishedDate={new Date('2024-01-13')}
              description='Explore the latest trends and best practices in modern web development. From React to TypeScript, we cover everything you need to know to stay ahead in the fast-paced world of web development.'
              onReadMore={() => console.log('Navigating to blog post...')}
            /> */}
            <BlogCard
              title='Android CTF Juicy Bar::Bruteforce'
              authors={[{ name: 'Ajin Deepak', avatar: '/images/authors/ad-profile.webp' }]}
              publishedDate={new Date('2024-04-21')}
              description={`Dive into the exciting world of Android CTF challenges with this detailed walkthrough of the Juicy Bar brute force level. In this post, Ajin Deepak guides you through identifying the validation method, crafting a Frida script, and brute-forcing a 4-digit PIN to uncover the flag. Whether you're a beginner or a seasoned reverse engineer, you'll find actionable insights, helpful tools, and links to deepen your Android security knowledge.`}
              onReadMore={() => navigate('/blogs/juicy-bar-bruteforce')}
            />
          </div>
        </div>
        <div />
      </div>
    </div>
  );
}

export default BlogList;
