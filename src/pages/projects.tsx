import { Separator } from '../components/ui/separator';
import ProjectCard, { ProjectStatus } from '../components/custom/project-card';
import NavMenu from '@/components/custom/nav-menu';
import Footer from '@/components/custom/footer';

function Projects() {
  const projects = [
    {
      title: 'RECONIZER V2',
      description:
        'Reconizer V2 introduces advanced features like user-created workflows and community integrations. It also includes YAML workflows to simplify and streamline bug bounty reconnaissance phases.',
      imageUrl: `/images/reconizer/rec2-dark.webp`,
      status: 'upcoming' as ProjectStatus,
      url: undefined,
    },
    {
      title: 'Unpacking the Packers',
      description:
        'Learn how to identify various packing techniques used to obfuscate Android applications and explore effective methods to analyze, unpack, and deal with them.',
      imageUrl: '/images/upack-packers.webp',
      status: 'upcoming' as ProjectStatus,
      url: undefined,
    },
    {
      title: 'Frida Labs',
      description:
        'Frida Labs offers beginner-friendly challenges to learn Frida for Android, covering key APIs from basics to intermediate levels. It’s designed to make mastering Frida approachable and effective.',
      imageUrl: `/images/frida-labs.webp`,
      status: 'released' as ProjectStatus,
      url: 'https://github.com/DERE-ad2001/Frida-Labs',
    },
    {
      title: 'R3C0NIzer',
      description:
        'R3C0NIzer is a command-line recon framework with a menu-driven system. It automates web app reconnaissance, manages tool installation, and runs modules with ease.',
      imageUrl: `/images/reconizer/rec1-dark.webp`,
      status: 'deprecated' as ProjectStatus,
      url: 'https://github.com/initcrew/R3C0Nizer',
    },
  ];

  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
      <div className='flex-grow'>
        <NavMenu />
        <div className='mt-12 flex flex-col justify-center items-center '>
          <h1 className='text-3xl text-center font-bold uppercase'>Projects</h1>
          <Separator className='my-2 mb-10 w-[100px] bg-gray-500' />
          <div className='mb-10 grid grid-cols-1 gap-6 lg:grid-cols-2'>
            {projects.map((project, index) => (
              <ProjectCard key={index} {...project} />
            ))}
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}

export default Projects;
