import EventCard from '@/components/custom/event-card';
import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';
import { Card, CardContent } from '@/components/ui/card';
import { Separator } from '@/components/ui/separator';
import { ChevronsDown } from 'lucide-react';

function Events() {
  const events = [
    {
      title: 'InitCon 2025',
      description:
        'Our first ever cybersecurity conference, InitCon 2025, is scheduled for June 2025. The event will feature workshops, talks, and networking opportunities for cybersecurity enthusiasts.',
      imageUrl: '/images/events/initcon.webp',
    },
    {
      title: 'InitX',
      description:
        'Conducted at Banglore and Kochi, InitX is a series of cybersecurity workshops and training sessions sponsored by industry leaders like Juspay and had panel from companies like Juspay, PayU and Groww.',
      imageUrl: '/images/events/initx.webp',
    },
    {
      title: 'Meetup 2022',
      description:
        'Held in October 2022, the Initcrew Meetup was sponsored by Lyminal and E-Hachify, drawing around 100 participants for an engaging and insightful event.',
      imageUrl: '/images/events/meetup.webp',
    },
    {
      title: 'Boot2Cloud CTF',
      description:
        'Our first onsite CTF event, Boot 2 Cloud Onsite CTF, was part of a larger meetup and saw participation from around 40 cybersecurity enthusiasts.',
      imageUrl: '/images/events/live-ctf.webp',
    },
    {
      title: 'Breakin CTF',
      description:
        'Conducted during the COVID-19 pandemic, Breakin CTF Challenge attracted over 650 participants. The event was proudly sponsored by industry leaders HackerOne, BugCrowd, and HackersEra.',
      imageUrl: '/images/events/break-in.webp',
    },
    {
      title: 'DISHA Webinar Series',
      description:
        'These virtual cybersecurity workshops and training sessions come in three variants, DISHA Mark I, DISHA Mark II, DISHA Mark III, offering comprehensive and advanced learning opportunities.',
      imageUrl: '/images/events/disha.webp',
    },
    {
      title: 'Onsite Training Sessions',
      description:
        'We have conducted over seven offline training sessions across various colleges in Kerala, delivering hands-on cybersecurity education to students and professionals.',
      imageUrl: '/images/events/training.webp',
    },
  ];

  const images = [
    {
      id: 1,
      src: '/images/initcrew_gallery/1.webp',
    },
    {
      id: 2,
      src: '/images/initcrew_gallery/2.webp',
    },
    {
      id: 3,
      src: '/images/initcrew_gallery/3.webp',
    },
    {
      id: 4,
      src: '/images/initcrew_gallery/4.webp',
    },
    {
      id: 5,
      src: '/images/initcrew_gallery/5.webp',
    },
    {
      id: 6,
      src: '/images/initcrew_gallery/6.webp',
    },
    {
      id: 7,
      src: '/images/initcrew_gallery/7.webp',
    },
    {
      id: 8,
      src: '/images/initcrew_gallery/8.webp',
    },
    {
      id: 9,
      src: '/images/initcrew_gallery/9.webp',
    },
    {
      id: 10,
      src: '/images/initcrew_gallery/10.webp',
    },
    {
      id: 11,
      src: '/images/initcrew_gallery/11.webp',
    },
    {
      id: 12,
      src: '/images/initcrew_gallery/12.webp',
    },
    {
      id: 13,
      src: '/images/initcrew_gallery/13.webp',
    },
    {
      id: 14,
      src: '/images/initcrew_gallery/14.webp',
    },
    {
      id: 15,
      src: '/images/initcrew_gallery/15.webp',
    },
  ];

  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
      <div className='flex-grow'>
        <NavMenu />
        <div className='mt-12 flex flex-col justify-center items-center '>
          <h1 className='text-3xl text-center font-bold uppercase'>Events</h1>
          <Separator className='my-2 mb-10 w-[50px] bg-gray-500' />
          <div className='mb-10 grid grid-cols-1 gap-6 lg:grid-cols-2'>
            {events.map((event, index) => (
              <EventCard key={index} {...event} />
            ))}
          </div>
          <div className='py-[3vh]'>
            {/* TODO: Onclick scroll to bottom */}
            <ChevronsDown
              // onClick={() => console.log('scroll 100vh')}
              className='animate-bounce hover:cursor-pointer'
              size={48}
            />
          </div>
          <h1 className='text-3xl text-center font-bold uppercase mt-[2rem]'>Gallery</h1>
          <Separator className='my-2 mb-10 w-[50px] bg-gray-500' />
          <div className='container mx-auto p-4'>
            <div className='grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4'>
              {images.map(image => (
                <Card key={image.id} className='overflow-hidden'>
                  <CardContent className='p-0'>
                    <img
                      src={image.src}
                      className='w-full h-60 object-cover transition-transform duration-200 hover:scale-105'
                    />
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}

export default Events;
