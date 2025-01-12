import Footer from '@/components/custom/footer';
import NavMenu from '@/components/custom/nav-menu';
import TeamMemberCard from '@/components/custom/team-member-card';
import { Separator } from '@/components/ui/separator';
import { Quote } from 'lucide-react';

function AboutUs() {
  const internalTeam = [
    {
      name: 'FAVAS M',
      imageUrl: '/images/team/founding_members/favas.webp',
      handle: 'clevrf0x',
      linkedin: 'https://www.linkedin.com/in/favasm72/',
      discord: '',
      twitter: 'https://x.com/clevrf0x',
      instagram: 'https://www.instagram.com/clevrf0x',
      github: 'https://github.com/clevrf0x',
      website: 'https://favas.dev',
    },
    {
      name: 'Ajin Deepak',
      imageUrl: '/public/images/team/founding_members/ad.webp',
      handle: 'ad2001',
      linkedin: 'https://in.linkedin.com/in/ajin-ad2001',
      discord: '',
      twitter: '',
      instagram: '',
      github: 'https://github.com/DERE-ad2001/',
      website: 'https://ad2001.com',
    },
    {
      name: 'Abhiram V',
      imageUrl: '/public/images/team/founding_members/abhiram.webp',
      handle: 'anon-artist',
      linkedin: 'https://www.linkedin.com/in/abhiramvabhi',
      discord: '',
      twitter: 'https://x.com/AbhiramV481206',
      instagram: '',
      github: 'https://github.com/Anon-Artist',
      website: '',
    },
    {
      name: 'Vimal V',
      imageUrl: '/public/images/team/founding_members/vimal.webp',
      handle: 'error404',
      linkedin: 'https://www.linkedin.com/in/vimal-varadan',
      discord: '',
      twitter: 'https://x.com/Error_decoder',
      instagram: 'https://www.instagram.com/overclocked_machine',
      github: '',
      website: '',
    },
    {
      name: 'Gokul VG',
      imageUrl: '/public/images/team/founding_members/gokul.webp',
      handle: 'pix',
      linkedin: 'https://www.linkedin.com/in/p1x1e',
      discord: '',
      twitter: 'https://x.com/g0_okul',
      instagram: 'https://www.instagram.com/go_0kul',
      github: '',
      website: '',
    },
    {
      name: 'Ananthakrishnan E R',
      imageUrl: '/public/images/team/founding_members/ak.webp',
      handle: 'abn00b',
      linkedin: 'https://www.linkedin.com/in/ananthakrishnaner',
      discord: '',
      twitter: 'https://x.com/4kn00b',
      instagram: 'https://www.instagram.com/akn00b',
      github: '',
      website: '',
    },
    {
      name: 'MUHAMMED SHANAVAS',
      imageUrl: '/public/images/team/founding_members/shanavas.webp',
      handle: 'alien_shanu',
      linkedin: 'https://www.linkedin.com/in/alienshanu/',
      discord: 'https://discord.com/users/612080689978015752',
      twitter: 'https://x.com/Alien_Shanu/',
      instagram: 'https://www.instagram.com/alien_shanu/',
      github: 'https://github.com/Alien-Shanu',
      website: 'https://www.alienshanu.me/',
    },
    {
      name: 'Akash Sebastian',
      imageUrl: '/public/images/team/founding_members/akash.webp',
      handle: 'akashsebastian',
      linkedin: 'https://www.linkedin.com/in/akash-sebastian',
      discord: '',
      twitter: 'https://x.com/akashseb',
      instagram: '',
      github: '',
      website: 'https://www.akashsebastian.com',
    },
    {
      name: 'Sreesankar G Warrier',
      imageUrl: '/public/images/team/founding_members/sreesankar.webp',
      handle: 'sree',
      linkedin: 'https://www.linkedin.com/in/sreesankar-g-warrier',
      discord: '',
      twitter: 'https://x.com/7r35p4553r',
      instagram: '',
      github: '',
      website: '',
    },
    {
      name: 'Govind Palakkal',
      imageUrl: '/public/images/team/founding_members/govind.webp',
      handle: 'd3lt4',
      linkedin: 'https://www.linkedin.com/in/d3lt4',
      discord: '',
      twitter: '',
      instagram: 'https://www.instagram.com/govindpalakkal__/',
      github: 'https://github.com/GovindPalakkal',
      website: '',
    },
  ];

  const coreTeam = [
    {
      name: 'Mahshooq Zubair',
      imageUrl: '/public/images/team/core_members/mahshooq.webp',
      handle: 'mahshooq',
      linkedin: 'https://www.linkedin.com/in/mahshooq/',
      discord: '',
      twitter: 'https://x.com/mq_xz_',
      instagram: 'https://www.instagram.com/mq.xz_/',
      github: 'https://github.com/mq-xz',
      website: 'https://mahshooq.dev/',
    },
    {
      name: 'Anugrah SR',
      imageUrl: '/public/images/team/core_members/anugrah.webp',
      handle: 'anugrahsr',
      linkedin: 'https://www.linkedin.com/in/anugrah-sr/',
      discord: '',
      twitter: 'https://x.com/Cyph3r_asr',
      instagram: 'https://www.instagram.com/anugrahsr',
      github: 'https://github.com/Anugrahsr/',
      website: 'http://anugrahsr.in',
    },
    {
      name: 'Ansan Binoy',
      imageUrl: '/public/images/team/core_members/ansan.webp',
      handle: 'ansan',
      linkedin: 'https://linkedin.com/in/ansanbinoy',
      discord: '',
      twitter: 'https://x.com/ansanbinoy',
      instagram: 'https://www.instagram.com/ansan_binoy',
      github: '',
      website: 'http://ansanbinoy.me',
    },
    {
      name: 'Amith',
      imageUrl: '/public/images/team/core_members/amith.webp',
      handle: '0x_amith',
      linkedin: 'https://www.linkedin.com/in/amith-c-61160517b',
      discord: '',
      twitter: 'https://x.com/amithc007',
      instagram: '',
      github: 'https://github.com/4m1Th',
      website: '',
    },
    {
      name: 'Aswin P Thambi',
      imageUrl: '/public/images/team/core_members/aswin.webp',
      handle: 'r0074g3n7',
      linkedin: 'https://www.linkedin.com/in/aswin-thambi-panikulangara',
      discord: '',
      twitter: 'https://x.com/r0074g3n7',
      instagram: '',
      github: '',
      website: '',
    },
    {
      name: 'Anand Jayaprakash',
      imageUrl: '/public/images/team/core_members/anand.webp',
      handle: 'anandjayapraksh',
      linkedin: 'https://www.linkedin.com/in/anand-jayaprakash-/',
      discord: '',
      twitter: 'https://x.com/cybertech_talks',
      instagram: 'https://www.instagram.com/thrill_comrade',
      // github: 'https://github.com/anandjayaprakash',
      website: 'https://anandjayaprakash.github.io/thrill-comrade.github.io/',
    },
    {
      name: 'Derin Shyju',
      imageUrl: '/public/images/team/core_members/derin.webp',
      handle: '0xspade',
      linkedin: 'https://www.linkedin.com/in/derin-shyju',
      discord: '',
      twitter: '',
      instagram: 'https://www.instagram.com/0xspade',
      github: '',
      website: '',
    },
    {
      name: 'Anuragh KP',
      imageUrl: '/public/images/team/core_members/anuragh.webp',
      handle: 'anuraghkp',
      linkedin: 'https://www.linkedin.com/in/anuraghkp/',
      discord: '',
      twitter: 'https://x.com/anuragh_kp',
      instagram: '',
      github: 'https://github.com/kpanuragh',
      website: 'https://iamanuragh.in/',
    },
    // {
    //   name: '',
    //   imageUrl: '/public/images/team/core_members',
    //   handle: '',
    //   linkedin: '',
    //   discord: '',
    //   twitter: '',
    //   instagram: '',
    //   github: '',
    //   website: '',
    // },
  ];

  return (
    <div className='min-h-screen flex flex-col px-[5%] pt-2 lg:px-[10%] lg:pt-5'>
      <div className='flex-grow'>
        <NavMenu />
        <div className='mt-12 flex flex-col justify-center items-center'>
          <h1 className='text-3xl text-center font-bold uppercase'>Our Vision</h1>
          <Separator className='my-2 mb-10 w-[150px] bg-gray-500' />
          <div className='p-8 rounded-lg max-w-3xl mx-auto'>
            <div className='relative'>
              <Quote className='w-8 h-8 absolute -left-4 -top-4 transform rotate-180 opacity-50' />
              <div className='text-center px-8 py-6'>
                <p className='text-xl md:text-2xl leading-relaxed'>
                  To become the primary information security community in the region, promoting
                  collaboration, knowledge sharing, and guiding and enhancing the cybersecurity
                  industry and ecosystem.
                </p>
              </div>
              <Quote className='w-8 h-8 absolute -right-4 -bottom-4 opacity-50' />
            </div>
          </div>
        </div>

        <div className='mt-12 flex flex-col justify-center items-center'>
          <h1 className='text-3xl text-center font-bold uppercase'>Founding Members</h1>
          <Separator className='my-2 mb-10 w-[150px] bg-gray-500' />
          <div className='mb-10 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4'>
            {internalTeam.map((team, index) => (
              <TeamMemberCard key={index} {...team} />
            ))}
          </div>
        </div>

        <div className='mt-12 flex flex-col justify-center items-center'>
          <h1 className='text-3xl text-center font-bold uppercase'>Core Members</h1>
          <Separator className='my-2 mb-10 w-[150px] bg-gray-500' />
          <div className='mb-10 grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4'>
            {coreTeam.map((team, index) => (
              <TeamMemberCard key={index} {...team} />
            ))}
          </div>
        </div>
      </div>
      <Footer />
    </div>
  );
}

export default AboutUs;
