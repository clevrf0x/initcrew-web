import React from 'react';
import { Twitter, Linkedin, Github, Instagram } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface SocialLink {
  href: string;
  icon: React.ReactNode;
  label: string;
}

function Footer() {
  const socialLinks: SocialLink[] = [
    {
      href: 'https://x.com/in1tcr3w',
      icon: <Twitter className='h-4 w-4' />,
      label: 'Twitter (X)',
    },
    {
      href: 'https://www.linkedin.com/company/initcrew-community',
      icon: <Linkedin className='h-4 w-4' />,
      label: 'LinkedIn',
    },
    {
      href: 'https://github.com/initcrew',
      icon: <Github className='h-4 w-4' />,
      label: 'GitHub',
    },
    {
      href: 'https://www.instagram.com/initcrew_community/',
      icon: <Instagram className='h-4 w-4' />,
      label: 'Instagram',
    },
  ];

  return (
    <React.Fragment>
      <footer className='w-full py-6'>
        <div className='container flex flex-col items-center gap-2'>
          <div className='flex items-center space-x-2'>
            <span className='text-sm text-gray-400'>© 2025 initcrew. All rights reserved.</span>
          </div>

          <div className='flex flex-row items-center space-x-4'>
            {socialLinks.map(link => (
              <Button
                key={link.label}
                variant='ghost'
                size='icon'
                className='h-8 w-8 text-slate-400 hover:text-white hover:bg-slate-800'
                asChild>
                <a
                  href={link.href}
                  target='_blank'
                  rel='noopener noreferrer'
                  aria-label={link.label}>
                  {link.icon}
                </a>
              </Button>
            ))}
          </div>
        </div>
      </footer>
    </React.Fragment>
  );
}

export default Footer;
