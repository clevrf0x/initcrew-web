import { Card, CardContent, CardHeader } from '@/components/ui/card';
import { Github, Linkedin, MessagesSquare, Twitter, Instagram, Globe } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface TeamMemberCardProps {
  name: string;
  imageUrl: string;
  handle: string;
  linkedin?: string;
  discord?: string;
  twitter?: string;
  instagram?: string;
  github?: string;
  website?: string;
}

const TeamMemberCard = ({
  name,
  imageUrl,
  handle,
  linkedin,
  discord,
  twitter,
  instagram,
  github,
  website,
}: TeamMemberCardProps) => {
  const socialLinks = [
    { url: website, icon: <Globe className='h-4 w-4' />, label: 'Website' },
    { url: github, icon: <Github className='h-4 w-4' />, label: 'GitHub' },
    { url: linkedin, icon: <Linkedin className='h-4 w-4' />, label: 'LinkedIn' },
    { url: twitter, icon: <Twitter className='h-4 w-4' />, label: 'Twitter' },
    { url: discord, icon: <MessagesSquare className='h-4 w-4' />, label: 'Discord' },
    { url: instagram, icon: <Instagram className='h-4 w-4' />, label: 'Instagram' },
  ].filter(link => link.url);

  return (
    <Card className='w-72'>
      <CardHeader className='text-center'>
        <div className='flex justify-center mb-4'>
          <img
            src={imageUrl}
            alt={`${name}'s profile`}
            className='rounded-full w-24 h-24 object-cover'
          />
        </div>
        <div>
          <h3 className='font-semibold text-lg uppercase'>{name}</h3>
          <p className='text-sm text-gray-400'>@{handle}</p>
        </div>
      </CardHeader>
      <CardContent>
        <div className='flex flex-wrap gap-2 justify-center'>
          {socialLinks.map(({ url, icon, label }) => (
            <Button key={label} variant='outline' size='sm' className='h-8 w-8 p-0' asChild>
              <a href={url} target='_blank' rel='noopener noreferrer' aria-label={label}>
                {icon}
              </a>
            </Button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
};

export default TeamMemberCard;
