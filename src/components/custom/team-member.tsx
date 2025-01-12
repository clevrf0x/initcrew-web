import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';

interface TeamMemberProfileProps {
  name: string;
  imageUrl: string;
  initials: string;
  handle: string;
}

function TeamMemberProfile({ name, imageUrl, initials, handle }: TeamMemberProfileProps) {
  return (
    <div className='flex flex-col items-center justify-center space-y-3 mb-2'>
      <Avatar className='w-28 h-28'>
        <AvatarImage src={imageUrl} alt={name} />
        <AvatarFallback>{initials}</AvatarFallback>
      </Avatar>
      <div className='text-center'>
        <h3 className='font-bold'>{name}</h3>
        <p className='text-sm text-gray-400 italic'>{handle}</p>
      </div>
    </div>
  );
}

export default TeamMemberProfile;
