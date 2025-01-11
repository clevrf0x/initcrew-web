import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { Button } from '../ui/button';

export type ProjectStatus = 'upcoming' | 'deprecated' | 'released';

interface ProjectProps {
  title: string;
  description: string;
  imageUrl: string;
  status?: ProjectStatus;
  url?: string;
}

function getStatusColor(status: ProjectStatus): string {
  switch (status) {
    case 'upcoming':
      return 'bg-red-500';
    case 'deprecated':
      return 'bg-yellow-500';
    case 'released':
      return 'bg-green-500';
    default:
      return 'bg-muted';
  }
}

function ProjectCard({ title, description, imageUrl, status, url }: ProjectProps) {
  return (
    <Card className='hover:border-muted-foreground transition-colors'>
      <div className='flex flex-col lg:flex-row gap-6 p-6'>
        <div className='w-full h-45 lg:w-72 lg:h-48 flex-shrink-0 bg-gray-950 rounded-md overflow-hidden'>
          <img src={imageUrl} alt={title} className='w-full h-full object-cover rounded-md' />
        </div>
        <CardContent className='p-0 flex-1'>
          <div className='flex items-center gap-3 mb-2'>
            <h3 className='text-xl font-semibold'>{title}</h3>
            {status && (
              <Badge
                className={`${getStatusColor(
                  status
                )} text-xs text-primary-foreground hover:cursor-pointer`}>
                {status.charAt(0).toUpperCase() + status.slice(1)}
              </Badge>
            )}
          </div>
          <p className='text-muted-foreground mb-4'>{description}</p>
          <Button onClick={() => window.open(url)} variant='secondary' disabled={!url}>
            Learn More
          </Button>
        </CardContent>
      </div>
    </Card>
  );
}

export default ProjectCard;
