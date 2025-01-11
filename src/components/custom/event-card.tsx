import { Card, CardContent } from '@/components/ui/card';

interface EventCardProps {
  title: string;
  description: string;
  imageUrl: string;
}

function EventCard({ title, description, imageUrl }: EventCardProps) {
  return (
    <Card className='hover:border-muted-foreground transition-colors'>
      <div className='flex flex-col lg:flex-row gap-6 p-6'>
        <div className='w-full h-45 lg:w-64 lg:h-40 flex-shrink-0 bg-gray-950 rounded-md overflow-hidden'>
          <img src={imageUrl} alt={title} className='w-full h-full object-cover rounded-md' />
        </div>
        <CardContent className='p-0 flex-1'>
          <div className='flex items-center gap-3 mb-2'>
            <h3 className='text-xl font-semibold'>{title}</h3>
          </div>
          <p className='text-muted-foreground mb-4'>{description}</p>
        </CardContent>
      </div>
    </Card>
  );
}

export default EventCard;
