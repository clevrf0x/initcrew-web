import React from 'react';
import { Card, CardHeader, CardTitle, CardContent, CardFooter } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { format } from 'date-fns';

interface Author {
  name: string;
  avatar?: string;
}

interface BlogCardProps {
  title: string;
  authors: Author[];
  publishedDate: Date;
  description: string;
  onReadMore: () => void;
}

const BlogCard: React.FC<BlogCardProps> = ({
  title,
  authors,
  publishedDate,
  description,
  onReadMore,
}) => {
  return (
    <Card className='w-full'>
      <CardHeader>
        <CardTitle className='text-2xl font-bold'>{title}</CardTitle>
        <div className='flex items-center space-x-4 mt-2'>
          <div className='flex -space-x-2'>
            {authors.map((author, index) => (
              <Avatar key={index} className='border-2 border-white'>
                {author.avatar ? (
                  <AvatarImage src={author.avatar} alt={author.name} />
                ) : (
                  <AvatarFallback>
                    {author.name
                      .split(' ')
                      .map(n => n[0])
                      .join('')}
                  </AvatarFallback>
                )}
              </Avatar>
            ))}
          </div>
          <div className='text-sm text-gray-500'>{authors.map(a => a.name).join(', ')}</div>
        </div>
        <div className='text-sm text-gray-500 mt-1'>{format(publishedDate, 'MMMM d, yyyy')}</div>
      </CardHeader>

      <CardContent>
        <p className='text-gray-600 line-clamp-3'>{description}</p>
      </CardContent>

      <CardFooter>
        <Button onClick={onReadMore} variant='outline'>
          Read More
        </Button>
      </CardFooter>
    </Card>
  );
};

export default BlogCard;
