import { useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import remarkMath from 'remark-math';
import rehypeKatex from 'rehype-katex';
import rehypeRaw from 'rehype-raw';
import rehypeSlug from 'rehype-slug';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { oneDark } from 'react-syntax-highlighter/dist/cjs/styles/prism';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Separator } from '@/components/ui/separator';
import { format } from 'date-fns';
import { Copy, Check } from 'lucide-react';

interface CodeBlockProps {
  language: string;
  children: string;
}

interface Frontmatter {
  title: string;
  authors: string[];
  date: string;
  tags: string[];
}

interface BlogPostProps {
  frontmatter: Frontmatter;
  content: string;
}

interface CustomComponentProps {
  children?: React.ReactNode;
  href?: string;
  src?: string;
  alt?: string;
  node?: unknown;
  inline?: boolean;
  className?: string;
}

const CodeBlock: React.FC<CodeBlockProps> = ({ language, children }) => {
  const [isCopied, setIsCopied] = useState(false);

  const copyToClipboard = async () => {
    await navigator.clipboard.writeText(children);
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <div className='relative group'>
      <div className='absolute right-2 top-2'>
        <button
          onClick={copyToClipboard}
          className='p-2 rounded-md bg-slate-800 hover:bg-slate-700 transition-colors'>
          {isCopied ? (
            <Check className='h-4 w-4 text-slate-400' />
          ) : (
            <Copy className='h-4 w-4 text-slate-400' />
          )}
        </button>
      </div>
      <div className='overflow-x-auto scrollbar-thin scrollbar-thumb-primary scrollbar-track-primary scrollbar-thumb-rounded-full scrollbar-track-rounded-full scrollbar-thumb-primary-hover scrollbar-track-primary-hover'>
        <SyntaxHighlighter
          language={language}
          style={oneDark}
          customStyle={{
            margin: 0,
            borderRadius: '0.5rem',
            fontSize: '14px',
            padding: '2rem 1rem',
          }}>
          {children}
        </SyntaxHighlighter>
      </div>
    </div>
  );
};

const BlogPost: React.FC<BlogPostProps> = ({ frontmatter, content }) => {
  const components: Record<string, React.FC<CustomComponentProps>> = {
    h1: ({ children }) => (
      <h1
        className='scroll-m-20 text-4xl font-extrabold tracking-tight lg:text-5xl mb-8'
        id={children?.toString().toLowerCase().replace(/\s+/g, '-')}>
        {children}
      </h1>
    ),
    h2: ({ children }) => (
      <h2
        className='scroll-m-20 text-3xl font-semibold tracking-tight mt-8 mb-4'
        id={children?.toString().toLowerCase().replace(/\s+/g, '-')}>
        {children}
      </h2>
    ),
    h3: ({ children }) => (
      <h3
        className='scroll-m-20 text-2xl font-semibold tracking-tight mt-6 mb-2'
        id={children?.toString().toLowerCase().replace(/\s+/g, '-')}>
        {children}
      </h3>
    ),
    p: ({ children }) => <p className='leading-7 [&:not(:first-child)]:mt-4'>{children}</p>,
    a: ({ href, children }) => (
      <a
        href={href}
        className='font-medium text-primary underline underline-offset-4 hover:text-primary/80 transition-colors'
        target='_blank'
        rel='noopener noreferrer'>
        {children}
      </a>
    ),
    img: ({ src, alt }) => (
      <div className='my-6'>
        <img src={src} alt={alt} className='rounded-lg border shadow-sm' loading='lazy' />
      </div>
    ),
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    code: ({ node, inline, className, children, ...props }) => {
      const match = /language-(\w+)/.exec(className || '');
      const language = match ? match[1] : '';

      if (inline) {
        return (
          <code className='rounded bg-muted px-[0.3rem] py-[0.2rem] font-mono text-sm'>
            {children}
          </code>
        );
      }

      return <CodeBlock language={language}>{String(children).replace(/\n$/, '')}</CodeBlock>;
    },
    blockquote: ({ children }) => (
      <blockquote className='mt-6 border-l-2 pl-6 italic'>{children}</blockquote>
    ),
    table: ({ children }) => (
      <div className='my-6 w-full overflow-y-auto'>
        <table className='w-full border-collapse border'>{children}</table>
      </div>
    ),
    th: ({ children }) => (
      <th className='border bg-muted px-4 py-2 text-left font-medium'>{children}</th>
    ),
    td: ({ children }) => <td className='border px-4 py-2'>{children}</td>,
  };

  const markdownContent = content.trim();

  return (
    <>
      <Card className='max-w-6xl mx-auto my-6 border-none'>
        <CardHeader>
          <CardTitle className='text-4xl text-center'>{frontmatter.title}</CardTitle>
          <CardDescription>
            <div className='flex flex-col gap-2'>
              <div className='flex flex-col lg:flex-row items-center gap-2 justify-center font-semibold my-2'>
                <span className='text-sm text-muted-foreground'>
                  {frontmatter.authors.join(',')}
                </span>
                <Separator className='w-[50px] h-[5px] bg-gray-500' />
                <span className='text-sm text-muted-foreground'>
                  {format(new Date(frontmatter.date), 'MMMM d, yyyy')}
                </span>
              </div>
              <div className='flex flex-wrap gap-2 items-center justify-center'>
                {frontmatter.tags.map(tag => (
                  <Badge key={tag} variant='secondary'>
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          </CardDescription>
        </CardHeader>

        <Separator className='mb-6' />

        <CardContent>
          <ReactMarkdown
            components={components}
            remarkPlugins={[remarkGfm, remarkMath]}
            rehypePlugins={[rehypeRaw, rehypeKatex, rehypeSlug]}
            className='prose prose-slate max-w-none dark:prose-invert'>
            {markdownContent}
          </ReactMarkdown>
        </CardContent>
      </Card>
    </>
  );
};

export default BlogPost;
