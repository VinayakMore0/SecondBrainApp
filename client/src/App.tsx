import React from 'react'
import Button from './components/Button'
import { PlusIcon } from '@heroicons/react/16/solid';


const App = () => {
  return (
    <div className='flex gap-2 m-4'>
      <Button variant="primary" startIcon={<PlusIcon className='h-5' />} text="Click me" />
      <Button variant="secondary" text="Click meeeeeeeee!" />
    </div>
  );
}

export default App