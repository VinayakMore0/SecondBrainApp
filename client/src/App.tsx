import React from "react";
import { Button } from "./components/Button";
import { Card } from "./components/Card";
import { ShareIcon } from "./icons/ShareIcon";
import { PlusIcon } from "./icons/PlusIcon";

const App = () => {
  return (
    <div className="w-full h-full p-4">
      <div className="flex justify-end gap-4">
        <Button
          varient="primary"
          text="Add Content"
          startIcon={<PlusIcon />}
        ></Button>
        <Button
          varient="secondary"
          text="Share Brain"
          startIcon={<ShareIcon />}
        ></Button>
      </div>
      <div className="flex gap-4">
        <Card
          type="twitter"
          link="https://x.com/VinayakMore0/status/1933436086522368079"
          title="First Tweet"
        />
        <Card
          type="youtube"
          link="https://www.youtube.com/watch?v=0j7lyza_ZIs"
          title="First Video"
        />
      </div>
    </div>
  );
};

export default App;
