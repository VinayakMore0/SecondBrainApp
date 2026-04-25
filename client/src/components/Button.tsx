import type { ReactElement } from "react";

interface ButtonProps {
  varient: "primary" | "secondary";
  text: string;
  startIcon: ReactElement;
}

const varientClasses = {
  "primary": "bg-purple-600 text-white",
  "secondary": "bg-purple-200 text-purple-600"


}

const defaultStyles = "px-4 py-2 rounded-md font-light flex items-center";

export function Button({varient, text, startIcon}: ButtonProps) {
  return (
    <button className={varientClasses[varient] + " " + defaultStyles}>
      <div className="pr-2">{startIcon}</div>
      {text}
    </button>
  );
}


