import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center whitespace-nowrap rounded-[8px] border border-border text-[12px] font-medium tracking-[0.01em] transition-all duration-200 ease-out focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:pointer-events-none disabled:opacity-50 active:scale-[0.98]",
  {
    variants: {
      variant: {
        default:
          "bg-foreground text-background border-foreground hover:bg-foreground/90",
        destructive:
          "bg-destructive text-destructive-foreground border-destructive hover:bg-destructive/90",
        outline:
          "bg-transparent text-foreground hover:bg-muted hover:border-border-hover",
        secondary:
          "bg-secondary text-secondary-foreground border-border hover:bg-muted-hover",
        ghost: "border-transparent hover:bg-muted hover:text-foreground",
        link: "border-transparent text-accent underline-offset-4 hover:underline",
      },
      size: {
        default: "h-9 px-3 py-1.5",
        sm: "h-7 px-2.5 text-[11px]",
        lg: "h-10 px-4 text-[12px]",
        icon: "h-8 w-8",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
  VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        className={cn(buttonVariants({ variant, size, className }))}
        ref={ref}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
