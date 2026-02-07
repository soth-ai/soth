import { cn } from "@/lib/utils";

interface DockIconProps {
  className?: string;
  weight?: string;
}

export function MetricLogo({ className }: DockIconProps) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("h-4 w-4", className)}
      aria-hidden="true"
    >
      <path
        d="M10 71.3449L22.7586 71.0001C22.7586 65.1866 24.6805 59.5362 28.225 54.9283L29.6552 53.069L20.3448 44.1035C14.5602 49.8882 11.0408 57.5547 10.4251 65.7122L10 71.3449Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeOpacity="0.9"
        strokeWidth="0.689655"
      />
      <path
        d="M22.7578 42.0345L31.7233 51C36.1811 46.7651 41.9758 44.2168 48.1098 43.7938L48.6199 43.7586V31C39.258 31.4458 30.3437 35.1382 23.4086 41.4429L22.7578 42.0345Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeOpacity="0.9"
        strokeWidth="0.689655"
      />
      <path
        d="M90 71.3449L77.2414 71.0001C77.2414 65.1866 75.3195 59.5362 71.775 54.9283L70.3448 53.069L79.6552 44.1035C85.4398 49.8882 88.9592 57.5547 89.5749 65.7122L90 71.3449Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeOpacity="0.9"
        strokeWidth="0.689655"
      />
      <path
        d="M77.2422 42.0345L68.2767 51C63.8189 46.7651 58.0242 44.2168 51.8902 43.7938L51.3801 43.7586V31C60.742 31.4458 69.6563 35.1382 76.5914 41.4429L77.2422 42.0345Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeOpacity="0.9"
        strokeWidth="0.689655"
      />
      <path
        d="M67.172 31.8935C67.42 31.4 68.0211 31.2011 68.5146 31.4491C69.008 31.6972 69.207 32.2983 68.9589 32.7917L49.7865 70.9335L47.9995 70.0352L67.172 31.8935Z"
        fill="currentColor"
      />
      <path
        d="M42.7578 72.0333C42.7578 68.2247 45.8457 65.1367 49.6544 65.1367C53.463 65.1367 56.5509 68.2247 56.5509 72.0333"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.6"
      />
    </svg>
  );
}

export function ObserverLogo({ className }: DockIconProps) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("h-4 w-4", className)}
      aria-hidden="true"
    >
      <rect
        x="9.5"
        y="16.5"
        width="81"
        height="65"
        stroke="currentColor"
        strokeOpacity="0.35"
        strokeDasharray="2 2"
      />
      <path
        d="M79 47.9281L78.6598 47.4583C64.1426 27.411 34.1942 27.6509 20 47.9281C34.0308 68.5253 64.316 68.7656 78.6719 48.3937L79 47.9281Z"
        stroke="currentColor"
      />
      <circle cx="50" cy="48" r="14.5" fill="currentColor" fillOpacity="0.12" stroke="currentColor" />
      <circle cx="49.5" cy="48.5" r="7" fill="none" stroke="currentColor" />
      <circle cx="59.5" cy="43.5" r="4" fill="currentColor" fillOpacity="0.35" stroke="currentColor" />
      <path d="M10 24V17H17" stroke="currentColor" strokeWidth="2" />
      <path d="M90 24V17H83" stroke="currentColor" strokeWidth="2" />
      <path d="M10 74V81H17" stroke="currentColor" strokeWidth="2" />
      <path d="M90 74V81H83" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

export function IdentityLogo({ className }: DockIconProps) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("h-4 w-4", className)}
      aria-hidden="true"
    >
      <circle cx="48.4829" cy="26.7524" r="12.7251" fill="currentColor" fillOpacity="0.12" stroke="currentColor" />
      <circle cx="42.9741" cy="25.3374" r="0.657725" fill="currentColor" fillOpacity="0.35" stroke="currentColor" />
      <rect
        x="30.668"
        y="40.4766"
        width="35.4829"
        height="45.8806"
        rx="5.64287"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
      />
      <rect
        x="48.5703"
        y="24.6797"
        width="5.94635"
        height="1.31545"
        rx="0.657725"
        fill="currentColor"
        fillOpacity="0.35"
        stroke="currentColor"
      />
      <circle
        cx="66.9032"
        cy="62.9032"
        r="18.4032"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeDasharray="0.43 0.43"
      />
      <circle
        cx="66.8"
        cy="62.7961"
        r="14.6008"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeDasharray="0.43 0.43"
      />
      <path
        d="M58.7539 60.776L63.3802 66.6195C63.9709 67.3657 65.0679 67.461 65.7785 66.8278L75.3018 58.3418"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
      />
      <path d="M10 19V12H17" stroke="currentColor" strokeWidth="2" />
      <path d="M90 19V12H83" stroke="currentColor" strokeWidth="2" />
      <path d="M90 79V86H83" stroke="currentColor" strokeWidth="2" />
      <path d="M10 79V86H17" stroke="currentColor" strokeWidth="2" />
    </svg>
  );
}

export function CostLogo({ className }: DockIconProps) {
  return (
    <svg
      viewBox="0 0 100 100"
      fill="none"
      xmlns="http://www.w3.org/2000/svg"
      className={cn("h-4 w-4", className)}
      aria-hidden="true"
    >
      <circle cx="49.5" cy="49.5" r="36" fill="currentColor" fillOpacity="0.12" stroke="currentColor" />
      <circle
        cx="49.5"
        cy="49.5"
        r="29"
        fill="currentColor"
        fillOpacity="0.08"
        stroke="currentColor"
        strokeDasharray="2 2"
      />
      <path
        d="M48.384 33.664H51.024V65.2032H48.384V33.664ZM44.9696 61.5072C43.5264 60.8032 42.4 59.7824 41.5552 58.48C40.7104 57.2128 40.2176 55.6992 40.0768 54.0096L43.2448 53.7984C43.3856 55.0656 43.7728 56.1216 44.336 56.9664C44.8992 57.8464 45.6384 58.5152 46.5888 58.9376C47.5392 59.3952 48.7008 59.6064 50.0384 59.6064C51.7984 59.6064 53.136 59.2896 54.1216 58.5856C55.072 57.9168 55.5648 56.9312 55.5648 55.664C55.5648 54.8544 55.3536 54.1504 55.0016 53.552C54.6144 52.9888 53.9104 52.4256 52.8896 51.9328C51.8336 51.44 50.3552 50.9472 48.4192 50.4544C46.448 49.9616 44.8992 49.4336 43.7728 48.8352C42.6464 48.272 41.8368 47.568 41.344 46.7232C40.8512 45.8784 40.6048 44.8224 40.6048 43.5552C40.6048 42.1824 40.9216 40.9504 41.5904 39.8592C42.2592 38.8032 43.2096 37.9584 44.4768 37.36C45.744 36.7616 47.2224 36.4448 48.912 36.4448C50.672 36.4448 52.2208 36.7968 53.5584 37.4656C54.896 38.1696 55.952 39.0848 56.7264 40.2816C57.5008 41.4784 57.9936 42.8512 58.2048 44.4L55.0368 44.6112C54.896 43.5904 54.544 42.6752 54.0512 41.9008C53.5232 41.1264 52.8192 40.4928 51.9744 40.0704C51.0944 39.648 50.0384 39.4016 48.8416 39.4016C47.2928 39.4016 46.0608 39.7888 45.1456 40.528C44.2304 41.2672 43.7728 42.2176 43.7728 43.4144C43.7728 44.224 43.9488 44.8576 44.3008 45.3504C44.6528 45.8432 45.2864 46.3008 46.2016 46.688C47.1168 47.0752 48.4896 47.4976 50.32 47.92C52.3616 48.448 54.016 49.0464 55.248 49.7504C56.48 50.4544 57.36 51.2992 57.9232 52.2144C58.4512 53.1296 58.7328 54.2208 58.7328 55.4528C58.7328 56.896 58.3456 58.1632 57.6064 59.2192C56.832 60.2752 55.8112 61.12 54.4736 61.6832C53.136 62.2816 51.6576 62.5632 49.968 62.5632C48.0672 62.5632 46.3776 62.2112 44.9696 61.5072Z"
        fill="currentColor"
      />
    </svg>
  );
}
