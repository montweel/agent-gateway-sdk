import React, { useId } from 'react';

export const MontLogo: React.FC<{ size?: number; className?: string }> = ({ size = 32, className = '' }) => {
  const gradId = useId();
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" xmlns="http://www.w3.org/2000/svg" className={className} aria-label="Mont logo">
      <rect width="40" height="40" rx="10" fill="#0B0F19" stroke="#6366F1" strokeOpacity="0.35" strokeWidth="1.5"/>
      <path d="M7 29L14.5 11L18.5 20.5L15 29H7Z" fill={`url(#${gradId})`}/>
      <path d="M33 29L25.5 11L21.5 20.5L25 29H33Z" fill={`url(#${gradId})`}/>
      <circle cx="20" cy="14" r="2.5" fill="#10B981"/>
      <defs>
        <linearGradient id={gradId} x1="7" y1="11" x2="33" y2="29" gradientUnits="userSpaceOnUse">
          <stop stopColor="#334155"/>
          <stop offset="1" stopColor="#475569"/>
        </linearGradient>
      </defs>
    </svg>
  );
};
