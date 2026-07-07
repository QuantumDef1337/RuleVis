export default function Logo({ size = 32 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32">
      <circle cx="8" cy="16" r="4" fill="var(--accent)" />
      <circle cx="24" cy="8" r="4" fill="var(--violet)" />
      <circle cx="24" cy="24" r="4" fill="var(--green)" />
      <path d="M11 14.5 21 9M11 17.5 21 23" stroke="var(--text-faint)" strokeWidth="2" />
    </svg>
  );
}
