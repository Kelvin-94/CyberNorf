'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';

export interface NavItem {
  href: string;
  label: string;
  group: 'Investigate' | 'Govern';
}

export function NavLinks({ items }: { items: NavItem[] }) {
  const pathname = usePathname();
  const groups: Array<NavItem['group']> = ['Investigate', 'Govern'];
  // Several entries can be prefixes of the current path (Settings and
  // Settings → Retention). Only the deepest match is the page being viewed.
  const activeHref = items
    .filter((item) => pathname === item.href || pathname.startsWith(`${item.href}/`))
    .sort((a, b) => b.href.length - a.href.length)[0]?.href;

  return (
    <nav className="nav" aria-label="Organization">
      {groups.map((group) => {
        const groupItems = items.filter((item) => item.group === group);
        if (groupItems.length === 0) {
          return null;
        }
        return (
          <div key={group} className="nav-group">
            <p className="nav-group-label">{group}</p>
            {groupItems.map((item) => {
              const active = item.href === activeHref;
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className="nav-link"
                  aria-current={active ? 'page' : undefined}
                >
                  {item.label}
                </Link>
              );
            })}
          </div>
        );
      })}
    </nav>
  );
}
