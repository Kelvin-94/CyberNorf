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
              const active = pathname === item.href || pathname.startsWith(`${item.href}/`);
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
