"use client";

import { Button } from "@/components/ui/button";

type NavProps = {
  authUser: { username: string; roles: string[] } | null;
  onLogout: () => void;
};

export function Nav({ authUser, onLogout }: NavProps) {
  return (
    <nav className="border-b border-slate-700/50 bg-slate-950/40 backdrop-blur-md sticky top-0 z-40">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <div className="flex items-center gap-3">
            <div className="w-2.5 h-2.5 rounded-full bg-gradient-to-r from-cyan-400 to-blue-500" />
            <span className="text-lg font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              ATTT
            </span>
            <span className="hidden sm:inline text-xs text-slate-400 ml-2">
              Security Platform
            </span>
          </div>

          {/* Right: User Info */}
          <div className="flex items-center gap-4">
            {authUser ? (
              <div className="flex items-center gap-3">
                <div className="hidden sm:block text-sm">
                  <p className="text-white font-medium">{authUser.username}</p>
                  <p className="text-xs text-slate-400">{authUser.roles.join(", ")}</p>
                </div>
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-cyan-400 to-blue-500 flex items-center justify-center">
                  <span className="text-xs font-bold text-white">
                    {authUser.username.charAt(0).toUpperCase()}
                  </span>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={onLogout}
                  className="text-slate-300 hover:text-white"
                >
                  Sign Out
                </Button>
              </div>
            ) : (
              <span className="text-sm text-slate-400">Not signed in</span>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}
