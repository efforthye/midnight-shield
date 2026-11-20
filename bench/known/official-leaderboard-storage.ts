// expect: MS104
// source: https://github.com/midnightntwrk/midnight-examples (examples/leaderboard/ui/src/contexts/BrowserLeaderboardManager.ts)
// note: minimal reproduction. The player's secret key is kept in localStorage.
export function remember(secretKey: string) {
  localStorage.setItem("leaderboard-secret-key", secretKey);
}
