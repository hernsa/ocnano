/**
 * The environment a child process inherits when the server spawns one on the user's
 * behalf.
 *
 * The server process can hold secrets of its own — an API key in its environment, a
 * credential the server decrypted — and those must not reach every command that runs
 * inside it. Only the variables a shell needs to work are passed on.
 */
const ALLOWLIST = [
  "PATH",
  "HOME",
  "USER",
  "USERNAME",
  "LOGNAME",
  "SHELL",
  "TERM",
  "PWD",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "TEMP",
  "TMP",
  "TMPDIR",
  // Windows needs these to run anything at all.
  "SystemRoot",
  "SYSTEMROOT",
  "SystemDrive",
  "USERPROFILE",
  "HOMEDRIVE",
  "HOMEPATH",
  "APPDATA",
  "LOCALAPPDATA",
  "ProgramData",
  "ProgramFiles",
  "ProgramFiles(x86)",
  "ProgramW6432",
  "COMSPEC",
  "PATHEXT",
  "WINDIR",
]

export function inheritedEnv(source: NodeJS.ProcessEnv = process.env): Record<string, string> {
  const env: Record<string, string> = {}
  for (const name of ALLOWLIST) {
    const value = source[name]
    if (value !== undefined) env[name] = value
  }
  // The application's own variables describe the server to its children and carry no
  // secret of the user.
  for (const [name, value] of Object.entries(source)) {
    if (name.startsWith("OCNANO_") && value !== undefined) env[name] = value
  }
  return env
}
