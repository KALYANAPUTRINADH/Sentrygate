export function logOperational(level, event, fields = {}) {
  const record = { timestamp: new Date().toISOString(), level, service: "sentrygate", event, ...fields };
  const line = JSON.stringify(record);
  if (level === "error") console.error(line);
  else console.log(line);
}
