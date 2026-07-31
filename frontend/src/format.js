export function formatTimestamp(iso) {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
        " " +
        d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
