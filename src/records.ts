import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { resolveVehicle, vehicleLabel, type RecordKind } from "./lubelogger.js";
import { KIND_LABEL, NOTES_FORMAT, fmt, guard, isRealDate, normDate, notesField, num, ownerOf, tagsField, vehicleField, type Deps } from "./tools.js";

// ---------- input fields ----------

const recordTypeField = z
  .enum(["service", "repair", "upgrade", "fuel", "odometer"])
  .describe("Which kind of record: 'service', 'repair', 'upgrade', 'fuel' or 'odometer'.");

const isoDateField = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/, "Use YYYY-MM-DD")
  .refine(isRealDate, "Not a real calendar date");

/** How a changeable field is shown in previews and lists. */
type FieldKind = "date" | "odometer" | "money" | "amount" | "flag" | "text";

const GENERIC: Record<string, FieldKind> = { date: "date", odometer: "odometer", description: "text", cost: "money", notes: "text", tags: "text" };

/** The fields each record type lets the user change. Everything else on the record is sent back as it was. */
const EDITABLE: Record<RecordKind, Record<string, FieldKind>> = {
  service: GENERIC,
  repair: GENERIC,
  upgrade: GENERIC,
  fuel: { date: "date", odometer: "odometer", fuelConsumed: "amount", cost: "money", isFillToFull: "flag", missedFuelUp: "flag", notes: "text", tags: "text" },
  odometer: { date: "date", odometer: "odometer", notes: "text", tags: "text" },
};

const LABELS: Record<string, string> = {
  date: "Date",
  odometer: "Odometer",
  description: "Description",
  cost: "Cost",
  fuelConsumed: "Fuel consumed",
  isFillToFull: "Filled to full",
  missedFuelUp: "Missed earlier fill-up",
  notes: "Notes",
  tags: "Tags",
};

// ---------- helpers ----------

/** LubeLogger may send dates as ISO or as MM/dd/yyyy (invariant culture). Returns YYYY-MM-DD when recognisable. */
function recordDate(raw: unknown): string | null {
  const s = String(raw ?? "").trim();
  const us = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})/);
  if (us) return `${us[3]}-${us[1]!.padStart(2, "0")}-${us[2]!.padStart(2, "0")}`;
  return normDate(s);
}

function show(kind: FieldKind, raw: unknown): string {
  if (kind === "date") return recordDate(raw) ?? String(raw ?? "");
  if (kind === "flag") return String(raw).toLowerCase() === "true" ? "yes" : "no";
  if (kind === "text") return String(raw ?? "");
  const n = num(raw);
  if (n === null) return "";
  if (kind === "money") return n.toFixed(2);
  // LubeLogger stores a missing odometer as 0 and shows it blank
  if (kind === "odometer") return n === 0 ? "none" : fmt(n);
  return fmt(n);
}

const count = (list: unknown, noun: string) => {
  const n = Array.isArray(list) ? list.length : 0;
  return `${n} ${noun}${n === 1 ? "" : "s"}`;
};

function recordLine(kind: RecordKind, r: Record<string, unknown>): string {
  const parts = [`- id ${String(r.id)}: ${show("date", r.date)}`];
  const odo = show("odometer", r.odometer);
  parts.push(`odometer ${odo || "none"}`);
  if (kind === "fuel") parts.push(`${show("amount", r.fuelConsumed)} fuel`);
  else if (kind !== "odometer") parts.push(String(r.description ?? "(no description)"));
  if (kind !== "odometer") parts.push(`cost ${show("money", r.cost)}`);
  parts.push(count(r.files, "attachment"));
  if (r.notes) parts.push(`notes: ${String(r.notes).slice(0, 80)}`);
  return parts.join(", ");
}

/** The record with this id, or an error naming the vehicle's most recent ones. */
function findRecord(kind: RecordKind, vehicle: string, records: Record<string, unknown>[], recordId: string | number): Record<string, unknown> {
  const found = records.find((r) => String(r.id) === String(recordId));
  if (found) return found;
  const recent = [...records]
    .sort((a, b) => (recordDate(b.date) ?? "").localeCompare(recordDate(a.date) ?? ""))
    .slice(0, 10)
    .map((r) => recordLine(kind, r))
    .join("\n");
  throw new Error(
    `${vehicle} has no ${KIND_LABEL[kind].toLowerCase()} with id ${String(recordId)}.` +
      (recent ? ` Its most recent ones:\n${recent}` : " It has none of that type."),
  );
}

const recordIdField = z.union([z.number().int(), z.string().regex(/^\d+$/)]).describe("Record id from list_records.");

// ---------- tool registration ----------

export function registerRecordTools(server: McpServer, deps: Deps): void {
  const { client, pending } = deps;

  server.registerTool(
    "list_records",
    {
      title: "List records",
      description:
        "List a vehicle's existing records of one type, newest first, with id, date, odometer, description or fuel amount, cost and attachment count. " +
        "Notes are cut short here: use get_record to read one record in full. Use it to find the record a user wants to correct before calling propose_record_update.",
      inputSchema: {
        vehicle: vehicleField,
        recordType: recordTypeField,
        since: isoDateField.optional().describe("Only records on or after this date, YYYY-MM-DD."),
        until: isoDateField.optional().describe("Only records on or before this date, YYYY-MM-DD."),
        limit: z.number().int().min(1).max(50).default(15).describe("How many records to show (newest first)."),
      },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    async (args) =>
      guard(async () => {
        const v = resolveVehicle(await client.listVehicles(), args.vehicle);
        const records = (await client.listRecords(args.recordType, v.id))
          .filter((r) => {
            const d = recordDate(r.date) ?? "";
            return (!args.since || d >= args.since) && (!args.until || d <= args.until);
          })
          .sort((a, b) => (recordDate(b.date) ?? "").localeCompare(recordDate(a.date) ?? ""));
        const head = `${vehicleLabel(v)} [id ${v.id}], ${KIND_LABEL[args.recordType].toLowerCase()}s`;
        if (!records.length) return `${head}: none found.`;
        const shown = records.slice(0, args.limit);
        const more = records.length > shown.length ? `\n(${records.length - shown.length} older not shown; narrow with since/until)` : "";
        return [`${head}:`, ...shown.map((r) => recordLine(args.recordType, r))].join("\n") + more;
      }),
  );

  server.registerTool(
    "get_record",
    {
      title: "Get record",
      description:
        "Read one existing record in full: every field, the complete notes, attachment names and extra fields. Call it before rewriting " +
        "or reformatting a record's notes, since propose_record_update replaces the whole note.",
      inputSchema: { vehicle: vehicleField, recordType: recordTypeField, recordId: recordIdField },
      annotations: { readOnlyHint: true, idempotentHint: true, openWorldHint: false },
    },
    async (args) =>
      guard(async () => {
        const kind = args.recordType;
        const v = resolveVehicle(await client.listVehicles(), args.vehicle);
        const r = findRecord(kind, vehicleLabel(v), await client.listRecords(kind, v.id), args.recordId);
        const fields = Object.entries(EDITABLE[kind])
          .filter(([field]) => field !== "notes")
          .map(([field, fieldKind]) => `- ${LABELS[field]}: ${show(fieldKind, r[field]) || "(none)"}`);
        const files = Array.isArray(r.files) ? r.files.map((f) => `  - ${String((f as Record<string, unknown>).name ?? "(unnamed)")}`) : [];
        const extras = Array.isArray(r.extraFields)
          ? r.extraFields.map((f) => `  - ${String((f as Record<string, unknown>).name)}: ${String((f as Record<string, unknown>).value ?? "")}`)
          : [];
        return [
          `${KIND_LABEL[kind]} id ${String(r.id)} for ${vehicleLabel(v)} [id ${v.id}]`,
          ...fields,
          `- Attachments: ${files.length ? "\n" + files.join("\n") : "none"}`,
          `- Extra fields: ${extras.length ? "\n" + extras.join("\n") : "none"}`,
          ``,
          `Notes (complete):`,
          String(r.notes ?? "") || "(none)",
        ].join("\n");
      }),
  );

  server.registerTool(
    "propose_record_update",
    {
      title: "Propose record update",
      description:
        "Prepare a correction to an EXISTING record. Get the id from list_records, and read the record with get_record first when changing " +
        "notes, because the notes you pass replace the whole note. Pass only the fields that change; everything else, " +
        "including attachments and extra fields, is kept exactly as it is. Nothing is saved: returns a before/after preview and a confirmation " +
        "token for commit_record. Service, repair and upgrade records can change date, odometer, description, cost, notes, tags; fuel records " +
        "date, odometer, fuelConsumed, cost, isFillToFull, missedFuelUp, notes, tags; odometer records date, odometer, notes, tags.",
      inputSchema: {
        vehicle: vehicleField,
        recordType: recordTypeField,
        recordId: recordIdField,
        date: isoDateField.optional(),
        odometer: z.number().int().min(0).max(2_000_000).optional().describe("New odometer reading. 0 means no reading (LubeLogger shows it blank)."),
        description: z.string().min(1).max(200).optional(),
        cost: z.number().min(0).max(1_000_000).optional(),
        fuelConsumed: z.number().positive().max(10_000).optional(),
        isFillToFull: z.boolean().optional(),
        missedFuelUp: z.boolean().optional(),
        notes: notesField.describe(`Replaces the existing notes. Pass an empty string to clear. ${NOTES_FORMAT}`),
        tags: tagsField,
      },
      annotations: { readOnlyHint: true, idempotentHint: false, openWorldHint: false },
    },
    async (args, extra) =>
      guard(async () => {
        const kind = args.recordType;
        const editable = EDITABLE[kind];
        const changes: Record<string, unknown> = {};
        for (const field of Object.keys(LABELS)) {
          const value = (args as Record<string, unknown>)[field];
          if (value !== undefined) changes[field] = value;
        }
        const unknownFields = Object.keys(changes).filter((f) => !(f in editable));
        if (unknownFields.length) {
          throw new Error(`${KIND_LABEL[kind]}s have no ${unknownFields.join(", ")} field. Fields that can change: ${Object.keys(editable).join(", ")}.`);
        }

        const v = resolveVehicle(await client.listVehicles(), args.vehicle);
        const records = await client.listRecords(kind, v.id);
        const cur = findRecord(kind, vehicleLabel(v), records, args.recordId);

        // LubeLogger's update overwrites every field, attachments and extra fields included, so start from the whole record as returned
        const body: Record<string, unknown> = { ...cur, ...changes, id: Number(cur.id) };

        const rows = Object.entries(editable).map(([field, fieldKind]) => {
          const before = show(fieldKind, cur[field]);
          const after = show(fieldKind, body[field]);
          return before === after
            ? `- ${LABELS[field]}: ${after || "(none)"}`
            : `- ${LABELS[field]}: ${before || "(none)"} -> ${after || "(none)"} (CHANGED)`;
        });
        const warnings = rows.some((r) => r.endsWith("(CHANGED)")) ? [] : ["Nothing changes compared to the current record."];

        const rec = pending.add({ kind, update: true, vehicleId: v.id, vehicleLabel: vehicleLabel(v), body, owner: ownerOf(extra) });
        const lines = [
          `PREVIEW: nothing has been saved yet.`,
          ``,
          `- Type: ${KIND_LABEL[kind]} update (id ${String(cur.id)})`,
          `- Vehicle: ${vehicleLabel(v)} [id ${v.id}]`,
          ...rows,
          `- Kept as is: ${count(cur.files, "attachment")}, ${count(cur.extraFields, "extra field")}`,
        ];
        if (warnings.length) lines.push(``, `Warnings:`, ...warnings.map((w) => `- ${w}`));
        lines.push(
          ``,
          `Confirmation token: ${rec.token} (valid for ${deps.ttlMinutes} minutes, single use)`,
          ``,
          `NEXT STEP: show this preview to the user and ask them to confirm or correct it. Call commit_record with the token ONLY after they explicitly confirm.`,
        );
        return lines.join("\n");
      }),
  );
}
