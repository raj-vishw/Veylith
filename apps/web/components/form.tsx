"use client";
import { zodResolver } from "@hookform/resolvers/zod";
import { useEffect, useMemo, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button, ErrorBox, Field, Input, Modal, Select, Textarea } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { humanize } from "@/lib/utils";

export interface FieldDef {
  name: string;
  label: string;
  type?: "text" | "textarea" | "select" | "checkbox" | "date" | "url";
  options?: (string | { value: string; label: string })[];
  required?: boolean;
  hint?: string;
  placeholder?: string;
  maxLength?: number;
}

/** Client-side validation mirrors the server rules for fast feedback; the API remains authoritative. */
export function buildSchema(fields: FieldDef[]) {
  const shape: Record<string, z.ZodTypeAny> = {};
  for (const f of fields) {
    if (f.type === "checkbox") {
      shape[f.name] = z.boolean().optional();
      continue;
    }
    let s = z.string().trim();
    if (f.maxLength) s = s.max(f.maxLength, `At most ${f.maxLength} characters`);
    shape[f.name] = f.required ? s.min(1, `${f.label} is required`) : s.optional();
  }
  return z.object(shape);
}

export function FormModal({
  open,
  title,
  fields,
  initial,
  submitLabel = "Save",
  onClose,
  onSubmit,
}: {
  open: boolean;
  title: string;
  fields: FieldDef[];
  initial?: Record<string, any>;
  submitLabel?: string;
  onClose: () => void;
  onSubmit: (values: Record<string, any>) => Promise<unknown>;
}) {
  const schema = useMemo(() => buildSchema(fields), [fields]);
  const form = useForm<Record<string, any>>({ resolver: zodResolver(schema) as any, defaultValues: {} });
  const [serverError, setServerError] = useState<unknown>(null);
  const { register, handleSubmit, reset, formState } = form;

  // Reset only when the dialog opens: `initial` is usually a new object on every parent render, and
  // depending on it would wipe what the user is typing whenever background data refreshes.
  useEffect(() => {
    if (open) {
      reset({ ...(initial ?? {}) });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const close = () => {
    setServerError(null);
    onClose();
  };

  const submit = handleSubmit(async (values) => {
    setServerError(null);
    try {
      const cleaned: Record<string, any> = {};
      for (const f of fields) {
        const v = values[f.name];
        if (f.type === "checkbox") cleaned[f.name] = !!v;
        else if (v !== undefined && v !== "") cleaned[f.name] = v;
        else if (initial && f.name in initial && initial[f.name]) cleaned[f.name] = f.type === "date" ? null : "";
      }
      await onSubmit(cleaned);
      close();
    } catch (err) {
      setServerError(err);
    }
  });

  const fieldError = (name: string) => {
    const e = formState.errors[name]?.message;
    return typeof e === "string" ? e : undefined;
  };
  // Server-side validation errors that name a field are shown next to it as well as in the summary.
  const serverFieldError = (name: string) => (serverError instanceof ApiError ? serverError.errors?.find((e) => e.loc[e.loc.length - 1] === name)?.msg : undefined);

  return (
    <Modal open={open} title={title} onClose={close}>
      <form onSubmit={submit} className="space-y-4" noValidate>
        {fields.map((f) => (
          <Field key={f.name} label={f.label} hint={f.hint} error={fieldError(f.name) ?? serverFieldError(f.name)}>
            {f.type === "textarea" ? (
              <Textarea {...register(f.name)} maxLength={f.maxLength} placeholder={f.placeholder} />
            ) : f.type === "select" ? (
              <Select {...register(f.name)}>
                {!f.required && <option value="">—</option>}
                {f.required && <option value="">Select…</option>}
                {f.options?.map((o) => {
                  const opt = typeof o === "string" ? { value: o, label: humanize(o) } : o;
                  return (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  );
                })}
              </Select>
            ) : f.type === "checkbox" ? (
              <input type="checkbox" className="h-4 w-4 rounded border-slate-300" {...register(f.name)} />
            ) : (
              <Input type={f.type === "date" ? "date" : "text"} {...register(f.name)} maxLength={f.maxLength} placeholder={f.placeholder} />
            )}
          </Field>
        ))}
        <ErrorBox error={serverError} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={close}>
            Cancel
          </Button>
          <Button type="submit" disabled={formState.isSubmitting}>
            {formState.isSubmitting ? "Saving…" : submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  );
}
