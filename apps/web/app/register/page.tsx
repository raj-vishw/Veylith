"use client";
import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button, ErrorBox, Field, Input } from "@/components/ui";
import { AuthFrame } from "@/components/auth-frame";
import { post } from "@/lib/api";

const schema = z.object({
  organization_name: z.string().trim().min(2, "At least 2 characters").max(200),
  display_name: z.string().trim().max(200).optional(),
  email: z.string().trim().min(1, "Email is required").email("Enter a valid email"),
  password: z.string().min(12, "At least 12 characters").max(200),
});
type Values = z.infer<typeof schema>;

export default function RegisterPage() {
  const { register, handleSubmit, formState } = useForm<Values>({ resolver: zodResolver(schema) });
  const [error, setError] = useState<unknown>(null);

  const submit = handleSubmit(async (values) => {
    setError(null);
    try {
      await post("/auth/register", { ...values, display_name: values.display_name ?? "" });
      window.location.assign("/");
    } catch (err) {
      setError(err);
    }
  });

  return (
    <AuthFrame>
      <div>
        <h1 className="text-4xl">Create your workspace</h1>
        <p className="mb-6 mt-1 text-sm text-slate-600">You become the owner of the new organization.</p>
        <form onSubmit={submit} className="space-y-4" noValidate>
          <Field label="Organization name" error={formState.errors.organization_name?.message}>
            <Input {...register("organization_name")} />
          </Field>
          <Field label="Your name">
            <Input {...register("display_name")} />
          </Field>
          <Field label="Email" error={formState.errors.email?.message}>
            <Input type="email" autoComplete="username" {...register("email")} />
          </Field>
          <Field label="Password" hint="At least 12 characters." error={formState.errors.password?.message}>
            <Input type="password" autoComplete="new-password" {...register("password")} />
          </Field>
          <ErrorBox error={error} />
          <Button type="submit" disabled={formState.isSubmitting} className="w-full">
            {formState.isSubmitting ? "Creating…" : "Create workspace"}
          </Button>
        </form>
        <p className="mt-5 text-center text-sm text-slate-600">
          Already have an account?{" "}
          <Link href="/login" className="font-medium text-brand hover:underline">
            Sign in
          </Link>
        </p>
      </div>
    </AuthFrame>
  );
}
