"use client";
import { zodResolver } from "@hookform/resolvers/zod";
import Link from "next/link";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { Button, ErrorBox, Field, Input } from "@/components/ui";
import { AuthFrame } from "@/components/auth-frame";
import { ApiError, post } from "@/lib/api";

const schema = z.object({ email: z.string().trim().min(1, "Email is required").email("Enter a valid email"), password: z.string().min(1, "Password is required") });
type Values = z.infer<typeof schema>;

export default function LoginPage() {
  const { register, handleSubmit, formState } = useForm<Values>({ resolver: zodResolver(schema) });
  const [error, setError] = useState<unknown>(null);

  const submit = handleSubmit(async (values) => {
    setError(null);
    try {
      await post("/auth/login", values);
      window.location.assign("/");
    } catch (err) {
      setError(err instanceof ApiError && err.status === 401 ? new Error("Invalid email or password") : err);
    }
  });

  return (
    <AuthFrame>
      <div>
        <h1 className="text-4xl">Veylith</h1>
        <p className="mb-6 mt-1 text-sm text-slate-600">From external threat to customer-specific investigation.</p>
        <form onSubmit={submit} className="space-y-4" noValidate>
          <Field label="Email" error={formState.errors.email?.message}>
            <Input type="email" autoComplete="username" {...register("email")} />
          </Field>
          <Field label="Password" error={formState.errors.password?.message}>
            <Input type="password" autoComplete="current-password" {...register("password")} />
          </Field>
          <ErrorBox error={error} />
          <Button type="submit" disabled={formState.isSubmitting} className="w-full">
            {formState.isSubmitting ? "Signing in…" : "Sign in"}
          </Button>
        </form>
        <p className="mt-5 text-center text-sm text-slate-600">
          New organization?{" "}
          <Link href="/register" className="font-medium text-brand hover:underline">
            Create a workspace
          </Link>
        </p>
      </div>
    </AuthFrame>
  );
}
