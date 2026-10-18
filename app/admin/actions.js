"use server";

import { redirect } from "next/navigation";
import { createSessionClient } from "@/lib/supabase/server";

export async function masuk(prevState, formData) {
  const data = formData instanceof FormData ? formData : prevState;
  const email = data?.get("email");
  const password = data?.get("password");

  if (!email || !password) {
    return { error: "Email dan password wajib diisi." };
  }

  let errorMessage = null;

  try {
    const supabase = await createSessionClient();
    const { error } = await supabase.auth.signInWithPassword({
      email: String(email).trim(),
      password: String(password),
    });

    if (error) {
      if (
        error.message === "Invalid login credentials" ||
        error.status === 400
      ) {
        errorMessage = "Email atau password salah.";
      } else if (error.message?.includes("Email not confirmed")) {
        errorMessage = "Email belum dikonfirmasi.";
      } else if (error.status === 429) {
        errorMessage = "Terlalu banyak percobaan masuk. Silakan tunggu beberapa saat.";
      } else {
        errorMessage = error.message || "Gagal masuk. Periksa kembali email dan password.";
      }
    }
  } catch (err) {
    errorMessage = err.message || "Terjadi kesalahan pada server.";
  }

  if (errorMessage) {
    return { error: errorMessage };
  }

  redirect("/admin");
}

export async function keluar() {
  const supabase = await createSessionClient();
  await supabase.auth.signOut();
  redirect("/admin/login");
}

export async function login(prevState, formData) {
  return masuk(prevState, formData);
}

export async function logout() {
  return keluar();
}

export async function gantiPassword(prevState, formData) {
  const data = formData instanceof FormData ? formData : prevState;
  const passwordBaru = data?.get("password_baru");
  const konfirmasiPassword = data?.get("konfirmasi_password");

  if (!passwordBaru || !konfirmasiPassword) {
    return { error: "Password baru dan konfirmasi password wajib diisi." };
  }

  if (String(passwordBaru).length < 8) {
    return { error: "Password baru minimal 8 karakter." };
  }

  if (passwordBaru !== konfirmasiPassword) {
    return { error: "Password baru dan konfirmasi password tidak sama." };
  }

  try {
    const supabase = await createSessionClient();
    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();

    if (userError || !user) {
      return { error: "Sesi login tidak ditemukan. Silakan login kembali." };
    }

    const { error } = await supabase.auth.updateUser({
      password: String(passwordBaru),
    });

    if (error) {
      return { error: error.message || "Gagal mengganti password." };
    }

    return { success: "Password berhasil diganti." };
  } catch (err) {
    return { error: err.message || "Terjadi kesalahan pada server saat mengganti password." };
  }
}

export async function changePassword(prevState, formData) {
  return gantiPassword(prevState, formData);
}
