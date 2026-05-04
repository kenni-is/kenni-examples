"use client";

import { useState } from "react";

type FetchButtonProps = {
  title: string;
  url: string;
  method?: "GET" | "POST";
  onFetched(data: Record<string, unknown>): void;
};

export const FetchButton = ({
  title,
  url,
  method = "GET",
  onFetched,
}: FetchButtonProps) => {
  const [loading, setLoading] = useState(false);

  const getData = async () => {
    setLoading(true);
    try {
      const response = await fetch(url, {
        method,
        credentials: "include",
      });
      const data = await response.json();
      onFetched(data);
    } catch (error) {
      onFetched({ error: (error as { message: string }).message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <button onClick={getData} disabled={loading} style={{ minWidth: "200px" }}>
      {loading ? "loading..." : title}
    </button>
  );
};
