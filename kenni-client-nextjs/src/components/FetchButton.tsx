"use client";

import { useState } from "react";

type FetchButtonProps = {
  onFetched(data: Record<string, unknown>): void;
};

export const FetchButton = ({ onFetched }: FetchButtonProps) => {
  const [loading, setLoading] = useState(false);

  const getData = async () => {
    setLoading(true);

    try {
      const response = await fetch("/api/protected", {
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
    <div>
      <button
        onClick={getData}
        disabled={loading}
        style={{ minWidth: "200px" }}
      >
        {loading ? "loading..." : "Access protected resource"}
      </button>
    </div>
  );
};
