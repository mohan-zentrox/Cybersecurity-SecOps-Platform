import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";

import { Navbar } from "@/components/Navbar";
import { ProtectedRoute } from "@/components/ProtectedRoute";
import { formatMinutes, formatRelative, Pagination } from "@/components/ui";
import { useAuthStore } from "@/store/authStore";

function signIn(role: "analyst" | "detection-engineer" | "compliance" | "admin") {
  useAuthStore.setState({ token: "test-token", username: "tester", role, userId: 1 });
}

function signOut() {
  useAuthStore.setState({ token: null, username: null, role: null, userId: null });
}

describe("formatMinutes", () => {
  it("distinguishes 'no data' from zero", () => {
    // An empty MTTR must not read as "we resolve everything instantly".
    expect(formatMinutes(null)).toBe("—");
    expect(formatMinutes(undefined)).toBe("—");
    expect(formatMinutes(0)).toBe("0m");
  });

  it("scales the unit with the magnitude", () => {
    expect(formatMinutes(45)).toBe("45m");
    expect(formatMinutes(90)).toBe("1.5h");
    expect(formatMinutes(2880)).toBe("2.0d");
  });
});

describe("formatRelative", () => {
  it("marks past deadlines as overdue", () => {
    const past = new Date(Date.now() - 30 * 60 * 1000).toISOString();
    expect(formatRelative(past)).toContain("overdue");
  });

  it("shows future deadlines as remaining time", () => {
    const future = new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString();
    expect(formatRelative(future)).toBe("in 2h");
  });

  it("handles a missing deadline", () => {
    expect(formatRelative(null)).toBe("—");
  });
});

describe("Pagination", () => {
  it("renders nothing when everything fits on one page", () => {
    const { container } = render(
      <Pagination total={10} limit={25} offset={0} onChange={() => undefined} />,
    );
    expect(container).toBeEmptyDOMElement();
  });

  it("disables Previous on the first page and advances on Next", async () => {
    const onChange = vi.fn();
    render(<Pagination total={100} limit={25} offset={0} onChange={onChange} />);

    expect(screen.getByText("1–25 of 100")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();

    await userEvent.click(screen.getByRole("button", { name: "Next" }));
    expect(onChange).toHaveBeenCalledWith(25);
  });

  it("disables Next on the final page", () => {
    render(<Pagination total={100} limit={25} offset={75} onChange={() => undefined} />);
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    expect(screen.getByText("76–100 of 100")).toBeInTheDocument();
  });
});

describe("Navbar role gating", () => {
  it("hides admin and compliance sections from an analyst", () => {
    signIn("analyst");
    render(
      <MemoryRouter>
        <Navbar />
      </MemoryRouter>,
    );

    expect(screen.getByText("Alerts")).toBeInTheDocument();
    expect(screen.getByText("Cases")).toBeInTheDocument();
    expect(screen.queryByText("Settings")).not.toBeInTheDocument();
    expect(screen.queryByText("Audit")).not.toBeInTheDocument();
    expect(screen.queryByText("Compliance")).not.toBeInTheDocument();
  });

  it("shows the audit and compliance sections to a compliance user, but not alert triage", () => {
    signIn("compliance");
    render(
      <MemoryRouter>
        <Navbar />
      </MemoryRouter>,
    );

    expect(screen.getByText("Audit")).toBeInTheDocument();
    expect(screen.getByText("Compliance")).toBeInTheDocument();
    expect(screen.queryByText("Alerts")).not.toBeInTheDocument();
    expect(screen.queryByText("Settings")).not.toBeInTheDocument();
  });

  it("shows everything to an admin", () => {
    signIn("admin");
    render(
      <MemoryRouter>
        <Navbar />
      </MemoryRouter>,
    );

    for (const label of ["Dashboard", "Alerts", "Cases", "Detection", "Audit", "Settings"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
  });

  it("renders nothing when signed out", () => {
    signOut();
    const { container } = render(
      <MemoryRouter>
        <Navbar />
      </MemoryRouter>,
    );
    expect(container).toBeEmptyDOMElement();
  });
});

describe("ProtectedRoute", () => {
  it("explains a role denial rather than showing a blank page", () => {
    signIn("analyst");
    render(
      <MemoryRouter>
        <ProtectedRoute roles={["admin"]}>
          <div>secret settings</div>
        </ProtectedRoute>
      </MemoryRouter>,
    );

    expect(screen.getByText("Not permitted")).toBeInTheDocument();
    expect(screen.queryByText("secret settings")).not.toBeInTheDocument();
  });

  it("renders the page when the role is allowed", () => {
    signIn("admin");
    render(
      <MemoryRouter>
        <ProtectedRoute roles={["admin"]}>
          <div>secret settings</div>
        </ProtectedRoute>
      </MemoryRouter>,
    );

    expect(screen.getByText("secret settings")).toBeInTheDocument();
  });

  it("redirects an unauthenticated visitor away from the page", () => {
    signOut();
    render(
      <MemoryRouter>
        <ProtectedRoute>
          <div>private</div>
        </ProtectedRoute>
      </MemoryRouter>,
    );

    expect(screen.queryByText("private")).not.toBeInTheDocument();
  });
});
