import { describe, expect, it } from "vitest";

import { errorMessage, queryParams } from "@/api/client";

describe("errorMessage", () => {
  it("returns a plain string detail unchanged", () => {
    const error = { response: { status: 400, data: { detail: "Rule not found" } } };
    expect(errorMessage(error)).toBe("Rule not found");
  });

  it("flattens FastAPI validation arrays instead of rendering [object Object]", () => {
    // This is the whole reason the helper exists: a 422 body is a list of
    // per-field objects, and passing it straight to a toast shows nothing useful.
    const error = {
      response: {
        status: 422,
        data: {
          detail: [
            { loc: ["body", "password"], msg: "String should have at least 12 characters" },
            { loc: ["body", "email"], msg: "value is not a valid email address" },
          ],
        },
      },
    };

    const message = errorMessage(error);

    expect(message).toContain("password: String should have at least 12 characters");
    expect(message).toContain("email: value is not a valid email address");
    expect(message).not.toContain("[object Object]");
  });

  it("falls back to the status code when there is no detail", () => {
    expect(errorMessage({ response: { status: 500, data: {} } }, "Save failed")).toBe(
      "Save failed (HTTP 500)",
    );
  });

  it("falls back to the supplied default for a non-HTTP failure", () => {
    expect(errorMessage({}, "Could not reach the API")).toBe("Could not reach the API");
  });
});

describe("queryParams", () => {
  it("drops undefined, null and empty-string values", () => {
    expect(
      queryParams({ status: "new", severity: undefined, search: "", assigned_to: null, limit: 25 }),
    ).toEqual({ status: "new", limit: 25 });
  });

  it("keeps false and zero, which are meaningful filter values", () => {
    // `sla_breached=false` means "not breached", not "no filter" — dropping it
    // would silently widen the query.
    expect(queryParams({ sla_breached: false, offset: 0 })).toEqual({
      sla_breached: false,
      offset: 0,
    });
  });
});
