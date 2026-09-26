import "@testing-library/jest-dom/vitest";
import { afterEach } from "vitest";
import { cleanup } from "@testing-library/react";

// Unmount between tests so a component from one test cannot satisfy a query
// in the next and make a broken assertion look like it passed.
afterEach(() => {
  cleanup();
  window.localStorage.clear();
});
