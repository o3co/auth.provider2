// The part of http's contract a server alone takes: the constructors of a request's values, the rule
// a server guards the routes by, refusing boot on what it finds, and a JSON answer as it is written.
export { guardedRoutes } from "./guards/guards.ts";
export { fieldsOf, readOnly, valuesOf } from "./values/values.ts";
export { writtenJson } from "./written/written.ts";
