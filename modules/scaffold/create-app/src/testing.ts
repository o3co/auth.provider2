/**
 * For a test running a generated app as an operator runs it: the app generated and linked to the
 * workspace, and its entries run in processes of their own. Its configuration is each module's own
 * (their `./testing`), composed by the test.
 */
export {
	asOperator,
	freePort,
	generated,
	generatedBy,
	listening,
	type Running,
	running,
	scripted,
} from "./apps.ts";
