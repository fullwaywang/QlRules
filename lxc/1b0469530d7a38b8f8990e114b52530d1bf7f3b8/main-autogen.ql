/**
 * @name lxc-1b0469530d7a38b8f8990e114b52530d1bf7f3b8-main
 * @id cpp/lxc/1b0469530d7a38b8f8990e114b52530d1bf7f3b8/main
 * @description lxc-1b0469530d7a38b8f8990e114b52530d1bf7f3b8-src/lxc/cmd/lxc_user_nic.c-main CVE-2022-47952
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="%s: %d: %s: Failed to open \"%s\"\n"
		and not target_0.getValue()="%s: %d: %s: Failed while opening netns file for \"%s\"\n"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="%s: %d: %s: Path \"%s\" does not refer to a network namespace path\n"
		and not target_1.getValue()="%s: %d: %s: Failed while opening netns file for \"%s\"\n"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, StringLiteral target_2) {
		target_2.getValue()="%s: %d: %s - %s - Failed to open \"%s\"\n\n"
		and not target_2.getValue()="%s: %d: %s - %s - Failed while opening netns file for \"%s\"\n\n"
		and target_2.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0, StringLiteral target_1, StringLiteral target_2
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
