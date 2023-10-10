/**
 * @name lua-066e0f93c4901e601d93e31fb700f8f66f95feb8-GCTM
 * @id cpp/lua/066e0f93c4901e601d93e31fb700f8f66f95feb8/GCTM
 * @description lua-066e0f93c4901e601d93e31fb700f8f66f95feb8-lgc.c-GCTM CVE-2021-44964
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, StringLiteral target_0) {
		target_0.getValue()="__gc metamethod"
		and not target_0.getValue()="__gc"
		and target_0.getEnclosingFunction() = func
}

from Function func, StringLiteral target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
