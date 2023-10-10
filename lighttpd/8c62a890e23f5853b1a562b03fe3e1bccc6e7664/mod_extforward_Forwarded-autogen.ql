/**
 * @name lighttpd-8c62a890e23f5853b1a562b03fe3e1bccc6e7664-mod_extforward_Forwarded
 * @id cpp/lighttpd/8c62a890e23f5853b1a562b03fe3e1bccc6e7664/mod-extforward-Forwarded
 * @description lighttpd-8c62a890e23f5853b1a562b03fe3e1bccc6e7664-src/mod_extforward.c-mod_extforward_Forwarded CVE-2022-22707
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(BreakStmt target_2, Function func) {
	exists(SubExpr target_0 |
		target_0.getValue()="255"
		and target_0.getParent().(GEExpr).getLesserOperand() instanceof DivExpr
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(BreakStmt target_2, Function func, DivExpr target_1) {
		target_1.getValue()="256"
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(BreakStmt target_2) {
		target_2.toString() = "break;"
}

from Function func, DivExpr target_1, BreakStmt target_2
where
not func_0(target_2, func)
and func_1(target_2, func, target_1)
and func_2(target_2)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
