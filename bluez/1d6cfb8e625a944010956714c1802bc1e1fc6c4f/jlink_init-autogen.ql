/**
 * @name bluez-1d6cfb8e625a944010956714c1802bc1e1fc6c4f-jlink_init
 * @id cpp/bluez/1d6cfb8e625a944010956714c1802bc1e1fc6c4f/jlink-init
 * @description bluez-1d6cfb8e625a944010956714c1802bc1e1fc6c4f-monitor/jlink.c-jlink_init CVE-2022-3637
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vso_83, ExprStmt target_1, Function func, ExprStmt target_0) {
		target_0.getExpr().(FunctionCall).getTarget().hasName("dlclose")
		and target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vso_83
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_1(Variable vso_83, ExprStmt target_1) {
		target_1.getExpr().(FunctionCall).getTarget().hasName("dlclose")
		and target_1.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vso_83
}

from Function func, Variable vso_83, ExprStmt target_0, ExprStmt target_1
where
func_0(vso_83, target_1, func, target_0)
and func_1(vso_83, target_1)
and vso_83.getType().hasName("void *")
and vso_83.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
