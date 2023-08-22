/**
 * @name redis-c6ad876774f3cc11e32681ea02a2eead00f2c521-sdsMakeRoomFor
 * @id cpp/redis/c6ad876774f3cc11e32681ea02a2eead00f2c521/sdsMakeRoomFor
 * @description redis-c6ad876774f3cc11e32681ea02a2eead00f2c521-src/sds.c-sdsMakeRoomFor CVE-2021-41099
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_208, Variable vnewlen_208, VariableAccess target_0) {
		target_0.getTarget()=vlen_208
		and target_0.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_0.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vnewlen_208
		and target_0.getParent().(GTExpr).getGreaterOperand().(AddExpr).getAnOperand() instanceof Literal
}

predicate func_1(Function func, StringLiteral target_1) {
		target_1.getValue()="hdrlen + newlen + 1 > len"
		and not target_1.getValue()="hdrlen + newlen + 1 > reqlen"
		and target_1.getEnclosingFunction() = func
}

predicate func_3(Function func) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getType().hasName("size_t")
		and target_3.getRValue() instanceof AssignExpr
		and target_3.getEnclosingFunction() = func)
}

predicate func_4(Parameter vaddlen_205, Variable vlen_208, Variable vnewlen_208, AssignExpr target_4) {
		target_4.getLValue().(VariableAccess).getTarget()=vnewlen_208
		and target_4.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen_208
		and target_4.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vaddlen_205
}

from Function func, Parameter vaddlen_205, Variable vlen_208, Variable vnewlen_208, VariableAccess target_0, StringLiteral target_1, AssignExpr target_4
where
func_0(vlen_208, vnewlen_208, target_0)
and func_1(func, target_1)
and not func_3(func)
and func_4(vaddlen_205, vlen_208, vnewlen_208, target_4)
and vaddlen_205.getType().hasName("size_t")
and vlen_208.getType().hasName("size_t")
and vnewlen_208.getType().hasName("size_t")
and vaddlen_205.getFunction() = func
and vlen_208.(LocalVariable).getFunction() = func
and vnewlen_208.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
