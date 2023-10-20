/**
 * @name libarchive-1fa9c7bf90f0862036a99896b0501c381584451a-check_symlinks
 * @id cpp/libarchive/1fa9c7bf90f0862036a99896b0501c381584451a/check-symlinks
 * @description libarchive-1fa9c7bf90f0862036a99896b0501c381584451a-libarchive/archive_write_disk_posix.c-check_symlinks CVE-2016-5418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(EqualityOperation target_2, Function func) {
	exists(ReturnStmt target_0 |
		target_0.getExpr().(UnaryMinusExpr).getValue()="-25"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_2
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(EqualityOperation target_2, Function func, BreakStmt target_1) {
		target_1.toString() = "break;"
		and target_1.getParent().(IfStmt).getCondition()=target_2
		and target_1.getEnclosingFunction() = func
}

predicate func_2(EqualityOperation target_2) {
		target_2.getAnOperand().(PointerDereferenceExpr).getOperand().(FunctionCall).getTarget().hasName("__errno_location")
		and target_2.getAnOperand().(Literal).getValue()="2"
}

from Function func, BreakStmt target_1, EqualityOperation target_2
where
not func_0(target_2, func)
and func_1(target_2, func, target_1)
and func_2(target_2)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
