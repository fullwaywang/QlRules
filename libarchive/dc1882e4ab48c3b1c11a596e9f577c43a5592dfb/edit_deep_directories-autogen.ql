/**
 * @name libarchive-dc1882e4ab48c3b1c11a596e9f577c43a5592dfb-edit_deep_directories
 * @id cpp/libarchive/dc1882e4ab48c3b1c11a596e9f577c43a5592dfb/edit-deep-directories
 * @description libarchive-dc1882e4ab48c3b1c11a596e9f577c43a5592dfb-libarchive/archive_write_disk_posix.c-edit_deep_directories CVE-2016-5418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(ReturnStmt target_8, Function func) {
	exists(RelationalOperation target_0 |
		 (target_0 instanceof GTExpr or target_0 instanceof LTExpr)
		and target_0.getLesserOperand() instanceof FunctionCall
		and target_0.getGreaterOperand() instanceof Literal
		and target_0.getParent().(IfStmt).getThen()=target_8
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand() instanceof FunctionCall
		and target_1.getLesserOperand() instanceof Literal
		and target_1.getEnclosingFunction() = func)
}

predicate func_2(Variable vtail_1796, FunctionCall target_2) {
		target_2.getTarget().hasName("strlen")
		and target_2.getArgument(0).(VariableAccess).getTarget()=vtail_1796
}

predicate func_3(Variable vtail_1796, FunctionCall target_3) {
		target_3.getTarget().hasName("strlen")
		and target_3.getArgument(0).(VariableAccess).getTarget()=vtail_1796
}

predicate func_6(ReturnStmt target_8, Function func, RelationalOperation target_6) {
		 (target_6 instanceof GEExpr or target_6 instanceof LEExpr)
		and target_6.getLesserOperand() instanceof FunctionCall
		and target_6.getGreaterOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen()=target_8
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand() instanceof FunctionCall
		and target_7.getLesserOperand() instanceof Literal
		and target_7.getEnclosingFunction() = func
}

predicate func_8(ReturnStmt target_8) {
		target_8.toString() = "return ..."
}

from Function func, Variable vtail_1796, FunctionCall target_2, FunctionCall target_3, RelationalOperation target_6, RelationalOperation target_7, ReturnStmt target_8
where
not func_0(target_8, func)
and not func_1(func)
and func_2(vtail_1796, target_2)
and func_3(vtail_1796, target_3)
and func_6(target_8, func, target_6)
and func_7(func, target_7)
and func_8(target_8)
and vtail_1796.getType().hasName("char *")
and vtail_1796.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
