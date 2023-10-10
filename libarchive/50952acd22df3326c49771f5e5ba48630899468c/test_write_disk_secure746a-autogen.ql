/**
 * @name libarchive-50952acd22df3326c49771f5e5ba48630899468c-test_write_disk_secure746a
 * @id cpp/libarchive/50952acd22df3326c49771f5e5ba48630899468c/test-write-disk-secure746a
 * @description libarchive-50952acd22df3326c49771f5e5ba48630899468c-libarchive/test/test_write_disk_secure746.c-test_write_disk_secure746a CVE-2016-5418
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, UnaryMinusExpr target_0) {
		target_0.getValue()="-25"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("assertion_equal_int")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getTarget().hasName("archive_write_data")
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(1) instanceof StringLiteral
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(FunctionCall).getArgument(2) instanceof Literal
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(StringLiteral).getValue()="archive_write_data(a, \"modified\", 8)"
		and target_0.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(6) instanceof Literal
		and target_0.getEnclosingFunction() = func
}

from Function func, UnaryMinusExpr target_0
where
func_0(func, target_0)
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
